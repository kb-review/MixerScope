import re

import pytest
from pydantic import ValidationError

from mixerscope.schema import (
    Attr, Attribute, InvariantLiteral, Pattern, ServiceEntry, Template, Tier, template_to_regex,
)

HEX64 = "a" * 32 + "b" * 32
OBS = [{"id": "obs-flow", "kind": "capture_flow", "provenance_class": "instrumentation", "tier": 0},
       {"id": "obs-disk", "kind": "disk_image", "provenance_class": "subject_evidence", "tier": 1},
       {"id": "obs-pages", "kind": "operator_page", "provenance_class": "operator_claim", "tier": 0}]


def entry(**sections):
    base = {"service": {"id": "stub", "display_name": "Stub"}, "observations": OBS}
    base.update(sections)
    return ServiceEntry.model_validate(base)


# ---- Attribute rules -----------------------------------------------------------------


def test_attribute_requires_sources_unless_unknown():
    with pytest.raises(ValidationError, match="at least one source"):
        Attribute[str](value="x", tier=0, basis="observed")
    u = Attribute[str].unknown(0, "later")
    assert u.value is None and not u.is_known()
    with pytest.raises(ValidationError, match="must not cite sources"):
        Attribute[str](tier=0, basis="unknown", sources=["obs-flow"])
    with pytest.raises(ValidationError, match="requires a value"):
        Attribute[str](tier=0, basis="observed", sources=["obs-flow"])


def test_instance_data_rejected_in_values_and_notes():
    with pytest.raises(ValidationError, match="case findings"):
        Attribute[str](value=f"seen {HEX64}", tier=0, basis="observed", sources=["obs-flow"])
    with pytest.raises(ValidationError, match="instance data"):
        Attr(tier=0, basis="observed", sources=["obs-flow"], notes="bc1q" + "q" * 38)


def test_pattern_template_literal():
    p = Pattern(regex=r"^Letter_<order_id>\.txt$", describes="order_id")
    assert p.compile(order_id_regex=r"^[0-9a-f]{14}\.\d+$").match("Letter_6a6000000abcde.12345678.txt")
    with pytest.raises(ValidationError, match="unknown placeholder"):
        Pattern(regex="<nope>")
    with pytest.raises(ValidationError, match="regular expression"):
        Pattern(regex="[unclosed")
    t = Template(text="Completed with TXID: <txid_hex64>", yields=["payout_txid"])
    assert re.search(t.to_regex(), f"Completed  with TXID: {HEX64}")
    with pytest.raises(ValidationError, match="instance data"):
        Template(text=f"Completed with TXID: {HEX64}")
    with pytest.raises(ValidationError):
        InvariantLiteral(literal="1" + "A" * 33, justification="short")
    lit = InvariantLiteral(literal="1" + "A" * 33, justification="fixed signing key shared by every letter")
    assert lit.literal.startswith("1")


def test_template_to_regex_relaxes_whitespace():
    rx = template_to_regex("Amount: <amount_btc> BTC | HASH: <txid_hex64>")
    assert re.search(rx, "Amount: 0.0025 BTC|HASH:" + HEX64)
    assert re.search(rx, "Amount:  1.5  BTC | HASH: " + HEX64)


# ---- cross references ----------------------------------------------------------------


def test_minimal_entry_and_introspection():
    e = entry(identity={"domains": [{"domain": "stub.test", "role": "canonical",
                                     "attr": {"tier": 0, "basis": "observed", "sources": ["obs-flow"]}}]})
    assert e.max_tier() == Tier.NO_FUNDS and e.canonical_domain() == "stub.test"
    assert e.coverage_by_tier()[0] == 1 and e.unknown_attrs() == []


def test_unknown_observation_id_fails():
    with pytest.raises(ValidationError, match="unknown observation id"):
        entry(identity={"cdn_proxy": {"value": "x", "tier": 0, "basis": "observed", "sources": ["nope"]}})


def test_tier_cannot_exceed_source_tier():
    with pytest.raises(ValidationError, match="exceeds the highest tier"):
        entry(identity={"cdn_proxy": {"value": "x", "tier": 1, "basis": "observed", "sources": ["obs-flow"]}})
    entry(identity={"cdn_proxy": {"value": "x", "tier": 0, "basis": "observed", "sources": ["obs-disk"]}})


def test_claimed_needs_operator_source():
    with pytest.raises(ValidationError, match="operator_claim"):
        entry(access={"kyc": {"value": False, "tier": 0, "basis": "claimed", "sources": ["obs-flow"]}})
    entry(access={"kyc": {"value": False, "tier": 0, "basis": "claimed", "sources": ["obs-pages"]}})


def test_retention_stated_policy_must_be_claimed():
    with pytest.raises(ValidationError, match="must be 'claimed'"):
        entry(retention={"stated_policy": [{"value": "no logs", "tier": 0, "basis": "observed", "sources": ["obs-pages"]}]})
    e = entry(retention={"stated_policy": [{"value": "no logs", "tier": 0, "basis": "claimed", "sources": ["obs-pages"]}]})
    assert e.retention.stated_policy[0].basis == "claimed"


def test_endpoint_and_artifact_references():
    ep = {"id": "check", "method": "post", "path": {"regex": "^/check$"}, "purpose": "p"}
    with pytest.raises(ValidationError, match="endpoint_ref"):
        entry(endpoints=[ep], status={"endpoint_ref": "nope"})
    e = entry(endpoints=[ep], status={"endpoint_ref": "check"})
    assert e.endpoints[0].method == "POST"
    art = {"id": "a1", "name": "A", "location": "chrome_cache", "produced_by": "nope"}
    with pytest.raises(ValidationError, match="produced_by"):
        entry(endpoints=[ep], artifacts=[art])
    art["produced_by"] = "client_js"
    with pytest.raises(ValidationError, match="unknown artifact id"):
        entry(endpoints=[ep], artifacts=[art], fact_coverage=[{"fact": "order_id", "best_persistence": "disk", "artifacts": ["zz"]}])
    e = entry(endpoints=[ep], artifacts=[art], fact_coverage=[{"fact": "order_id", "best_persistence": "disk", "artifacts": ["a1"]}])
    assert e.artifact("a1").location == "chrome_cache"


def test_duplicate_ids_and_vocab_enforced():
    ep = {"id": "x", "method": "GET", "path": {"regex": "^/$"}, "purpose": "p"}
    with pytest.raises(ValidationError, match="duplicate endpoint"):
        entry(endpoints=[ep, ep])
    with pytest.raises(ValidationError):
        entry(artifacts=[{"id": "a", "name": "A", "location": "firefox_history"}])
    with pytest.raises(ValidationError):
        entry(schema_version="9.9")
