"""The shipped seed entries validate, are correctly tiered, and contain no instance data."""

import copy
import re

import pytest
import yaml
from pydantic import ValidationError

from mixerscope.knowledge_base import SERVICES_DIR, load_all_seeds, load_service_yaml
from mixerscope.schema import CachePolicy, Fact, GateMechanism, InvariantLiteral, Location, PersistenceClass, ServiceEntry, Tier
from mixerscope.schema.guards import find_instance_data

HEX64 = "a" * 32 + "b" * 32


@pytest.fixture(scope="module")
def seeds():
    return load_all_seeds()


def test_all_seed_files_validate(seeds):
    assert "mixero" in seeds  # further services may be added by the analyst at any time


def test_raw_yaml_files_contain_no_instance_data():
    """Meta-check over the raw text: nothing instance-like except declared InvariantLiterals."""
    for path in SERVICES_DIR.glob("*.yaml"):
        text = path.read_text(encoding="utf-8")
        for lit in re.findall(r"literal:\s*([^\s,}]+)", text):
            text = text.replace(lit, "<declared-literal>")
        assert find_instance_data(text) is None, path


# ---- Mixero --------------------------------------------------------------------------


def test_mixero_fully_tiered(seeds):
    m: ServiceEntry = seeds["mixero"]
    assert m.max_tier() == Tier.FUNDED and set(m.service.tiers_completed) == {0, 1}
    cov = m.coverage_by_tier()
    assert cov[0] > cov[1] > 0, cov  # most facts need no funds; the funded ones are the post-payment states, retention, on-chain
    # the only unknowns are deliberate (letter gate not tested, fee coverage unchecked)
    assert all(p.startswith(("endpoints[", "receipts[")) for p in m.unknown_attrs())  # letter gate, signature verification


def test_mixero_key_invariants(seeds):
    m = seeds["mixero"]
    assert m.canonical_domain() == "mixero.io"
    assert m.order_id_regex() == r"^[0-9a-f]{14}\.\d+$"
    ck = {c.name: c for c in m.cookies}
    assert ck["ci_session"].encodes_fact == [Fact.SESSION_ID] and ck["__ddg9_"].encodes_fact == [Fact.CLIENT_IP]
    ep = {e.id: e for e in m.endpoints}
    assert ep["check_transaction"].cache_policy.value == CachePolicy.NO_STORE
    assert ep["check_transaction"].ownership_check.value is False
    assert ep["check_transaction"].field_facts["bitcoin_address"] == Fact.DEPOSIT_ADDRESS
    assert ep["letter"].cache_policy.value == CachePolicy.CACHEABLE_HEURISTIC
    assert ep["letter"].field_facts == {"address": Fact.DEPOSIT_ADDRESS, "session": Fact.ORDER_ID, "mode": Fact.MIX_MODE}
    assert m.status.endpoint_ref == "check_transaction"
    assert [s.label for s in m.status.states] == ["awaiting", "detected", "mixing", "completed"]
    assert m.status.states[3].template.yields == [Fact.PAYOUT_TXID]


def test_mixero_templates_match_shaped_text(seeds):
    m = seeds["mixero"]
    detected = m.status.states[1].template.compile()
    assert detected.search(f"We have detected a transaction. Waiting for 1 confirmation... <br> Incoming amount: 0.0025 BTC | HASH: {HEX64}")
    assert detected.search(f"We have detected a transaction. Waiting for 1 confirmation...<br>Incoming amount: 0.0025 BTC | HASH:{HEX64}")
    letter = m.artifact("letter_file").filename_pattern.compile(order_id_regex=m.order_id_regex())
    assert letter.match("Letter_6a6000000abcde.12345678.txt") and not letter.match("Letter_x.txt")


def test_mixero_artifacts_and_coverage(seeds):
    m = seeds["mixero"]
    arts = {a.id: a for a in m.artifacts}
    assert "status_response_memory" not in arts  # memory is out of the KB's scope
    assert arts["destination_autofill"].location == Location.CHROME_AUTOFILL
    assert Fact.DESTINATION_ADDRESS in arts["destination_autofill"].carries_facts
    cov = {c.fact: c for c in m.fact_coverage}
    assert set(cov) == set(Fact), "one coverage row per canonical fact"
    assert cov[Fact.PAYOUT_TXID].best_persistence == PersistenceClass.ON_CHAIN
    assert cov[Fact.PAYOUT_TXID].dead_box_recoverable() is False
    assert cov[Fact.DEPOSIT_ADDRESS].dead_box_recoverable() is True
    assert str(cov[Fact.CLIENT_IP].cell("cookies")).startswith("metadata_only")
    assert cov[Fact.PAYOUT_TXID].cell("replay").value == "live_only"
    assert all(len(r.cells) == 10 for r in m.fact_coverage), "every matrix row covers all ten sources"
    assert m.receipt("letter_of_guarantee").structure.templates and m.artifact("letter_file").receipt_ref == "letter_of_guarantee"
    assert [r.variant.value for r in m.endpoint("check_transaction").replay_results] == ["original", "superseded_session", "no_cookies", "foreign_order_key"]
    assert m.observation("mx-disk").os == "Windows 10"
    assert {n.location for n in m.negative_findings} >= {Location.CHROME_LOCAL_STORAGE, Location.CHROME_AUTOFILL}
    assert any(i.kind == "string" and isinstance(i.value, InvariantLiteral) and i.weight == 1.0 for i in m.indicators)
    assert m.endpoint("set_transaction_coinjoin").gate.value == [GateMechanism.SESSION, GateMechanism.CSRF, GateMechanism.CAPTCHA]
    assert m.matrix_row("receipt").cell("downloads").value == "recovered"


def test_mixero_provenance(seeds):
    m = seeds["mixero"]
    assert not any(o.kind == "memory_image" for o in m.observations)
    classes = {m.observation(s).provenance_class.value for _, a in m.known_attrs() for s in a.sources}
    assert {"instrumentation", "subject_evidence", "operator_claim", "public_record"} <= classes
    assert all(sp.basis == "claimed" for sp in m.retention.stated_policy) and len(m.retention.stated_policy) >= 2



# ---- the instance-vs-invariant rule on real seed data --------------------------------


def test_injected_instance_data_fails_validation():
    raw = yaml.safe_load((SERVICES_DIR / "mixero.yaml").read_text(encoding="utf-8"))
    bad = copy.deepcopy(raw)
    bad["identity"]["cdn_proxy"]["value"] = f"ddos-guard (order {HEX64})"
    with pytest.raises(ValidationError, match="case findings"):
        ServiceEntry.model_validate(bad)
    bad = copy.deepcopy(raw)
    bad["artifacts"][0]["recovery_route"]["value"] = "seen at bc1q" + "q" * 38
    with pytest.raises(ValidationError, match="instance data"):
        ServiceEntry.model_validate(bad)
    bad = copy.deepcopy(raw)
    bad["status"]["states"][3]["template"]["text"] = f"Transaction has been completed with TXID: {HEX64}"
    with pytest.raises(ValidationError, match="instance data"):
        ServiceEntry.model_validate(bad)


def test_load_service_yaml_rejects_non_mapping(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        load_service_yaml(p)
