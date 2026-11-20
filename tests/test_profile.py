"""The investigator profile is assembled from the entry alone: every item carries tier, basis and a
ref that resolves to a field of the entry; the Markdown prints only entry values, definition
labels and view strings (the renderer raises otherwise).
"""

import re

import pytest

from mixerscope.knowledge_base import load_all_seeds
from mixerscope.knowledge_base.profile import build_profile, load_view, render_markdown

SECTIONS = ("recognise", "domains", "where_is", "interpret", "expected_absences", "design_findings_without_cell", "not_found", "beyond_disk")


@pytest.fixture(scope="module")
def seeds():
    return load_all_seeds()


def _resolve(entry_json: dict, ref: str):
    """Resolve a profile ref against the entry's JSON dump: dotted path with [i] indexes and
    id/name/fact lookups into lists."""
    node = entry_json
    for part in re.split(r"\.(?![^\[]*\])", ref):
        m = re.fullmatch(r"([a-z_]+)\[(\d+)\]", part)
        if m:
            node = node[m.group(1)][int(m.group(2))]
            continue
        if isinstance(node, list):
            node = next(x for x in node if part in (x.get("id"), x.get("name"), x.get("fact")))
        else:
            node = node[part]
    return node


def test_profiles_build_and_render(seeds):
    view = load_view()
    for sid, e in seeds.items():
        prof = build_profile(e)
        assert prof["service"] == sid
        md = render_markdown(prof, view, entry=e)
        assert md.startswith(f"# {e.service.display_name}: ")
        for sec in view["sections"].values():
            assert sec["title"] in md


def test_every_item_has_provenance_and_a_resolving_ref(seeds):
    for sid, e in seeds.items():
        prof = build_profile(e)
        dump = e.model_dump(mode="json")
        for sec in SECTIONS:
            for item in prof[sec]:
                assert "tier" in item and "basis" in item and item["ref"], (sid, sec, item)
                assert _resolve(dump, item["ref"]) is not None, (sid, sec, item["ref"])
                for f in item.get("findings", []):
                    assert _resolve(dump, f["ref"]) is not None, (sid, sec, f["ref"])
        for d in prof["scope"]["disk"]:
            assert _resolve(dump, d["ref"])["kind"] == "disk_image"


def test_where_is_rows_are_backed_by_artifacts(seeds):
    for sid, e in seeds.items():
        prof = build_profile(e)
        arts = {a.id: a for a in e.artifacts}
        for it in prof["where_is"]:
            a = arts[it["artifact"]]
            assert it["fact"] in [f.value for f in a.carries_facts]
            assert it["outcome"] in ("recovered", "metadata_only")


def test_coinomize_profile_content(seeds):
    prof = build_profile(seeds["coinomize"])
    auto = [it for it in prof["where_is"] if it["fact"] == "destination_address" and it["location"] == "chrome_autofill"]
    assert auto and auto[0]["caveat"] and "rejected" in auto[0]["caveat"]
    assert any(it["kind"] == "lookup" and it["lookup_key"] == "order_id" and it["ownership_check"] is False for it in prof["beyond_disk"])
    assert any(it["kind"] == "field_map" for it in prof["interpret"])
    assert prof["limits"]["tiers_not_run"] == [1]
    assert "deposit_txid" in prof["limits"]["facts_not_tested"]
    assert prof["limits"]["columns_not_tested"] == []  # the chain column has not_applicable cells
    # matrix row notes (the Coinomize Code inference) and the signature scheme's notes are surfaced
    notes = [it for it in prof["interpret"] if it["kind"] == "row_notes" and it["subject"] == "user_identifier"]
    assert notes and notes[0]["ref"] == "fact_coverage.user_identifier.notes" and "Inferred" in notes[0]["text"]
    sig = [it for it in prof["beyond_disk"] if it["kind"] == "signature"]
    assert sig and "Electrum" in sig[0]["scheme_notes"]
    # the Coinomize Code cells are not_tested: they must not appear as expected absences
    assert not any(it["fact"] == "user_identifier" and it["source"] in ("autofill", "sessions") for it in prof["expected_absences"])


def test_mixero_findings_pair_only_with_the_facts_they_name(seeds):
    e = seeds["mixero"]
    prof = build_profile(e)
    hist = {it["fact"]: it for it in prof["expected_absences"] if it["source"] == "history"}
    assert [f["ref"] for f in hist["order_id"]["findings"]] == ["negative_findings[4]"]
    assert hist["payout_txid"]["findings"] == []  # the order-ID finding does not explain it
    # section 2 is disk only; the chain cells are in beyond_disk
    assert not any(it["source"] == "chain" for it in prof["where_is"])
    assert any(it["kind"] == "chain" for it in prof["beyond_disk"])
    # a tier-1 fact in a tier-0 artifact keeps its own tier
    snss = [it for it in prof["where_is"] if it["artifact"] == "session_restore_state" and it["fact"] == "deposit_txid"]
    assert snss and snss[0]["fact_tier"] == 1 and snss[0]["tier"] == 0
    # the baseline replay row cites the capture, the purge the replay
    rep = [it for it in prof["beyond_disk"] if it["kind"] == "replay"]
    assert rep[0]["variant"] == "original" and rep[0]["cites"][0]["id"] == "mx-flow" and rep[0]["cites"][0]["date"]
    md = render_markdown(prof, load_view(), entry=e)
    assert "cites: mx-flow (2026-07-22)" in md and "Local Storage: Not written" in md


def test_empty_section_prints_the_view_line(seeds):
    e = seeds["mixtum"]
    prof = build_profile(e)
    prof["beyond_disk"] = []
    md = render_markdown(prof, load_view(), entry=e)
    sec = md.split("## 5. Beyond the disk")[1].split("## 6.")[0]
    assert sec.strip() == "None recorded in the entry."


def test_renderer_refuses_added_text(seeds):
    e = seeds["mixtum"]
    prof = build_profile(e)
    view = load_view()
    view["sections"]["limits"]["title"] = "6. A heading nobody wrote in the view"  # allowed: it is in the view now
    render_markdown(prof, view, entry=e)
    prof["interpret"].append({"kind": "caveat", "subject": "x", "text": "text that is not in the entry", "tier": 0, "basis": "observed", "ref": "artifacts.x"})
    with pytest.raises(ValueError, match="neither the entry"):
        render_markdown(prof, load_view(), entry=e)
