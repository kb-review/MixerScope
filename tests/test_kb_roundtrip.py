"""YAML seeds -> SQLite -> loader round trip."""

import re
import sqlite3

import pytest

from mixerscope.knowledge_base import SERVICES_DIR, load_all_seeds
from mixerscope.knowledge_base.build import build_kb, main as build_main
from mixerscope.knowledge_base.loader import KnowledgeBase, UnknownServiceError
from mixerscope.schema import Tier


@pytest.fixture(scope="module")
def db_path(tmp_path_factory):
    path = tmp_path_factory.mktemp("kb") / "kb.sqlite"
    report = build_kb(path)
    assert "mixero" in report.services
    return path


@pytest.fixture
def kb(db_path):
    with KnowledgeBase.open(db_path) as kb:
        yield kb


def test_meta_and_summaries(kb):
    assert kb.meta()["marker"] == "mixerscope-kb" and kb.meta()["schema_version"] == "0.4"
    s = {x.id: x for x in kb.list_services()}
    assert s["mixero"].canonical_domain == "mixero.io" and s["mixero"].max_tier == 1
    assert s["mixero"].tiers_completed == [0, 1] and s["mixero"].attribute_count > 100


def test_get_service_round_trips_exactly(kb):
    for sid, seed in load_all_seeds().items():
        assert kb.get_service(sid).model_dump(mode="json") == seed.model_dump(mode="json")
    with pytest.raises(UnknownServiceError):
        kb.get_service("nope")


def test_artifact_map(kb):
    amap = kb.get_artifact_map("mixero")
    assert "process_memory" not in amap["by_location"]
    assert "destination_autofill" in amap["by_location"]["chrome_autofill"]
    cov = {c["fact"]: c for c in amap["fact_coverage"]}
    assert cov["payout_txid"]["dead_box_recoverable"] is False and cov["payout_txid"]["on_chain_reconstructable"] is True
    assert amap["cache_policy"]["check_transaction"] == "no_store" and amap["cache_policy"]["letter"] == "cacheable_heuristic"
    assert [s["label"] for s in amap["status_states"]] == ["awaiting", "detected", "mixing", "completed"]
    assert re.search(amap["status_states"][3]["template_regex"], "Transaction has been completed with TXID: " + "ab" * 32)
    assert {c["name"] for c in amap["cookies"]} >= {"ci_session", "__ddg9_"}
    letter = next(a for a in amap["artifacts"] if a["id"] == "letter_file")
    assert any("literal" in k for k in letter["search_keys"]) and letter["filename_regex"].startswith("^Letter_")


def test_domain_lookup_and_indicators(kb):
    assert kb.find_by_domain("MIXERO.co") == [{"service": "mixero", "role": "assets_api"}]
    assert kb.find_by_domain("api.mixero.co") == [{"service": "mixero", "role": "assets_api"}]
    assert kb.find_by_domain("mixero.org") == [{"service": "mixero", "role": "alias"}]
    assert kb.find_by_domain("example.invalid") == []
    ind = kb.indicators("mixero")
    assert ind[0]["weight"] == 1.0 and ind[0]["is_literal"]
    assert any(i["kind"] == "url_path" and re.match(i["regex"], "/Home/check_transaction") for i in ind)


def test_patterns_and_attributes(kb):
    kinds = {p.kind for p in kb.patterns(service="mixero")}
    assert {"identifier", "endpoint_path", "status_template", "filename", "search_key", "cookie_value"} <= kinds
    fn = [p for p in kb.patterns(service="mixero", kind="filename")]
    assert fn and re.match(fn[0].regex, "Letter_6a6000000abcde.12345678.txt")  # <order_id> expanded
    t0 = kb.attributes("mixero", tier=Tier.NO_FUNDS, known_only=True)
    assert t0 and all(a["tier"] == 0 for a in t0)
    cdn = next(a for a in t0 if a["path"] == "identity.cdn_proxy")
    assert cdn["value"] == "ddos-guard" and cdn["provenance_classes"] == ["instrumentation", "subject_evidence"]
    assert cdn["validity"]["status"] == "current"  # service validity_default applied
    amap = kb.get_artifact_map("mixero")
    row = next(r for r in amap["fact_coverage"] if r["fact"] == "payout_txid")
    assert row["cells"]["replay"]["value"] == "live_only" and row["dead_box_recoverable"] is False
    assert amap["receipts"][0]["id"] == "letter_of_guarantee" and amap["receipts"][0]["templates"]
    assert kb.observations("mixero")[0]["browser_version"] == "Chrome 150"
    assert kb.observations("mixero")[0]["kind"] == "capture_flow"


def test_loader_is_read_only(kb):
    with pytest.raises(sqlite3.OperationalError):
        kb._conn.execute("DELETE FROM services")


def test_build_refuses_to_clobber_foreign_file(tmp_path):
    target = tmp_path / "notes.sqlite"
    target.write_text("not a kb", encoding="utf-8")
    with pytest.raises(FileExistsError):
        build_kb(target)
    assert target.read_text(encoding="utf-8") == "not a kb"
    build_kb(target, force=True)
    build_kb(target)


def test_build_fails_on_invalid_seed(tmp_path, capsys):
    bad_dir = tmp_path / "services"
    bad_dir.mkdir()
    src = (SERVICES_DIR / "mixero.yaml").read_text(encoding="utf-8")
    assert "domain: mixero.io" in src
    bad_dir.joinpath("mixero.yaml").write_text(src.replace("domain: mixero.io", "domain: " + "a" * 64, 1), encoding="utf-8")
    assert build_main(["--services-dir", str(bad_dir), "--out", str(tmp_path / "kb.sqlite")]) == 1
    assert "instance data" in capsys.readouterr().err


def test_cli_builds(tmp_path, capsys):
    out = tmp_path / "kb.sqlite"
    assert build_main(["--out", str(out)]) == 0 and out.exists()
    assert "mixero" in capsys.readouterr().out
