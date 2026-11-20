from pathlib import Path

from mixerscope.schema.jsonschema import DEFAULT_OUT, export_json_schema, render

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_schema_exports_all_groups():
    s = export_json_schema()
    props = set(s["properties"])
    assert {"service", "observations", "identity", "access", "modes", "order_model", "cookies", "endpoints",
            "status", "receipts", "artifacts", "fact_coverage", "retention", "negative_findings", "indicators",
            "extensions"} <= props
    assert {"Tier", "Basis", "Observation", "Fact", "Location", "Pattern", "Template", "InvariantLiteral",
            "MatrixRow", "Cell", "Receipt", "ReplayResult", "Validity"} <= set(s["$defs"])
    assert s["title"].endswith("v0.4")


def test_committed_schema_is_current():
    committed = (REPO_ROOT / DEFAULT_OUT).read_text(encoding="utf-8")
    assert committed == render(), (
        "docs/service-entry.schema.json is stale; run: python -m mixerscope.schema.jsonschema"
    )
