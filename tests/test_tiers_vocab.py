"""tiers.yaml documents the Tier vocabulary and must stay in step with the code."""

from pathlib import Path

import yaml

from mixerscope.schema import ObservationKind, ProvenanceClass, Tier

TIERS_YAML = Path(__file__).resolve().parents[1] / "mixerscope" / "knowledge_base" / "tiers.yaml"


def test_tiers_yaml_matches_enum():
    doc = yaml.safe_load(TIERS_YAML.read_text(encoding="utf-8"))
    rows = doc["tiers"]
    assert [r["number"] for r in rows] == [int(t) for t in Tier]
    assert [r["id"] for r in rows] == [t.name.lower() for t in Tier]
    for r in rows:
        assert r["requires"].strip() and r["establishes"] and r["cost"]
        assert all(ObservationKind(k) for k in r["observation_kinds"])
        assert all(ProvenanceClass(p) for p in r["typical_provenance"])
