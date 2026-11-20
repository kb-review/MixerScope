"""Shared definitions (knowledge_base/definitions.yaml): the one place codes, labels and meanings
live. Service files refer to codes; renderers look labels up here; the test suite checks that
the enums in `vocab.py` equal these codes in both directions.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

DEFINITIONS_PATH = Path(__file__).resolve().parent.parent / "knowledge_base" / "definitions.yaml"


class Definitions:
    def __init__(self, data: dict[str, Any]) -> None:
        self._d = data

    @property
    def version(self) -> str:
        return str(self._d["version"])

    def vocab(self, name: str) -> dict[str, dict[str, Any]]:
        if name not in self._d or name in self.NON_VOCABULARY_KEYS:
            raise KeyError(f"no vocabulary {name!r} in definitions")
        return {str(k): (v or {}) for k, v in self._d[name].items()}

    #: Top-level keys that are not code vocabularies.
    NON_VOCABULARY_KEYS = frozenset({"version", "building_blocks"})

    def vocabularies(self) -> list[str]:
        return [k for k in self._d if k not in self.NON_VOCABULARY_KEYS]

    def building_blocks(self) -> dict[str, dict[str, Any]]:
        """The forms every value is written in (paper Table 4a): name -> {meaning, fields}."""
        return dict(self._d.get("building_blocks", {}))

    def block_fields(self, name: str) -> list[str]:
        return list(self.building_blocks()[name]["fields"])

    def codes(self, name: str) -> list[str]:
        return list(self.vocab(name))

    def has(self, name: str, code: Any) -> bool:
        return str(code) in self.vocab(name)

    def label(self, name: str, code: Any, default: str | None = None) -> str:
        entry = self.vocab(name).get(str(code))
        if entry is None:
            if default is not None:
                return default
            raise KeyError(f"code {code!r} is not defined in {name!r}")
        return str(entry.get("label", code))

    def meaning(self, name: str, code: Any) -> str | None:
        entry = self.vocab(name).get(str(code))
        return entry.get("meaning") if entry else None

    # ---- conveniences used across the package -------------------------------------------

    def matrix_sources(self) -> list[str]:
        return self.codes("matrix_sources")

    def disk_sources(self) -> frozenset[str]:
        return frozenset(c for c, v in self.vocab("matrix_sources").items() if v.get("disk"))

    def location_to_source(self) -> dict[str, str]:
        return {c: v["source"] for c, v in self.vocab("locations").items() if v.get("source")}

    def placeholders(self) -> dict[str, str]:
        return {c: v["regex"] for c, v in self.vocab("placeholders").items()}

    def non_fact_placeholders(self) -> frozenset[str]:
        return frozenset(c for c, v in self.vocab("placeholders").items() if v.get("fact_bearing") is False)


@lru_cache(maxsize=1)
def load_definitions(path: Path | str = DEFINITIONS_PATH) -> Definitions:
    with Path(path).open("r", encoding="utf-8") as fh:
        return Definitions(yaml.safe_load(fh))


#: Which enum in vocab.py mirrors which vocabulary here.
ENUM_VOCABULARIES: dict[str, str] = {
    "Tier": "tiers",
    "Basis": "basis",
    "ProvenanceClass": "provenance",
    "ObservationKind": "observation_kinds",
    "CellValue": "outcomes",
    "MatrixSource": "matrix_sources",
    "Fact": "facts",
    "Location": "locations",
    "PersistenceClass": "persistence",
    "CachePolicy": "cache_policies",
    "GateMechanism": "gate_mechanisms",
    "IdentifierRole": "roles",
    "CookieSetBy": "set_by",
    "ReplayVariant": "replay_variants",
    "ReplayOutcome": "replay_outcomes",
    "IndicatorKind": "indicator_kinds",
    "Consistency": "consistency",
    "ReceiptDelivery": "delivery",
    "ReceiptContainer": "receipt_containers",
    "SignatureScheme": "signature_schemes",
    "StatusMechanism": "status_mechanisms",
    "AccountModel": "account_models",
    "DomainRole": "domain_roles",
    "EntryStatus": "entry_status",
    "ValidityStatus": "validity_status",
    "ContentEncoding": "content_encodings",
}


#: Which schema model mirrors which building block.
BLOCK_MODELS: dict[str, str] = {
    "attribute": "Attribute",
    "validity": "Validity",
    "observation": "Observation",
    "pattern": "Pattern",
    "template": "Template",
    "invariant_literal": "InvariantLiteral",
    "cell": "Cell",
}


def check_building_blocks_match(schema_package) -> list[str]:
    """Return mismatches between the models' fields and the building blocks in the definitions."""
    defs = load_definitions()
    problems: list[str] = []
    for block, model_name in BLOCK_MODELS.items():
        model = getattr(schema_package, model_name, None)
        if model is None:
            problems.append(f"model {model_name} missing")
            continue
        have, want = set(model.model_fields), set(defs.block_fields(block))
        if have != want:
            problems.append(f"{model_name} fields {sorted(have)} != definitions.building_blocks.{block} {sorted(want)}")
    extra = set(defs.building_blocks()) - set(BLOCK_MODELS)
    if extra:
        problems.append(f"building blocks without a model: {sorted(extra)}")
    return problems


def check_enums_match(vocab_module) -> list[str]:
    """Return a list of mismatches between the enums in `vocab_module` and the definitions."""
    defs = load_definitions()
    problems: list[str] = []
    for enum_name, vocab_name in ENUM_VOCABULARIES.items():
        enum = getattr(vocab_module, enum_name, None)
        if enum is None:
            problems.append(f"enum {enum_name} missing from vocab.py")
            continue
        enum_codes = [str(int(m)) if isinstance(m, int) else m.value for m in enum]
        def_codes = defs.codes(vocab_name)
        if enum_codes != def_codes:
            problems.append(f"{enum_name} != definitions.{vocab_name}: enum={enum_codes} definitions={def_codes}")
    if set(vocab_module.PLACEHOLDERS) != set(defs.placeholders()):
        problems.append(f"PLACEHOLDERS differ: code={sorted(vocab_module.PLACEHOLDERS)} definitions={sorted(defs.placeholders())}")
    if vocab_module.NON_FACT_PLACEHOLDERS != defs.non_fact_placeholders():
        problems.append("NON_FACT_PLACEHOLDERS differ from definitions")
    if vocab_module.SCHEMA_VERSION != defs.version:
        problems.append(f"SCHEMA_VERSION {vocab_module.SCHEMA_VERSION} != definitions version {defs.version}")
    return problems
