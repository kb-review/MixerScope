"""knowledge_base/definitions.yaml is the single vocabulary: the enums in vocab.py mirror it, every
service file's codes come from it, and the built KB carries it.
"""

import re

from mixerscope.knowledge_base import load_all_seeds
from mixerscope.knowledge_base.build import build_kb
from mixerscope.knowledge_base.loader import KnowledgeBase
from mixerscope.schema import Fact, MatrixSource, SCHEMA_VERSION, load_definitions
from mixerscope.schema import vocab as vocab_module
import mixerscope.schema as schema_package
from mixerscope.schema.definitions import ENUM_VOCABULARIES, check_building_blocks_match, check_enums_match


def test_enums_match_definitions_both_ways():
    assert check_enums_match(vocab_module) == []
    defs = load_definitions()
    assert defs.version == SCHEMA_VERSION
    # every vocabulary in the file that an enum should mirror is covered
    vocab_names = set(ENUM_VOCABULARIES.values())
    assert vocab_names <= set(defs.vocabularies())


def test_every_code_has_a_label_and_locations_map_to_matrix_columns():
    defs = load_definitions()
    for name in defs.vocabularies():
        for code, entry in defs.vocab(name).items():
            assert isinstance(entry, dict) and entry.get("label"), f"{name}.{code} has no label"
    sources = set(defs.matrix_sources())
    for loc, src in defs.location_to_source().items():
        assert src in sources, f"location {loc} maps to unknown source {src}"
    assert defs.label("outcomes", "required_to_query") == "Required to query"
    assert defs.meaning("basis", "claimed").startswith("Stated by the operator")
    assert defs.label("tiers", 0) == "0"


def test_placeholders_compile_and_non_fact_ones_are_marked():
    defs = load_definitions()
    for code, rx in defs.placeholders().items():
        re.compile(rx)
    assert {"hex", "int", "text", "signature"} <= defs.non_fact_placeholders()
    assert "btc_address" not in defs.non_fact_placeholders()


def test_seeds_use_only_defined_facts_and_sources():
    defs = load_definitions()
    for entry in load_all_seeds().values():
        for row in entry.fact_coverage:
            assert defs.has("facts", row.fact.value)
            assert all(defs.has("matrix_sources", s.value) for s in row.cells)
        for art in entry.artifacts:
            assert defs.has("locations", art.location.value)
            assert all(defs.has("facts", f.value) for f in art.carries_facts)
    assert len(Fact) == len(defs.codes("facts")) and len(MatrixSource) == len(defs.codes("matrix_sources"))


def test_kb_carries_definitions(tmp_path):
    p = tmp_path / "kb.sqlite"
    build_kb(p)
    with KnowledgeBase.open(p) as kb:
        assert kb.meta()["definitions_version"] == SCHEMA_VERSION
        rows = kb.definitions("outcomes")
        assert [r["code"] for r in rows] == load_definitions().codes("outcomes")
        assert kb.label("matrix_sources", "web_storage") == "Web Storage / IndexedDB"
        assert kb.label("facts", "nonexistent") == "nonexistent"
        assert any(r["vocab"] == "placeholders" and r["extra"].get("regex") for r in kb.definitions())


def test_building_blocks_match_the_models():
    """Table 4a is the definitions file: every building block's fields equal the model's fields."""
    assert check_building_blocks_match(schema_package) == []
    defs = load_definitions()
    for name, block in defs.building_blocks().items():
        assert block.get("meaning"), f"{name} has no meaning"
        assert all(isinstance(v, str) and v for v in block["fields"].values()), f"{name}: every field needs a meaning"
    assert "building_blocks" not in defs.vocabularies()
