"""Export the ServiceEntry model as JSON Schema (for documentation and non-Python tooling)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .service import ServiceEntry
from .vocab import SCHEMA_VERSION

DEFAULT_OUT = Path("docs") / "service-entry.schema.json"


def export_json_schema() -> dict:
    schema = ServiceEntry.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = f"mixerscope ServiceEntry v{SCHEMA_VERSION}"
    schema["description"] = (
        "One mixer service's invariant record (codes defined in knowledge_base/definitions.yaml). Every fact is an Attribute (value, tier 0 = no funds / 1 = funded, "
        "confidence observed|inferred|claimed|unknown, sources = observation ids). Instance data "
        "(specific addresses, TXIDs, order IDs, cookie values, amounts, timestamps) is rejected by "
        "the Python validators and belongs in a per-case findings file, never the KB."
    )
    return schema


def render() -> str:
    return json.dumps(export_json_schema(), indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Write the ServiceEntry JSON Schema.")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
