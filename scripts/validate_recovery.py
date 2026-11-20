"""Recovery-accuracy check: which ground-truth values did the scanner recover, from where, and were
they labelled with the right fact?

    python scripts/validate_recovery.py ground_truth.json scan1.json [scan2.json ...]
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path


def mask(v: str) -> str:
    return v if len(v) <= 10 else f"{v[:5]}...{v[-4:]}"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    gt = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    values: dict[str, str] = gt["values"]
    service = gt.get("service")

    hits: dict[str, list[dict]] = defaultdict(list)
    for scan_path in argv[1:]:
        scan = json.loads(Path(scan_path).read_text(encoding="utf-8"))
        etype = scan["evidence_type"]
        for f in scan["findings"]:
            hay = f["value"] + " " + " ".join(t["value"] for t in f.get("tokens", []))
            hay += " " + str(f.get("extra", {}).get("plaintext_value") or "")
            for name, v in values.items():
                if v and v in hay:
                    facts = sorted({t["fact"] for t in f.get("tokens", []) if t.get("value") == v and t.get("fact")})
                    hits[name].append({"type": etype, "source": Path(f["source"]["path"]).name,
                                       "locator": f["source"]["offset_or_row"], "location": f["location"],
                                       "artifact": f.get("artifact_ref") or f["match"], "facts": facts})

    print(f"Ground truth for service {service!r}: {len(values)} values; scans: {len(argv) - 1}")
    print()
    print(f"{'ground truth':22} {'value':16} {'found':5} {'labelled as':24} locations / artifacts")
    recovered = labelled_ok = 0
    for name, v in values.items():
        rows = hits.get(name, [])
        found = bool(rows)
        recovered += found
        facts = sorted({x for r in rows for x in r["facts"]})
        ok = name in facts
        labelled_ok += ok
        summary = "; ".join(sorted({f"{r['location']}:{r['artifact']}" for r in rows}))[:140]
        print(f"{name:22} {mask(v):16} {'yes' if found else 'NO':5} {(', '.join(facts) or '-'):24} {summary}")
    print()
    print(f"recovered {recovered}/{len(values)} ground-truth values; {labelled_ok} labelled with the matching fact")
    for name, rows in hits.items():
        locs = sorted({f"{r['source']}:{r['locator']}" for r in rows})
        print(f"  {name}: {len(rows)} finding(s), e.g. {', '.join(locs[:4])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
