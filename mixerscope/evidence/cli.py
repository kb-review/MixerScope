"""Command-line entry point: mixerscope-scan."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from mixerscope.knowledge_base.build import DEFAULT_DB_PATH

from . import scan_evidence
from .adapters import ADAPTERS


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mixerscope-scan",
                                 description="Read-only scan of evidence against the mixer knowledge base.")
    ap.add_argument("evidence", help="Chrome profile dir, files dir / single file, or a strings dump")
    ap.add_argument("--type", choices=sorted(ADAPTERS), help="evidence type (default: detect)")
    ap.add_argument("--kb", default=str(DEFAULT_DB_PATH), help="knowledge base SQLite (build it first)")
    ap.add_argument("--service", action="append", help="restrict matching to these services (repeatable)")
    ap.add_argument("--out", help="write findings JSON here (default: scan_out/<name>.scan.json)")
    ap.add_argument("--max-findings", type=int, default=None)
    ap.add_argument("--no-hash", action="store_true", help="skip sha256 of source files (faster on huge dumps)")
    ap.add_argument("--location", default=None,
                    help="for --type strings: the disk region the dump came from (default unallocated)")
    args = ap.parse_args(argv)

    path = Path(args.evidence)
    if not path.exists():
        print(f"evidence not found: {path}", file=sys.stderr)
        return 2
    try:
        result = scan_evidence(path, kb_path=args.kb, evidence_type=args.type, services=args.service,
                               max_findings=args.max_findings, hash_sources=not args.no_hash, location=args.location)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        print(f"scan failed: {e}", file=sys.stderr)
        return 1

    out = Path(args.out) if args.out else Path("scan_out") / f"{path.name or 'evidence'}.scan.json"
    result.write(out)

    print(f"evidence: {path} ({result.evidence_type}), {result.candidates_seen} candidates, "
          f"{len(result.findings)} findings, {len(result.sources_scanned)} source file(s)")
    for w in result.warnings:
        print(f"  warning: {w}")
    if result.services:
        print("services:")
        for s in result.services:
            print(f"  {s.service:12} score={s.score:<7} " + ", ".join(f"{k}x{v}" for k, v in s.rules.items()))
    else:
        print("services: none identified")
    by = Counter()
    for f in result.findings:
        by[(f.artifact_ref or f"{f.service or '-'}:{f.match}", f.candidate.location, f.persistence_class or "-")] += 1
    if by:
        print("findings by artifact / location:")
        for (art, loc, pc), n in sorted(by.items()):
            print(f"  {art:40} {loc:22} {pc:12} x{n}")
    facts = result.by_fact()
    if facts:
        print("fact-labelled tokens: " + ", ".join(f"{k} x{v}" for k, v in facts.items()))
    print(f"written: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
