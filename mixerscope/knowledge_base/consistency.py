"""Cross-field consistency of a service entry: the matrix cells against the artifacts and the
negative findings that are supposed to back them.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from mixerscope.schema import Basis, CellValue, MatrixSource, ReplayOutcome, ServiceEntry, load_definitions

from . import SERVICES_DIR, iter_seed_paths, load_service_yaml

PRESENT = (CellValue.RECOVERED, CellValue.METADATA_ONLY)


@dataclass(frozen=True)
class Violation:
    service: str
    rule: int
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.service}: [{self.rule}] {self.path}: {self.message}"


def source_locations() -> dict[str, list[str]]:
    """Matrix column -> storage locations it covers, derived from `locations.<id>.source`."""
    out: dict[str, list[str]] = {c: [] for c in load_definitions().matrix_sources()}
    for loc, src in load_definitions().location_to_source().items():
        out.setdefault(src, []).append(loc)
    return out


def check_entry(e: ServiceEntry) -> list[Violation]:
    sid = e.service.id
    cols = source_locations()
    loc_col = load_definitions().location_to_source()
    out: list[Violation] = []
    arts = {a.id: a for a in e.artifacts}
    rows = {r.fact: r for r in e.fact_coverage}

    def observed_artifact(a) -> bool:
        return a.persistence_class is not None and a.persistence_class.basis is Basis.OBSERVED

    # 4. artifact persistence basis
    for a in e.artifacts:
        if a.persistence_class is None:
            out.append(Violation(sid, 4, f"artifacts[{a.id}]", "no persistence_class; an artifact is an observed record"))
        elif a.persistence_class.basis is not Basis.OBSERVED:
            out.append(Violation(sid, 4, f"artifacts[{a.id}].persistence_class",
                                 f"basis is {a.persistence_class.basis.value}; an unconfirmed prediction is a negative finding or a note, not an artifact"))
        if a.location.value not in loc_col:
            out.append(Violation(sid, 2, f"artifacts[{a.id}].location", f"{a.location.value} maps to no matrix column"))

    # 5. row artifact ids
    for r in e.fact_coverage:
        for x in r.artifacts:
            if x not in arts:
                out.append(Violation(sid, 5, f"fact_coverage[{r.fact.value}].artifacts", f"unknown artifact id {x!r}"))

    replay_backed = any(rr.outcome.value in (ReplayOutcome.LIVE, ReplayOutcome.ACCEPTED)
                        for ep in e.endpoints for rr in ep.replay_results if rr.outcome and rr.outcome.value)

    # 1. present cells need an observed artifact (replay: replay results; chain: on_chain artifact)
    for r in e.fact_coverage:
        for src, cell in r.cells.items():
            if cell.value not in PRESENT:
                continue
            path = f"fact_coverage[{r.fact.value}].cells.{src.value}"
            if src is MatrixSource.REPLAY:
                if not replay_backed:
                    out.append(Violation(sid, 1, path, f"{cell.value.value} in the replay column, but no endpoint has a live or accepted replay result"))
                continue
            backing = [a for a in e.artifacts if a.location.value in cols.get(src.value, []) and r.fact in a.carries_facts]
            if not backing:
                out.append(Violation(sid, 1, path, f"{cell.value.value} but no artifact at a {src.value} location carries {r.fact.value}"))
            elif not any(observed_artifact(a) for a in backing):
                out.append(Violation(sid, 1, path, f"backed only by artifacts whose persistence is not observed: {[a.id for a in backing]}"))

    # 2. artifact facts are present in the matching column
    for a in e.artifacts:
        col = loc_col.get(a.location.value)
        if col is None:
            continue
        for f in a.carries_facts:
            row = rows.get(f)
            cell = row.cells.get(MatrixSource(col)) if row else None
            if cell is None:
                out.append(Violation(sid, 2, f"artifacts[{a.id}].carries_facts", f"{f.value}: no {col} cell in that fact's row"))
            elif cell.value not in PRESENT:
                out.append(Violation(sid, 2, f"artifacts[{a.id}].carries_facts",
                                     f"{f.value} is {cell.value.value} in the {col} column, but this artifact carries it"))

    # 3. not_stored_by_design needs a negative finding at the column's location or a reason
    def finding_covers(r, src) -> bool:
        return any(loc_col.get(nf.location.value) == src.value and (not nf.facts or r.fact in nf.facts)
                   for nf in e.negative_findings)

    for r in e.fact_coverage:
        for src, cell in r.cells.items():
            if cell.value is CellValue.NOT_STORED_BY_DESIGN and not finding_covers(r, src) and not cell.detail:
                out.append(Violation(sid, 3, f"fact_coverage[{r.fact.value}].cells.{src.value}",
                                     "not_stored_by_design without a negative finding in this column or a reason in the cell"))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Report cross-field consistency violations of the service entries.")
    ap.add_argument("--services-dir", default=str(SERVICES_DIR))
    ap.add_argument("--strict", action="store_true", help="exit 1 if there is any violation")
    args = ap.parse_args(argv)
    total = 0
    for p in iter_seed_paths(Path(args.services_dir)):
        e = load_service_yaml(p)
        vs = check_entry(e)
        total += len(vs)
        print(f"{e.service.id}: {len(vs)} violation(s)")
        for v in vs:
            print(f"  [{v.rule}] {v.path}: {v.message}")
    return 1 if (args.strict and total) else 0


if __name__ == "__main__":
    sys.exit(main())
