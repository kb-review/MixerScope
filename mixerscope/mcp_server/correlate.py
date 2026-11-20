"""Correlation over scan results: facts, timeline, deposit -> payout triangulation, and the fact-
by-source checklist.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mixerscope.evidence.findings import Finding, ScanResult
from mixerscope.evidence.matcher import identify_service
from mixerscope.knowledge_base.loader import KnowledgeBase
from mixerscope.schema import CellValue, Fact, ServiceEntry, load_definitions
from mixerscope.schema.vocab import LOCATION_TO_SOURCE

FACT_ORDER = [f.value for f in Fact]
UNLABELLED = {"btc_address": "address_unlabelled", "evm_address": "address_unlabelled", "txid": "txid_unlabelled",
              "uniqid": "order_id_candidate", "ipv4": "ip_unlabelled"}
_CAPPED = {"txid_unlabelled": 25, "address_unlabelled": 50, "order_id_candidate": 10, "ip_unlabelled": 10,
           "order_id_implausible": 10}
_PLAUSIBLE_FROM = datetime(2015, 1, 1, tzinfo=timezone.utc)
_DERIVATION = "first 8 hex chars of a PHP uniqid are unix seconds (format invariant; see the KB identifier derivation)"


def load_scans(paths: list[str | Path]) -> list[ScanResult]:
    return [ScanResult.from_dict(json.loads(Path(p).read_text(encoding="utf-8"))) for p in paths]


def correlate(scans: list[ScanResult], kb_path: str | Path, *, max_timeline: int = 1000) -> dict[str, Any]:
    findings: list[Finding] = [f for s in scans for f in s.findings]
    services = identify_service(findings)
    primary = services[0].service if services else None
    entry: ServiceEntry | None = None
    with KnowledgeBase.open(kb_path) as kb:
        meta = kb.meta()
        if primary and kb.has_service(primary):
            entry = kb.get_service(primary)

    identifiers = _identifiers(findings, entry)
    timeline = _timeline(findings, identifiers, max_timeline)
    triangulation = _triangulate(identifiers, entry)
    checklist = _checklist(findings, entry, primary)
    return {
        "kb": {"path": str(kb_path), **{k: meta.get(k) for k in ("built_at", "schema_version", "mixerscope_version")}},
        "scans": [{"evidence": s.evidence, "type": s.evidence_type, "findings": len(s.findings),
                   "candidates": s.candidates_seen, "warnings": s.warnings} for s in scans],
        "services": [s.__dict__ for s in services],
        "primary_service": primary,
        "identifiers": identifiers,
        "timeline": timeline,
        "triangulation": triangulation,
        "fact_checklist": checklist,
    }


# --------------------------------------------------------------------------------------


def _evidence_ref(f: Finding, basis: str | None) -> dict[str, Any]:
    c = f.candidate
    return {"source": Path(c.source).name, "locator": c.locator, "location": c.location, "medium": c.medium,
            "provenance_class": c.provenance_class, "artifact_ref": f.artifact_ref, "match": f.match,
            "basis": basis, "timestamp": c.timestamp}


def _plausible(iso: str) -> bool:
    try:
        t = datetime.fromisoformat(iso)
    except ValueError:
        return False
    now = datetime.now(timezone.utc)
    return _PLAUSIBLE_FROM <= t <= now.replace(year=now.year + 1)


def _derive_uniqid_time(order_id: str) -> str | None:
    try:
        return datetime.fromtimestamp(int(order_id[:8], 16), tz=timezone.utc).isoformat(timespec="seconds")
    except (ValueError, OverflowError, OSError):
        return None


def _identifiers(findings: list[Finding], entry: ServiceEntry | None) -> dict[str, Any]:
    buckets: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

    def add(role: str, value: str, f: Finding, basis: str | None, **extra):
        slot = buckets[role].setdefault(value, {"value": value, "role": role, "evidence": [], "bases": set(), **extra})
        slot["evidence"].append(_evidence_ref(f, basis))
        if basis:
            slot["bases"].add(basis)

    for f in findings:
        for t in f.tokens:
            if t.fact:
                role = t.fact
            else:
                role = UNLABELLED.get(t.kind)
                if role is None:
                    continue
            extra = {}
            if t.kind == "uniqid":
                derived = _derive_uniqid_time(t.value)
                if derived and not _plausible(derived):
                    role = "order_id_implausible"
                extra = {"derived_creation_time_utc": derived, "derivation": _DERIVATION if derived else None}
            add(role, t.value, f, t.basis, **extra)

    out: dict[str, Any] = {}
    for role in FACT_ORDER + list(dict.fromkeys(UNLABELLED.values())) + ["order_id_implausible"]:
        items = list(buckets.get(role, {}).values())
        for it in items:
            it["bases"] = sorted(it["bases"])
            it["evidence_count"] = len(it["evidence"])
            it["locations"] = sorted({e["location"] for e in it["evidence"]})
            it["media"] = sorted({e["medium"] for e in it["evidence"]})
            it["provenance_classes"] = sorted({e["provenance_class"] for e in it["evidence"]})
        items.sort(key=lambda it: -it["evidence_count"])
        cap = _CAPPED.get(role)
        if cap:
            out[role] = items[:cap]
            out[f"{role}_total"] = len(items)
        else:
            out[role] = items
    return out


def _timeline(findings: list[Finding], identifiers: dict, cap: int) -> list[dict[str, Any]]:
    events: dict[tuple, dict] = {}
    for f in findings:
        c = f.candidate
        if not c.timestamp:
            continue
        if c.kind == "url":
            ev = ("visit " if c.provenance_class == "subject_evidence" else f"request {c.extra.get('method', '')} ") + f.match
        elif c.kind == "download":
            ev = f"download {c.extra.get('filename') or c.value}"
        elif c.kind == "cookie":
            ev = f"cookie {c.value} " + ("created" if c.provenance_class == "subject_evidence" else "set")
        elif c.kind == "file":
            ev = f"file {c.value} (mtime)"
        else:
            continue
        key = (c.timestamp, ev, Path(c.source).name)
        if key in events:
            events[key]["count"] += 1
            continue
        events[key] = {"time": c.timestamp, "event": ev.strip(), "value": c.value[:200], "source": Path(c.source).name,
                       "locator": c.locator, "location": c.location, "provenance_class": c.provenance_class,
                       "kind": "extracted", "count": 1}
    for it in identifiers.get("order_id", []):
        if it.get("derived_creation_time_utc"):
            key = (it["derived_creation_time_utc"], "order created (derived)", "order_id")
            events[key] = {"time": it["derived_creation_time_utc"], "event": "order created (derived from order ID)",
                           "value": it["value"], "source": "order_id", "locator": it["derivation"], "location": "-",
                           "provenance_class": "derived", "kind": "derived", "count": 1}
    return sorted(events.values(), key=lambda e: e["time"])[:cap]


def _disk_routes(entry: ServiceEntry | None, fact: str) -> str:
    """Where the entry says this fact is recovered on disk: the recovered cells of its matrix row
    with their detail, read from the entry rather than from a hard-coded list."""
    row = entry.matrix_row(fact) if entry is not None else None
    if row is None:
        return "no entry for the identified service; see the service's investigator profile"
    defs = load_definitions()
    parts = []
    for src, cell in row.cells.items():
        if cell.value in (CellValue.RECOVERED, CellValue.METADATA_ONLY) and defs.vocab("matrix_sources")[src.value].get("disk"):
            parts.append(defs.label("matrix_sources", src.value) + (f" ({cell.detail})" if cell.detail else ""))
    return ("the entry recovers it from " + "; ".join(parts)) if parts else "the entry recovers it from no disk source"


def _triangulate(ids: dict, entry: ServiceEntry | None = None) -> dict[str, Any]:
    vals = lambda role: [i["value"] for i in ids.get(role, [])]  # noqa: E731
    dep, dst = vals("deposit_address"), vals("destination_address")
    dep_tx, pay_tx = vals("deposit_txid"), vals("payout_txid")
    orders = ids.get("order_id", [])
    created = next((o["derived_creation_time_utc"] for o in orders if o.get("derived_creation_time_utc")), None)
    unl_tx = vals("txid_unlabelled")
    steps: list[str] = []
    if not dep:
        steps.append("Deposit address not established; " + _disk_routes(entry, "deposit_address") + ".")
    if not dst:
        steps.append("Destination address not established; " + _disk_routes(entry, "destination_address") + ".")
    if dep and not dep_tx:
        if unl_tx:
            steps.append(f"Confirm on-chain which of the {len(unl_tx)} unlabelled TXID(s) pays deposit address {dep[0]}; "
                         "that one is the deposit TXID.")
        else:
            steps.append(f"On-chain: list incoming transactions to deposit address {dep[0]}"
                         + (f" after {created}" if created else "") + " to obtain the deposit TXID.")
    if dst and not pay_tx:
        pay_row = entry.matrix_row("payout_txid") if entry is not None else None
        on_chain_only = pay_row is not None and pay_row.best_persistence is not None and pay_row.best_persistence.value == "on_chain"
        steps.append(f"On-chain: list incoming transactions to destination address {dst[0]}"
                     + (f" after {created}" if created else "")
                     + ("; the payout TXID is not recoverable from disk (entry: on-chain only)." if on_chain_only
                        else "; " + _disk_routes(entry, "payout_txid") + "."))
    if dep_tx and pay_tx:
        steps.append("Deposit and payout TXIDs both present; confirm on-chain that the deposit TXID pays the deposit "
                     "address and the payout TXID pays the destination address.")
    if not steps:
        steps.append("Nothing to triangulate: no addresses recovered.")
    status = ("complete" if dep and dst and dep_tx and pay_tx else "on-chain step required" if (dep or dst)
              else "insufficient evidence")
    return {"status": status, "deposit_addresses": dep, "destination_addresses": dst, "deposit_txids": dep_tx,
            "payout_txids": pay_tx, "order_ids": [o["value"] for o in orders], "derived_order_creation_utc": created,
            "on_chain_steps": steps,
            "note": "The tool performs no on-chain lookups; every step above is for the analyst to run with an "
                    "explorer or node and record as a separate observation."}


def _checklist(findings: list[Finding], entry: ServiceEntry | None, primary: str | None) -> list[dict[str, Any]]:
    """One row per canonical fact from the KB's fact-by-source matrix, with what the evidence
    showed: which sources the KB says yield the fact, and which sources actually did."""
    if entry is None:
        return []
    found: dict[str, dict[str, Any]] = defaultdict(lambda: {"values": set(), "locations": set(), "sources": set(), "artifacts": set()})
    found_arts: dict[str, int] = defaultdict(int)
    for f in findings:
        if f.service != primary:
            continue
        if f.artifact_ref:
            found_arts[f.artifact_ref.split(":", 1)[1]] += 1
        for t in f.tokens:
            if t.fact:
                slot = found[t.fact]
                slot["values"].add(t.value)
                slot["locations"].add(f.candidate.location)
                src = LOCATION_TO_SOURCE.get(f.candidate.location)
                if src:
                    slot["sources"].add(src.value)
                if f.artifact_ref:
                    slot["artifacts"].add(f.artifact_ref.split(":", 1)[1])
    derived_times = [t for f in findings for t in f.tokens if t.kind == "uniqid" and t.fact == "order_id"]
    out = []
    for row in entry.fact_coverage:
        slot = found.get(row.fact.value)
        if row.fact.value == "order_created_time" and slot is None and derived_times:
            slot = {"values": {_derive_uniqid_time(t.value) for t in derived_times if _derive_uniqid_time(t.value)},
                    "locations": {"derived"}, "sources": set(), "artifacts": set()}
        expected = sorted(s.value for s, c in row.cells.items() if c.value is CellValue.RECOVERED)
        out.append({
            "fact": row.fact.value,
            "best_persistence": row.best_persistence.value if row.best_persistence else None,
            "dead_box_recoverable": row.dead_box_recoverable(),
            "on_chain_reconstructable": row.on_chain_reconstructable(),
            "cells": {s.value: str(c) for s, c in row.cells.items()},
            "expected_sources": expected,
            "sources_found": sorted(slot["sources"]) if slot else [],
            "expected_artifacts": list(row.artifacts),
            "artifacts_found": sorted(a for a in row.artifacts if found_arts.get(a)),
            "recovered": bool(slot),
            "distinct_values": len(slot["values"]) if slot else 0,
            "locations_found": sorted(slot["locations"]) if slot else [],
        })
    return out
