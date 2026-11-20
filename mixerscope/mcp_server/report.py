"""Analyst-reviewable markdown report from a correlation result."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from mixerscope import __version__

_FACT_ROLES = ("deposit_address", "destination_address", "order_id", "deposit_txid", "payout_txid", "amounts",
               "fee_and_delay", "client_ip", "session_id", "user_identifier", "mix_mode")


def render_report(corr: dict[str, Any], *, max_timeline_rows: int = 200, max_evidence_rows: int = 8) -> str:
    L: list[str] = []
    add = L.append
    primary = corr.get("primary_service")
    add(f"# Mixer artifact report{': ' + primary if primary else ''}")
    add("")
    add(f"Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')} by mixerscope {__version__}. "
        f"Knowledge base built {corr['kb'].get('built_at')} (schema v{corr['kb'].get('schema_version')}).")
    add("")
    add("All values below were extracted byte-for-byte from the listed sources and labelled with knowledge-base "
        "facts; the tool does not originate evidential values. The only derived value is the order-creation time "
        "computed from the order-ID scheme, marked *derived*. Sources tagged `instrumentation` are research "
        "captures, not artifacts recoverable from the subject's device.")
    add("")

    add("## Evidence scanned")
    add("")
    add("| Evidence | Type | Candidates | Findings |")
    add("| --- | --- | --- | --- |")
    for s in corr["scans"]:
        add(f"| {s['evidence']} | {s['type']} | {s['candidates']} | {s['findings']} |")
    warns = [w for s in corr["scans"] for w in s.get("warnings", [])]
    if warns:
        add("")
        add("Warnings: " + "; ".join(warns))
    add("")

    add("## Service identification")
    add("")
    if corr["services"]:
        add("| Service | Score | Evidence rules |")
        add("| --- | --- | --- |")
        for s in corr["services"]:
            add(f"| {s['service']} | {s['score']} | " + ", ".join(f"{k} x{v}" for k, v in s["rules"].items()) + " |")
    else:
        add("No service in the knowledge base matched. Unlabelled tokens (if any) are listed below.")
    add("")

    add("## Facts recovered")
    add("")
    ids = corr["identifiers"]
    add("| Fact | Value | Evidence | Locations | Provenance | Basis |")
    add("| --- | --- | --- | --- | --- | --- |")
    for role in _FACT_ROLES:
        for it in ids.get(role, []):
            basis = "; ".join(it.get("bases", []))
            if it.get("derived_creation_time_utc"):
                basis += f"; *derived* creation {it['derived_creation_time_utc']}"
            add(f"| {role} | `{it['value']}` | {it['evidence_count']} | {', '.join(it['locations'])} | "
                f"{', '.join(it['provenance_classes'])} | {basis} |")
    notes = []
    for role, label in (("txid_unlabelled", "64-hex token(s) (hashes of any kind)"),
                        ("address_unlabelled", "address-shaped token(s) whose role the context does not fix"),
                        ("order_id_candidate", "order-ID-shaped token(s) not tied to the service"),
                        ("order_id_implausible", "uniqid-shaped token(s) with an implausible embedded time")):
        if ids.get(f"{role}_total"):
            notes.append(f"{ids[f'{role}_total']} {label}, {len(ids.get(role, []))} kept in the correlation JSON")
    if notes:
        add("")
        add("Candidates not promoted to facts: " + "; ".join(notes) + ". They remain candidates until confirmed "
            "on-chain or by context.")
    add("")

    add("## Fact coverage: knowledge base vs evidence")
    add("")
    add("| Fact | KB best persistence | Dead-box (KB) | Recovered | KB sources (recovered cells) | Sources found | Artifacts found / expected |")
    add("| --- | --- | --- | --- | --- | --- | --- |")
    for r in corr["fact_checklist"]:
        add(f"| {r['fact']} | {r['best_persistence']} | {_yn(r['dead_box_recoverable'])} | {'yes' if r['recovered'] else 'no'} | "
            f"{', '.join(r['expected_sources']) or '-'} | {', '.join(r['sources_found']) or '-'} | "
            f"{len(r['artifacts_found'])} / {len(r['expected_artifacts'])} |")
    add("")

    add("## Triangulation (deposit -> payout)")
    add("")
    t = corr["triangulation"]
    add(f"Status: **{t['status']}**")
    add("")
    for k in ("deposit_addresses", "destination_addresses", "deposit_txids", "payout_txids", "order_ids"):
        if t.get(k):
            add(f"- {k.replace('_', ' ')}: " + ", ".join(f"`{v}`" for v in t[k]))
    if t.get("derived_order_creation_utc"):
        add(f"- order creation (*derived*): {t['derived_order_creation_utc']}")
    add("")
    add("Analyst steps:")
    add("")
    for s in t["on_chain_steps"]:
        add(f"1. {s}")
    add("")
    add(f"_{t['note']}_")
    add("")

    add("## Timeline")
    add("")
    tl = corr["timeline"]
    add("| Time (UTC) | Event | Value | Source | Locator | Provenance |")
    add("| --- | --- | --- | --- | --- | --- |")
    for e in tl[:max_timeline_rows]:
        val = e["value"] if len(e["value"]) <= 80 else e["value"][:77] + "..."
        cnt = f" (x{e['count']})" if e.get("count", 1) > 1 else ""
        add(f"| {e['time']} | {e['event']}{cnt} | `{val}` | {e['source']} | {e['locator']} | {e['provenance_class']} |")
    if len(tl) > max_timeline_rows:
        add("")
        add(f"... {len(tl) - max_timeline_rows} more events in the correlation JSON.")
    add("")

    add("## Provenance")
    add("")
    add("Per-fact evidence (first entries; the full list is in the correlation JSON):")
    add("")
    for role in _FACT_ROLES:
        for it in ids.get(role, []):
            add(f"- {role} `{it['value']}`:")
            for e in it["evidence"][:max_evidence_rows]:
                add(f"  - {e['source']} @ {e['locator']} [{e['location']}, {e['provenance_class']}]"
                    + (f" as {e['artifact_ref']}" if e.get("artifact_ref") else f" via {e['match']}"))
            if len(it["evidence"]) > max_evidence_rows:
                add(f"  - ... {len(it['evidence']) - max_evidence_rows} more")
    add("")
    return "\n".join(L)


def _yn(v) -> str:
    return "?" if v is None else ("yes" if v else "no")
