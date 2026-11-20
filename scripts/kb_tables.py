"""Render paper tables and entry excerpts straight from a service file, so that what the paper
shows is what the knowledge base contains.

    python scripts/kb_tables.py matrix mixero                      # fact-by-source matrix (markdown)
    python scripts/kb_tables.py matrix mixero --facts deposit_address order_id payout_txid client_ip
    python scripts/kb_tables.py excerpt mixero endpoints.letter receipts.letter_of_guarantee fact_coverage.deposit_address
    python scripts/kb_tables.py observations mixero               # observation registry (markdown)
    python scripts/kb_tables.py replay mixero check_transaction   # replay results (markdown)
    python scripts/kb_tables.py definitions outcomes              # a vocabulary as a label / meaning table
    python scripts/kb_tables.py appendix mixero [--letter A]      # Appendix tables A1-A8 (markdown)
"""

from __future__ import annotations

import argparse
import sys

import yaml

from mixerscope.knowledge_base import SERVICES_DIR, load_service_yaml
from mixerscope.schema import MatrixSource, load_definitions

DEFS = load_definitions()


def _label(vocab: str, code) -> str:
    return DEFS.label(vocab, code.value if hasattr(code, 'value') else code)


def _entry(service: str):
    return load_service_yaml(SERVICES_DIR / f"{service}.yaml")


def matrix(service: str, facts: list[str] | None, sources: list[str] | None) -> str:
    e = _entry(service)
    cols = [MatrixSource(s) for s in sources] if sources else list(MatrixSource)
    rows = [r for r in e.fact_coverage if not facts or r.fact.value in facts]
    out = ["| Fact | " + " | ".join(_label("matrix_sources", c) for c in cols) + " |", "| --- |" + " --- |" * len(cols)]
    for r in rows:
        cells = []
        for c in cols:
            cell = r.cells.get(c)
            if cell is None:
                cells.append("–")
            else:
                cells.append(_label("outcomes", cell.value) + (f": {cell.detail}" if cell.detail else ""))
        out.append(f"| {_label('facts', r.fact)} | " + " | ".join(cells) + " |")
    return "\n".join(out)


def observations(service: str) -> str:
    e = _entry(service)
    out = ["| Id | Kind | Provenance | Tier | Date | OS / browser | Reference |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for o in e.observations:
        env = ", ".join(x for x in (o.os, o.browser_version) if x) or "–"
        out.append(f"| {o.id} | {_label('observation_kinds', o.kind)} | {_label('provenance', o.provenance_class)} | {int(o.tier)} | {o.date or '–'} | {env} | {o.case_ref or '–'} |")
    return "\n".join(out)


def replay(service: str, endpoint_id: str) -> str:
    e = _entry(service)
    ep = e.endpoint(endpoint_id)
    out = ["| Variant | Reply (template) | Reading | Outcome |", "| --- | --- | --- | --- |"]
    for r in ep.replay_results:
        out.append(f"| {_label('replay_variants', r.variant)} | `{r.reply.text if r.reply else '–'}` | {r.reading or '–'} | {_label('replay_outcomes', r.outcome.value) if r.outcome.value else '–'} |")
    return "\n".join(out)


def excerpt(service: str, paths: list[str]) -> str:
    """YAML excerpt of selected records: section.id (endpoints.letter, artifacts.letter_file,
    receipts.letter_of_guarantee, fact_coverage.deposit_address, cookies.ci_session)."""
    raw = yaml.safe_load((SERVICES_DIR / f"{service}.yaml").read_text(encoding="utf-8"))
    chunks = []
    for p in paths:
        section, _, key = p.partition(".")
        items = raw.get(section)
        if not key:
            chunks.append(yaml.safe_dump({section: items}, sort_keys=False, allow_unicode=True, width=100))
            continue
        if isinstance(items, list):
            hit = next((i for i in items if i.get("id") == key or i.get("name") == key or i.get("fact") == key), None)
        else:
            hit = (items or {}).get(key)
        if hit is None:
            print(f"warning: {p} not found", file=sys.stderr)
            continue
        chunks.append(yaml.safe_dump({section: [hit] if isinstance(items, list) else {key: hit}},
                                     sort_keys=False, allow_unicode=True, width=100))
    return "\n".join(chunks)


def definitions(vocab: str) -> str:
    out = ["| Code | Label | Meaning |", "| --- | --- | --- |"]
    for code, entry in DEFS.vocab(vocab).items():
        out.append(f"| `{code}` | {entry.get('label', code)} | {entry.get('meaning') or '–'} |")
    return "\n".join(out)


# --- Appendix tables (A1-A8) --------------------------------------------------------------

def _tb(attr) -> str:
    """Tier/Basis cell: `0/O` style, from an Attr or Attribute."""
    if attr is None:
        return "–"
    return f"{int(attr.tier)}/{DEFS.label('basis', attr.basis)}"


def _val(attr, default: str = "unknown") -> str:
    if attr is None or attr.value is None:
        return default
    v = attr.value
    if isinstance(v, list):
        return ", ".join(_val_one(x) for x in v) if v else "none"
    return _val_one(v)


def _val_one(v) -> str:
    if hasattr(v, "value"):
        code = v.value
        for vocab in ("cache_policies", "gate_mechanisms", "delivery", "receipt_containers", "signature_schemes",
                      "status_mechanisms", "account_models", "persistence", "replay_outcomes", "consistency",
                      "outcomes", "domain_roles", "roles"):
            if DEFS.has(vocab, code):
                return DEFS.label(vocab, code)
        return str(code)
    if isinstance(v, bool):
        return DEFS.label("booleans", str(v).lower())
    return str(v)


def _facts(facts) -> str:
    return ", ".join(DEFS.label("facts", f.value) for f in facts) if facts else "–"


def _rx(p) -> str:
    if p is None:
        return "–"
    return f"`{p.literal}`" if hasattr(p, "literal") else f"`{p.regex}`"


def _row(*cells) -> str:
    return "| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in cells) + " |"


def appendix(service: str, letter: str = "A") -> str:
    e = _entry(service)
    m = e.service
    vd = m.validity_default
    L = letter
    out = [f"# Appendix {L}. Knowledge base entry: {m.display_name}", "",
           f"Rendered from `services/{service}.yaml` (schema {e.schema_version}). Entry status: *{m.entry_status.value}*; "
           f"tiers completed: {', '.join(str(int(t)) for t in m.tiers_completed)}"
           + (f"; validity {vd.first_seen} to {vd.last_seen}" if vd else "") + ". "
           "In the Tier/Basis columns, the number is the collection tier (Table 1) and the letter the evidence basis: "
           "O observed, I inferred, C claimed, U unknown. Values from the test orders do not appear; "
           "`<btc_address>`, `<order_id>` and `<txid_hex64>` are placeholders.", ""]
    n = 0

    def table(title: str, header: list[str], rows: list[str]) -> None:
        nonlocal n
        if not rows:
            return  # a section the entry does not fill yet is left out rather than printed empty
        n += 1
        out.extend([f"**Table {L}{n}.** {title}", "", _row(*header), "|" + "---|" * len(header), *rows, ""])

    # A1 observations
    table("Observations", ["ID", "Kind", "Provenance", "Tier", "Date", "OS / browser"],
          [_row(o.id, DEFS.label("observation_kinds", o.kind), DEFS.label("provenance", o.provenance_class),
                int(o.tier), o.date or "–", ", ".join(x for x in (o.os, o.browser_version) if x) or "–")
           for o in e.observations])

    # A2 identity, access, modes, cookies
    rows = []
    for d in e.identity.domains:
        rows.append(_row(f"Domain ({DEFS.label('domain_roles', d.role)})", d.domain, _tb(d.attr)))
    if e.identity.cdn_proxy:
        rows.append(_row("CDN / reverse proxy", _val(e.identity.cdn_proxy), _tb(e.identity.cdn_proxy)))
    if e.identity.framework.name:
        rows.append(_row("Framework", _val(e.identity.framework.name)
                         + (f" (signals: {'; '.join(e.identity.framework.signals)})" if e.identity.framework.signals else ""),
                         _tb(e.identity.framework.name)))
    if e.identity.client_ip_leak.mechanism:
        rows.append(_row("Client IP exposure", _val(e.identity.client_ip_leak.mechanism), _tb(e.identity.client_ip_leak.mechanism)))
    if e.access.account_model:
        rows.append(_row("Account model", _val(e.access.account_model), _tb(e.access.account_model)))
    if e.access.kyc:
        rows.append(_row("KYC", _val(e.access.kyc), _tb(e.access.kyc)))
    for mode in e.modes:
        parts = []
        if mode.chain_flow: parts.append(f"flow: {_val(mode.chain_flow)}")
        if mode.limits.min or mode.limits.max: parts.append(f"limits: {_val(mode.limits.min, '?')} to {_val(mode.limits.max, '?')}")
        if mode.fee_model: parts.append(f"fee: {_val(mode.fee_model)}")
        if mode.delay_options: parts.append(f"delay: {_val(mode.delay_options)}")
        if mode.page_paths: parts.append("pages: " + ", ".join(f"`{p}`" for p in mode.page_paths))
        rows.append(_row(f"Mode `{mode.id}`", "; ".join(parts) or "–", _tb(mode.attr)))
    for c in e.cookies:
        parts = []
        if c.purpose: parts.append(_val(c.purpose))
        if c.client_max_age: parts.append(f"lifetime: {_val(c.client_max_age)}")
        if c.rotation_interval: parts.append(f"rotated: {_val(c.rotation_interval)}")
        if c.server_side_validity: parts.append(f"server: {_val(c.server_side_validity)}")
        if c.persists_to_disk: parts.append("on disk: " + ("name and metadata, value encrypted" if c.persists_to_disk.value else "no"))
        if c.encodes_fact: parts.append("encodes: " + _facts(c.encodes_fact))
        rows.append(_row(f"Cookie `{c.name}` ({DEFS.label('set_by', c.set_by)})", "; ".join(parts), _tb(c.attr)))
    table("Identity, access, modes and session", ["Field", "Value", "Tier/Basis"], rows)

    # A3 identifiers, endpoints, receipts
    rows = []
    for i in e.order_model.identifiers:
        props = []
        if i.role: props.append(f"role: {_val(i.role)}")
        if i.derivation: props.append(_val(i.derivation))
        if i.exposed_in: props.append("exposed in: " + ", ".join(DEFS.label("locations", x) for x in i.exposed_in))
        rows.append(_row(f"{DEFS.label('facts', i.fact)} (`{i.name}`)", _rx(i.scheme), "; ".join(props), _tb(i.attr)))
    for ep in e.endpoints:
        props = []
        if ep.cache_policy: props.append(f"cache: {_val(ep.cache_policy)}")
        if ep.gate: props.append(f"gate: {_val(ep.gate)}")
        if ep.ownership_check: props.append(f"ownership check: {_val(ep.ownership_check)}")
        if ep.field_facts: props.append("fields: " + ", ".join(f"{k} = {DEFS.label('facts', v)}" for k, v in ep.field_facts.items()))
        rows.append(_row(f"Endpoint `{ep.id}`: {ep.purpose}", f"`{ep.method} {ep.path.regex}`", "; ".join(props) or "–", _tb(ep.attr)))
    for r in e.receipts:
        props = []
        if r.obtained_via.delivery: props.append(f"delivery: {_val(r.obtained_via.delivery)}" + (f" via `{r.obtained_via.endpoint_ref}`" if r.obtained_via.endpoint_ref else ""))
        if r.obtained_via.cache_policy: props.append(f"cache: {_val(r.obtained_via.cache_policy)}")
        if r.structure.container: props.append(f"container: {_val(r.structure.container)}")
        if r.signature.scheme: props.append(f"signature: {_val(r.signature.scheme)}" + (f", signing identity `{r.signature.signing_identity.literal}`" if r.signature.signing_identity else ""))
        if r.signature.verification: props.append(f"verification: {_val(r.signature.verification)}")
        if r.evidentiary_value.binds_facts: props.append("binds: " + _facts(r.evidentiary_value.binds_facts))
        if r.evidentiary_value.survives_server_purge: props.append(f"survives server purge: {_val(r.evidentiary_value.survives_server_purge)}")
        rows.append(_row(f"Receipt: {r.name}", _rx(r.file.filename_pattern), "; ".join(props), _tb(r.attr)))
    table("Order identifiers, endpoints and receipts", ["Element", "Pattern", "Properties", "Tier/Basis"], rows)

    # A4 status and replay
    rows = []
    if e.status.mechanism:
        rows.append(_row("Mechanism", _val(e.status.mechanism) + (f", endpoint `{e.status.endpoint_ref}`" if e.status.endpoint_ref else "") + (f", interval {_val(e.status.interval)}" if e.status.interval else ""), "–", _tb(e.status.mechanism)))
    for st in e.status.states:
        rows.append(_row(f"State {st.order}: {st.label}", f"*{st.template.text}*", "yields " + _facts(st.template.yields), _tb(st.attr)))
    ep = e.endpoint(e.status.endpoint_ref) if e.status.endpoint_ref else None
    if ep:
        for rr in ep.replay_results:
            rows.append(_row("Replay: " + DEFS.label("replay_variants", rr.variant), f"*{rr.reply.text}*" if rr.reply else "–",
                             (rr.reading or "–") + f" (outcome: {_val(rr.outcome)})", _tb(rr.outcome)))
    if e.status.replay_behavior:
        rows.append(_row("Replay behaviour", _val(e.status.replay_behavior), "–", _tb(e.status.replay_behavior)))
    table("Status messages and replay of the status request", ["Element", "Text / reply", "Reading", "Tier/Basis"], rows)

    # A5 artifacts
    table("Artifacts", ["Artifact", "Location", "Facts carried", "Persistence", "Tier/Basis"],
          [_row(a.name, f"{DEFS.label('locations', a.location)}: `{a.path_pattern}`" if a.path_pattern else DEFS.label("locations", a.location),
                _facts(a.carries_facts), _val(a.persistence_class), _tb(a.attr)) for a in e.artifacts])

    # A6 matrix
    cols = list(MatrixSource)
    rows = []
    for r in e.fact_coverage:
        cells = []
        for c in cols:
            cell = r.cells.get(c)
            cells.append("–" if cell is None else _label("outcomes", cell.value) + (f": {cell.detail}" if cell.detail else ""))
        rows.append(_row(_label("facts", r.fact), *cells))
    table("Fact-by-source matrix (cell values as in Table 3)", ["Fact"] + [_label("matrix_sources", c) for c in cols], rows)

    # A7 retention and negative findings
    rows = []
    for sp in e.retention.stated_policy:
        rows.append(_row("Operator claim", _val(sp), _tb(sp)))
    for ob in e.retention.observed:
        rows.append(_row("Observed", _val(ob), _tb(ob)))
    if e.retention.consistency:
        rows.append(_row("Consistency", _val(e.retention.consistency) + (f": {e.retention.consistency.notes}" if e.retention.consistency.notes else ""), _tb(e.retention.consistency)))
    for nf in e.negative_findings:
        facts = f" [{', '.join(DEFS.label('facts', f) for f in nf.facts)}]" if nf.facts else ""
        rows.append(_row(f"Negative ({DEFS.label('locations', nf.location)})", f"{nf.finding}" + (f": {nf.reason}" if nf.reason else "") + facts + f" ({_val(nf.attr)})", _tb(nf.attr)))
    table("Retention claims, observed behaviour and negative findings", ["Kind", "Statement", "Tier/Basis"], rows)

    # A8 indicators
    table("Identification indicators (weight = analyst-assigned specificity, 0 to 1)", ["Kind", "Value", "Weight", "Tier/Basis"],
          [_row(DEFS.label("indicator_kinds", i.kind), _rx(i.value), i.weight, _tb(i.attr)) for i in e.indicators])
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("matrix"); m.add_argument("service"); m.add_argument("--facts", nargs="*"); m.add_argument("--sources", nargs="*")
    o = sub.add_parser("observations"); o.add_argument("service")
    r = sub.add_parser("replay"); r.add_argument("service"); r.add_argument("endpoint")
    x = sub.add_parser("excerpt"); x.add_argument("service"); x.add_argument("paths", nargs="+")
    d = sub.add_parser("definitions"); d.add_argument("vocab")
    ax = sub.add_parser("appendix"); ax.add_argument("service"); ax.add_argument("--letter", default="A")
    a = ap.parse_args(argv)
    if a.cmd == "matrix":
        print(matrix(a.service, a.facts, a.sources))
    elif a.cmd == "observations":
        print(observations(a.service))
    elif a.cmd == "replay":
        print(replay(a.service, a.endpoint))
    elif a.cmd == "definitions":
        print(definitions(a.vocab))
    elif a.cmd == "appendix":
        print(appendix(a.service, a.letter))
    else:
        print(excerpt(a.service, a.paths))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
