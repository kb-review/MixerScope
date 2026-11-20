"""Investigator profile: the six questions an examiner asks, answered from one service entry."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

from mixerscope.schema import Basis, CellValue, InvariantLiteral, MatrixSource, ReplayOutcome, ServiceEntry, load_definitions

from . import SERVICES_DIR, iter_seed_paths, load_service_yaml
from .consistency import source_locations

VIEW_PATH = Path(__file__).resolve().parents[2] / "views" / "profile_view.yaml"
DEFAULT_OUT_DIR = Path("build") / "profiles"
PRESENT = (CellValue.RECOVERED, CellValue.METADATA_ONLY)
WEAK_WEIGHT = 0.2


def load_view(path: Path | str = VIEW_PATH) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# --- JSON -----------------------------------------------------------------------------------


def _tb(attr) -> dict[str, Any]:
    if attr is None:
        return {"tier": None, "basis": None}
    return {"tier": int(attr.tier), "basis": attr.basis.value}


def _val(attr):
    if attr is None or attr.value is None:
        return None
    v = attr.value
    if isinstance(v, list):
        return [x.value if hasattr(x, "value") else x for x in v]
    if isinstance(v, dict):
        return {k: (x.value if hasattr(x, "value") else x) for k, x in v.items()}
    return v.value if hasattr(v, "value") and not isinstance(v, (str, int, float, bool)) else v


def _pattern_text(p) -> str:
    return p.literal if isinstance(p, InvariantLiteral) else p.regex


def build_profile(e: ServiceEntry) -> dict[str, Any]:
    defs = load_definitions()
    cols = source_locations()
    loc_col = defs.location_to_source()
    sid = e.service.id
    m = e.service

    # scope
    disks = [o for o in e.observations if o.kind.value == "disk_image"]
    vd = m.validity_default
    scope = {
        "status": m.entry_status.value,
        "tiers": [int(t) for t in m.tiers_completed],
        "valid": {"first_seen": vd.first_seen, "last_seen": vd.last_seen} if vd else None,
        "disk": [{"id": o.id, "os": o.os, "browser": o.browser_version,
                  "conditions": o.conditions, "tier": int(o.tier), "ref": f"observations.{o.id}"} for o in disks],
    }

    # recognise
    recognise: list[dict[str, Any]] = []
    for i, ind in sorted(enumerate(e.indicators), key=lambda x: -x[1].weight):
        recognise.append({"value": _pattern_text(ind.value), "literal": isinstance(ind.value, InvariantLiteral),
                          "kind": ind.kind.value, "weight": ind.weight, "weak": ind.weight <= WEAK_WEIGHT,
                          **_tb(ind.attr), "ref": f"indicators[{i}]"})
    domains = [{"domain": d.domain, "role": d.role.value, "clone": d.role.value == "suspected_clone",
                **_tb(d.attr), "ref": f"identity.domains[{i}]"} for i, d in enumerate(e.identity.domains)]

    # where_is
    where_is: list[dict[str, Any]] = []
    for fact in defs.codes("facts"):
        row = e.matrix_row(fact)
        if row is None:
            continue
        for src, cell in row.cells.items():
            if cell.value not in PRESENT or not defs.vocab("matrix_sources")[src.value].get("disk", False):
                continue
            ft = _tb(row.attr)
            for a in e.artifacts:
                if a.location.value in cols.get(src.value, []) and row.fact in a.carries_facts:
                    where_is.append({
                        "fact": fact, "fact_tier": ft.get("tier"), "fact_basis": ft.get("basis"),
                        "source": src.value, "outcome": cell.value.value, "detail": cell.detail,
                        "location": a.location.value, "artifact": a.id, "field": a.path_pattern,
                        "recovery": _val(a.recovery_route), "caveat": _val(a.caveat),
                        **_tb(a.attr or a.persistence_class), "ref": f"artifacts.{a.id}"})

    # interpret
    interpret: list[dict[str, Any]] = []
    for ident in e.order_model.identifiers:
        interpret.append({"kind": "identifier", "subject": ident.name, "fact": ident.fact.value,
                          "role": _val(ident.role), "derivation": _val(ident.derivation),
                          "scheme": ident.scheme.regex if ident.scheme else None,
                          **_tb(ident.attr or ident.role or ident.derivation), "ref": f"order_model.identifiers.{ident.name}"})
    for r in e.receipts:
        if r.field_map and r.field_map.value:
            interpret.append({"kind": "field_map", "subject": r.name, "map": _val(r.field_map),
                              **_tb(r.field_map), "ref": f"receipts.{r.id}.field_map"})
        if r.signature.signing_identity:
            interpret.append({"kind": "signing_identity", "subject": r.name, "literal": r.signature.signing_identity.literal,
                              "scheme": _val(r.signature.scheme), **_tb(r.signature.scheme or r.attr),
                              "ref": f"receipts.{r.id}.signature"})
    for a in e.artifacts:
        if a.caveat and a.caveat.value:
            interpret.append({"kind": "caveat", "subject": a.name, "text": a.caveat.value, **_tb(a.caveat),
                              "ref": f"artifacts.{a.id}.caveat"})
    for r in e.fact_coverage:
        if r.notes:
            interpret.append({"kind": "row_notes", "subject": r.fact.value, "text": r.notes, **_tb(r.attr),
                              "ref": f"fact_coverage.{r.fact.value}.notes"})
    if len(e.retention.stated_policy) > 1:
        for i, sp in enumerate(e.retention.stated_policy):
            if sp.value:
                interpret.append({"kind": "retention_claim", "subject": None, "text": sp.value, **_tb(sp),
                                  "ref": f"retention.stated_policy[{i}]"})

    # expected absences
    absences: list[dict[str, Any]] = []
    nfs = list(enumerate(e.negative_findings))
    for fact in defs.codes("facts"):
        row = e.matrix_row(fact)
        if row is None:
            continue
        for src, cell in row.cells.items():
            if cell.value is not CellValue.NOT_STORED_BY_DESIGN:
                continue
            findings = [{"location": nf.location.value, "finding": nf.finding, "reason": nf.reason,
                         "implication": _val(nf.implication), "outcome": _val(nf.attr), **_tb(nf.attr),
                         "ref": f"negative_findings[{i}]"}
                        for i, nf in nfs if loc_col.get(nf.location.value) == src.value
                        and nf.attr.value is CellValue.NOT_STORED_BY_DESIGN
                        and (not nf.facts or fact in [f.value for f in nf.facts])]
            absences.append({"fact": fact, "source": src.value, "outcome": cell.value.value, "detail": cell.detail,
                             "findings": findings, **_tb(row.attr), "ref": f"fact_coverage.{fact}.cells.{src.value}"})
    paired = {f["ref"] for it in absences for f in it["findings"]}
    unpaired = [{"location": nf.location.value, "source": loc_col.get(nf.location.value), "finding": nf.finding,
                 "reason": nf.reason, "implication": _val(nf.implication), "outcome": _val(nf.attr), **_tb(nf.attr),
                 "ref": f"negative_findings[{i}]"}
                for i, nf in nfs if nf.attr.value is CellValue.NOT_STORED_BY_DESIGN and f"negative_findings[{i}]" not in paired]
    not_found = [{"fact": None, "source": loc_col.get(nf.location.value), "outcome": nf.attr.value.value, "detail": None,
                  "findings": [{"location": nf.location.value, "finding": nf.finding, "reason": nf.reason,
                                "implication": _val(nf.implication), "outcome": _val(nf.attr), **_tb(nf.attr),
                                "ref": f"negative_findings[{i}]"}],
                  **_tb(nf.attr), "ref": f"negative_findings[{i}]"}
                 for i, nf in nfs if nf.attr.value is CellValue.NOT_FOUND]

    # beyond disk
    obs_by_id = {o.id: o for o in e.observations}

    def cites(attr) -> list[dict[str, Any]]:
        return [{"id": oid, "date": obs_by_id[oid].date if oid in obs_by_id else None} for oid in (attr.sources or [])]

    beyond: list[dict[str, Any]] = []
    for ep in e.endpoints:
        if ep.lookup_key and ep.lookup_key.value:
            beyond.append({"kind": "lookup", "subject": ep.id, "method": ep.method, "path": ep.path.regex,
                           "lookup_key": _val(ep.lookup_key), "ownership_check": _val(ep.ownership_check),
                           "gate": _val(ep.gate), **_tb(ep.lookup_key), "ref": f"endpoints.{ep.id}"})
    for ep in e.endpoints:
        for i, rr in enumerate(ep.replay_results):
            if rr.outcome and rr.outcome.value in (ReplayOutcome.LIVE, ReplayOutcome.ACCEPTED):
                beyond.append({"kind": "replay", "subject": ep.id, "variant": rr.variant.value, "reading": rr.reading,
                               "outcome": rr.outcome.value.value, "cites": cites(rr.outcome), **_tb(rr.outcome),
                               "ref": f"endpoints.{ep.id}.replay_results[{i}]"})
    for i, sp in enumerate(e.retention.stated_policy):
        if sp.value:
            beyond.append({"kind": "retention_claim", "subject": None, "text": sp.value, **_tb(sp), "ref": f"retention.stated_policy[{i}]"})
    for i, ob in enumerate(e.retention.observed):
        if ob.value:
            beyond.append({"kind": "retention_observed", "subject": None, "text": ob.value, "cites": cites(ob), **_tb(ob),
                           "ref": f"retention.observed[{i}]"})
    if e.retention.consistency and e.retention.consistency.value:
        c = e.retention.consistency
        beyond.append({"kind": "retention_consistency", "subject": None, "value": c.value.value, "text": c.notes, **_tb(c),
                       "ref": "retention.consistency"})
    for r in e.receipts:
        if r.signature.scheme or r.signature.verification:
            beyond.append({"kind": "signature", "subject": r.name, "scheme": _val(r.signature.scheme),
                           "scheme_notes": r.signature.scheme.notes if r.signature.scheme else None,
                           "verification": _val(r.signature.verification),
                           "verification_notes": r.signature.verification.notes if r.signature.verification else None,
                           "signing_identity": r.signature.signing_identity.literal if r.signature.signing_identity else None,
                           **_tb(r.signature.scheme or r.signature.verification), "ref": f"receipts.{r.id}.signature"})
    for fact in defs.codes("facts"):
        row = e.matrix_row(fact)
        cell = row.cells.get(MatrixSource.CHAIN) if row else None
        if cell and cell.value not in (CellValue.NOT_APPLICABLE, CellValue.NOT_TESTED):
            beyond.append({"kind": "chain", "subject": fact, "outcome": cell.value.value, "detail": cell.detail,
                           **_tb(row.attr), "ref": f"fact_coverage.{fact}.cells.chain"})

    # limits
    all_tiers = [int(t) for t in defs.codes("tiers")]
    limits: dict[str, Any] = {
        "tiers_not_run": [t for t in all_tiers if t not in scope["tiers"]],
        "facts_not_tested": [r.fact.value for r in e.fact_coverage
                             if r.cells and all(c.value is CellValue.NOT_TESTED for c in r.cells.values())],
        "columns_not_tested": [c for c in defs.codes("matrix_sources")
                               if any(MatrixSource(c) in r.cells for r in e.fact_coverage)
                               and all(r.cells[MatrixSource(c)].value is CellValue.NOT_TESTED
                                       for r in e.fact_coverage if MatrixSource(c) in r.cells)],
        "unknown": [{"ref": p, "notes": a.notes} for p, a in e.iter_attrs() if a.basis is Basis.UNKNOWN],
        "status": m.entry_status.value,
        "disk": scope["disk"],
    }

    return {"service": sid, "display_name": m.display_name, "scope": scope,
            "recognise": recognise, "domains": domains, "where_is": where_is, "interpret": interpret,
            "expected_absences": absences, "design_findings_without_cell": unpaired, "not_found": not_found,
            "beyond_disk": beyond, "limits": limits}


# --- Markdown -------------------------------------------------------------------------------


class _Allowed:
    """The strings a rendering may print: values of the entry (or, without the entry, of the
    profile), the profile's refs, definition labels and view strings."""

    def __init__(self, profile: dict[str, Any], view: dict[str, Any], entry_dump: dict[str, Any] | None = None) -> None:
        self.ok: set[str] = set()
        if entry_dump is not None:
            self._collect(entry_dump)
            self._collect_refs(profile)
        else:
            self._collect(profile)
        self._collect(view)
        defs = load_definitions()
        for vocab in defs.vocabularies():
            for code, entry in defs.vocab(vocab).items():
                self.ok.add(str(code))
                self.ok.add(str(entry.get("label", code)))
                if entry.get("meaning"):
                    self.ok.add(str(entry["meaning"]))

    def _collect(self, obj) -> None:
        if isinstance(obj, str):
            self.ok.add(obj)
        elif isinstance(obj, bool):
            return
        elif isinstance(obj, (int, float)):
            self.ok.add(str(obj))
        elif isinstance(obj, dict):
            for k, v in obj.items():
                self._collect(k)
                self._collect(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                self._collect(v)

    def _collect_refs(self, obj) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "ref" and isinstance(v, str):
                    self.ok.add(v)
                else:
                    self._collect_refs(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                self._collect_refs(v)

    def t(self, s) -> str:
        if s is None:
            return ""
        s = str(s)
        if s not in self.ok and not re.fullmatch(r"-?\d+(\.\d+)?", s):
            raise ValueError(f"profile renderer tried to print text that is in neither the entry, the definitions nor the view: {s!r}")
        return s


def render_markdown(profile: dict[str, Any], view: dict[str, Any] | None = None, entry: ServiceEntry | None = None) -> str:
    """Markdown layout of a profile. With `entry`, every printed string must be a value of that
    entry (the no-added-text rule is then checked against the source, not the derived JSON)."""
    view = view or load_view()
    A = _Allowed(profile, view, entry.model_dump(mode="json") if entry is not None else None)
    T = A.t
    defs = load_definitions()
    L = view["labels"]
    S = view["sections"]

    def lab(vocab: str, code) -> str:
        return T(defs.label(vocab, code)) if code is not None and defs.has(vocab, code) else T(code)

    def tb(item) -> str:
        if item.get("tier") is None or item.get("basis") is None:
            return ""
        return f"{T(item['tier'])}/{lab('basis', item['basis'])}"

    def ref(item) -> str:
        return f"`{T(item['ref'])}`"

    def row(*cells) -> str:
        return "| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in cells) + " |"

    def table(cols: list[str], rows: list[str]) -> list[str]:
        if not rows:
            return [T(L["empty"]), ""]
        return [row(*(T(c) for c in cols)), "|" + "---|" * len(cols), *rows, ""]

    def code(s) -> str:
        return f"`{T(s)}`" if s else ""

    out = [f"# {T(profile['display_name'])}: {T(view['title'])}", ""]
    sc = profile["scope"]
    I = view["intro"]
    parts = [f"{T(I['status'])}: *{lab('entry_status', sc['status'])}*",
             f"{T(I['tiers'])}: " + ", ".join(lab("tiers", t) for t in sc["tiers"])]
    if sc["valid"]:
        parts.append(f"{T(I['valid'])}: {T(sc['valid']['first_seen'])} to {T(sc['valid']['last_seen'])}")
    def env(d) -> str:
        return ", ".join(T(x) for x in (d["os"], d["browser"]) if x)

    for d in sc["disk"]:
        if env(d):
            parts.append(f"{T(I['env'])}: {env(d)}")
        if d["conditions"]:
            parts.append(f"{T(I['conditions'])}: {T(d['conditions'])}")
    out.append(f"**{T(I['scope'])}.** " + "; ".join(parts) + ".")
    out.append("")
    out.append(T(I["legend"]))
    out.append("")

    # 1 recognise
    sec = S["recognise"]
    out += [f"## {T(sec['title'])}", ""]
    rows = []
    for it in profile["recognise"]:
        kind = lab("indicator_kinds", it["kind"]) + (f" ({T(sec['weak'])})" if it["weak"] else "")
        rows.append(row(code(it["value"]), kind, tb(it), ref(it)))
    out += table(sec["columns"], rows)
    rows = [row(code(d["domain"]), lab("domain_roles", d["role"]) + (f": {T(sec['clone'])}" if d["clone"] else ""), tb(d), ref(d))
            for d in profile["domains"]]
    out += table(sec["domains_columns"], rows)

    # 2 where_is
    sec = S["where_is"]
    out += [f"## {T(sec['title'])}", ""]
    groups: dict[str, list[dict[str, Any]]] = {}
    for it in profile["where_is"]:
        groups.setdefault(it["artifact"], []).append(it)
    rows = []
    def fact_tb(it, first) -> str:
        # the fact's own tier and basis (its matrix row), shown when they differ from the artifact's
        if (it.get("fact_tier"), it.get("fact_basis")) in ((None, None), (first["tier"], first["basis"])):
            return ""
        return f" ({T(it['fact_tier'])}/{lab('basis', it['fact_basis'])})"

    for items in groups.values():
        first = items[0]
        facts = "; ".join(f"**{lab('facts', it['fact'])}**" + fact_tb(it, first) + (f": {T(it['detail'])}" if it["detail"] else "")
                          for it in items)
        rows.append(row(facts, lab("locations", first["location"]), code(first["field"]) if first["field"] else "",
                        T(first["recovery"]), T(first["caveat"]), tb(first), ref(first)))
    out += table(sec["columns"], rows)

    # 3 interpret
    sec = S["interpret"]
    out += [f"## {T(sec['title'])}", ""]
    rows = []
    for it in profile["interpret"]:
        k = it["kind"]
        if k == "identifier":
            stmt = "; ".join(x for x in (lab("facts", it["fact"]), lab("roles", it["role"]) if it["role"] else "",
                                         code(it["scheme"]), T(it["derivation"])) if x)
            rows.append(row(T(sec["identifier"]), code(it["subject"]), stmt, tb(it), ref(it)))
        elif k == "field_map":
            stmt = "; ".join(f"{code(label)} {lab('facts', fact)}" for label, fact in it["map"].items())
            rows.append(row(T(sec["field_map"]), T(it["subject"]), stmt, tb(it), ref(it)))
        elif k == "signing_identity":
            stmt = code(it["literal"]) + (f" ({lab('signature_schemes', it['scheme'])})" if it["scheme"] else "")
            rows.append(row(T(sec["signing_identity"]), T(it["subject"]), stmt, tb(it), ref(it)))
        elif k == "caveat":
            rows.append(row(T(sec["caveat"]), T(it["subject"]), T(it["text"]), tb(it), ref(it)))
        elif k == "row_notes":
            rows.append(row(T(sec["row_notes"]), lab("facts", it["subject"]), T(it["text"]), tb(it), ref(it)))
        elif k == "retention_claim":
            rows.append(row(T(sec["retention_claims"]), "", T(it["text"]), tb(it), ref(it)))
    out += table(sec["columns"], rows)

    # 4 expected absences
    sec = S["expected_absences"]
    out += [f"## {T(sec['title'])}", ""]
    by_finding: dict[str, tuple[dict[str, Any], list[dict[str, Any]]]] = {}
    orphan: dict[str, list[dict[str, Any]]] = {}
    for it in profile["expected_absences"]:
        if it["findings"]:
            for f in it["findings"]:
                by_finding.setdefault(f["ref"], (f, []))[1].append(it)
        else:
            orphan.setdefault(it["source"], []).append(it)

    def facts_of(items) -> str:
        return "; ".join(lab("facts", it["fact"]) + (f": {T(it['detail'])}" if it["detail"] else "") for it in items)

    def finding_text(f, src) -> str:
        # the finding's location, when the column groups several locations (Local vs Session Storage)
        loc = lab("locations", f["location"])
        prefix = f"{loc}: " if src and loc != lab("matrix_sources", src) else ""
        return prefix + T(f["finding"]) + (f": {T(f['reason'])}" if f["reason"] else "")

    rows = []
    for f, items in by_finding.values():
        src = items[0]["source"]
        rows.append(row(lab("matrix_sources", src), finding_text(f, src), facts_of(items), T(f["implication"]), tb(f), ref(f)))
    for src, items in orphan.items():
        rows.append(row(lab("matrix_sources", src), "", facts_of(items), "", tb(items[0]), ref(items[0])))
    for f in profile["design_findings_without_cell"]:
        rows.append(row(lab("matrix_sources", f["source"]) if f["source"] else lab("locations", f["location"]),
                        finding_text(f, f["source"]), "", T(f["implication"]), tb(f), ref(f)))
    for it in profile["not_found"]:
        f = it["findings"][0]
        rows.append(row(lab("matrix_sources", it["source"]) if it["source"] else lab("locations", f["location"]),
                        f"{T(sec['no_design_reason'])}: " + finding_text(f, it["source"]),
                        "", T(f["implication"]), tb(f), ref(f)))
    out += table(sec["columns"], rows)

    # 5 beyond disk
    sec = S["beyond_disk"]
    out += [f"## {T(sec['title'])}", ""]
    def cited(it) -> str:
        srcs = it.get("cites") or []
        if not srcs:
            return ""
        return f"; {T(L['cites'])}: " + ", ".join(T(s["id"]) + (f" ({T(s['date'])})" if s["date"] else "") for s in srcs)

    rows = []
    for it in profile["beyond_disk"]:
        k = it["kind"]
        if k == "lookup":
            parts = [f"{T(L['lookup_key'])}: {lab('facts', it['lookup_key'])}"]
            if it["ownership_check"] is not None:
                parts.append(f"{T(L['ownership_check'])}: {T(L['yes'] if it['ownership_check'] else L['no'])}")
            if it["gate"] is not None:
                parts.append(f"{T(L['gate'])}: " + (", ".join(lab("gate_mechanisms", g) for g in it["gate"]) if it["gate"] else T(L["none"])))
            rows.append(row(T(sec["lookup"]), f"{T(it['method'])} {code(it['path'])}", "; ".join(parts), tb(it), ref(it)))
        elif k == "replay":
            rows.append(row(T(sec["replay"]), code(it["subject"]),
                            f"{lab('replay_variants', it['variant'])}: {T(it['reading'])} ({lab('replay_outcomes', it['outcome'])})" + cited(it),
                            tb(it), ref(it)))
        elif k == "retention_claim":
            rows.append(row(T(sec["retention_claim"]), "", T(it["text"]), tb(it), ref(it)))
        elif k == "retention_observed":
            rows.append(row(T(sec["retention_observed"]), "", T(it["text"]) + cited(it), tb(it), ref(it)))
        elif k == "retention_consistency":
            rows.append(row(T(sec["retention_consistency"]), "", lab("consistency", it["value"]) + (f": {T(it['text'])}" if it["text"] else ""), tb(it), ref(it)))
        elif k == "signature":
            parts = []
            if it["scheme"]:
                parts.append(f"{T(L['scheme'])}: {lab('signature_schemes', it['scheme'])}"
                             + (f" ({T(it['scheme_notes'])})" if it.get("scheme_notes") else ""))
            if it["signing_identity"]:
                parts.append(code(it["signing_identity"]))
            parts.append(f"{T(L['verification'])}: " + (T(it["verification"]) if it["verification"]
                                                       else T(it.get("verification_notes")) or lab("basis", "unknown")))
            rows.append(row(T(sec["signature"]), T(it["subject"]), "; ".join(parts), tb(it), ref(it)))
        elif k == "chain":
            rows.append(row(T(sec["chain"]), lab("facts", it["subject"]), lab("outcomes", it["outcome"]) + (f": {T(it['detail'])}" if it["detail"] else ""), tb(it), ref(it)))
    out += table(sec["columns"], rows)

    # 6 limits
    sec = S["limits"]
    out += [f"## {T(sec['title'])}", ""]
    lim = profile["limits"]
    rows = []
    rows.append(row(T(sec["tiers_not_run"]), ", ".join(lab("tiers", t) for t in lim["tiers_not_run"]) or T(L["none"]), ""))
    rows.append(row(T(sec["facts_not_tested"]), ", ".join(lab("facts", f) for f in lim["facts_not_tested"]) or T(L["none"]), ""))
    rows.append(row(T(sec["columns_not_tested"]), ", ".join(lab("matrix_sources", c) for c in lim["columns_not_tested"]) or T(L["none"]), ""))
    for u in lim["unknown"]:
        rows.append(row(T(sec["unknown"]), T(u["notes"]), code(u["ref"])))
    rows.append(row(T(sec["status"]), lab("entry_status", lim["status"]), ""))
    for d in lim["disk"]:
        rows.append(row(T(sec["conditions"]), "; ".join(x for x in (env(d), T(d["conditions"])) if x), code(d["ref"])))
    out += table(sec["columns"], rows)
    return "\n".join(out)


# --- CLI / build hook -----------------------------------------------------------------------


def write_profiles(entries: list[ServiceEntry], out_dir: Path | str = DEFAULT_OUT_DIR) -> list[Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    view = load_view()
    written = []
    for e in entries:
        prof = build_profile(e)
        jp = out_dir / f"{e.service.id}.json"
        mp = out_dir / f"{e.service.id}.md"
        jp.write_text(json.dumps(prof, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
        mp.write_text(render_markdown(prof, view, entry=e) + "\n", encoding="utf-8", newline="\n")
        written += [jp, mp]
    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate investigator profiles (JSON and Markdown) from the service entries.")
    ap.add_argument("--services-dir", default=str(SERVICES_DIR))
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    ap.add_argument("services", nargs="*", help="service ids (default: all)")
    args = ap.parse_args(argv)
    entries = [load_service_yaml(p) for p in iter_seed_paths(Path(args.services_dir))]
    if args.services:
        entries = [e for e in entries if e.service.id in args.services]
    for p in write_profiles(entries, args.out_dir):
        print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
