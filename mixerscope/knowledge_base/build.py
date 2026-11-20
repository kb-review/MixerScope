"""Build the SQLite knowledge base from the YAML seed files."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from mixerscope import __version__
from mixerscope.schema import SCHEMA_VERSION, Attribute, InvariantLiteral, Pattern, ServiceEntry, load_definitions

from . import SERVICES_DIR, iter_seed_paths, load_service_yaml
from .consistency import check_entry

DEFAULT_DB_PATH = Path("build") / "kb.sqlite"
KB_MARKER = "mixerscope-kb"

DDL = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

-- Shared definitions (knowledge_base/definitions.yaml): every code a service file may use,
-- with its label and meaning. Renderers and the MCP tools read labels from here.
CREATE TABLE definitions (
    vocab TEXT NOT NULL, code TEXT NOT NULL, position INTEGER NOT NULL, label TEXT NOT NULL, meaning TEXT,
    extra TEXT NOT NULL, PRIMARY KEY (vocab, code)
);

CREATE TABLE services (
    id TEXT PRIMARY KEY, display_name TEXT NOT NULL, entry_status TEXT NOT NULL,
    tiers_completed TEXT NOT NULL, canonical_domain TEXT, max_tier INTEGER,
    schema_version TEXT NOT NULL, source_file TEXT NOT NULL, entry_json TEXT NOT NULL
);

CREATE TABLE observations (
    service TEXT NOT NULL REFERENCES services(id), id TEXT NOT NULL, kind TEXT NOT NULL,
    provenance_class TEXT NOT NULL, tier INTEGER NOT NULL, date TEXT, os TEXT, browser_version TEXT,
    case_ref TEXT, notes TEXT, conditions TEXT, PRIMARY KEY (service, id)
);

-- One row per Attr / Attribute reachable in the entry (ServiceEntry.iter_attrs()).
CREATE TABLE attributes (
    id INTEGER PRIMARY KEY, service TEXT NOT NULL REFERENCES services(id),
    path TEXT NOT NULL, section TEXT NOT NULL, tier INTEGER NOT NULL, basis TEXT NOT NULL,
    sources TEXT NOT NULL, provenance_classes TEXT NOT NULL, validity TEXT, notes TEXT, value_json TEXT,
    UNIQUE (service, path)
);

CREATE TABLE domains (
    service TEXT NOT NULL REFERENCES services(id), domain TEXT NOT NULL, role TEXT NOT NULL,
    PRIMARY KEY (service, domain, role)
);

CREATE TABLE cookies (
    service TEXT NOT NULL REFERENCES services(id), name TEXT NOT NULL, set_by TEXT NOT NULL,
    encodes_facts TEXT NOT NULL, persists_to_disk INTEGER, value_scheme TEXT, PRIMARY KEY (service, name)
);

CREATE TABLE endpoints (
    service TEXT NOT NULL REFERENCES services(id), id TEXT NOT NULL, method TEXT NOT NULL,
    path_regex TEXT NOT NULL, purpose TEXT NOT NULL, request_fields TEXT NOT NULL, field_facts TEXT NOT NULL,
    gate TEXT, ownership_check INTEGER, cache_policy TEXT, templates TEXT NOT NULL, replay_results TEXT NOT NULL,
    lookup_key TEXT, PRIMARY KEY (service, id)
);

CREATE TABLE status_states (
    service TEXT NOT NULL REFERENCES services(id), position INTEGER NOT NULL, label TEXT NOT NULL,
    template_text TEXT NOT NULL, template_regex TEXT NOT NULL, yields TEXT NOT NULL, tier INTEGER,
    PRIMARY KEY (service, position)
);

CREATE TABLE receipts (
    service TEXT NOT NULL REFERENCES services(id), id TEXT NOT NULL, name TEXT NOT NULL,
    endpoint_ref TEXT, delivery TEXT, cache_policy TEXT, filename_regex TEXT, mime_type TEXT,
    signature_scheme TEXT, signing_identity TEXT, binds_facts TEXT NOT NULL, artifact_refs TEXT NOT NULL,
    templates TEXT NOT NULL, field_map TEXT, PRIMARY KEY (service, id)
);

CREATE TABLE artifacts (
    service TEXT NOT NULL REFERENCES services(id), id TEXT NOT NULL, name TEXT NOT NULL,
    location TEXT NOT NULL, path_pattern TEXT, filename_regex TEXT, produced_by TEXT, receipt_ref TEXT, format TEXT,
    carries_facts TEXT NOT NULL, persistence_class TEXT, persistence_basis TEXT, recovery_route TEXT,
    search_keys TEXT NOT NULL, content_templates TEXT NOT NULL, case_uco_class TEXT, caveat TEXT, PRIMARY KEY (service, id)
);

-- The fact-by-source matrix, one row per (fact, source).
CREATE TABLE matrix (
    service TEXT NOT NULL REFERENCES services(id), fact TEXT NOT NULL, source TEXT NOT NULL,
    value TEXT NOT NULL, detail TEXT, PRIMARY KEY (service, fact, source)
);

CREATE TABLE fact_rows (
    service TEXT NOT NULL REFERENCES services(id), fact TEXT NOT NULL, best_persistence TEXT,
    artifacts TEXT NOT NULL, dead_box_recoverable INTEGER NOT NULL, on_chain_reconstructable INTEGER NOT NULL,
    notes TEXT, PRIMARY KEY (service, fact)
);

CREATE TABLE negative_findings (
    id INTEGER PRIMARY KEY, service TEXT NOT NULL REFERENCES services(id),
    location TEXT NOT NULL, finding TEXT NOT NULL, reason TEXT, value TEXT, tier INTEGER NOT NULL, basis TEXT NOT NULL,
    implication TEXT, facts TEXT NOT NULL
);

CREATE TABLE indicators (
    id INTEGER PRIMARY KEY, service TEXT NOT NULL REFERENCES services(id),
    kind TEXT NOT NULL, is_literal INTEGER NOT NULL, value TEXT NOT NULL, regex TEXT NOT NULL,
    describes TEXT, weight REAL NOT NULL, tier INTEGER NOT NULL, basis TEXT NOT NULL
);

-- Every regex in the entry (expanded placeholders), for the matcher.
CREATE TABLE patterns (
    id INTEGER PRIMARY KEY, service TEXT NOT NULL REFERENCES services(id),
    path TEXT NOT NULL, kind TEXT NOT NULL, label TEXT, regex TEXT NOT NULL, describes TEXT
);

CREATE INDEX idx_attr_service_tier ON attributes(service, tier);
CREATE INDEX idx_patterns_kind ON patterns(kind);
"""


@dataclass
class BuildReport:
    db_path: Path
    services: list[str] = field(default_factory=list)
    attribute_counts: dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        lines = [f"knowledge base written to {self.db_path}"]
        for s in self.services:
            lines.append(f"  {s}: {self.attribute_counts.get(s, 0)} attributes")
        return "\n".join(lines)


def _j(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _b(attr: Attribute | None) -> int | None:
    return None if attr is None or attr.value is None else int(bool(attr.value))


def _v(attr: Attribute | None):
    """Plain value of an Attribute (enum members as their string value)."""
    if attr is None or attr.value is None:
        return None
    v = attr.value
    return v.value if hasattr(v, "value") and not isinstance(v, (str, int, float, bool, list, dict)) else v


def _tpl(t, oid_rx) -> dict:
    return {"text": t.text, "regex": t.to_regex(order_id_regex=oid_rx), "yields": [f.value for f in t.yields],
            "literals": [lit.literal for lit in t.literals]}


def _insert_service(conn: sqlite3.Connection, e: ServiceEntry, source_file: Path) -> int:
    sid = e.service.id
    obs_class = {o.id: o.provenance_class.value for o in e.observations}
    max_tier = e.max_tier()
    conn.execute("INSERT INTO services VALUES (?,?,?,?,?,?,?,?,?)",
                 (sid, e.service.display_name, e.service.entry_status.value, _j([int(t) for t in e.service.tiers_completed]),
                  e.canonical_domain(), int(max_tier) if max_tier is not None else None, e.schema_version,
                  str(source_file), _j(e.model_dump(mode="json"))))
    for o in e.observations:
        conn.execute("INSERT INTO observations VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                     (sid, o.id, o.kind.value, o.provenance_class.value, int(o.tier), o.date, o.os, o.browser_version,
                      o.case_ref, o.notes, o.conditions))

    n = 0
    default_validity = e.service.validity_default.model_dump(mode="json") if e.service.validity_default else None
    for path, a in e.iter_attrs():
        value = a.value if isinstance(a, Attribute) else None
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="json")
        validity = a.validity.model_dump(mode="json") if a.validity else default_validity
        conn.execute(
            "INSERT INTO attributes (service, path, section, tier, basis, sources, provenance_classes, validity, notes, value_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (sid, path, path.split(".", 1)[0].split("[", 1)[0], int(a.tier), a.basis.value, _j(a.sources),
             _j(sorted({obs_class[s] for s in a.sources})), _j(validity) if validity else None, a.notes,
             None if value is None else _j(value)))
        n += 1

    oid_rx = e.order_id_regex()

    def pattern_row(path: str, kind: str, label: str | None, p: Pattern) -> None:
        conn.execute("INSERT INTO patterns (service, path, kind, label, regex, describes) VALUES (?,?,?,?,?,?)",
                     (sid, path, kind, label, p.compile(order_id_regex=oid_rx).pattern,
                      p.describes.value if p.describes else None))

    conn.executemany("INSERT OR IGNORE INTO domains VALUES (?,?,?)",
                     [(sid, d.domain.lower(), d.role.value) for d in e.identity.domains])
    for i, ident in enumerate(e.order_model.identifiers):
        if ident.scheme:
            pattern_row(f"order_model.identifiers[{i}].scheme", "identifier", ident.name, ident.scheme)
    for c in e.cookies:
        conn.execute("INSERT INTO cookies VALUES (?,?,?,?,?,?)",
                     (sid, c.name, c.set_by.value, _j([f.value for f in c.encodes_fact]), _b(c.persists_to_disk),
                      c.value_scheme.compile(order_id_regex=oid_rx).pattern if c.value_scheme else None))
        if c.value_scheme:
            pattern_row(f"cookies[{c.name}].value_scheme", "cookie_value", c.name, c.value_scheme)
    for ep in e.endpoints:
        replay = [{"variant": r.variant.value, "reply": _tpl(r.reply, oid_rx) if r.reply else None, "reading": r.reading,
                   "outcome": _v(r.outcome)} for r in ep.replay_results]
        conn.execute("INSERT INTO endpoints VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (sid, ep.id, ep.method, ep.path.compile(order_id_regex=oid_rx).pattern, ep.purpose,
                      _j(ep.request_fields), _j({k: v.value for k, v in ep.field_facts.items()}),
                      _j(_v(ep.gate)) if _v(ep.gate) is not None else None, _b(ep.ownership_check), _v(ep.cache_policy),
                      _j([_tpl(t, oid_rx) for t in ep.response_templates]), _j(replay), _v(ep.lookup_key)))
        pattern_row(f"endpoints[{ep.id}].path", "endpoint_path", ep.id, ep.path)
    for st in e.status.states:
        conn.execute("INSERT INTO status_states VALUES (?,?,?,?,?,?,?)",
                     (sid, st.order, st.label, st.template.text, st.template.to_regex(order_id_regex=oid_rx),
                      _j([f.value for f in st.template.yields]), int(st.attr.tier) if st.attr else None))
        conn.execute("INSERT INTO patterns (service, path, kind, label, regex, describes) VALUES (?,?,?,?,?,?)",
                     (sid, f"status.states[{st.order}].template", "status_template", st.label,
                      st.template.to_regex(order_id_regex=oid_rx), None))
    for r in e.receipts:
        conn.execute("INSERT INTO receipts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (sid, r.id, r.name, r.obtained_via.endpoint_ref, _v(r.obtained_via.delivery), _v(r.obtained_via.cache_policy),
                      r.file.filename_pattern.compile(order_id_regex=oid_rx).pattern if r.file.filename_pattern else None,
                      _v(r.file.mime_type), _v(r.signature.scheme),
                      r.signature.signing_identity.literal if r.signature.signing_identity else None,
                      _j([f.value for f in r.evidentiary_value.binds_facts]), _j(r.artifact_refs),
                      _j([_tpl(t, oid_rx) for t in r.structure.templates]),
                      _j({k: v.value for k, v in r.field_map.value.items()}) if r.field_map and r.field_map.value else None))
        for i, t in enumerate(r.structure.templates):
            conn.execute("INSERT INTO patterns (service, path, kind, label, regex, describes) VALUES (?,?,?,?,?,?)",
                         (sid, f"receipts[{r.id}].structure.templates[{i}]", "content_template", r.id,
                          t.to_regex(order_id_regex=oid_rx), None))
        if r.file.filename_pattern:
            pattern_row(f"receipts[{r.id}].file.filename_pattern", "filename", r.id, r.file.filename_pattern)
    for a in e.artifacts:
        keys = []
        for k in a.search_keys:
            if isinstance(k, InvariantLiteral):
                keys.append({"literal": k.literal})
            else:
                keys.append({"regex": k.compile(order_id_regex=oid_rx).pattern, "describes": k.describes.value if k.describes else None})
        conn.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (sid, a.id, a.name, a.location.value, a.path_pattern,
                      a.filename_pattern.compile(order_id_regex=oid_rx).pattern if a.filename_pattern else None,
                      a.produced_by, a.receipt_ref, a.format, _j([f.value for f in a.carries_facts]),
                      _v(a.persistence_class), a.persistence_class.basis.value if a.persistence_class else None,
                      _v(a.recovery_route), _j(keys), _j([_tpl(t, oid_rx) for t in e.content_templates_for(a)]),
                      a.case_uco_class, _v(a.caveat)))
        if a.filename_pattern:
            pattern_row(f"artifacts[{a.id}].filename_pattern", "filename", a.id, a.filename_pattern)
        for i, k in enumerate(a.search_keys):
            if isinstance(k, Pattern):
                pattern_row(f"artifacts[{a.id}].search_keys[{i}]", "search_key", a.id, k)
        for i, t in enumerate(a.content_templates):
            conn.execute("INSERT INTO patterns (service, path, kind, label, regex, describes) VALUES (?,?,?,?,?,?)",
                         (sid, f"artifacts[{a.id}].content_templates[{i}]", "content_template", a.id,
                          t.to_regex(order_id_regex=oid_rx), None))
    for row in e.fact_coverage:
        for src, cell in row.cells.items():
            conn.execute("INSERT INTO matrix VALUES (?,?,?,?,?)", (sid, row.fact.value, src.value, cell.value.value, cell.detail))
        conn.execute("INSERT INTO fact_rows VALUES (?,?,?,?,?,?,?)",
                     (sid, row.fact.value, row.best_persistence.value if row.best_persistence else None, _j(row.artifacts),
                      int(row.dead_box_recoverable()), int(row.on_chain_reconstructable()), row.notes))
    for nf in e.negative_findings:
        conn.execute("INSERT INTO negative_findings (service, location, finding, reason, value, tier, basis, implication, facts) VALUES (?,?,?,?,?,?,?,?,?)",
                     (sid, nf.location.value, nf.finding, nf.reason, _v(nf.attr), int(nf.attr.tier), nf.attr.basis.value, _v(nf.implication),
                      json.dumps([f.value for f in nf.facts])))
    for i, ind in enumerate(e.indicators):
        if isinstance(ind.value, InvariantLiteral):
            conn.execute("INSERT INTO indicators (service, kind, is_literal, value, regex, describes, weight, tier, basis) VALUES (?,?,?,?,?,?,?,?,?)",
                         (sid, ind.kind.value, 1, ind.value.literal, "", None, ind.weight, int(ind.attr.tier), ind.attr.basis.value))
        else:
            conn.execute("INSERT INTO indicators (service, kind, is_literal, value, regex, describes, weight, tier, basis) VALUES (?,?,?,?,?,?,?,?,?)",
                         (sid, ind.kind.value, 0, ind.value.regex, ind.value.compile(order_id_regex=oid_rx).pattern,
                          ind.value.describes.value if ind.value.describes else None, ind.weight, int(ind.attr.tier), ind.attr.basis.value))
            pattern_row(f"indicators[{i}]", f"indicator_{ind.kind.value}", None, ind.value)
    return n


def is_mixerscope_db(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error:
        return False
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='marker'").fetchone()
        return bool(row) and row[0] == KB_MARKER
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def _write_definitions(conn: sqlite3.Connection) -> None:
    defs = load_definitions()
    for vocab in defs.vocabularies():
        for pos, (code, entry) in enumerate(defs.vocab(vocab).items()):
            extra = {k: v for k, v in entry.items() if k not in ('label', 'meaning')}
            conn.execute("INSERT INTO definitions VALUES (?,?,?,?,?,?)",
                         (vocab, code, pos, str(entry.get('label', code)), entry.get('meaning'), _j(extra)))


def build_kb(db_path: Path | str = DEFAULT_DB_PATH, services_dir: Path | str = SERVICES_DIR, *,
             force: bool = False) -> BuildReport:
    db_path = Path(db_path)
    if db_path.exists():
        if not force and not is_mixerscope_db(db_path):
            raise FileExistsError(f"{db_path} exists and is not a mixerscope knowledge base; refusing to overwrite "
                                  "(pass force=True / --force if you really mean it)")
        db_path.unlink()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    entries = [(p, load_service_yaml(p)) for p in iter_seed_paths(services_dir)]
    ids = [e.service.id for _, e in entries]
    if len(set(ids)) != len(ids):
        raise ValueError(f"duplicate service ids in {services_dir}: {ids}")
    violations = [v for _, e in entries for v in check_entry(e)]
    if violations:
        raise ValueError("cross-field consistency:\n  " + "\n  ".join(str(v) for v in violations))
    report = BuildReport(db_path=db_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(DDL)
        conn.executemany("INSERT INTO meta VALUES (?,?)", [
            ("marker", KB_MARKER), ("schema_version", SCHEMA_VERSION), ("mixerscope_version", __version__),
            ("built_at", datetime.now(timezone.utc).isoformat(timespec="seconds")), ("services_dir", str(Path(services_dir))),
            ("definitions_version", load_definitions().version)])
        _write_definitions(conn)
        for path, entry in entries:
            report.attribute_counts[entry.service.id] = _insert_service(conn, entry, path)
            report.services.append(entry.service.id)
        conn.commit()
    finally:
        conn.close()
    from .profile import write_profiles  # local import: profile depends on this package's loaders
    write_profiles([e for _, e in entries], db_path.parent / "profiles")
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the mixerscope SQLite knowledge base from YAML seeds.")
    ap.add_argument("--services-dir", default=str(SERVICES_DIR))
    ap.add_argument("--out", default=str(DEFAULT_DB_PATH))
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)
    try:
        report = build_kb(args.out, args.services_dir, force=args.force)
    except Exception as exc:  # noqa: BLE001
        print(f"build failed: {exc}", file=sys.stderr)
        return 1
    print(report.summary())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
