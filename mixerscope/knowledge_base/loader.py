"""Read-only loader API over the SQLite knowledge base."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mixerscope.schema import ServiceEntry, Tier

from .build import KB_MARKER


class UnknownServiceError(KeyError):
    pass


@dataclass(frozen=True)
class ServiceSummary:
    id: str
    display_name: str
    entry_status: str
    tiers_completed: list[int]
    canonical_domain: str | None
    max_tier: int | None
    attribute_count: int

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass(frozen=True)
class PatternRow:
    service: str
    path: str
    kind: str
    label: str | None
    regex: str
    describes: str | None

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _rows(cur) -> list[dict[str, Any]]:
    return [dict(r) for r in cur]


def _unjson(d: dict[str, Any], *keys: str) -> dict[str, Any]:
    for k in keys:
        if k in d and isinstance(d[k], str):
            d[k] = json.loads(d[k])
    return d


class KnowledgeBase:
    def __init__(self, conn: sqlite3.Connection, path: Path) -> None:
        self._conn = conn
        self._conn.row_factory = sqlite3.Row
        self.path = path

    @classmethod
    def open(cls, db_path: Path | str) -> KnowledgeBase:
        db_path = Path(db_path)
        if not db_path.exists():
            raise FileNotFoundError(f"knowledge base not found: {db_path} (run mixerscope-build-kb first)")
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            row = conn.execute("SELECT value FROM meta WHERE key='marker'").fetchone()
        except sqlite3.Error as e:
            conn.close()
            raise ValueError(f"{db_path} is not a mixerscope knowledge base") from e
        if not row or row[0] != KB_MARKER:
            conn.close()
            raise ValueError(f"{db_path} is not a mixerscope knowledge base")
        return cls(conn, db_path)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> KnowledgeBase:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def meta(self) -> dict[str, str]:
        return {r["key"]: r["value"] for r in self._conn.execute("SELECT key, value FROM meta")}

    # ---- services -------------------------------------------------------------------

    def definitions(self, vocab: str | None = None) -> list[dict[str, Any]]:
        """Shared definitions (codes with labels and meanings), optionally one vocabulary."""
        sql, args = "SELECT vocab, code, label, meaning, extra FROM definitions", []
        if vocab:
            sql += " WHERE vocab=?"; args.append(vocab)
        return [_unjson(r, "extra") for r in _rows(self._conn.execute(sql + " ORDER BY vocab, position", args))]

    def label(self, vocab: str, code: Any) -> str:
        row = self._conn.execute("SELECT label FROM definitions WHERE vocab=? AND code=?", (vocab, str(code))).fetchone()
        return row[0] if row else str(code)

    def list_services(self) -> list[ServiceSummary]:
        rows = self._conn.execute(
            "SELECT s.*, (SELECT COUNT(*) FROM attributes a WHERE a.service = s.id) AS n FROM services s ORDER BY s.id"
        ).fetchall()
        return [ServiceSummary(id=r["id"], display_name=r["display_name"], entry_status=r["entry_status"],
                               tiers_completed=json.loads(r["tiers_completed"]), canonical_domain=r["canonical_domain"],
                               max_tier=r["max_tier"], attribute_count=r["n"]) for r in rows]

    def has_service(self, sid: str) -> bool:
        return self._conn.execute("SELECT 1 FROM services WHERE id=?", (sid,)).fetchone() is not None

    def get_service(self, sid: str) -> ServiceEntry:
        row = self._conn.execute("SELECT entry_json FROM services WHERE id=?", (sid,)).fetchone()
        if row is None:
            raise UnknownServiceError(sid)
        return ServiceEntry.model_validate_json(row["entry_json"])

    def get_service_raw(self, sid: str) -> dict[str, Any]:
        row = self._conn.execute("SELECT entry_json FROM services WHERE id=?", (sid,)).fetchone()
        if row is None:
            raise UnknownServiceError(sid)
        return json.loads(row["entry_json"])

    # ---- artifact map ---------------------------------------------------------------

    def get_artifact_map(self, sid: str) -> dict[str, Any]:
        """What the service leaves where: artifacts by location, the fact-coverage matrix,
        cookies, endpoint cache policies, status states and negative findings."""
        if not self.has_service(sid):
            raise UnknownServiceError(sid)
        arts = [_unjson(d, "carries_facts", "search_keys", "content_templates") for d in
                _rows(self._conn.execute("SELECT * FROM artifacts WHERE service=? ORDER BY rowid", (sid,)))]
        by_loc: dict[str, list[str]] = {}
        for a in arts:
            by_loc.setdefault(a["location"], []).append(a["id"])
        cov = [_unjson(d, "artifacts") for d in
               _rows(self._conn.execute("SELECT * FROM fact_rows WHERE service=? ORDER BY rowid", (sid,)))]
        cells = _rows(self._conn.execute("SELECT fact, source, value, detail FROM matrix WHERE service=? ORDER BY rowid", (sid,)))
        for c in cov:
            for k in ("dead_box_recoverable", "on_chain_reconstructable"):
                c[k] = bool(c[k])
            c["cells"] = {m["source"]: {"value": m["value"], "detail": m["detail"]} for m in cells if m["fact"] == c["fact"]}
        receipts = [_unjson(d, "binds_facts", "artifact_refs", "templates") for d in
                    _rows(self._conn.execute("SELECT * FROM receipts WHERE service=? ORDER BY rowid", (sid,)))]
        cookies = [_unjson(d, "encodes_facts") for d in
                   _rows(self._conn.execute("SELECT * FROM cookies WHERE service=? ORDER BY rowid", (sid,)))]
        eps = [_unjson(d, "request_fields", "field_facts", "templates", "replay_results") for d in
               _rows(self._conn.execute("SELECT * FROM endpoints WHERE service=? ORDER BY rowid", (sid,)))]
        states = [_unjson(d, "yields") for d in
                  _rows(self._conn.execute("SELECT * FROM status_states WHERE service=? ORDER BY position", (sid,)))]
        neg = [_unjson(d, "facts") for d in
               _rows(self._conn.execute("SELECT location, finding, reason, implication, facts, value, tier, basis "
                                        "FROM negative_findings WHERE service=? ORDER BY id", (sid,)))]
        return {
            "service": sid,
            "artifacts": arts,
            "by_location": by_loc,
            "fact_coverage": cov,
            "receipts": receipts,
            "cookies": cookies,
            "endpoints": eps,
            "cache_policy": {e["id"]: e["cache_policy"] for e in eps if e["cache_policy"]},
            "status_states": states,
            "negative_findings": neg,
        }

    # ---- lookups --------------------------------------------------------------------

    def find_by_domain(self, domain: str) -> list[dict[str, str]]:
        host = domain.strip().lower().lstrip(".")
        rows = _rows(self._conn.execute("SELECT service, domain, role FROM domains ORDER BY service, role"))
        return [{"service": r["service"], "role": r["role"]} for r in rows
                if host == r["domain"] or host.endswith("." + r["domain"])]

    def domains(self, sid: str | None = None) -> list[dict[str, str]]:
        sql, args = "SELECT service, domain, role FROM domains", ()
        if sid:
            sql, args = sql + " WHERE service=?", (sid,)
        return _rows(self._conn.execute(sql + " ORDER BY service, role, domain", args))

    def indicators(self, sid: str | None = None) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM indicators", ()
        if sid:
            sql, args = sql + " WHERE service=?", (sid,)
        out = _rows(self._conn.execute(sql + " ORDER BY service, weight DESC, id", args))
        for r in out:
            r["is_literal"] = bool(r["is_literal"])
        return out

    def patterns(self, *, service: str | None = None, kind: str | None = None) -> list[PatternRow]:
        sql, clauses, args = "SELECT service, path, kind, label, regex, describes FROM patterns", [], []
        if service:
            clauses.append("service=?"); args.append(service)
        if kind:
            clauses.append("kind=?"); args.append(kind)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        return [PatternRow(**dict(r)) for r in self._conn.execute(sql + " ORDER BY service, id", args)]

    def observations(self, sid: str) -> list[dict[str, Any]]:
        return _rows(self._conn.execute("SELECT * FROM observations WHERE service=? ORDER BY rowid", (sid,)))

    def attributes(self, sid: str | None = None, *, tier: Tier | int | None = None, max_tier: Tier | int | None = None,
                   section: str | None = None, known_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM attributes"
        clauses, args = [], []
        if sid:
            clauses.append("service=?"); args.append(sid)
        if tier is not None:
            clauses.append("tier=?"); args.append(int(tier))
        if max_tier is not None:
            clauses.append("tier<=?"); args.append(int(max_tier))
        if section:
            clauses.append("section=?"); args.append(section)
        if known_only:
            clauses.append("basis != 'unknown'")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        out = []
        for r in self._conn.execute(sql + " ORDER BY service, id", args):
            d = _unjson(dict(r), "sources", "provenance_classes", "validity")
            d["value"] = json.loads(d.pop("value_json")) if d.get("value_json") else None
            out.append(d)
        return out
