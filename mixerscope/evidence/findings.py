"""Candidates and findings for the evidence matcher."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SUBJECT_EVIDENCE = "subject_evidence"
INSTRUMENTATION = "instrumentation"


@dataclass
class Candidate:
    kind: str
    """url | download | cookie | autofill | string | file | header"""
    value: str
    source: str
    locator: str
    method: str
    location: str
    """§V.location the value was found in (chrome_history, chrome_cache, unallocated ...)."""
    provenance_class: str = SUBJECT_EVIDENCE
    timestamp: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def medium(self) -> str:
        if self.location in ("network_only",):
            return "network"
        if self.location == "on_chain":
            return "on_chain"
        return "disk"


@dataclass
class Token:
    kind: str
    value: str
    fact: str | None = None
    basis: str | None = None
    """Why the fact was assigned (field_facts, encodes_fact, yields, carries_facts)."""


@dataclass
class Finding:
    match: str
    """Rule label: indicator:url_path, endpoint:<id>, cookie:<name>, template:<label>,
    artifact:<id>, identifier:<name>, domain:<role>, explorer_tx_visit, token:<kinds>."""
    strength: float
    candidate: Candidate
    service: str | None = None
    artifact_ref: str | None = None
    """<service>:<artifact id>"""
    fact: str | None = None
    """The single fact this finding evidences when exactly one applies."""
    persistence_class: str | None = None
    tokens: list[Token] = field(default_factory=list)
    note: str | None = None
    sha256_of_source: str | None = None
    extracted_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_record(self) -> dict[str, Any]:
        c = self.candidate
        return {
            "fact": self.fact,
            "kind": c.kind,
            "value": c.value,
            "artifact_ref": self.artifact_ref,
            "service": self.service,
            "match": self.match,
            "strength": self.strength,
            "location": c.location,
            "persistence_class": self.persistence_class,
            "tokens": [asdict(t) for t in self.tokens],
            "source": {"path": c.source, "offset_or_row": c.locator, "method": c.method,
                       "sha256_of_source": self.sha256_of_source},
            "provenance_class": c.provenance_class,
            "timestamp": c.timestamp,
            "extracted_at": self.extracted_at,
            "note": self.note,
            "extra": c.extra,
        }

    @classmethod
    def from_record(cls, r: dict[str, Any]) -> Finding:
        src = r["source"]
        c = Candidate(kind=r["kind"], value=r["value"], source=src["path"], locator=src["offset_or_row"],
                      method=src["method"], location=r["location"], provenance_class=r["provenance_class"],
                      timestamp=r.get("timestamp"), extra=r.get("extra") or {})
        return cls(match=r["match"], strength=r["strength"], candidate=c, service=r.get("service"),
                   artifact_ref=r.get("artifact_ref"), fact=r.get("fact"), persistence_class=r.get("persistence_class"),
                   tokens=[Token(**t) for t in r.get("tokens", [])], note=r.get("note"),
                   sha256_of_source=src.get("sha256_of_source"), extracted_at=r.get("extracted_at", ""))


@dataclass
class ServiceScore:
    service: str
    score: float
    rules: dict[str, int]


class SourceHasher:
    """sha256 of each evidence source, computed once per file."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._cache: dict[str, str | None] = {}

    def __call__(self, path: str) -> str | None:
        if not self.enabled:
            return None
        if path not in self._cache:
            try:
                h = hashlib.sha256()
                with open(path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(8 * 1024 * 1024), b""):
                        h.update(chunk)
                self._cache[path] = h.hexdigest()
            except OSError:
                self._cache[path] = None
        return self._cache[path]


@dataclass
class ScanResult:
    evidence: str
    evidence_type: str
    kb_path: str
    candidates_seen: int = 0
    findings: list[Finding] = field(default_factory=list)
    services: list[ServiceScore] = field(default_factory=list)
    sources_scanned: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def by_artifact(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            key = f.artifact_ref or f"{f.service or '-'}:{f.match}"
            out[key] = out.get(key, 0) + 1
        return dict(sorted(out.items()))

    def by_fact(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            for t in f.tokens:
                if t.fact:
                    out[t.fact] = out.get(t.fact, 0) + 1
        return dict(sorted(out.items()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_findings_schema": "0.1",
            "evidence": self.evidence,
            "evidence_type": self.evidence_type,
            "kb": self.kb_path,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "read_only": True,
            "warning": "Contains instance data for one case. Never merge into the knowledge base.",
            "candidates_seen": self.candidates_seen,
            "sources_scanned": self.sources_scanned,
            "warnings": self.warnings,
            "services": [asdict(s) for s in self.services],
            "by_artifact": self.by_artifact(),
            "by_fact": self.by_fact(),
            "findings": [f.to_record() for f in self.findings],
        }

    def write(self, path: Path | str) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False, default=str) + "\n",
                        encoding="utf-8", newline="\n")
        return path

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ScanResult:
        r = cls(evidence=d["evidence"], evidence_type=d["evidence_type"], kb_path=d.get("kb", ""),
                candidates_seen=d.get("candidates_seen", 0), sources_scanned=d.get("sources_scanned", []),
                warnings=d.get("warnings", []))
        r.findings = [Finding.from_record(x) for x in d.get("findings", [])]
        r.services = [ServiceScore(**s) for s in d.get("services", [])]
        return r
