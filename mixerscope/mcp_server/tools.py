"""Plain-Python implementations of the MCP tools (testable without a transport)."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mixerscope.evidence import scan_evidence as _scan
from mixerscope.evidence.findings import Candidate
from mixerscope.evidence.matcher import Matcher
from mixerscope.evidence.matcher import identify_service as _identify
from mixerscope.knowledge_base.build import DEFAULT_DB_PATH
from mixerscope.knowledge_base.loader import KnowledgeBase
from mixerscope.knowledge_base.profile import build_profile

from .correlate import correlate as _correlate
from .correlate import load_scans
from .report import render_report


@dataclass
class Settings:
    kb_path: Path = field(default_factory=lambda: Path(DEFAULT_DB_PATH))
    out_dir: Path = field(default_factory=lambda: Path("scan_out"))
    allow_network: bool = False
    """Opt-in for fetch_surface_metadata. Off by default: the tool never contacts a service."""


# ---- knowledge base -------------------------------------------------------------------


def kb_list_services(s: Settings) -> list[dict[str, Any]]:
    with KnowledgeBase.open(s.kb_path) as kb:
        return [x.as_dict() for x in kb.list_services()]


def kb_get_service(s: Settings, name: str) -> dict[str, Any]:
    with KnowledgeBase.open(s.kb_path) as kb:
        return kb.get_service_raw(name)


def kb_get_artifact_map(s: Settings, name: str) -> dict[str, Any]:
    with KnowledgeBase.open(s.kb_path) as kb:
        return kb.get_artifact_map(name)


def kb_get_profile(s: Settings, name: str) -> dict[str, Any]:
    """The investigator profile of one service, built from its entry in the knowledge base:
    the six questions (recognise, where_is, interpret, expected_absences, beyond_disk, limits),
    every item with tier, basis and the entry field it comes from."""
    with KnowledgeBase.open(s.kb_path) as kb:
        return build_profile(kb.get_service(name))


def kb_where_is(s: Settings, name: str, fact: str) -> dict[str, Any]:
    """One fact of one service: where it is on disk (artifact, field, recovery route, caveat),
    the absences that are expected and why, what lies beyond the disk, and the full matrix row."""
    with KnowledgeBase.open(s.kb_path) as kb:
        entry = kb.get_service(name)
    try:
        row = entry.matrix_row(fact)
    except ValueError:
        row = None
    if row is None:
        raise KeyError(f"{name} has no matrix row for fact {fact!r}")
    prof = build_profile(entry)
    return {
        "service": name,
        "fact": fact,
        "cells": {src.value: str(cell) for src, cell in row.cells.items()},
        "best_persistence": row.best_persistence.value if row.best_persistence else None,
        "notes": row.notes,
        "on_disk": [it for it in prof["where_is"] if it["fact"] == fact],
        "expected_absences": [it for it in prof["expected_absences"] if it["fact"] == fact],
        "beyond_disk": [it for it in prof["beyond_disk"]
                        if it.get("subject") == fact or it.get("lookup_key") == fact
                        or it["kind"] in ("retention_claim", "retention_observed", "retention_consistency")],
        "not_tested": fact in prof["limits"]["facts_not_tested"],
    }


# ---- identification from loose artifacts ----------------------------------------------

_URL = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_COOKIE = re.compile(r"^([A-Za-z0-9_.\-]+)=(.*)$")
_HEADER = re.compile(r"^([A-Za-z][A-Za-z0-9\-]*):\s+(.+)$")


def _candidates_from_text(i: int, text: str) -> list[Candidate]:
    base = dict(
        source="<caller>",
        locator=f"artifact[{i}]",
        method="supplied by caller",
        provenance_class="subject_evidence",
        location="unknown",
    )
    text = text.strip()
    out = []
    if _URL.match(text):
        return [Candidate(kind="url", value=text, **base)]
    m = _COOKIE.match(text)
    if m and " " not in m.group(1):
        out.append(
            Candidate(
                kind="cookie",
                value=m.group(1),
                extra={"plaintext_value": m.group(2)},
                **base,
            )
        )
    h = _HEADER.match(text)
    if h and " " not in h.group(1):
        out.append(Candidate(kind="header", value=text.lower(), **base))
    if re.fullmatch(r"[\w.\-]+\.[A-Za-z0-9]{1,5}", text):
        out.append(
            Candidate(
                kind="file",
                value=text,
                extra={"filename": text},
                **{**base, "location": "filesystem"},
            )
        )
    out.append(Candidate(kind="string", value=text, **base))
    return out


def identify_service(s: Settings, artifacts: list[str]) -> dict[str, Any]:
    with KnowledgeBase.open(s.kb_path) as kb:
        matcher = Matcher(kb)
    findings = []
    for i, text in enumerate(artifacts):
        for c in _candidates_from_text(i, text):
            findings += matcher.match(c)
    ranking = _identify(findings)
    return {
        "services": [r.__dict__ for r in ranking],
        "matches": [
            {
                "artifact": f.candidate.locator,
                "match": f.match,
                "strength": f.strength,
                "service": f.service,
                "artifact_ref": f.artifact_ref,
                "fact": f.fact,
                "tokens": [t.__dict__ for t in f.tokens],
                "note": f.note,
            }
            for f in findings
        ],
        "note": "Inputs are treated as untrusted text; matching is against KB invariants only.",
    }


# ---- evidence -------------------------------------------------------------------------


def scan_evidence(
    s: Settings,
    path: str,
    evidence_type: str | None = None,
    out_path: str | None = None,
    max_findings: int | None = None,
    include_findings: int = 0,
    services: list[str] | None = None,
    hash_sources: bool = True,
    location: str | None = None,
) -> dict[str, Any]:
    p = Path(path)
    result = _scan(
        p,
        kb_path=s.kb_path,
        evidence_type=evidence_type,
        services=services,
        max_findings=max_findings,
        hash_sources=hash_sources,
        location=location,
    )
    out = (
        Path(out_path) if out_path else s.out_dir / f"{p.name or 'evidence'}.scan.json"
    )
    result.write(out)
    doc = {
        "evidence": str(p),
        "evidence_type": result.evidence_type,
        "read_only": True,
        "candidates_seen": result.candidates_seen,
        "findings": len(result.findings),
        "sources_scanned": len(result.sources_scanned),
        "warnings": result.warnings,
        "services": [x.__dict__ for x in result.services],
        "by_artifact": result.by_artifact(),
        "by_fact": result.by_fact(),
        "scan_path": str(out),
    }
    if include_findings:
        doc["findings_sample"] = [
            f.to_record() for f in result.findings[:include_findings]
        ]
    return doc


def correlate(
    s: Settings, scan_paths: list[str], out_path: str | None = None
) -> dict[str, Any]:
    corr = _correlate(load_scans(scan_paths), s.kb_path)
    if out_path:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(
            json.dumps(corr, indent=2, ensure_ascii=False, default=str) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        corr["correlation_path"] = out_path
    return corr


def emit_report(
    s: Settings, scan_paths: list[str], out_path: str | None = None
) -> dict[str, Any]:
    corr = _correlate(load_scans(scan_paths), s.kb_path)
    md = render_report(corr)
    out = Path(out_path) if out_path else s.out_dir / "report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8", newline="\n")
    return {
        "report_path": str(out),
        "primary_service": corr["primary_service"],
        "triangulation_status": corr["triangulation"]["status"],
        "markdown": md,
    }


# ---- opt-in single-request surface metadata --------------------------------------------

_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$",
    re.IGNORECASE,
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_surface_metadata(
    s: Settings, domain: str, *, timeout: float = 10.0, opener=None
) -> dict[str, Any]:
    """One GET to https://<domain>/ recording status and response headers only. No redirects
    are followed, no body is retained, no linked page is fetched. Disabled unless the server
    was started with network access explicitly allowed."""
    if not s.allow_network:
        return {
            "error": "network access is disabled; start the server with --allow-network to opt in "
            "(single request, headers only)",
            "domain": domain,
        }
    domain = domain.strip().lower()
    if not _DOMAIN.match(domain):
        return {"error": "not a bare domain name", "domain": domain}
    url = f"https://{domain}/"
    opener = opener or urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(
        url, method="GET", headers={"User-Agent": "mixerscope-surface-metadata/1"}
    )
    fetched = datetime.now(UTC).isoformat(timespec="seconds")
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = resp.status
            headers = [(k, v) for k, v in resp.headers.items()]
    except urllib.error.HTTPError as e:
        status = e.code
        headers = [(k, v) for k, v in e.headers.items()] if e.headers else []
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {
            "error": f"request failed: {e}",
            "domain": domain,
            "url": url,
            "fetched_at": fetched,
        }
    return {
        "domain": domain,
        "url": url,
        "status": status,
        "headers": headers,
        "fetched_at": fetched,
        "provenance_class": "instrumentation",
        "observation_kind": "operator_page",
        "tier": 0,
        "server": next((v for k, v in headers if k.lower() == "server"), None),
        "set_cookie_names": [
            v.split("=", 1)[0].strip() for k, v in headers if k.lower() == "set-cookie"
        ],
        "note": "Single request, headers only; body discarded; redirects not followed. Tier-0 evidence for "
        "identity.cdn_proxy and cookies[] names; record as an observation of kind operator_page.",
    }
