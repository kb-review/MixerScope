"""Read-only evidence artifact matching against the knowledge base."""

from __future__ import annotations

from pathlib import Path

from mixerscope.knowledge_base.loader import KnowledgeBase

from .adapters import detect_type, iter_candidates
from .findings import Candidate, Finding, ScanResult, ServiceScore, SourceHasher, Token
from .matcher import Matcher, identify_service


def scan_evidence(path: Path | str, *, kb_path: Path | str, evidence_type: str | None = None,
                  services: list[str] | None = None, max_findings: int | None = None,
                  hash_sources: bool = True, location: str | None = None) -> ScanResult:
    path = Path(path)
    warnings: list[str] = []
    kind, candidates = iter_candidates(path, evidence_type, warnings, location=location)
    with KnowledgeBase.open(kb_path) as kb:
        matcher = Matcher(kb, services)
    result = ScanResult(evidence=str(path), evidence_type=kind, kb_path=str(kb_path), warnings=warnings)
    sources: set[str] = set()
    stop = False
    for c in candidates:
        result.candidates_seen += 1
        sources.add(c.source)
        for f in matcher.match(c):
            result.findings.append(f)
            if max_findings and len(result.findings) >= max_findings:
                warnings.append(f"stopped after {max_findings} findings")
                stop = True
                break
        if stop:
            break
    hasher = SourceHasher(hash_sources)
    for f in result.findings:
        f.sha256_of_source = hasher(f.candidate.source)
    result.sources_scanned = sorted(sources)
    result.services = identify_service(result.findings)
    return result


__all__ = ["Candidate", "Finding", "ScanResult", "ServiceScore", "Token", "Matcher", "detect_type",
           "identify_service", "scan_evidence"]
