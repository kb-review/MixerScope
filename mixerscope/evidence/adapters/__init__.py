"""Read-only evidence adapters. Each yields `Candidate` records lazily."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ..findings import Candidate
from .chrome import iter_chrome_profile
from .files import iter_files
from .strings import STRINGS_LOCATIONS, iter_strings_dump

ADAPTERS = {
    "chrome": iter_chrome_profile,
    "files": iter_files,
    "strings": iter_strings_dump,
}


def detect_type(path: Path) -> str:
    if path.is_dir():
        if (path / "History").exists() or (path / "Network" / "Cookies").exists() or (path / "Cookies").exists():
            return "chrome"
        return "files"
    if path.suffix.lower() in (".strings", ".lst"):
        return "strings"
    return "files"


def iter_candidates(path: Path | str, evidence_type: str | None = None, warnings: list[str] | None = None,
                    *, location: str | None = None) -> tuple[str, Iterator[Candidate]]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    kind = evidence_type or detect_type(path)
    if kind not in ADAPTERS:
        raise ValueError(f"unknown evidence type {kind!r}; choose from {', '.join(ADAPTERS)}")
    warnings = warnings if warnings is not None else []
    if kind == "strings":
        return kind, iter_strings_dump(path, warnings, location=location or "unallocated")
    return kind, ADAPTERS[kind](path, warnings)


__all__ = ["ADAPTERS", "STRINGS_LOCATIONS", "detect_type", "iter_candidates"]
