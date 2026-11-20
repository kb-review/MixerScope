"""Strings-dump adapter: a text file with one string per line, as produced by `strings -t d` or a
carving tool over a disk region (unallocated space, a pagefile, a raw partition).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ..carve import read_strings_dump
from ..findings import Candidate

DUMP_METHOD = "strings dump line read"
STRINGS_LOCATIONS = ("unallocated", "pagefile", "filesystem", "chrome_cache", "chrome_sessions")


def iter_strings_dump(path: Path | str, warnings: list[str], *, location: str = "unallocated") -> Iterator[Candidate]:
    path = Path(path)
    if location not in STRINGS_LOCATIONS:
        warnings.append(f"location {location!r} is not one of {', '.join(STRINGS_LOCATIONS)}; recorded as given")
    for locator, text in read_strings_dump(path):
        yield Candidate(kind="string", value=text, source=str(path), locator=locator,
                        method=DUMP_METHOD, location=location)
