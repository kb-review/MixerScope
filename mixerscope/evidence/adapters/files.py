"""Loose-files adapter: a folder such as a user's Downloads directory, or a single file."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from ..carve import carve_strings
from ..findings import Candidate

MAX_CARVE_BYTES = 8 * 1024 * 1024
MAX_TEXT_BYTES = 2 * 1024 * 1024
TEXT_METHOD = "whole-file text read (utf-8, errors replaced)"
FILE_METHOD = "directory listing (stat)"
CARVE_METHOD = "printable-string carve (ascii + utf-16le, min 8)"


def iter_files(root: Path | str, warnings: list[str]) -> Iterator[Candidate]:
    root = Path(root)
    paths = [root] if root.is_file() else sorted(root.rglob("*"))
    base = root.parent if root.is_file() else root
    for p in paths:
        if not p.is_file():
            continue
        try:
            st = p.stat()
        except OSError as e:
            warnings.append(f"{p}: stat failed ({e})")
            continue
        yield Candidate(
            kind="file", value=p.name, source=str(p), locator="name", method=FILE_METHOD, location="filesystem",
            timestamp=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
            extra={"size": st.st_size, "relative_path": p.relative_to(base).as_posix(), "filename": p.name},
        )
        if st.st_size > MAX_CARVE_BYTES:
            continue
        if st.st_size <= MAX_TEXT_BYTES:
            try:
                raw = p.read_bytes()
                if b"\x00" not in raw[:4096]:
                    yield Candidate(kind="text", value=raw.decode("utf-8", errors="replace"), source=str(p),
                                    locator="content", method=TEXT_METHOD, location="filesystem",
                                    extra={"filename": p.name, "size": st.st_size})
            except OSError as e:
                warnings.append(f"{p}: cannot read ({e})")
        try:
            for offset, enc, text in carve_strings(p):
                yield Candidate(kind="string", value=text, source=str(p), locator=f"offset {offset:#x}",
                                method=CARVE_METHOD, location="filesystem", extra={"store": "file", "encoding": enc})
        except OSError as e:
            warnings.append(f"{p}: cannot read ({e})")
