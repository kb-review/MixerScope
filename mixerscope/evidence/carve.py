"""Printable-string carving over binary files (cache entries, LevelDB logs, memory images)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

MIN_LEN = 8
CHUNK = 8 * 1024 * 1024
MAX_STR = 64 * 1024

_ASCII = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN)
_TAIL_ASCII = re.compile(rb"[\x20-\x7e]*\Z")
_TAIL_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00)*[\x20-\x7e]?\Z")


def carve_strings(path: Path | str, *, min_len: int = MIN_LEN, utf16: bool = True,
                  chunk_size: int = CHUNK) -> Iterator[tuple[int, str, str]]:
    """Yield (offset, encoding, text) for every printable run of at least `min_len` chars."""
    ascii_rx = _ASCII if min_len == MIN_LEN else re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    utf16_rx = _UTF16 if min_len == MIN_LEN else re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    passes = [("ascii", ascii_rx)] + ([("utf-16le", utf16_rx)] if utf16 else [])

    with Path(path).open("rb") as fh:
        carry = b""
        carry_offset = 0
        pos = 0
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            buf = carry + chunk
            base = carry_offset if carry else pos
            pos += len(chunk)
            end = len(buf)
            # any printable run touching the end of the buffer (even one shorter than
            # min_len) may continue in the next chunk: carry it over instead of emitting
            cut = end
            for rx in (_TAIL_ASCII, _TAIL_UTF16):
                m = rx.search(buf)
                if m:
                    cut = min(cut, m.start())
            cut = max(cut, end - MAX_STR)
            emit, carry = buf[:cut], buf[cut:]
            carry_offset = base + cut
            for enc, rx in passes:
                for m in rx.finditer(emit):
                    yield base + m.start(), enc, _decode(m.group(0), enc)
        if carry:
            for enc, rx in passes:
                for m in rx.finditer(carry):
                    yield carry_offset + m.start(), enc, _decode(m.group(0), enc)


def _decode(raw: bytes, enc: str) -> str:
    if enc == "ascii":
        return raw.decode("ascii")
    return raw.decode("utf-16le", errors="replace")


def read_strings_dump(path: Path | str) -> Iterator[tuple[str, str]]:
    """Read a text strings dump (one string per line). Lines produced by `strings -t d/x`
    carry a leading offset, which becomes the locator; otherwise the line number does."""
    with Path(path).open("r", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\r\n")
            if not line:
                continue
            m = _OFFSET_LINE.match(line)
            if m:
                yield f"offset {m.group(1)}", m.group(2)
            else:
                yield f"line {n}", line


_OFFSET_LINE = re.compile(r"^\s*((?:0x)?[0-9a-fA-F]+)\s(.*)$")
