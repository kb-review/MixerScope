"""Evidence-class token detection: find addresses, TXIDs, order IDs and IPs inside strings."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Detector:
    kind: str
    regex: re.Pattern[str]


_B = r"(?<![0-9a-zA-Z])"
_E = r"(?![0-9a-zA-Z])"

DETECTORS: tuple[Detector, ...] = (
    Detector("txid", re.compile(_B + r"[0-9a-fA-F]{64}" + _E)),
    Detector("btc_address", re.compile(_B + r"(?:bc1|tb1|bcrt1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,87}" + _E)),
    Detector("btc_address", re.compile(_B + r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}" + _E)),
    Detector("evm_address", re.compile(_B + r"0x[0-9a-fA-F]{40}" + _E)),
    Detector("uniqid", re.compile(_B + r"[0-9a-f]{14}\.\d{6,}" + _E)),
    Detector("iso_timestamp", re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?")),
    Detector("ipv4", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")),
    Detector("unix_timestamp", re.compile(r"(?<![\d.])1[6-9]\d{8}(?:\d{3})?(?![\d.])")),
    Detector("amount", re.compile(r"(?<![\w.])\d+\.\d{2,}(?![\w.])")),
)


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    start: int
    end: int


def find_tokens(text: str) -> list[Token]:
    """Non-overlapping evidence-like tokens in `text`, earlier detectors taking precedence."""
    taken: list[tuple[int, int]] = []
    found: list[Token] = []
    for d in DETECTORS:
        for m in d.regex.finditer(text):
            s, e = m.span()
            if any(s < te and e > ts for ts, te in taken):
                continue
            taken.append((s, e))
            found.append(Token(d.kind, m.group(0), s, e))
    found.sort(key=lambda t: t.start)
    return found
