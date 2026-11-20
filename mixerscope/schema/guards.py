"""Instance-data guards: the validation half of the instance-vs-invariant rule."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

# Each detector: (kind, compiled regex). Word boundaries keep them from firing inside
# longer tokens such as onion hostnames.
INSTANCE_DETECTORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("64-hex hash / TXID", re.compile(r"(?<![0-9a-zA-Z])[0-9a-fA-F]{64}(?![0-9a-zA-Z])")),
    ("bech32 address", re.compile(r"(?<![0-9a-zA-Z])(?:bc1|tb1|bcrt1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,87}(?![0-9a-zA-Z])")),
    ("base58 BTC address", re.compile(r"(?<![0-9a-zA-Z])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![0-9a-zA-Z])")),
    ("EVM address", re.compile(r"(?<![0-9a-zA-Z])0x[0-9a-fA-F]{40}(?![0-9a-zA-Z])")),
    ("PHP uniqid order ID", re.compile(r"(?<![0-9a-zA-Z])[0-9a-f]{14}\.\d{6,}(?![0-9a-zA-Z])")),
    ("ISO-8601 timestamp", re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")),
)

CASE_FINDINGS_HINT = (
    "The knowledge base stores service invariants only (patterns, endpoints, policies, "
    "templates). Record this value in the per-case findings output instead. If it is a "
    "genuine service invariant (e.g. a fixed signing address), set invariant_literal='<reason>' "
    "on the record."
)


class InstanceDataError(ValueError):
    """Raised when a value that looks like instance data is found in a KB record."""

    def __init__(self, path: str, kind: str, sample: str) -> None:
        self.path = path
        self.kind = kind
        self.sample = sample
        super().__init__(
            f"{path}: contains what looks like instance data ({kind}: {_mask(sample)!r}). "
            + CASE_FINDINGS_HINT
        )


def _mask(token: str) -> str:
    """Show enough of the offending token to locate it without echoing the whole value."""
    if len(token) <= 12:
        return token
    return f"{token[:6]}...{token[-4:]}"


def find_instance_data(text: str) -> tuple[str, str] | None:
    """Return (kind, matched_token) for the first instance-like token in `text`, else None."""
    for kind, rx in INSTANCE_DETECTORS:
        m = rx.search(text)
        if m:
            return kind, m.group(0)
    return None


def iter_strings(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield (dotted_path, string) for every string reachable in plain data (str/list/dict)."""
    if isinstance(obj, str):
        yield path or "<value>", obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from iter_strings(k, f"{path}.{k}" if path else str(k))
            yield from iter_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, (list, tuple, set)):
        for i, v in enumerate(obj):
            yield from iter_strings(v, f"{path}[{i}]")


def assert_no_instance_data(obj: Any, path: str = "") -> None:
    """Raise InstanceDataError if any string reachable in `obj` looks like instance data."""
    for p, s in iter_strings(obj, path):
        hit = find_instance_data(s)
        if hit:
            raise InstanceDataError(p, hit[0], hit[1])
