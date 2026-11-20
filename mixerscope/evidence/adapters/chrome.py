"""Chrome / Chromium profile adapter (read-only)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..carve import carve_strings
from ..findings import Candidate

SQLITE_METHOD = "sqlite3 read-only (uri mode=ro&immutable=1)"
CARVE_METHOD = "printable-string carve (ascii + utf-16le, min 8)"

_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def chrome_time(value) -> str | None:
    """WebKit/Chrome timestamps: microseconds since 1601-01-01 UTC."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    try:
        return (_WEBKIT_EPOCH + timedelta(microseconds=v)).isoformat(timespec="seconds")
    except OverflowError:
        return None


def open_ro(path: Path) -> sqlite3.Connection:
    uri = f"file:{path.resolve().as_posix()}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info('{table}')")}


# --------------------------------------------------------------------------------------


def iter_chrome_profile(profile: Path | str, warnings: list[str]) -> Iterator[Candidate]:
    profile = Path(profile)
    if not profile.is_dir():
        raise NotADirectoryError(profile)

    history = profile / "History"
    if history.is_file():
        yield from _history(history, warnings)
    else:
        warnings.append("no History database found")

    cookies = profile / "Network" / "Cookies"
    if not cookies.is_file():
        cookies = profile / "Cookies"
    if cookies.is_file():
        yield from _cookies(cookies, warnings)
    else:
        warnings.append("no Cookies database found")

    webdata = profile / "Web Data"
    if webdata.is_file():
        yield from _autofill(webdata, warnings)

    for store in ("Local Storage", "Session Storage"):
        d = profile / store
        if d.is_dir():
            yield from _carve_dir(d, store, warnings, exts=(".ldb", ".log", ".sst"))
    for cache_dir in (profile / "Cache" / "Cache_Data", profile / "Cache", profile / "Code Cache"):
        if cache_dir.is_dir():
            yield from _carve_dir(cache_dir, "Cache", warnings, exts=None, skip_dirs=("Cache_Data",))
            if cache_dir.name == "Cache_Data":
                pass
    sessions = profile / "Sessions"
    if sessions.is_dir():
        yield from _carve_dir(sessions, "Sessions", warnings, exts=None)

    for db in (history, cookies, webdata):
        wal = Path(str(db) + "-wal")
        if wal.is_file() and wal.stat().st_size > 0:
            warnings.append(f"{wal.name}: uncheckpointed WAL present; carved as strings only")
            yield from _carve_file(wal, wal.parent.name + "/" + wal.name, warnings)


# --------------------------------------------------------------------------------------


def _history(path: Path, warnings: list[str]) -> Iterator[Candidate]:
    try:
        conn = open_ro(path)
    except sqlite3.Error as e:
        warnings.append(f"History: cannot open ({e})")
        return
    try:
        tables = _tables(conn)
        if "urls" in tables:
            urls = {r["id"]: r for r in conn.execute("SELECT id, url, title, visit_count, last_visit_time FROM urls")}
            visited: set[int] = set()
            if "visits" in tables:
                for r in conn.execute("SELECT id, url, visit_time, from_visit, transition FROM visits ORDER BY id"):
                    u = urls.get(r["url"])
                    if u is None:
                        continue
                    visited.add(r["url"])
                    yield Candidate(
                        kind="url", value=u["url"], source=str(path), locator=f"visits#{r['id']}",
                        method=SQLITE_METHOD, location="chrome_history", timestamp=chrome_time(r["visit_time"]),
                        extra={"table": "visits", "url_id": r["url"], "title": u["title"],
                               "from_visit": r["from_visit"], "transition": r["transition"]},
                    )
            for uid, u in urls.items():
                if uid in visited:
                    continue
                yield Candidate(
                    kind="url", value=u["url"], source=str(path), locator=f"urls#{uid}",
                    method=SQLITE_METHOD, location="chrome_history", timestamp=chrome_time(u["last_visit_time"]),
                    extra={"table": "urls", "title": u["title"], "visit_count": u["visit_count"]},
                )
        if "downloads" in tables:
            chains: dict[int, list[str]] = {}
            if "downloads_url_chains" in tables:
                for r in conn.execute("SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index"):
                    chains.setdefault(r["id"], []).append(r["url"])
            cols = _columns(conn, "downloads")
            want = [c for c in ("id", "current_path", "target_path", "start_time", "end_time", "received_bytes",
                                "total_bytes", "state", "tab_url", "tab_referrer_url", "referrer", "site_url",
                                "mime_type", "original_mime_type") if c in cols]
            for r in conn.execute(f"SELECT {', '.join(want)} FROM downloads ORDER BY id"):
                d = dict(r)
                target = d.get("target_path") or d.get("current_path") or ""
                yield Candidate(
                    kind="download", value=target, source=str(path), locator=f"downloads#{d['id']}",
                    method=SQLITE_METHOD, location="chrome_downloads", timestamp=chrome_time(d.get("start_time")),
                    extra={"table": "downloads", "filename": _basename(target),
                           "url_chain": chains.get(d["id"], []), "tab_url": d.get("tab_url"),
                           "referrer": d.get("referrer"), "mime_type": d.get("mime_type"),
                           "state": d.get("state"), "total_bytes": d.get("total_bytes"),
                           "end_time": chrome_time(d.get("end_time"))},
                )
                for i, u in enumerate(chains.get(d["id"], [])):
                    yield Candidate(
                        kind="url", value=u, source=str(path), locator=f"downloads_url_chains#{d['id']}.{i}",
                        method=SQLITE_METHOD, location="chrome_downloads", timestamp=chrome_time(d.get("start_time")),
                        extra={"table": "downloads_url_chains", "download_id": d["id"]},
                    )
    except sqlite3.Error as e:
        warnings.append(f"History: read error ({e})")
    finally:
        conn.close()


def _cookies(path: Path, warnings: list[str]) -> Iterator[Candidate]:
    try:
        conn = open_ro(path)
    except sqlite3.Error as e:
        warnings.append(f"Cookies: cannot open ({e})")
        return
    try:
        if "cookies" not in _tables(conn):
            warnings.append("Cookies: no cookies table")
            return
        cols = _columns(conn, "cookies")
        want = [c for c in ("creation_utc", "host_key", "name", "value", "encrypted_value", "path", "expires_utc",
                            "last_access_utc", "is_secure", "is_httponly", "is_persistent", "has_expires",
                            "samesite") if c in cols]
        for n, r in enumerate(conn.execute(f"SELECT rowid, {', '.join(want)} FROM cookies ORDER BY rowid")):
            d = dict(r)
            enc = d.get("encrypted_value")
            plaintext = d.get("value") or ""
            yield Candidate(
                kind="cookie", value=d["name"], source=str(path), locator=f"cookies#{d['rowid']}",
                method=SQLITE_METHOD, location="chrome_cookies", timestamp=chrome_time(d.get("creation_utc")),
                extra={"host_key": d.get("host_key"), "path": d.get("path"),
                       "plaintext_value": plaintext or None,
                       "encrypted": bool(enc) and not plaintext,
                       "expires": chrome_time(d.get("expires_utc")),
                       "last_access": chrome_time(d.get("last_access_utc")),
                       "httponly": bool(d.get("is_httponly")), "secure": bool(d.get("is_secure")),
                       "persistent": bool(d.get("is_persistent"))},
            )
    except sqlite3.Error as e:
        warnings.append(f"Cookies: read error ({e})")
    finally:
        conn.close()


def _autofill(path: Path, warnings: list[str]) -> Iterator[Candidate]:
    try:
        conn = open_ro(path)
    except sqlite3.Error as e:
        warnings.append(f"Web Data: cannot open ({e})")
        return
    try:
        if "autofill" not in _tables(conn):
            return
        cols = _columns(conn, "autofill")
        want = [c for c in ("name", "value", "count", "date_created", "date_last_used") if c in cols]
        for r in conn.execute(f"SELECT rowid, {', '.join(want)} FROM autofill ORDER BY rowid"):
            d = dict(r)
            ts = d.get("date_created")
            yield Candidate(
                kind="autofill", value=d.get("value") or "", source=str(path), locator=f"autofill#{d['rowid']}",
                method=SQLITE_METHOD, location="chrome_autofill",
                timestamp=datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds") if ts else None,
                extra={"field_name": d.get("name"), "count": d.get("count")},
            )
    except sqlite3.Error as e:
        warnings.append(f"Web Data: read error ({e})")
    finally:
        conn.close()


def _carve_dir(d: Path, label: str, warnings: list[str], *, exts: tuple[str, ...] | None,
               skip_dirs: tuple[str, ...] = ()) -> Iterator[Candidate]:
    for p in sorted(d.rglob("*")):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.relative_to(d).parts[:-1]):
            continue
        if exts is not None and p.suffix.lower() not in exts:
            continue
        if p.name.endswith("-slack") or p.name in ("LOCK", "CURRENT", "LOG", "LOG.old") or p.name.startswith("MANIFEST"):
            continue
        yield from _carve_file(p, f"{label}/{p.relative_to(d).as_posix()}", warnings)


_LOCATION_BY_STORE = {"Local Storage": "chrome_local_storage", "Session Storage": "chrome_session_storage",
                      "Cache": "chrome_cache", "Sessions": "chrome_sessions"}


def _carve_file(p: Path, label: str, warnings: list[str]) -> Iterator[Candidate]:
    location = _LOCATION_BY_STORE.get(label.split("/", 1)[0], "chrome_cache" if "Cache" in label else "filesystem")
    if label.startswith(("History", "Network", "Web Data")) or label.endswith("-wal"):
        location = {"History": "chrome_history", "Network": "chrome_cookies", "Web Data": "chrome_autofill"}.get(
            label.split("/", 1)[0], location)
    try:
        joined: list[str] = []
        for offset, enc, text in carve_strings(p):
            yield Candidate(
                kind="string", value=text, source=str(p), locator=f"offset {offset:#x}",
                method=CARVE_METHOD, location=location, extra={"store": label, "encoding": enc},
            )
            if len(joined) < 20000:
                joined.append(text)
        if joined and p.stat().st_size <= 2 * 1024 * 1024:
            yield Candidate(kind="text", value="\n".join(joined), source=str(p), locator="carved strings joined",
                            method=CARVE_METHOD + ", joined with newlines", location=location,
                            extra={"store": label})
    except OSError as e:
        warnings.append(f"{label}: cannot read ({e})")


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


__all__ = ["iter_chrome_profile", "chrome_time", "open_ro", "SQLITE_METHOD", "CARVE_METHOD"]
