"""Controlled vocabularies and the placeholder vocabulary (§P)."""

from __future__ import annotations

import re
from enum import IntEnum, StrEnum

from .definitions import load_definitions

SCHEMA_VERSION = "0.4"


class Tier(IntEnum):
    """Stage of the transaction at which a fact can first be established. The observation
    kind (capture, disk image, operator page, replay, explorer) records HOW it was seen."""

    NO_FUNDS = 0   # public pages, order creation, invoice, letter download: nothing funded
    FUNDED = 1     # a real deposit goes through: post-payment states, payout, retention


class Basis(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    CLAIMED = "claimed"
    UNKNOWN = "unknown"


class ProvenanceClass(StrEnum):
    SUBJECT_EVIDENCE = "subject_evidence"
    INSTRUMENTATION = "instrumentation"
    OPERATOR_CLAIM = "operator_claim"
    PUBLIC_RECORD = "public_record"


class ObservationKind(StrEnum):
    CAPTURE_FLOW = "capture_flow"
    DISK_IMAGE = "disk_image"
    OPERATOR_PAGE = "operator_page"
    REPLAY = "replay"
    EXPLORER = "explorer"


class CellValue(StrEnum):
    """Table 3 vocabulary: what a source yields for a fact."""

    RECOVERED = "recovered"
    METADATA_ONLY = "metadata_only"
    LIVE_ONLY = "live_only"
    REQUIRED_TO_QUERY = "required_to_query"
    NOT_STORED_BY_DESIGN = "not_stored_by_design"
    NOT_FOUND = "not_found"
    NOT_TESTED = "not_tested"
    NOT_APPLICABLE = "not_applicable"


class MatrixSource(StrEnum):
    """Columns of the fact-by-source matrix, in display order."""

    HISTORY = "history"
    DOWNLOADS = "downloads"
    CACHE = "cache"
    COOKIES = "cookies"
    WEB_STORAGE = "web_storage"
    AUTOFILL = "autofill"
    SESSIONS = "sessions"
    FILESYSTEM = "filesystem"
    REPLAY = "replay"
    CHAIN = "chain"


class Fact(StrEnum):
    """Canonical transaction facts: the comparison axis across services."""

    DEPOSIT_ADDRESS = "deposit_address"
    DESTINATION_ADDRESS = "destination_address"
    ORDER_ID = "order_id"
    RECEIPT = "receipt"
    DEPOSIT_TXID = "deposit_txid"
    PAYOUT_TXID = "payout_txid"
    AMOUNTS = "amounts"
    FEE_AND_DELAY = "fee_and_delay"
    MIX_MODE = "mix_mode"
    ORDER_CREATED_TIME = "order_created_time"
    SESSION_ID = "session_id"
    CLIENT_IP = "client_ip"
    USER_IDENTIFIER = "user_identifier"
    STATUS_PROGRESSION = "status_progression"


class Location(StrEnum):
    CHROME_HISTORY = "chrome_history"
    CHROME_DOWNLOADS = "chrome_downloads"
    CHROME_CACHE = "chrome_cache"
    CHROME_COOKIES = "chrome_cookies"
    CHROME_LOCAL_STORAGE = "chrome_local_storage"
    CHROME_SESSION_STORAGE = "chrome_session_storage"
    CHROME_INDEXEDDB = "chrome_indexeddb"
    CHROME_AUTOFILL = "chrome_autofill"
    CHROME_SESSIONS = "chrome_sessions"
    FILESYSTEM = "filesystem"
    PAGEFILE = "pagefile"
    UNALLOCATED = "unallocated"
    ON_CHAIN = "on_chain"
    NETWORK_ONLY = "network_only"


class PersistenceClass(StrEnum):
    DISK = "disk"
    ON_CHAIN = "on_chain"
    NONE_BY_DESIGN = "none_by_design"


class CachePolicy(StrEnum):
    NO_STORE = "no_store"
    NO_CACHE = "no_cache"
    CACHEABLE_HEURISTIC = "cacheable_heuristic"
    CACHEABLE_EXPLICIT = "cacheable_explicit"
    CACHE_BUSTED = "cache_busted"
    UNKNOWN = "unknown"


class GateMechanism(StrEnum):
    """An endpoint's gate is a list of these (empty list = open)."""

    SESSION = "session"
    CSRF = "csrf"
    CAPTCHA = "captcha"
    CDN_CHALLENGE = "cdn_challenge"


class IdentifierRole(StrEnum):
    RECORD_KEY = "record_key"
    STATUS_LOOKUP_KEY = "status_lookup_key"
    DISPLAY_ONLY = "display_only"
    CROSS_ORDER_USER_KEY = "cross_order_user_key"


class CookieSetBy(StrEnum):
    APPLICATION = "application"
    CDN = "cdn"
    ANALYTICS = "analytics"


class ReplayVariant(StrEnum):
    ORIGINAL = "original"
    SUPERSEDED_SESSION = "superseded_session"
    NO_COOKIES = "no_cookies"
    FOREIGN_ORDER_KEY = "foreign_order_key"


class ReplayOutcome(StrEnum):
    LIVE = "live"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class IndicatorKind(StrEnum):
    DOMAIN = "domain"
    URL_PATH = "url_path"
    FILENAME = "filename"
    STRING = "string"
    COOKIE_NAME = "cookie_name"
    HEADER = "header"


class Consistency(StrEnum):
    CONSISTENT = "consistent"
    PARTIALLY_CONSISTENT = "partially_consistent"
    CONTRADICTED = "contradicted"
    UNTESTED = "untested"


class ReceiptDelivery(StrEnum):
    SERVER_FILE = "server_file"
    CLIENT_BLOB = "client_blob"
    PAGE_TEXT = "page_text"
    NONE = "none"


class ReceiptContainer(StrEnum):
    PLAIN_TEXT = "plain_text"
    BITCOIN_SIGNED_MESSAGE = "bitcoin_signed_message"
    PGP_CLEARSIGNED = "pgp_clearsigned"
    PGP_DETACHED = "pgp_detached"
    JSON = "json"
    HTML = "html"
    PDF = "pdf"


class SignatureScheme(StrEnum):
    BITCOIN_SIGNED_MESSAGE = "bitcoin_signed_message"
    PGP = "pgp"
    RSA = "rsa"
    NONE = "none"
    UNKNOWN = "unknown"


class StatusMechanism(StrEnum):
    POLLING = "polling"
    WEBSOCKET = "websocket"
    SERVER_RENDERED_REFRESH = "server_rendered_refresh"
    NONE = "none"


class AccountModel(StrEnum):
    ACCOUNT_LESS = "account_less"
    OPTIONAL_ACCOUNT = "optional_account"
    REQUIRED_ACCOUNT = "required_account"


class DomainRole(StrEnum):
    CANONICAL = "canonical"
    ASSETS_API = "assets_api"
    ALIAS = "alias"
    SUSPECTED_CLONE = "suspected_clone"
    ONION = "onion"


class EntryStatus(StrEnum):
    DRAFT = "draft"
    REVIEWED = "reviewed"
    CONFIRMED = "confirmed"


class ValidityStatus(StrEnum):
    CURRENT = "current"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


class ContentEncoding(StrEnum):
    GZIP = "gzip"
    BR = "br"
    ZSTD = "zstd"
    NONE = "none"


PRODUCED_BY_SPECIAL = ("client_js", "browser", "user_action", "service_wallet")

# --------------------------------------------------------------------------------------
# Derived from the definitions file (single source)
# --------------------------------------------------------------------------------------

_DEFS = load_definitions()

DISK_SOURCES: frozenset[MatrixSource] = frozenset(MatrixSource(c) for c in _DEFS.disk_sources())
LOCATION_TO_SOURCE: dict[str, MatrixSource] = {loc: MatrixSource(src) for loc, src in _DEFS.location_to_source().items()}
PLACEHOLDERS: dict[str, str] = _DEFS.placeholders()
NON_FACT_PLACEHOLDERS: frozenset[str] = _DEFS.non_fact_placeholders()

#: Inline HTML tags that appear verbatim in status responses; `<br>` is literal text.
HTML_LITERAL_TAGS = frozenset({"br", "b", "i", "p", "span", "div", "hr", "strong", "em", "small", "u"})

PLACEHOLDER_RX = re.compile(r"<(?!(?:" + "|".join(sorted(HTML_LITERAL_TAGS)) + r")>)([a-z0-9_]+)>")


def placeholders_in(text: str) -> list[str]:
    return PLACEHOLDER_RX.findall(text)


def unknown_placeholders(text: str) -> list[str]:
    return [p for p in placeholders_in(text) if p not in PLACEHOLDERS]


def expand_placeholders(regex: str, *, order_id_regex: str | None = None) -> str:
    """Replace <placeholder> tokens inside a regex with their classes (regex already escaped)."""
    def sub(m: re.Match[str]) -> str:
        name = m.group(1)
        if name == "order_id" and order_id_regex:
            return "(?:" + order_id_regex.strip("^$") + ")"
        return "(?:" + PLACEHOLDERS[name] + ")"
    return PLACEHOLDER_RX.sub(sub, regex)


def template_to_regex(text: str, *, order_id_regex: str | None = None, anchored: bool = False) -> str:
    """Turn a Template text (literal with placeholders) into a regex. Literal runs are
    escaped, whitespace runs become \\s*, placeholders become their classes."""
    out: list[str] = []
    pos = 0
    for m in PLACEHOLDER_RX.finditer(text):
        out.append(_escape_literal(text[pos:m.start()]))
        name = m.group(1)
        if name == "order_id" and order_id_regex:
            out.append("(" + order_id_regex.strip("^$") + ")")
        else:
            out.append("(" + PLACEHOLDERS[name] + ")")
        pos = m.end()
    out.append(_escape_literal(text[pos:]))
    rx = "".join(out)
    return f"^{rx}$" if anchored else rx


def _escape_literal(literal: str) -> str:
    if not literal:
        return ""
    return r"\s*".join(re.escape(part) for part in re.split(r"\s+", literal))
