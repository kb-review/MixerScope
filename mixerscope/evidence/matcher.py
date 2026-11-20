"""Match candidates against the knowledge base and identify the service."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

from .tokens import find_tokens
from mixerscope.knowledge_base.loader import KnowledgeBase
from mixerscope.schema import InvariantLiteral, ServiceEntry
from mixerscope.schema.vocab import NON_FACT_PLACEHOLDERS, PLACEHOLDER_RX

from .findings import Candidate, Finding, ServiceScore, Token

EXPLORER_HOSTS = ("mempool.space", "blockstream.info", "blockchain.com", "blockchair.com", "btc.com",
                  "blockcypher.com", "oxt.me", "etherscan.io", "xmrchain.net")
EVIDENCE_TOKEN_KINDS = ("txid", "btc_address", "evm_address", "uniqid")
DOMAIN_WEIGHT = {"canonical": 0.9, "assets_api": 0.9, "onion": 1.0, "alias": 0.5, "suspected_clone": 0.3}
FACT_FAMILY = {
    "btc_address": ("deposit_address", "destination_address"),
    "evm_address": ("deposit_address", "destination_address"),
    "txid": ("deposit_txid", "payout_txid"),
    "uniqid": ("order_id",),
    "ipv4": ("client_ip",),
    "amount": ("amounts",),
    "datetime": ("order_created_time",),
    "percent": ("fee_and_delay",),
}
_QUICK_TOKEN = re.compile(
    r"[0-9a-fA-F]{64}|(?:bc1|tb1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,}|"
    r"(?<![0-9a-zA-Z])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![0-9a-zA-Z])|0x[0-9a-fA-F]{40}|[0-9a-f]{14}\.\d{6,}"
)
_URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>]+")
_PAIR = re.compile(r"(?:^|[&?\s;])([A-Za-z0-9_\-\[\]]+)=([^&\s;]+)")


def _split(url: str):
    try:
        p = urlsplit(url)
        p.hostname  # may raise on malformed IPv6 literals
        return p
    except ValueError:
        return None


@dataclass
class _ArtifactRule:
    id: str
    location: str
    produced_by: str | None
    carries: list[str]
    persistence: str | None
    filename_rx: re.Pattern[str] | None
    keys: list[tuple[str, re.Pattern[str] | str, str | None]]  # (kind: regex|literal, matcher, describes)
    content: list[tuple[re.Pattern[str], list[str], list[str]]] = field(default_factory=list)  # (rx, placeholders, yields)


@dataclass
class _IndicatorRule:
    kind: str
    rx: re.Pattern[str] | None
    literal: str | None
    weight: float
    describes: str | None


@dataclass
class _Rules:
    service: str
    domains: dict[str, str]
    indicators: list[_IndicatorRule]
    endpoints: list[tuple[str, re.Pattern[str], dict[str, str]]]        # (id, path rx, field_facts)
    field_facts_all: dict[str, str]                                      # any field name -> fact (carved strings)
    cookies: dict[str, tuple[str, list[str]]]                            # name -> (set_by, encodes)
    templates: list[tuple[str, re.Pattern[str], list[str], list[str]]]  # (label, rx, placeholders, yields)
    status_endpoint: str | None
    artifacts: list[_ArtifactRule]
    identifiers: list[tuple[str, re.Pattern[str], str]]                  # (name, rx, fact)
    prefilter: re.Pattern[str] = field(default=None)  # type: ignore[assignment]


def _compile(entry: ServiceEntry) -> _Rules:
    oid = entry.order_id_regex()
    domains = {d.domain.lower(): d.role.value for d in entry.identity.domains}
    indicators = []
    literals: set[str] = set(domains)
    for ind in entry.indicators:
        if isinstance(ind.value, InvariantLiteral):
            indicators.append(_IndicatorRule(ind.kind.value, None, ind.value.literal, ind.weight, None))
            literals.add(ind.value.literal)
        else:
            rx = ind.value.compile(order_id_regex=oid)
            indicators.append(_IndicatorRule(ind.kind.value, rx, None, ind.weight,
                                             ind.value.describes.value if ind.value.describes else None))
            lit = _literal_head(ind.value.regex)
            if lit:
                literals.add(lit)
    endpoints, all_ff = [], {}
    for ep in entry.endpoints:
        ff = {k: v.value for k, v in ep.field_facts.items()}
        endpoints.append((ep.id, ep.path.compile(order_id_regex=oid), ff))
        all_ff.update(ff)
    cookies = {c.name: (c.set_by.value, [f.value for f in c.encodes_fact]) for c in entry.cookies}
    literals |= set(cookies)
    templates = []
    for st in entry.status.states:
        rx = st.template.compile(order_id_regex=oid)
        templates.append((st.label, rx, PLACEHOLDER_RX.findall(st.template.text), [f.value for f in st.template.yields]))
        head = _literal_head(st.template.text, escaped=False)
        if head:
            literals.add(head)
    artifacts = []
    for a in entry.artifacts:
        keys = []
        for k in a.search_keys:
            if isinstance(k, InvariantLiteral):
                keys.append(("literal", k.literal, None))
                literals.add(k.literal)
            else:
                keys.append(("regex", k.compile(order_id_regex=oid), k.describes.value if k.describes else None))
                lit = _literal_head(k.regex)
                if lit:
                    literals.add(lit)
        artifacts.append(_ArtifactRule(
            id=a.id, location=a.location.value, produced_by=a.produced_by, carries=[f.value for f in a.carries_facts],
            persistence=a.persistence_class.value.value if a.persistence_class and a.persistence_class.value else None,
            filename_rx=a.filename_pattern.compile(order_id_regex=oid) if a.filename_pattern else None, keys=keys,
            content=[(t.compile(order_id_regex=oid), PLACEHOLDER_RX.findall(t.text), [f.value for f in t.yields])
                     for t in entry.content_templates_for(a)]))
        for t in entry.content_templates_for(a):
            head = _literal_head(t.text, escaped=False)
            if head:
                literals.add(head)
    identifiers = [(i.name, i.scheme.compile(order_id_regex=oid), i.fact.value)
                   for i in entry.order_model.identifiers if i.scheme]
    lits = sorted((x for x in literals if len(x) >= 4), key=len, reverse=True)
    prefilter = re.compile("|".join(re.escape(x) for x in lits), re.I) if lits else re.compile(r"(?!)")
    return _Rules(service=entry.service.id, domains=domains, indicators=indicators, endpoints=endpoints,
                  field_facts_all=all_ff, cookies=cookies, templates=templates,
                  status_endpoint=entry.status.endpoint_ref, artifacts=artifacts, identifiers=identifiers,
                  prefilter=prefilter)


def _literal_head(regex: str, *, escaped: bool = True) -> str | None:
    """Longest leading literal run of a regex / template, for the cheap prefilter."""
    s = regex.lstrip("^")
    s = re.sub(r"\\(.)", r"\1", s) if escaped else s
    head = re.split(r"[\[\(\\.\*\+\?\{\}\|\$<]", s)[0].strip()
    return head if len(head) >= 6 else None


class Matcher:
    def __init__(self, kb: KnowledgeBase, services: list[str] | None = None) -> None:
        ids = services or [s.id for s in kb.list_services()]
        self.rules = [_compile(kb.get_service(i)) for i in ids]

    # ---- public --------------------------------------------------------------------------

    def match(self, c: Candidate) -> list[Finding]:
        if c.kind in ("string", "autofill", "text"):
            if not _QUICK_TOKEN.search(c.value) and not any(r.prefilter.search(c.value) for r in self.rules):
                return []
        tokens = [Token(t.kind, t.value) for t in find_tokens(c.value) if t.kind in EVIDENCE_TOKEN_KINDS or t.kind == "ipv4"]
        out: list[Finding] = []
        for r in self.rules:
            if c.kind == "url":
                out += self._url(r, c, tokens)
            elif c.kind == "cookie":
                out += self._cookie(r, c)
            elif c.kind in ("download", "file"):
                out += self._file(r, c, tokens)
            elif c.kind in ("string", "autofill"):
                out += self._string(r, c, tokens)
            elif c.kind == "text":
                out += self._text(r, c, tokens)
            elif c.kind == "header":
                out += self._header(r, c)
        if not out:
            out += self._generic(c, tokens)
        return out

    # ---- helpers -----------------------------------------------------------------------

    @staticmethod
    def _host_role(r: _Rules, host: str) -> str | None:
        host = (host or "").lower().lstrip(".")
        for d, role in r.domains.items():
            if host == d or host.endswith("." + d):
                return role
        return None

    @staticmethod
    def _artifact_for(r: _Rules, c: Candidate, *, produced_by: str | None = None) -> _ArtifactRule | None:
        """Artifact at the candidate's location, preferring one produced by the given endpoint."""
        same = [a for a in r.artifacts if a.location == c.location]
        if produced_by:
            for a in same:
                if a.produced_by == produced_by:
                    return a
        for a in same:
            for kind, m, _ in a.keys:
                if (kind == "literal" and m in c.value) or (kind == "regex" and m.search(c.value)):
                    return a
        return None

    @staticmethod
    def _label_tokens(tokens: list[Token], facts: list[str], basis: str) -> list[Token]:
        """Assign facts to tokens when the candidate facts fix exactly one per token family."""
        out = []
        for t in tokens:
            fam = FACT_FAMILY.get(t.kind, ())
            fitting = [f for f in facts if f in fam]
            fact = fitting[0] if len(fitting) == 1 else None
            out.append(Token(t.kind, t.value, fact, basis if fact else None))
        return out

    def _finding(self, r: _Rules, match: str, strength: float, c: Candidate, art: _ArtifactRule | None,
                 tokens: list[Token], note: str | None = None, fact: str | None = None) -> Finding:
        if art and not any(t.fact for t in tokens):
            tokens = self._label_tokens(tokens, art.carries, f"artifact {art.id} carries_facts")
        if fact is None:
            facts = {t.fact for t in tokens if t.fact}
            fact = facts.pop() if len(facts) == 1 else None
        return Finding(match=match, strength=strength, candidate=c, service=r.service,
                       artifact_ref=f"{r.service}:{art.id}" if art else None, fact=fact,
                       persistence_class=art.persistence if art else None, tokens=tokens, note=note)

    # ---- per kind ----------------------------------------------------------------------

    def _url(self, r: _Rules, c: Candidate, tokens: list[Token], *, from_string: bool = False) -> list[Finding]:
        parts = _split(c.value)
        if parts is None:
            return []
        host = (parts.hostname or "").lower()
        role = self._host_role(r, host)
        path = parts.path or "/"
        out: list[Finding] = []
        # identification indicators score real URL candidates; a URL carved out of a longer
        # string already yields an artifact / endpoint finding and must not count twice
        for ind in ([] if from_string else r.indicators):
            if ind.kind == "url_path" and ind.rx and ind.rx.search(path):
                out.append(self._finding(r, "indicator:url_path", ind.weight, c, None, [], note=ind.rx.pattern))
            elif ind.kind == "domain" and ind.literal and (host == ind.literal or host.endswith("." + ind.literal)):
                out.append(self._finding(r, "indicator:domain", ind.weight, c, None, []))
            elif ind.kind == "string" and ind.literal and ind.literal in c.value:
                out.append(self._finding(r, "indicator:string", ind.weight, c, None, []))
        if role is None:
            # not a service host: still an artifact if a KB artifact at this location keys on
            # the URL (e.g. a block-explorer visit for the deposit transaction)
            art = self._artifact_for(r, c)
            if art:
                out.append(self._finding(r, f"artifact:{art.id}", 0.3, c, art, tokens,
                                         note="third-party URL listed as a service artifact"))
            return out
        matched = None
        for eid, rx, ff in r.endpoints:
            if rx.match(path):
                matched = (eid, ff)
                break
        if role == "alias":
            out.append(self._finding(r, "domain:alias", DOMAIN_WEIGHT["alias"], c, None, tokens,
                                     note="alias or clone domain listed in the KB"))
        if matched:
            eid, ff = matched
            labelled = []
            q = parse_qs(parts.query, keep_blank_values=True)
            for t in tokens:
                param = next((k for k, vs in q.items() if any(t.value in v for v in vs)), None)
                fact = ff.get(param) if param else None
                labelled.append(Token(t.kind, t.value, fact, f"query param {param!r} (field_facts of {eid})" if fact else None))
            art = self._artifact_for(r, c, produced_by=eid)
            out.append(self._finding(r, f"endpoint:{eid}", 0.5 if role == "alias" else 0.8, c, art, labelled,
                                     note="on alias domain" if role == "alias" else None))
        else:
            art = self._artifact_for(r, c)
            out.append(self._finding(r, f"domain:{role}", DOMAIN_WEIGHT.get(role, 0.3), c, art, tokens))
        return out

    def _cookie(self, r: _Rules, c: Candidate) -> list[Finding]:
        name = c.value
        host = c.extra.get("host_key") or ""
        role = self._host_role(r, host)
        info = r.cookies.get(name)
        out: list[Finding] = []
        for ind in r.indicators:
            if ind.kind == "cookie_name" and ind.rx and ind.rx.search(name):
                out.append(self._finding(r, "indicator:cookie_name", ind.weight, c, None, []))
            elif ind.kind == "domain" and ind.literal and host and (host.lstrip(".") == ind.literal or host.endswith("." + ind.literal)):
                out.append(self._finding(r, "indicator:domain", ind.weight, c, None, []))
        if info is None:
            if role:
                out.append(self._finding(r, f"cookie:{name}", 0.2, c, None, [],
                                         note=f"cookie on a {role} domain of the service; name not in the KB"))
            return out
        set_by, encodes = info
        if role is None and set_by != "application":
            return out + [Finding(match=f"infra_cookie:{name}", strength=0.0, candidate=c,
                                  note=f"{set_by} cookie on {host!r}, not a KB domain of {r.service}")]
        tokens: list[Token] = []
        pv = c.extra.get("plaintext_value")
        if pv:
            tokens = [Token(t.kind, t.value) for t in find_tokens(pv)]
            tokens = self._label_tokens(tokens, encodes, f"cookie {name} encodes_fact") if encodes else tokens
            if encodes and not tokens:
                tokens = [Token("cookie_value", pv, encodes[0], f"cookie {name} encodes_fact")]
        elif encodes and encodes[0] == "session_id":
            tokens = []
        art = self._artifact_for(r, c)
        strength = 0.9 if role else (0.4 if set_by == "application" else 0.1)
        fact = encodes[0] if len(encodes) == 1 else None
        out.append(self._finding(r, f"cookie:{name}", strength, c, art, tokens, fact=fact))
        return out

    def _file(self, r: _Rules, c: Candidate, tokens: list[Token]) -> list[Finding]:
        name = c.extra.get("filename") or c.value.replace("\\", "/").rsplit("/", 1)[-1]
        out: list[Finding] = []
        for a in r.artifacts:
            if a.location != c.location:
                continue
            hit = bool(a.filename_rx and a.filename_rx.search(name)) or any(
                (k == "regex" and m.search(name)) or (k == "literal" and m in name) for k, m, _ in a.keys)
            if hit:
                toks = [Token(t.kind, t.value) for t in find_tokens(name)]
                out.append(self._finding(r, f"artifact:{a.id}", 0.7, c, a, toks or tokens))
        for ind in r.indicators:
            if ind.kind in ("string", "filename") and ind.rx and ind.rx.search(name):
                out.append(self._finding(r, f"indicator:{ind.kind}", ind.weight, c, None, [], note="filename"))
        if not out and c.kind == "download":
            for u in c.extra.get("url_chain", []):
                p = _split(u)
                if p is not None and self._host_role(r, p.hostname or ""):
                    out.append(self._finding(r, "download:from-service-domain", 0.8, c, None, tokens))
                    break
        return out

    def _string(self, r: _Rules, c: Candidate, tokens: list[Token]) -> list[Finding]:
        s = c.value
        out: list[Finding] = []
        # status templates (memory, carved cache, capture bodies)
        for label, rx, placeholders, yields in r.templates:
            m = rx.search(s)
            if m:
                labelled = self._label_from_template(m, placeholders, yields, tokens, label)
                art = self._artifact_for(r, c, produced_by=r.status_endpoint)
                out.append(self._finding(r, f"template:{label}", 0.8, c, art, labelled))
                break
        # indicators
        for ind in r.indicators:
            if ind.kind in ("string", "url_path", "header") and ind.rx and ind.rx.search(s):
                out.append(self._finding(r, f"indicator:{ind.kind}", ind.weight, c, None, []))
            elif ind.kind == "string" and ind.literal and ind.literal in s:
                out.append(self._finding(r, "indicator:string", ind.weight, c, None, []))
        # URL inside a carved string -> endpoint rule with field_facts
        m = _URL_IN_TEXT.search(s)
        if m and not any(f.match.startswith("template:") for f in out):
            sub = Candidate(**{**c.__dict__, "kind": "url", "value": m.group(0)})
            for f in self._url(r, sub, tokens, from_string=True):
                f.candidate = c
                f.note = (f.note + "; " if f.note else "") + "URL within string"
                out.append(f)
        # name=value pairs (request bodies carved from memory)
        if tokens and not any(t.fact for f in out for t in f.tokens):
            labelled = []
            for t in tokens:
                fact, basis = None, None
                for pm in _PAIR.finditer(s):
                    if t.value in pm.group(2) and pm.group(1) in r.field_facts_all:
                        fact, basis = r.field_facts_all[pm.group(1)], f"field {pm.group(1)!r} (endpoint field_facts)"
                        break
                labelled.append(Token(t.kind, t.value, fact, basis))
            if any(t.fact for t in labelled):
                # field names such as `address` recur across services: good for labelling the
                # value, weak as identification evidence
                out.append(self._finding(r, "request_fields", 0.3, c, self._artifact_for(r, c), labelled))
        # autofill: artifact search keys match the field NAME
        if c.kind == "autofill":
            fname = c.extra.get("field_name") or ""
            for a in r.artifacts:
                if a.location == c.location and any(k == "regex" and m_.search(fname) for k, m_, _ in a.keys):
                    out.append(self._finding(r, f"artifact:{a.id}", 0.7, c, a, tokens,
                                             note=f"autofill field {fname!r}"))
        # artifact search keys on the string itself (location-gated)
        if not out:
            for a in r.artifacts:
                if a.location != c.location:
                    continue
                for kind, mm, _ in a.keys:
                    if (kind == "literal" and mm in s) or (kind == "regex" and mm.search(s)):
                        out.append(self._finding(r, f"artifact:{a.id}", 1.0 if kind == "literal" else 0.5, c, a, tokens))
                        break
        # identifier schemes (weak)
        for name, rx, fact in r.identifiers:
            if rx.fullmatch(s.strip()):
                # a scheme labels the value only when its fact family is unambiguous (an order-ID
                # scheme does; a bare address regex cannot tell deposit from destination)
                specific = all(len(FACT_FAMILY.get(t.kind, ())) == 1 for t in tokens) and bool(tokens)
                toks = [Token(t.kind, t.value, fact if specific else None, f"identifier {name} scheme" if specific else None)
                        for t in tokens]
                out.append(self._finding(r, f"identifier:{name}", 0.2, c, None, toks, fact=fact if specific else None))
        # cookie name mentioned in a string
        if not out:
            for name in r.cookies:
                if re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", s):
                    out.append(self._finding(r, f"cookie:{name}", 0.2, c, None, tokens, note="name seen in string"))
                    break
        # a bare mention of a service domain, only when nothing more specific matched and the
        # string carries an evidence token (otherwise every page asset would count)
        if not out and tokens:
            for ind in r.indicators:
                if ind.kind == "domain" and ind.literal and ind.literal in s:
                    out.append(self._finding(r, "indicator:domain", ind.weight * 0.5, c, None, tokens, note="domain in string"))
                    break
        return out

    def _text(self, r: _Rules, c: Candidate, tokens: list[Token]) -> list[Finding]:
        """Whole-file / joined text: only document content templates apply (the per-line
        rules already ran on the carved strings)."""
        out: list[Finding] = []
        for a in r.artifacts:
            for rx, placeholders, yields in a.content:
                m = rx.search(c.value)
                if not m:
                    continue
                labelled = self._label_from_template(m, placeholders, yields, tokens, f"content of {a.id}")
                same_loc = a.location == c.location
                out.append(self._finding(r, f"artifact:{a.id}", 0.9 if same_loc else 0.6, c, a if same_loc else None,
                                         labelled, note="content template matched" + ("" if same_loc else
                                                                                      f" at {c.location}, artifact location is {a.location}")))
                break
        return out

    def _header(self, r: _Rules, c: Candidate) -> list[Finding]:
        out = []
        for ind in r.indicators:
            if ind.kind == "header" and ind.rx and ind.rx.search(c.value):
                out.append(self._finding(r, "indicator:header", ind.weight, c, None, []))
        return out

    @staticmethod
    def _label_from_template(m: re.Match[str], placeholders: list[str], yields: list[str], tokens: list[Token],
                             label: str) -> list[Token]:
        """Pair captured placeholders with the template's yields. Non-fact placeholders (text,
        hex, int, signature) are skipped; the remaining groups pair with `yields` by position
        when the counts agree, else by fact family. Captured values without a detector token
        (dates, percentages) become tokens of their placeholder kind."""
        groups = list(m.groups())
        fact_slots = [(g, ph) for g, ph in zip(groups, placeholders) if ph not in NON_FACT_PLACEHOLDERS]
        by_value: dict[str, tuple[str, str]] = {}
        if len(fact_slots) == len(yields):
            for (g, ph), y in zip(fact_slots, yields):
                if g and g not in by_value:
                    by_value[g] = (y, ph)
        else:
            for g, ph in fact_slots:
                fam = FACT_FAMILY.get(ph, ()) or FACT_FAMILY.get(_token_kind_for(ph), ())
                fit = [y for y in yields if y in fam]
                if g and len(fit) == 1:
                    by_value[g] = (fit[0], ph)
        out = []
        seen = set()
        for t in tokens:
            fact = by_value.get(t.value, (None, None))[0]
            out.append(Token(t.kind, t.value, fact, f"template {label!r} yields" if fact else None))
            seen.add(t.value)
        for value, (fact, ph) in by_value.items():
            if value not in seen:
                out.append(Token(_token_kind_for(ph), value.strip(), fact, f"template {label!r} yields"))
        return out

    def _generic(self, c: Candidate, tokens: list[Token]) -> list[Finding]:
        if c.kind == "url":
            p = _split(c.value)
            host = (p.hostname or "").lower() if p is not None else ""
            if any(host == h or host.endswith("." + h) for h in EXPLORER_HOSTS):
                txids = [t for t in tokens if t.kind == "txid"]
                if txids:
                    return [Finding(match="explorer_tx_visit", strength=0.0, candidate=c, tokens=txids,
                                    note="block-explorer visit carrying a TXID; service-agnostic")]
        ev = [t for t in tokens if t.kind in EVIDENCE_TOKEN_KINDS]
        if ev:
            note = None
            if c.kind == "autofill":
                note = f"Chrome autofill entry, form field name {c.extra.get('field_name')!r}"
            elif c.location == "chrome_sessions":
                note = "session-restore (SNSS) page state"
            return [Finding(match="token:" + "+".join(sorted({t.kind for t in ev})), strength=0.0, candidate=c,
                            tokens=ev, note=note)]
        return []


def _token_kind_for(placeholder: str) -> str:
    return {"txid_hex64": "txid", "btc_address": "btc_address", "eth_address": "evm_address", "order_id": "uniqid",
            "amount_btc": "amount", "unix_ts": "unix_timestamp", "unix_ts_ms": "unix_timestamp"}.get(placeholder, placeholder)


def identify_service(findings: list[Finding]) -> list[ServiceScore]:
    """Rank services by evidence weight. A service whose best rule is weaker than 0.5
    (generic cookie names, identifier schemes) is not reported."""
    scores: dict[str, float] = {}
    rules: dict[str, dict[str, int]] = {}
    best: dict[str, float] = {}
    for f in findings:
        if not f.service:
            continue
        scores[f.service] = scores.get(f.service, 0.0) + f.strength
        best[f.service] = max(best.get(f.service, 0.0), f.strength)
        rules.setdefault(f.service, {})
        rules[f.service][f.match] = rules[f.service].get(f.match, 0) + 1
    out = [ServiceScore(service=s, score=round(sc + 2.0 * len(rules[s]), 2), rules=dict(sorted(rules[s].items())))
           for s, sc in scores.items() if best[s] >= 0.5]
    return sorted(out, key=lambda x: -x.score)


__all__ = ["Matcher", "identify_service", "EXPLORER_HOSTS", "FACT_FAMILY"]
