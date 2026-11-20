"""Service entry, schema v0.4 (one file per service under knowledge_base/services/)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .attribute import Attr, Attribute, Cell, InvariantLiteral, Pattern, Template, Validity, scan_for_instance_data
from .vocab import (
    DISK_SOURCES,
    PRODUCED_BY_SPECIAL,
    SCHEMA_VERSION,
    AccountModel,
    Basis,
    CachePolicy,
    CellValue,
    Consistency,
    ContentEncoding,
    CookieSetBy,
    DomainRole,
    EntryStatus,
    Fact,
    GateMechanism,
    IdentifierRole,
    IndicatorKind,
    Location,
    MatrixSource,
    ObservationKind,
    PersistenceClass,
    ProvenanceClass,
    ReceiptContainer,
    ReceiptDelivery,
    ReplayOutcome,
    ReplayVariant,
    SignatureScheme,
    StatusMechanism,
    Tier,
)

_MONTH = r"^\d{4}-\d{2}(?:-\d{2})?$"


class _Rec(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- §S observations ------------------------------------------------------------------


class Observation(_Rec):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]*$")
    kind: ObservationKind
    provenance_class: ProvenanceClass
    tier: Tier
    date: str | None = Field(default=None, pattern=_MONTH, description="YYYY-MM or YYYY-MM-DD")
    os: str | None = Field(default=None, description="Operating system of the subject machine, e.g. Windows 10")
    browser_version: str | None = Field(default=None, description="e.g. Chrome 150")
    case_ref: str | None = Field(default=None, description="Pointer to the case file / evidence log, never its contents.")
    notes: str | None = None
    conditions: str | None = Field(default=None, description="Acquisition conditions of a disk image: how the browser and the machine were closed, what else the profile holds.")


# --- service header -----------------------------------------------------------------------


class ServiceMeta(_Rec):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    display_name: str
    entry_status: EntryStatus = EntryStatus.DRAFT
    tiers_completed: list[Tier] = Field(default_factory=list)
    analysts: list[str] = Field(default_factory=list)
    first_analyzed: str | None = Field(default=None, pattern=_MONTH)
    validity_default: Validity | None = Field(default=None, description="Applies to every attribute without its own validity.")


# --- 1 identity -------------------------------------------------------------------------


class DomainRecord(_Rec):
    domain: str
    role: DomainRole
    attr: Attr


class Framework(_Rec):
    name: Attribute[str] | None = None
    signals: list[str] = Field(default_factory=list)


class ClientIpLeak(_Rec):
    present: Attribute[bool] | None = None
    mechanism: Attribute[str] | None = None


class Identity(_Rec):
    domains: list[DomainRecord] = Field(default_factory=list)
    cdn_proxy: Attribute[str] | None = None
    framework: Framework = Field(default_factory=Framework)
    client_ip_leak: ClientIpLeak = Field(default_factory=ClientIpLeak)


# --- 2 access & modes ------------------------------------------------------------------


class Access(_Rec):
    account_model: Attribute[AccountModel] | None = None
    kyc: Attribute[bool] | None = None


class Limits(_Rec):
    min: Attribute[str] | None = None
    max: Attribute[str] | None = None


class Mode(_Rec):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    page_paths: list[str] = Field(default_factory=list)
    chain_flow: Attribute[str] | None = None
    limits: Limits = Field(default_factory=Limits)
    fee_model: Attribute[str] | None = None
    delay_options: Attribute[str] | None = None
    order_params: list[str] = Field(default_factory=list, description="Request field names.")
    attr: Attr | None = None


# --- 3 order model ----------------------------------------------------------------------


class Identifier(_Rec):
    name: str
    fact: Fact
    scheme: Pattern | None = None
    derivation: Attribute[str] | None = None
    role: Attribute[IdentifierRole] | None = None
    exposed_in: list[Location] = Field(default_factory=list)
    attr: Attr | None = None


class OrderModel(_Rec):
    identifiers: list[Identifier] = Field(default_factory=list)


# --- 4 cookies ----------------------------------------------------------------------------


class Cookie(_Rec):
    name: str = Field(description="Cookie NAME only, never a value.")
    set_by: CookieSetBy
    purpose: Attribute[str] | None = None
    value_scheme: Pattern | None = None
    flags: Attribute[list[str]] | None = None
    client_max_age: Attribute[str] | None = None
    rotation_interval: Attribute[str] | None = None
    server_side_validity: Attribute[str] | None = None
    persists_to_disk: Attribute[bool] | None = None
    encodes_fact: list[Fact] = Field(default_factory=list)
    attr: Attr | None = None


# --- 5 endpoints ------------------------------------------------------------------------


class ReplayResult(_Rec):
    """One variant of the four-request replay protocol and what its reply showed."""

    variant: ReplayVariant
    reply: Template | None = None
    reading: str | None = None
    outcome: Attribute[ReplayOutcome]


class Endpoint(_Rec):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    method: str
    path: Pattern
    purpose: str
    request_fields: list[str] = Field(default_factory=list, description="Body / query field NAMES only.")
    field_facts: dict[str, Fact] = Field(default_factory=dict, description="Request field name -> canonical fact it carries.")
    gate: Attribute[list[GateMechanism]] | None = Field(default=None, description="Mechanisms required; an empty list means open.")
    ownership_check: Attribute[bool] | None = None
    cache_policy: Attribute[CachePolicy] | None = None
    content_encoding: Attribute[ContentEncoding] | None = None
    lookup_key: Attribute[Fact] | None = Field(default=None, description="Fact the endpoint looks an order up by.")
    response_templates: list[Template] = Field(default_factory=list)
    replay_results: list[ReplayResult] = Field(default_factory=list)
    attr: Attr | None = None

    @model_validator(mode="after")
    def _upper(self) -> Endpoint:
        self.__dict__["method"] = self.method.upper()
        return self


# --- 6 status ---------------------------------------------------------------------------


class StatusState(_Rec):
    order: int
    label: str
    template: Template
    attr: Attr | None = None


class Status(_Rec):
    mechanism: Attribute[StatusMechanism] | None = None
    endpoint_ref: str | None = None
    interval: Attribute[str] | None = None
    states: list[StatusState] = Field(default_factory=list)
    replay_behavior: Attribute[str] | None = None


# --- 7 receipts -------------------------------------------------------------------------


class ReceiptObtainedVia(_Rec):
    endpoint_ref: str | None = None
    request_params: list[str] = Field(default_factory=list)
    delivery: Attribute[ReceiptDelivery] | None = None
    cache_policy: Attribute[CachePolicy] | None = None


class ReceiptFile(_Rec):
    filename_pattern: Pattern | None = None
    mime_type: Attribute[str] | None = None
    encoding: Attribute[str] | None = None


class ReceiptStructure(_Rec):
    container: Attribute[ReceiptContainer] | None = None
    container_notes: str | None = None
    boundary_markers: list[Pattern] = Field(default_factory=list, description="Lines that open / close a signed block.")
    templates: list[Template] = Field(default_factory=list, description="Content templates, one per variant.")


class ReceiptSignature(_Rec):
    scheme: Attribute[SignatureScheme] | None = None
    signing_identity: InvariantLiteral | None = None
    identity_published_at: list[str] = Field(default_factory=list)
    signed_content: Attribute[str] | None = None
    verification: Attribute[str] | None = None
    key_history: Attribute[str] | None = None


class ReceiptEvidentiaryValue(_Rec):
    binds_facts: list[Fact] = Field(default_factory=list)
    survives_server_purge: Attribute[bool] | None = None


class Receipt(_Rec):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    name: str
    offered: Attribute[str] | None = Field(default=None, description="always | optional | none")
    obtained_via: ReceiptObtainedVia = Field(default_factory=ReceiptObtainedVia)
    file: ReceiptFile = Field(default_factory=ReceiptFile)
    structure: ReceiptStructure = Field(default_factory=ReceiptStructure)
    signature: ReceiptSignature = Field(default_factory=ReceiptSignature)
    evidentiary_value: ReceiptEvidentiaryValue = Field(default_factory=ReceiptEvidentiaryValue)
    field_map: Attribute[dict[str, Fact]] | None = Field(default=None, description="Printed label -> fact it introduces in the receipt text.")
    artifact_refs: list[str] = Field(default_factory=list)
    attr: Attr | None = None


# --- 8 artifacts -------------------------------------------------------------------------


class Artifact(_Rec):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    name: str
    location: Location
    path_pattern: str | None = None
    filename_pattern: Pattern | None = None
    produced_by: str | None = Field(default=None, description="endpoint id | receipt id | client_js | browser | user_action | service_wallet")
    receipt_ref: str | None = Field(default=None, description="Receipt whose content templates parse this artifact.")
    format: str | None = None
    carries_facts: list[Fact] = Field(default_factory=list)
    persistence_class: Attribute[PersistenceClass] | None = None
    recovery_route: Attribute[str] | None = None
    search_keys: list[Pattern | InvariantLiteral] = Field(default_factory=list)
    content_templates: list[Template] = Field(default_factory=list)
    case_uco_class: str | None = None
    caveat: Attribute[str] | None = Field(default=None, description="What can mislead about this artifact.")
    attr: Attr | None = None


# --- 9 fact coverage: the stored fact-by-source matrix ----------------------------------


class MatrixRow(_Rec):
    fact: Fact
    cells: dict[MatrixSource, Cell] = Field(default_factory=dict)
    best_persistence: PersistenceClass | None = None
    artifacts: list[str] = Field(default_factory=list)
    notes: str | None = None
    attr: Attr | None = None

    def cell(self, source: MatrixSource | str) -> Cell | None:
        return self.cells.get(MatrixSource(source))

    def dead_box_recoverable(self) -> bool:
        return any(c.value is CellValue.RECOVERED for s, c in self.cells.items() if s in DISK_SOURCES)

    def on_chain_reconstructable(self) -> bool:
        c = self.cells.get(MatrixSource.CHAIN)
        return bool(c) and c.value in (CellValue.RECOVERED, CellValue.REQUIRED_TO_QUERY)


# --- 10 retention --------------------------------------------------------------------------


class Retention(_Rec):
    stated_policy: list[Attribute[str]] = Field(default_factory=list)
    observed: list[Attribute[str]] = Field(default_factory=list)
    consistency: Attribute[Consistency] | None = None

    @model_validator(mode="after")
    def _claimed(self) -> Retention:
        for i, sp in enumerate(self.stated_policy):
            if sp.is_known() and sp.basis is not Basis.CLAIMED:
                raise ValueError(f"retention.stated_policy[{i}] is an operator statement: basis must be 'claimed'")
        return self


# --- 11 negative findings ---------------------------------------------------------------


class NegativeFinding(_Rec):
    location: Location
    finding: str
    reason: str | None = None
    implication: Attribute[str] | None = Field(default=None, description="What the absence means for an examiner.")
    facts: list[Fact] = Field(default_factory=list,
                              description="The facts this finding explains; empty means every fact absent from the location's column.")
    attr: Attribute[CellValue]

    @field_validator("attr")
    @classmethod
    def _absence(cls, v: Attribute[CellValue]) -> Attribute[CellValue]:
        if v.value is not None and v.value not in (CellValue.NOT_STORED_BY_DESIGN, CellValue.NOT_FOUND,
                                                   CellValue.NOT_TESTED, CellValue.NOT_APPLICABLE):
            raise ValueError("a negative finding records an absence: not_stored_by_design, not_found, not_tested or not_applicable")
        return v


# --- 12 indicators -----------------------------------------------------------------------


class Indicator(_Rec):
    kind: IndicatorKind
    value: Pattern | InvariantLiteral
    weight: float = Field(ge=0.0, le=1.0)
    attr: Attr


# --- 13 extensions ---------------------------------------------------------------------------


class Extension(_Rec):
    description: str
    attr: Attribute[Any]


# =========================================================================================


class ServiceEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    service: ServiceMeta
    observations: list[Observation] = Field(default_factory=list)
    identity: Identity = Field(default_factory=Identity)
    access: Access = Field(default_factory=Access)
    modes: list[Mode] = Field(default_factory=list)
    order_model: OrderModel = Field(default_factory=OrderModel)
    cookies: list[Cookie] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    status: Status = Field(default_factory=Status)
    receipts: list[Receipt] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    fact_coverage: list[MatrixRow] = Field(default_factory=list)
    retention: Retention = Field(default_factory=Retention)
    negative_findings: list[NegativeFinding] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    extensions: dict[str, Extension] = Field(default_factory=dict)

    # ---- validation --------------------------------------------------------------------

    @model_validator(mode="after")
    def _cross_refs(self) -> ServiceEntry:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"schema_version {self.schema_version!r} not supported (expected {SCHEMA_VERSION!r})")
        obs = {o.id: o for o in self.observations}
        if len(obs) != len(self.observations):
            raise ValueError("observation ids must be unique")
        _unique([e.id for e in self.endpoints], "endpoint")
        _unique([a.id for a in self.artifacts], "artifact")
        _unique([r.id for r in self.receipts], "receipt")
        _unique([m.id for m in self.modes], "mode")
        _unique([c.name for c in self.cookies], "cookie name")
        _unique([f.fact for f in self.fact_coverage], "fact_coverage fact")

        for path, attr in self.iter_attrs():
            missing = [s for s in attr.sources if s not in obs]
            if missing:
                raise ValueError(f"{path}: unknown observation id(s) {missing}")
            if attr.sources:
                top = max(obs[s].tier for s in attr.sources)
                if attr.tier > top:
                    raise ValueError(f"{path}: tier {int(attr.tier)} exceeds the highest tier ({int(top)}) of its sources")
            if attr.basis is Basis.CLAIMED and not any(
                obs[s].provenance_class is ProvenanceClass.OPERATOR_CLAIM for s in attr.sources
            ):
                raise ValueError(f"{path}: basis=claimed must cite an operator_claim observation")

        ep_ids = {e.id for e in self.endpoints}
        rc_ids = {r.id for r in self.receipts}
        art_ids = {a.id for a in self.artifacts}
        if self.status.endpoint_ref and self.status.endpoint_ref not in ep_ids:
            raise ValueError(f"status.endpoint_ref {self.status.endpoint_ref!r} is not an endpoint id")
        for r in self.receipts:
            ref = r.obtained_via.endpoint_ref
            if ref and ref not in ep_ids:
                raise ValueError(f"receipts[{r.id}].obtained_via.endpoint_ref {ref!r} is not an endpoint id")
            bad = [x for x in r.artifact_refs if x not in art_ids]
            if bad:
                raise ValueError(f"receipts[{r.id}].artifact_refs: unknown artifact id(s) {bad}")
        for a in self.artifacts:
            if a.produced_by and a.produced_by not in ep_ids and a.produced_by not in rc_ids \
                    and a.produced_by not in PRODUCED_BY_SPECIAL:
                raise ValueError(f"artifacts[{a.id}].produced_by {a.produced_by!r} is neither an endpoint / receipt id nor one of {PRODUCED_BY_SPECIAL}")
            if a.receipt_ref and a.receipt_ref not in rc_ids:
                raise ValueError(f"artifacts[{a.id}].receipt_ref {a.receipt_ref!r} is not a receipt id")
        for row in self.fact_coverage:
            bad = [x for x in row.artifacts if x not in art_ids]
            if bad:
                raise ValueError(f"fact_coverage[{row.fact.value}]: unknown artifact id(s) {bad}")
        scan_for_instance_data(self, "entry")
        return self

    # ---- introspection -------------------------------------------------------------------

    def iter_attrs(self) -> Iterator[tuple[str, Attr]]:
        yield from _walk(self, "")

    def known_attrs(self) -> list[tuple[str, Attr]]:
        return [(p, a) for p, a in self.iter_attrs() if a.is_known()]

    def unknown_attrs(self) -> list[str]:
        return [p for p, a in self.iter_attrs() if not a.is_known()]

    def coverage_by_tier(self) -> dict[int, int]:
        cov = {t.value: 0 for t in Tier}
        for _, a in self.known_attrs():
            cov[a.tier.value] += 1
        return cov

    def max_tier(self) -> Tier | None:
        tiers = [a.tier for _, a in self.known_attrs()]
        return max(tiers) if tiers else None

    def observation(self, obs_id: str) -> Observation:
        return next(o for o in self.observations if o.id == obs_id)

    def endpoint(self, ep_id: str) -> Endpoint:
        return next(e for e in self.endpoints if e.id == ep_id)

    def artifact(self, art_id: str) -> Artifact:
        return next(a for a in self.artifacts if a.id == art_id)

    def receipt(self, rc_id: str) -> Receipt:
        return next(r for r in self.receipts if r.id == rc_id)

    def matrix_row(self, fact: Fact | str) -> MatrixRow | None:
        fact = Fact(fact)
        return next((r for r in self.fact_coverage if r.fact is fact), None)

    def canonical_domain(self) -> str | None:
        return next((d.domain for d in self.identity.domains if d.role is DomainRole.CANONICAL), None)

    def order_id_regex(self) -> str | None:
        for ident in self.order_model.identifiers:
            if ident.fact is Fact.ORDER_ID and ident.scheme is not None:
                return ident.scheme.regex
        return None

    def content_templates_for(self, artifact: Artifact) -> list[Template]:
        """The artifact's own content templates plus those of the receipt it references."""
        out = list(artifact.content_templates)
        if artifact.receipt_ref:
            out += self.receipt(artifact.receipt_ref).structure.templates
        return out


def _unique(ids: list, what: str) -> None:
    seen = set()
    for i in ids:
        if i in seen:
            raise ValueError(f"duplicate {what} {i!r}")
        seen.add(i)


def _walk(obj: Any, path: str) -> Iterator[tuple[str, Attr]]:
    if isinstance(obj, Attr):
        yield path, obj
        return
    if isinstance(obj, (Pattern, Template, InvariantLiteral, Observation, Cell, Validity)):
        return
    if isinstance(obj, BaseModel):
        for name in type(obj).model_fields:
            yield from _walk(getattr(obj, name), f"{path}.{name}" if path else name)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
