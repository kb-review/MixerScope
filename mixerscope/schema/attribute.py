"""§A Attribute wrapper and §P typed values (Pattern, Template, InvariantLiteral, Cell)."""

from __future__ import annotations

import re
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .guards import assert_no_instance_data
from .vocab import Basis, CellValue, Fact, Tier, ValidityStatus, expand_placeholders, unknown_placeholders

T = TypeVar("T")

_MONTH_OR_DATE = re.compile(r"^\d{4}-\d{2}(?:-\d{2})?$")


class Pattern(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    regex: str = Field(description="Regular expression; may use <placeholders> from §P.")
    describes: Fact | None = Field(default=None, description="The fact this pattern matches, if any.")

    @model_validator(mode="after")
    def _compiles(self) -> Pattern:
        bad = unknown_placeholders(self.regex)
        if bad:
            raise ValueError(f"unknown placeholder(s) {bad} in pattern")
        try:
            re.compile(expand_placeholders(self.regex))
        except re.error as e:
            raise ValueError(f"not a valid regular expression: {e}") from e
        return self

    def compile(self, *, order_id_regex: str | None = None) -> re.Pattern[str]:
        return re.compile(expand_placeholders(self.regex, order_id_regex=order_id_regex))


class InvariantLiteral(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    literal: str
    justification: str = Field(min_length=10, description="Why this is service-level, not instance data.")


class Template(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(description="Literal response / document text with <placeholders> for instance values.")
    yields: list[Fact] = Field(default_factory=list, description="Facts carried by the fact-bearing placeholders, in order.")
    literals: list[InvariantLiteral] = Field(
        default_factory=list,
        description="Service-level literals that occur verbatim in the text (e.g. a signing address).",
    )

    @model_validator(mode="after")
    def _check(self) -> Template:
        bad = unknown_placeholders(self.text)
        if bad:
            raise ValueError(f"unknown placeholder(s) {bad} in template")
        masked = self.text
        for lit in self.literals:
            if lit.literal not in self.text:
                raise ValueError(f"declared literal {lit.literal[:12]!r}... does not occur in the template text")
            masked = masked.replace(lit.literal, "<literal>")
        assert_no_instance_data(masked, "template.text")
        return self

    def to_regex(self, *, order_id_regex: str | None = None, anchored: bool = False) -> str:
        from .vocab import template_to_regex

        return template_to_regex(self.text, order_id_regex=order_id_regex, anchored=anchored)

    def compile(self, *, order_id_regex: str | None = None) -> re.Pattern[str]:
        return re.compile(self.to_regex(order_id_regex=order_id_regex))


class Validity(BaseModel):
    """When a value was true. Front ends change: a superseded record is kept and dated."""

    model_config = ConfigDict(extra="forbid")

    first_seen: str | None = Field(default=None, description="YYYY-MM or YYYY-MM-DD")
    last_seen: str | None = Field(default=None, description="YYYY-MM or YYYY-MM-DD")
    status: ValidityStatus = ValidityStatus.CURRENT
    superseded_by: str | None = Field(default=None, description="Path of the record that replaces this one.")

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _month(cls, v: str | None) -> str | None:
        if v is not None and not _MONTH_OR_DATE.match(v):
            raise ValueError("use YYYY-MM or YYYY-MM-DD")
        return v


class Attr(BaseModel):
    """Provenance block carried by every fact and every record."""

    model_config = ConfigDict(extra="forbid")

    tier: Tier = Field(description="Lowest tier that establishes this.")
    basis: Basis
    sources: list[str] = Field(default_factory=list, description="Observation ids (§S); required unless unknown.")
    validity: Validity | None = None
    notes: str | None = None

    @model_validator(mode="after")
    def _sources_rule(self) -> Attr:
        if self.basis is Basis.UNKNOWN:
            if self.sources:
                raise ValueError("basis=unknown must not cite sources; set observed/inferred/claimed instead")
        elif not self.sources:
            raise ValueError(f"basis={self.basis.value!r} requires at least one source observation id")
        if self.notes:
            assert_no_instance_data(self.notes, "notes")
        return self

    def is_known(self) -> bool:
        return self.basis is not Basis.UNKNOWN


class Attribute(Attr, Generic[T]):
    """A typed fact: value + provenance."""

    value: T | None = None

    @model_validator(mode="after")
    def _value_rule(self) -> Attribute[T]:
        if self.basis is Basis.UNKNOWN:
            if self.value is not None:
                raise ValueError("basis=unknown requires value to be null")
        elif self.value is None:
            raise ValueError(f"basis={self.basis.value!r} requires a value")
        scan_for_instance_data(self.value, "value")
        return self

    @classmethod
    def unknown(cls, tier: Tier | int, notes: str | None = None) -> Attribute[T]:
        return cls(tier=Tier(tier), basis=Basis.UNKNOWN, notes=notes)


class Cell(BaseModel):
    """One cell of the fact-by-source matrix. In YAML a cell is written as a string:
    `recovered`, or `recovered: letter body` (value, colon, free-text detail)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    value: CellValue
    detail: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _from_string(cls, data: Any) -> Any:
        if isinstance(data, str):
            head, sep, tail = data.partition(":")
            return {"value": head.strip(), "detail": tail.strip() or None} if sep else {"value": data.strip()}
        return data

    @model_validator(mode="after")
    def _guard(self) -> Cell:
        if self.detail:
            assert_no_instance_data(self.detail, "cell.detail")
        return self

    def __str__(self) -> str:
        return f"{self.value.value}: {self.detail}" if self.detail else self.value.value


def scan_for_instance_data(obj: Any, path: str) -> None:
    """Instance guard that understands the typed values: Pattern regexes and literals are
    exempt, Template text is scanned on construction, everything else is walked."""
    if obj is None:
        return
    if isinstance(obj, (Pattern, InvariantLiteral, Template, Cell)):
        return
    if isinstance(obj, BaseModel):
        for name in type(obj).model_fields:
            scan_for_instance_data(getattr(obj, name), f"{path}.{name}")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            scan_for_instance_data(k, f"{path}.{k}")
            scan_for_instance_data(v, f"{path}.{k}")
        return
    if isinstance(obj, (list, tuple, set)):
        for i, v in enumerate(obj):
            scan_for_instance_data(v, f"{path}[{i}]")
        return
    if isinstance(obj, str):
        assert_no_instance_data(obj, path)
