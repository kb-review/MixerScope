"""Knowledge base: YAML seed entries (source of truth) and the SQLite build/loader."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import yaml

from mixerscope.schema import ServiceEntry

SERVICES_DIR = Path(__file__).parent / "services"


def load_service_yaml(path: Path | str) -> ServiceEntry:
    """Parse and validate one seed file. Raises pydantic.ValidationError on any violation,
    including instance data in an invariant field or a dangling observation id."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    for key in [k for k in raw if str(k).startswith("_")]:
        raw.pop(key)  # authoring helpers (YAML anchors etc.)
    return ServiceEntry.model_validate(raw)


def iter_seed_paths(services_dir: Path | str = SERVICES_DIR) -> Iterator[Path]:
    yield from sorted(Path(services_dir).glob("*.yaml"))


def load_all_seeds(services_dir: Path | str = SERVICES_DIR) -> dict[str, ServiceEntry]:
    """Load every seed file; keys are service ids. Duplicate ids are an error."""
    out: dict[str, ServiceEntry] = {}
    for p in iter_seed_paths(services_dir):
        entry = load_service_yaml(p)
        if entry.service.id in out:
            raise ValueError(f"duplicate service id {entry.service.id!r} in {p}")
        out[entry.service.id] = entry
    return out
