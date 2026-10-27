"""Load closed JSON-form YAML dev specifications without executing source."""

import json
from pathlib import Path

from bbr.contracts import FamilySpec
from .families import family_spec
from .render import render


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate specification key")
        result[key] = value
    return result


def load_spec(path: str | Path) -> FamilySpec:
    """Accept the repository's bounded JSON subset of YAML, not arbitrary YAML."""
    source = Path(path)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 16384:
        raise ValueError("invalid or oversized family specification")
    data = json.loads(source.read_text(encoding="utf-8"), object_pairs_hook=_unique)
    spec = FamilySpec.model_validate(data)
    if spec != family_spec(spec.family_id):
        raise ValueError("specification differs from original dev definition")
    return spec


def render_spec(spec: FamilySpec, codec: str) -> str:
    if spec != family_spec(spec.family_id):
        raise ValueError("unrecognized dev family specification")
    return render(spec.family_id, codec)
