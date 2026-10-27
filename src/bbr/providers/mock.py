"""Public fixture replay binds the complete request, never a task-name fallback."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


class ProviderError(ValueError):
    """A refused request is retained as a failed attempt by its controller."""


@dataclass(frozen=True)
class ModelConfig:
    model_id: str = "scripted-public-v1"
    config_id: str = "fixture-v1"
    endpoint_id: str = "offline"
    seed: int = 0
    origin: str = "fixture"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def request_digest(request: Mapping[str, Any]) -> str:
    return sha256(canonical(request)).hexdigest()


def prepare_request(visible_task: Any, history: Sequence[Mapping[str, Any]],
                    model_config: ModelConfig) -> dict[str, Any]:
    from bbr.contracts import VisibleTask

    task = VisibleTask.model_validate(visible_task)
    if any(len(row.stdin_bytes) > 64 or len(row.stdout_bytes) > 4096 for row in task.examples):
        raise ProviderError("visible examples exceed public I/O caps")
    return {"visible_task": task.model_dump(mode="json"),
            "history": list(history), "model_config": asdict(model_config)}


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProviderError("duplicate JSON key")
        result[key] = value
    return result


class MockProvider:
    """Each fixture stores request, SHA256, response and explicit zero-cost usage.

    No generated code is parsed, imported or executed on the host. Structural
    response validation belongs to CandidateResponse; syntax/import diagnostics
    must come from the isolated candidate validator supplied to the controller.
    """

    def __init__(self, fixtures: Sequence[Mapping[str, Any]]):
        self._fixtures: dict[str, dict[str, Any]] = {}
        for supplied in fixtures:
            row = json.loads(canonical(supplied), object_pairs_hook=_closed_object)
            if set(row) != {"request", "request_sha256", "response", "usage", "origin"}:
                raise ProviderError("fixture fields differ from closed schema")
            digest = request_digest(row["request"])
            if digest != row["request_sha256"] or digest in self._fixtures:
                raise ProviderError("fixture digest mismatch or duplicate")
            if row["origin"] != "fixture" or row["usage"] != {
                "input_tokens": 0, "output_tokens": 0, "usd": "0"
            } or any(type(row["usage"].get(key)) is not int
                     for key in ("input_tokens", "output_tokens")):
                raise ProviderError("scripted fixtures require explicit zero-cost lineage")
            self._fixtures[digest] = row

    @classmethod
    def from_file(cls, path: Path) -> MockProvider:
        if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
            raise ProviderError("invalid public fixture file")
        rows = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_closed_object)
        if not isinstance(rows, list):
            raise ProviderError("fixture root must be an array")
        return cls(rows)

    def propose(self, visible_task: Any, history: Sequence[Mapping[str, Any]],
                model_config: ModelConfig, reservation: Any) -> Any:
        from bbr.contracts import CandidateResponse

        if model_config.origin != "fixture" or model_config.endpoint_id != "offline":
            raise ProviderError("live adapters disabled pending Roy and preflight")
        request = prepare_request(visible_task, history, model_config)
        digest = request_digest(request)
        # Reservation is supplied by the caller after durable reserve. Request
        # identity cannot be substituted by a task ID or a fuzzy fixture match.
        reserved_digest = (reservation.get("request_sha256") if isinstance(reservation, Mapping)
                           else getattr(reservation, "request_sha256", None))
        if reserved_digest != digest:
            raise ProviderError("reservation does not bind exact request")
        row = self._fixtures.get(digest)
        if row is None or canonical(row["request"]) != canonical(request):
            raise ProviderError("no exact public scripted request")
        try:
            response = CandidateResponse.model_validate_json(canonical(row["response"]))
        except (ValueError, TypeError) as exc:
            raise ProviderError("fixture response schema invalid") from exc
        code = getattr(response, "code", None)
        if code is not None and len(code.encode("utf-8")) > 32768:
            raise ProviderError("candidate source exceeds 32 KiB")
        return response


def live_provider(*_args: Any, **_kwargs: Any) -> None:
    raise ProviderError("live_not_run: adapters disabled; no credentials or SDKs loaded")
