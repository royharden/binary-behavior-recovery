"""One-task fixture driver composition for later authorized activation.

Configuration is inert public data. It cannot select/import a backend, callback,
worker class or hidden scorer. The ordinary CLI supplies no dependencies and the
producer therefore returns unavailable with zero dispatch. Dirty builders do not
invoke this module's source functions.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping

from bbr.report.archive import canonical, safe_file
from .journey import _closed, _extract, _json

if TYPE_CHECKING:
    from bbr.arms import Submission
    from bbr.ledger import Ledger
    from bbr.runner import CandidateValidator, Runner


@dataclass(frozen=True)
class FixtureDependencies:
    """Trusted caller-owned producer objects; never constructed from config."""

    ledger: Ledger | None = None
    oracle: Runner | None = None
    candidate: Runner | None = None
    validator: CandidateValidator | None = None
    candidate_ref: Callable[[Submission], str] | None = None
    receipt_sink: Callable[[Mapping[str, Any]], None] | None = None


def _fixed_batches(raw: Any, public_pool: tuple[bytes, ...]) -> tuple[tuple[bytes, ...], ...]:
    if not isinstance(raw, list) or len(raw) != 3:
        raise ValueError("exactly three precommitted public fixed batches required")
    batches = []
    for batch in raw:
        if not isinstance(batch, list) or len(batch) != 8:
            raise ValueError("each fixed batch requires exactly eight public inputs")
        values = []
        for value in batch:
            if not isinstance(value, str) or len(value) > 128:
                raise ValueError("bounded canonical hex fixed input required")
            item = bytes.fromhex(value)
            if item.hex() != value or item not in public_pool:
                raise ValueError("fixed feedback input is noncanonical or outside public pool")
            values.append(item)
        batches.append(tuple(values))
    return tuple(batches)


def _fixture_records(root: Path, descriptor: Any) -> list[dict] | None:
    if descriptor is None:
        return None
    raw = _closed(descriptor, {"path", "sha256"})
    from bbr.runner.policy import require_digest

    require_digest(raw["sha256"])
    if not isinstance(raw["path"], str):
        raise ValueError("relative authored public fixture path required")
    source = safe_file(root, raw["path"])
    if source.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("authored public fixture file exceeds producer 4 MiB ceiling")
    with source.open("rb") as stream:
        content = stream.read(4 * 1024 * 1024 + 1)
    if len(content) > 4 * 1024 * 1024 or sha256(content).hexdigest() != raw["sha256"]:
        raise ValueError("authored public fixture bytes differ from expected file commitment")
    # The existing bounded, duplicate-key/nonfinite-refusing parser is reused.
    records = _json(source)
    if (not isinstance(records, list) or not 1 <= len(records) <= 7
            or any(not isinstance(record, dict) for record in records)):
        raise ValueError("one through seven actual authored fixture records required")
    # A concurrent change cannot silently bind different parsed fixture bytes.
    with source.open("rb") as stream:
        after = stream.read(4 * 1024 * 1024 + 1)
    if after != content:
        raise ValueError("authored public fixture file changed while reading")
    return records


def run_journey(config_path: Path, selected_arm: str, *,
                dependencies: FixtureDependencies | None = None) -> tuple[dict, int]:
    """Forward actual public source and explicit dependencies to the sole driver.

    `selected_arm` labels the requested view; the producer retains the complete
    S/control/M/R/P one-task journey. Its local candidate locks never authorize
    hidden scoring or stand in for all-campaign final locks.
    """
    from bbr.arms.fixture_journey import run_fixture_task
    from bbr.contracts import ExecutionLimits, VisibleTask
    from bbr.evidence import PublicEvidenceEnvelope
    from bbr.providers.mock import ModelConfig

    if selected_arm not in {"S", "M", "R", "P"}:
        raise ValueError("unknown selected fixture arm")
    if dependencies is not None and not isinstance(dependencies, FixtureDependencies):
        raise ValueError("trusted FixtureDependencies composition required")
    raw = _closed(_json(config_path), {"schema", "origin", "campaign_id", "artifact",
        "artifact_sha256", "visible_task", "fixed_batches", "limits", "fixture_records",
        "model_config"})
    if raw["schema"] != "bbr.fixture-journey.v1" or raw["origin"] != "fixture":
        raise ValueError("only closed one-task public fixture journey config is accepted")
    if (not isinstance(raw["campaign_id"], str) or not raw["campaign_id"].strip()
            or len(raw["campaign_id"]) > 256):
        raise ValueError("actual bounded campaign ID required")
    if not isinstance(raw["artifact"], str):
        raise ValueError("artifact must be a relative public source path")
    artifact = safe_file(config_path.parent, raw["artifact"])
    bundle = _extract(artifact, raw["artifact_sha256"])
    task = VisibleTask.model_validate_json(canonical(raw["visible_task"]))
    envelope = PublicEvidenceEnvelope.from_bundle(bundle,
        expected_artifact_sha256=raw["artifact_sha256"])
    envelope.validate_for(artifact_sha256=raw["artifact_sha256"],
                          evidence_sha256=task.evidence_sha256)
    fixed = _fixed_batches(raw["fixed_batches"], task.probe_inputs)
    limits = ExecutionLimits.model_validate_json(canonical(raw["limits"]))
    fixtures = _fixture_records(config_path.parent, raw["fixture_records"])
    config = ModelConfig()
    if raw["model_config"] is not None:
        supplied = _closed(raw["model_config"],
            {"model_id", "config_id", "endpoint_id", "seed", "origin"})
        if (any(not isinstance(supplied[name], str) or not supplied[name].strip()
                or len(supplied[name]) > 256 for name in ("model_id", "config_id", "endpoint_id"))
                or type(supplied["seed"]) is not int
                or supplied["origin"] != "fixture" or supplied["endpoint_id"] != "offline"):
            raise ValueError("exact offline fixture model/config identity required")
        config = ModelConfig(**supplied)
    services = FixtureDependencies() if dependencies is None else dependencies
    result = run_fixture_task(task, campaign_id=raw["campaign_id"],
        artifact_sha256=raw["artifact_sha256"], evidence_json=envelope.canonical_json(),
        fixed_batches=fixed, fixture_records=fixtures, ledger=services.ledger,
        model_config=config, oracle=services.oracle, candidate=services.candidate,
        validator=services.validator, candidate_ref=services.candidate_ref,
        limits=limits, receipt_sink=services.receipt_sink)
    detached = json.loads(canonical(result))
    if (not isinstance(detached, dict)
            or detached.get("status") not in {"unavailable", "refused", "infrastructure_unknown",
                                               "fixture_candidates_locked"}
            or detached.get("origin") != "fixture"
            or detached.get("campaign_id") != raw["campaign_id"]
            or detached.get("task_id") != task.task_id
            or detached.get("scope") != "one_task_source_driver"
            or detached.get("runtime_validation") != "unverified"
            or detached.get("hidden_scoring") != "not_performed"
            or detached.get("campaign_lock_authorization") != "not_supplied_by_task_driver"
            or type(detached.get("attempted_provider_calls")) is not int
            or not 0 <= detached["attempted_provider_calls"] <= 7):
        raise ValueError("fixture source driver returned an incompatible provenance/result")
    if dependencies is None and (detached["attempted_provider_calls"] != 0
                                 or detached["status"] == "fixture_candidates_locked"):
        raise ValueError("ordinary CLI without admitted dependencies cannot dispatch or lock candidates")
    return {"origin": "fixture", "scope": "one_task_fixture",
            "selected_arm": selected_arm,
            "selection_semantics": "view label only; complete S/controls/M/R/P source journey retained",
            "driver": detached, "runtime_validation": "unverified",
            "hidden_scoring": "not_performed",
            "campaign_lock_authorization": "not_supplied_by_task_driver"}, (
                0 if detached["status"] == "fixture_candidates_locked" else 2)
