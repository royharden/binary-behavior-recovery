"""One-task fixture source driver; no hidden scorer or host candidate execution."""
from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import json
from typing import Any, Callable, Mapping, Sequence, TYPE_CHECKING

from bbr.providers.mock import MockProvider, ModelConfig, ProviderError, canonical
from .baselines import VisiblePair, baseline_for_task, controls
from .interventions import (ArmArchive, InfrastructureUnknown, ProbeBroker,
                            Submission, run_interventions, validate_submission)
from .probes import RunnerProbeAdapter

if TYPE_CHECKING:
    from bbr.contracts import ExecutionLimits, VisibleTask
    from bbr.ledger import Ledger
    from bbr.runner import CandidateValidator, Runner


def run_fixture_task(
    visible_task: VisibleTask, *, campaign_id: str, artifact_sha256: str,
    evidence_json: bytes, fixed_batches: Sequence[Sequence[bytes]],
    fixture_records: Sequence[Mapping[str, Any]] | None = None,
    ledger: Ledger | None = None, model_config: ModelConfig = ModelConfig(),
    oracle: Runner | None = None, candidate: Runner | None = None,
    validator: CandidateValidator | None = None,
    candidate_ref: Callable[[Submission], str] | None = None,
    limits: ExecutionLimits | None = None,
    receipt_sink: Callable[[Mapping[str, Any]], None] | None = None,
    evidence_constants: Sequence[int] = (),
) -> dict[str, Any]:
    """Join existing producers on caller-supplied, admitted public inputs only.

    This function is written for later invocation, never run by Dirty builders.
    Supplied workers/registration remain trusted admission seams, not an isolation
    proof. A local task lock is never an ALL-final-campaign lock authorization.
    """
    from bbr.contracts import CandidateResponse, ExecutionLimits, VisibleTask
    from bbr.ledger import Ledger
    from bbr.providers.dispatch import FixtureDispatch
    from bbr.providers.mock import prepare_request
    from bbr.runner import CandidateValidator, Runner

    dispatch: FixtureDispatch | None = None
    builder_locks: dict[str, Mapping[str, Any]] = {}
    arm_locks: dict[str, Mapping[str, Any]] = {}
    baseline: dict[str, Any] | None = None
    current_phase = "public_input_validation"
    task_id: str | None = None
    fixed_digest: str | None = None

    def result(status: str, failure: Mapping[str, Any] | None) -> dict[str, Any]:
        # Canonical detachment also separates sink/caller-owned mutable containers.
        return json.loads(canonical({
            "status": status, "origin": "fixture", "scope": "one_task_source_driver",
            "campaign_id": campaign_id if type(campaign_id) is str else None, "task_id": task_id,
            "runtime_validation": "unverified", "hidden_scoring": "not_performed",
            "campaign_lock_authorization": "not_supplied_by_task_driver",
            "fixed_batches_sha256": fixed_digest, "baseline": baseline,
            "builder_locks": builder_locks, "arm_locks": arm_locks,
            "attempted_provider_calls": 0 if dispatch is None else len(dispatch.labels),
            "resource_receipts": [] if dispatch is None else list(dispatch.receipt_snapshots()),
            "failure": failure}))

    try:
        task = VisibleTask.model_validate(visible_task)
        task_id = task.task_id
        if type(campaign_id) is not str or not campaign_id.strip() or len(campaign_id) > 256:
            raise ValueError("bounded actual campaign ID required")
        if model_config.origin != "fixture" or model_config.endpoint_id != "offline":
            raise ValueError("one-task source driver admits offline fixtures only")
        # Bind the full producer envelope even on the unavailable default path.
        prepare_request(task, (), model_config, evidence_json=evidence_json,
                        artifact_sha256=artifact_sha256)
        if fixture_records is None or not fixture_records:
            return result("unavailable", {"phase": current_phase,
                "reason": "admitted_public_scripted_fixtures_unavailable"})
        provider = MockProvider(fixture_records)
        missing = [name for name, value in (("ledger", ledger), ("oracle", oracle),
            ("candidate", candidate), ("validator", validator),
            ("candidate_registration", candidate_ref), ("execution_limits", limits)) if value is None]
        if missing:
            return result("unavailable", {"phase": "admitted_backend_preflight",
                "reason": "explicit_admitted_dependencies_required", "missing": missing})
        if (not isinstance(ledger, Ledger) or not isinstance(oracle, Runner)
                or not isinstance(candidate, Runner) or not isinstance(validator, CandidateValidator)):
            raise ValueError("shared Ledger/Runner/CandidateValidator producers required")
        if not callable(candidate_ref) or (receipt_sink is not None and not callable(receipt_sink)):
            raise ValueError("registration/sink must be explicit callables")
        if oracle is candidate or oracle.policy.worker_kind != "oracle" or candidate.policy.worker_kind != "candidate":
            raise ValueError("distinct oracle/candidate worker roles required")
        if oracle.backend is None or candidate.backend is None or validator.backend is None:
            return result("unavailable", {"phase": "admitted_backend_preflight",
                "reason": "isolated_backend_unavailable"})
        if oracle.backend is candidate.backend:
            raise ValueError("oracle/candidate backend instances must be separate")
        checked_limits = ExecutionLimits.model_validate(limits)
        if validator.policy != candidate.policy or validator.limits != checked_limits:
            raise ValueError("validator policy/limits differ from candidate execution")

        adapter = RunnerProbeAdapter(artifact_sha256, oracle=oracle, candidate=candidate,
                                     limits=checked_limits, candidate_ref=candidate_ref)
        broker = ProbeBroker.for_task(task, fixed_batches, adapter)
        fixed_digest = sha256(canonical([[raw.hex() for raw in batch]
                                        for batch in broker.fixed])).hexdigest()
        dispatch = FixtureDispatch(task.task_id, task, provider, ledger, model_config,
            campaign_id=campaign_id, evidence_json=evidence_json,
            artifact_sha256=artifact_sha256, receipt_sink=receipt_sink)

        current_phase = "baseline_and_control_source"
        found = baseline_for_task(task, evidence_constants=evidence_constants)
        baseline = asdict(found)
        pairs = tuple(VisiblePair(row.stdin_bytes, row.stdout_bytes, row.exit_code)
                      for row in task.examples)
        source_controls = controls(pairs)
        source_responses = {"S": CandidateResponse(code=found.code) if found.code is not None
                            else CandidateResponse(abstain=True, hypothesis=found.status)}
        source_responses.update({"control:" + name: CandidateResponse(code=code)
                                 for name, code in source_controls.items()})
        for arm, response in source_responses.items():
            current_phase = "isolated_validation:" + arm
            submission = validate_submission(response, arm + ":0", validator)
            builder_locks[arm] = ArmArchive(arm, [submission]).lock_snapshot()

        current_phase = "fixture_interventions"

        def retained_dispatch(label: str, history: Sequence[Mapping[str, Any]]) -> Any:
            try:
                return dispatch(label, history)
            except ProviderError:
                # Only explicit producer refusals enter the controller's parse-fail
                # path. Generic ValueError/TypeError may be pre-dispatch faults.
                raise
            except Exception as exc:
                # Convert transport/ledger/config/sink faults to the controller's
                # existing partial-lock receipt path, without an implicit retry.
                raise InfrastructureUnknown(label, "fixture_dispatch_infrastructure_unknown",
                                            origin="fixture") from exc

        arm_locks = run_interventions(retained_dispatch,
            lambda response, label: validate_submission(response, label, validator), broker)
        return result("fixture_candidates_locked", None)
    except InfrastructureUnknown as exc:
        arm_locks = dict(exc.snapshot()["archive_snapshots"])
        return result("infrastructure_unknown", {"phase": current_phase,
                                                "receipt": exc.snapshot()})
    except (ValueError, TypeError) as exc:
        return result("refused", {"phase": current_phase, "reason": type(exc).__name__})
    except Exception as exc:
        return result("infrastructure_unknown", {"phase": current_phase,
                                                "reason": type(exc).__name__})
