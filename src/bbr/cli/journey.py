"""CLI adapters for retained source data, not a candidate execution backend.

Imports are lazy so report verification needs neither compiler nor provider SDK.
No path in this module imports/compiles candidate source or launches a process.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any

from bbr.report.archive import canonical, read_json, safe_file


def _json(path: Path) -> Any:
    return read_json(safe_file(path.parent, path.name))


def _closed(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("unknown/missing input fields")
    return value


def corpus_build(spec_dir: Path, pin_path: Path) -> tuple[dict, int]:
    from bbr.build import ToolchainPin, build_plan
    from bbr.corpus import load_spec

    pin = ToolchainPin.model_validate_json(canonical(_json(pin_path)))
    paths = sorted(spec_dir.glob("*.yaml"))
    if len(paths) != 8:
        raise ValueError("exactly eight dev specification files required")
    specs = tuple(load_spec(safe_file(spec_dir, path.name)) for path in paths)
    schedule = build_plan(specs, pin)
    return {"status": "build_schedule_planned", "scheduled": len(schedule),
            "cells": [cell.model_dump(mode="json") for cell in schedule],
            "toolchain_pin": pin.model_dump(mode="json"),
            "compiled": False, "admission": "pending_independent_receipts",
            "runtime_validation": "unverified"}, 0


def corpus_gate(receipts_path: Path) -> tuple[dict, int]:
    from bbr.build import ValidityReceipt, validate_instance
    from bbr.contracts import BuildArtifact, FamilySpec

    raw = _closed(_json(receipts_path), {"schema", "spec", "artifacts", "receipts"})
    if raw["schema"] != "bbr.instance-receipts.v1":
        raise ValueError("unsupported instance receipt schema")
    if not isinstance(raw["artifacts"], list) or not isinstance(raw["receipts"], list):
        raise ValueError("artifact/receipt arrays required")
    if len(raw["artifacts"]) > 12 or len(raw["receipts"]) > 12:
        raise ValueError("one complete twelve-variant instance only")
    spec = FamilySpec.model_validate_json(canonical(raw["spec"]))
    artifacts = tuple(BuildArtifact.model_validate_json(canonical(a)) for a in raw["artifacts"])
    receipts = tuple(ValidityReceipt.model_validate_json(canonical(r)) for r in raw["receipts"])
    verdict = validate_instance(spec, artifacts, receipts)
    return {"status": "retained_receipt_consistency", "verdict": verdict.model_dump(mode="json"),
            "fresh_execution": False, "independent_admission": "pending_authenticity_verification",
            "runtime_validation": "unverified"}, 0 if verdict.status == "accepted" else 2


def _extract(path: Path, expected_sha256: str):
    from bbr.evidence import EvidenceLimits, extract
    from bbr.runner.policy import require_digest

    require_digest(expected_sha256)
    safe = safe_file(path.parent, path.name)
    with safe.open("rb") as stream:
        raw = stream.read(EvidenceLimits().max_artifact_bytes + 1)
    if len(raw) > EvidenceLimits().max_artifact_bytes:
        raise ValueError("artifact exceeds extractor cap")
    if sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("artifact differs from trusted expected digest")
    bundle = extract(raw)
    if bundle.artifact_sha256 != expected_sha256:
        raise ValueError("extractor artifact identity differs")
    return bundle


def evidence(path: Path, expected_sha256: str) -> tuple[dict, int]:
    from bbr.evidence import PublicEvidenceEnvelope

    bundle = _extract(path, expected_sha256)
    envelope = PublicEvidenceEnvelope.from_bundle(bundle,
        expected_artifact_sha256=expected_sha256)
    envelope.validate_for(artifact_sha256=expected_sha256, evidence_sha256=bundle.digest())
    return {"status": "static_evidence_extracted", "evidence_sha256": bundle.digest(),
            "public_evidence": envelope.to_dict(),
            "evidence_bytes": len(bundle.canonical_json()),
            "envelope_bytes": len(envelope.canonical_json()),
            "fresh_execution": False, "runtime_validation": "unverified"}, 0


def replay_retained(path: Path, expected_record_sha256: str) -> tuple[dict, int]:
    from bbr.replay import load_record, verify_record

    record = load_record(path.parent, path.name,
                         expected_record_sha256=expected_record_sha256)
    bundle = verify_record(record, expected_record_sha256=expected_record_sha256)
    # Do not self-authorize a fresh sandbox from retained configuration. Later
    # deployment may call bbr.replay.replay with separately admitted workers.
    return {"status": "pending_isolated_replay", "retained_consistency": "verified",
            "record_sha256": expected_record_sha256,
            "artifact_sha256": bundle.artifact_sha256,
            "candidate_sha256": bundle.candidate_sha256,
            "reduced_input_hex": bundle.reduced.stdin_bytes.hex(),
            "retained_pair": bundle.reduced.outcome.model_dump(mode="json"),
            "fresh_execution": False, "runtime_validation": "unverified",
            "reason": "No independently admitted isolated worker backend is configured."}, 2


def ledger_report(path: Path) -> tuple[dict, int]:
    """Delegate accounting and the 64 MiB existing-DB bound to its sole producer."""
    import sqlite3
    from bbr.ledger import BudgetStop, read_report

    try:
        snapshot = read_report(path)
    except (BudgetStop, sqlite3.Error, OSError, ValueError) as error:
        return {"status": "refused", "command": "ledger report", "reason": str(error),
                "runtime_validation": "unverified"}, 2
    return {"status": "retained_ledger_snapshot", "ledger": snapshot,
            "read_only": True, "runtime_validation": "unverified"}, 0


def fixture_preflight(config_path: Path, arm: str) -> tuple[dict, int]:
    """Trace public source inputs and real fail-closed worker ports.

    This preflight prepares an exact offline request but never dispatches it.
    Independent admission and configured isolated workers remain prerequisites.
    Config data cannot nominate a Python module, backend or executable callback.
    """
    from bbr.contracts import ExecutionLimits, VisibleTask
    from bbr.evidence import PublicEvidenceEnvelope
    from bbr.providers.mock import ModelConfig, prepare_request, request_digest
    from bbr.runner import CandidateValidator, Runner, SandboxPolicy

    raw = _closed(_json(config_path), {"schema", "origin", "artifact", "artifact_sha256",
        "visible_task", "candidate_source", "image_sha256", "toolchain_sha256", "limits"})
    if raw["schema"] != "bbr.fixture-preflight.v1" or raw["origin"] != "fixture":
        raise ValueError("only closed public fixture preflight configuration is accepted")
    if arm not in {"S", "M", "R", "P"}:
        raise ValueError("unknown arm")
    if not isinstance(raw["artifact"], str):
        raise ValueError("artifact must be relative to configuration directory")
    artifact = safe_file(config_path.parent, raw["artifact"])
    bundle = _extract(artifact, raw["artifact_sha256"])
    task = VisibleTask.model_validate_json(canonical(raw["visible_task"]))
    if task.evidence_sha256 != bundle.digest():
        raise ValueError("visible task does not bind full canonical evidence")
    envelope = PublicEvidenceEnvelope.from_bundle(bundle,
        expected_artifact_sha256=raw["artifact_sha256"])
    envelope.validate_for(artifact_sha256=raw["artifact_sha256"],
                          evidence_sha256=task.evidence_sha256)
    request = prepare_request(task, (), ModelConfig(),
        evidence_json=envelope.canonical_json(), artifact_sha256=raw["artifact_sha256"])
    limits = ExecutionLimits.model_validate_json(canonical(raw["limits"]))
    oracle_policy = SandboxPolicy(raw["image_sha256"], raw["toolchain_sha256"], worker_kind="oracle")
    candidate_policy = SandboxPolicy(raw["image_sha256"], raw["toolchain_sha256"], worker_kind="candidate")
    source = raw["candidate_source"]
    if not isinstance(source, str):
        raise ValueError("candidate_source must be inert UTF-8 source text")
    valid, diagnostic = CandidateValidator(candidate_policy, limits, backend=None)(source)
    # This exact Runner has no backend, so it can only return infrastructure
    # unknown; it cannot launch an oracle or consult hidden/source assets.
    unavailable = Runner(oracle_policy, backend=None).execute(
        bundle.artifact_sha256, task.examples[0].stdin_bytes, limits)
    return {"status": "preflight_blocked", "origin": "fixture", "arm": arm,
            "live_status": "not_run", "runtime_validation": "unverified",
            "evidence_sha256": bundle.digest(), "evidence_bytes": len(bundle.canonical_json()),
            "public_evidence": envelope.to_dict(),
            "envelope_bytes": len(envelope.canonical_json()),
            "visible_task_id": task.task_id, "visible_pairs": len(task.examples),
            "public_probe_inputs": len(task.probe_inputs),
            "candidate_validation": {"valid": valid, "diagnostic": diagnostic,
                "status": "infrastructure_error" if valid is None else "subject_checked_failure"},
            "runner": unavailable.model_dump(mode="json"),
            "provider_module_integrated": True, "provider_dispatched": False,
            "prepared_request_sha256": request_digest(request),
            "prepared_request_bytes": len(canonical(request)),
            "pending": ["independent admission and custody authenticity",
                "admitted isolated candidate/oracle backends",
                "verified pre-dispatch leak/token controls"],
            "reason": "Exact offline request prepared; no provider dispatch or subject execution initiated."}, 2
