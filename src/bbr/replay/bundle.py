"""Closed replay envelope around shared ReplayBundle; integrity is not authority.

Callers obtain expected_record_sha256 from a separately trusted run manifest.
Recomputing an embedded digest alone cannot authenticate modified evidence.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import stat
from typing import TYPE_CHECKING, Any

from bbr.differential.compare import COMPARATOR_VERSION, compare, compare_observations
from bbr.runner.policy import require_digest

if TYPE_CHECKING:
    from bbr.contracts import ExecutionLimits, PairOutcome, ReplayBundle
    from bbr.runner import Runner
    from bbr.shrink import ShrinkResult

_KEYS = {"bundle", "image_sha256", "argv", "environment", "comparator_version",
         "move_policy", "minimality_status", "trace", "record_sha256"}
_MINIMALITY = {"one_minimal_under_moves": "locally_minimal",
               "reduced_budget_limited": "budget_exhausted",
               "shrink_exhausted": "not_shrunk"}
_MAX_RECORD_BYTES = 32 * 1024 * 1024  # Nested + envelope 256-pair hex traces plus metadata


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def execution_contract(runner: Runner, limits: ExecutionLimits) -> str:
    """Pin all declared worker controls, argv/env and limits, not just image."""
    from dataclasses import asdict
    return sha256(_canonical({"policy": asdict(runner.policy),
                              "argv": runner.argv, "environment": runner.environment,
                              "limits": limits.model_dump(mode="json")})).hexdigest()


def make_record(result: ShrinkResult, *, artifact_sha256: str,
                candidate_sha256: str, oracle: Runner, candidate: Runner,
                limits: ExecutionLimits) -> dict[str, Any]:
    from bbr.contracts import Counterexample, ReplayBundle

    if oracle.policy.worker_kind != "oracle" or candidate.policy.worker_kind != "candidate":
        raise ValueError("worker roles must be separated")
    if (oracle.policy.image_sha256 != candidate.policy.image_sha256
            or oracle.policy.toolchain_sha256 != candidate.policy.toolchain_sha256
            or oracle.argv != candidate.argv or oracle.environment != candidate.environment):
        raise ValueError("v1 replay requires common image/toolchain/argv/environment")
    trace = tuple(Counterexample(stdin_bytes=raw, outcome=outcome,
                                 input_sha256=sha256(raw).hexdigest())
                  for raw, outcome in result.trace)
    bundle = ReplayBundle(artifact_sha256=require_digest(artifact_sha256),
                          candidate_sha256=require_digest(candidate_sha256),
                          execution_contract_sha256=sha256(_canonical([
                              execution_contract(oracle, limits),
                              execution_contract(candidate, limits)])).hexdigest(),
                          toolchain_sha256=oracle.policy.toolchain_sha256,
                          original=Counterexample(stdin_bytes=result.original,
                              outcome=result.original_outcome,
                              input_sha256=sha256(result.original).hexdigest()),
                          reduced=Counterexample(stdin_bytes=result.reduced,
                              outcome=result.reduced_outcome,
                              input_sha256=sha256(result.reduced).hexdigest()),
                          attempts=result.paired_executions,
                          minimality=_MINIMALITY[result.status], limits=limits,
                          image_sha256=oracle.policy.image_sha256,
                          argv=oracle.argv, environment=oracle.environment,
                          comparator_version=COMPARATOR_VERSION,
                          move_policy=result.move_policy, trace=trace)
    body = {"bundle": bundle.model_dump(mode="json"),
            "image_sha256": oracle.policy.image_sha256,
            "argv": list(oracle.argv),
            "environment": [list(pair) for pair in oracle.environment],
            "comparator_version": COMPARATOR_VERSION,
            "move_policy": result.move_policy, "minimality_status": result.status,
            "trace": [item.model_dump(mode="json") for item in trace]}
    body["record_sha256"] = sha256(_canonical(body)).hexdigest()
    verify_record(body, expected_record_sha256=body["record_sha256"])
    return body


def verify_record(record: dict[str, Any], *, expected_record_sha256: str) -> ReplayBundle:
    """Check retained bytes, comparator lineage and pins without executing code.

    This does not certify that a worker ran or that a claimed final move pass was
    exhaustive. Those runtime/independent validation gates remain separate.
    """
    from bbr.contracts import Counterexample, ReplayBundle

    require_digest(expected_record_sha256)
    if type(record) is not dict or set(record) != _KEYS:
        raise ValueError("unexpected replay envelope fields")
    body = {k: v for k, v in record.items() if k != "record_sha256"}
    actual = sha256(_canonical(body)).hexdigest()
    if actual != expected_record_sha256 or record["record_sha256"] != actual:
        raise ValueError("replay digest mismatch")
    require_digest(record["image_sha256"])
    if record["comparator_version"] != COMPARATOR_VERSION:
        raise ValueError("comparator version drift")
    if record["move_policy"] != "contiguous-deletion-numeric-boundary-v1":
        raise ValueError("unknown move policy")
    minimality = record["minimality_status"]
    if minimality not in _MINIMALITY:
        raise ValueError("unknown minimality status")
    argv, environment = record["argv"], record["environment"]
    if (type(argv) is not list or any(type(v) is not str or "\x00" in v for v in argv)
            or type(environment) is not list):
        raise ValueError("invalid replay argv/environment")
    if any(type(p) is not list or len(p) != 2 or
           any(type(v) is not str or "\x00" in v for v in p) or not p[0] or "=" in p[0]
           for p in environment):
        raise ValueError("invalid environment entries")
    if len({p[0] for p in environment}) != len(environment):
        raise ValueError("duplicate environment keys")
    # JSON validation preserves strict tuple/hex semantics of the shared model.
    bundle = ReplayBundle.model_validate_json(_canonical(record["bundle"]))
    bundle.require_replay_pins()
    if (bundle.image_sha256 != record["image_sha256"] or
            list(bundle.argv) != argv or
            [list(pair) for pair in bundle.environment] != environment or
            bundle.comparator_version != record["comparator_version"] or
            bundle.move_policy != record["move_policy"] or
            [item.model_dump(mode="json") for item in bundle.trace] != record["trace"]):
        raise ValueError("nested replay pins differ from envelope")
    if bundle.minimality != _MINIMALITY[minimality]:
        raise ValueError("minimality label drift")
    if type(record["trace"]) is not list or not 1 <= len(record["trace"]) <= 256:
        raise ValueError("invalid trace length")
    trace = tuple(Counterexample.model_validate_json(_canonical(item))
                  for item in record["trace"])
    if len(trace) != bundle.attempts or trace[0] != bundle.original:
        raise ValueError("trace attempt/original mismatch")
    if bundle.reduced not in trace:
        raise ValueError("reduced case absent from trace")
    for item in (bundle.original, bundle.reduced, *trace):
        if (len(item.stdin_bytes) > 64 or
                sha256(item.stdin_bytes).hexdigest() != item.input_sha256 or
                item.outcome.input_sha256 != item.input_sha256):
            raise ValueError("input hash mismatch")
        recomputed = compare_observations(item.outcome.binary, item.outcome.candidate,
                                          stdin_bytes=item.stdin_bytes)
        if (recomputed.status, recomputed.reason) != (item.outcome.status, item.outcome.reason):
            raise ValueError("retained comparator outcome drift")
    if (len(bundle.reduced.stdin_bytes), bundle.reduced.stdin_bytes) > (
            len(bundle.original.stdin_bytes), bundle.original.stdin_bytes):
        raise ValueError("reduced case grew")
    return bundle


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _safe_file(root: Path, relative: str) -> Path:
    """Reject path aliases/escapes, symlinks and Windows junctions.

    Local artifact storage must also be read-only against concurrent writers;
    this portable path check alone does not close hostile filesystem races.
    """
    path = PurePosixPath(relative)
    if (not relative or "\\" in relative or ":" in relative or path.is_absolute()
            or any(part in {"", ".", ".."} or part.endswith((".", " "))
                   for part in relative.split("/"))):
        raise ValueError("unsafe artifact path")
    root = root.absolute()
    resolved_root = root.resolve(strict=True)
    current = Path(root.anchor)
    for component in (*root.parts[1:], *path.parts):
        current = current / component
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("symlink/reparse point refused")
    resolved = current.resolve(strict=True)
    if not resolved.is_relative_to(resolved_root):
        raise ValueError("artifact path escapes storage root")
    if not resolved.is_file():
        raise ValueError("expected regular artifact file")
    return resolved


def load_record(root: Path, relative: str, *, expected_record_sha256: str) -> dict[str, Any]:
    path = _safe_file(root, relative)
    with path.open("rb") as stream:
        raw = stream.read(_MAX_RECORD_BYTES + 1)
    if len(raw) > _MAX_RECORD_BYTES:
        raise ValueError("replay record exceeds 32 MiB")
    record = json.loads(raw, object_pairs_hook=_unique_object)
    verify_record(record, expected_record_sha256=expected_record_sha256)
    return record


def replay(record: dict[str, Any], *, expected_record_sha256: str, root: Path,
           artifact_path: str, candidate_path: str, oracle: Runner,
           candidate: Runner) -> PairOutcome:
    bundle = verify_record(record, expected_record_sha256=expected_record_sha256)
    for relative, expected in ((artifact_path, bundle.artifact_sha256),
                                (candidate_path, bundle.candidate_sha256)):
        path = _safe_file(root, relative)
        with path.open("rb") as stream:
            digest = sha256()
            total = 0
            while block := stream.read(65536):
                total += len(block)
                if total > 32 * 1024 * 1024:
                    raise ValueError("artifact exceeds 32 MiB")
                digest.update(block)
        if digest.hexdigest() != expected:
            raise ValueError("artifact hash mismatch")
    if oracle.policy.worker_kind != "oracle" or candidate.policy.worker_kind != "candidate":
        raise ValueError("worker role drift")
    for runner in (oracle, candidate):
        if (runner.policy.image_sha256 != record["image_sha256"] or
                runner.policy.toolchain_sha256 != bundle.toolchain_sha256 or
                list(runner.argv) != record["argv"] or
                [list(p) for p in runner.environment] != record["environment"]):
            raise ValueError("execution pins drifted")
    combined = sha256(_canonical([execution_contract(oracle, bundle.limits),
                                  execution_contract(candidate, bundle.limits)])).hexdigest()
    if combined != bundle.execution_contract_sha256:
        raise ValueError("execution contract drift")
    fresh = compare(bundle.artifact_sha256, bundle.candidate_sha256,
                    bundle.reduced.stdin_bytes, oracle=oracle,
                    candidate=candidate, limits=bundle.limits)
    old = bundle.reduced.outcome
    # Wall-clock timing and diagnostics are retained, never equality criteria.
    if fresh.status == "infrastructure_error":
        return fresh
    for retained, observed in ((old.binary, fresh.binary), (old.candidate, fresh.candidate)):
        if ((retained.stdout_bytes, retained.exit_code, retained.signal,
             retained.timed_out, retained.output_limited, retained.status) !=
                (observed.stdout_bytes, observed.exit_code, observed.signal,
                 observed.timed_out, observed.output_limited, observed.status)):
            raise ValueError("fresh execution diverged from retained observations")
    return fresh
