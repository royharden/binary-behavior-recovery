"""No trimming, decoding or tolerance; infrastructure faults remain unknown."""

from __future__ import annotations

from hashlib import sha256
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from bbr.contracts import ExecutionLimits, Observation, PairOutcome

COMPARATOR_VERSION = "bbr-exact-v1"


class Executor(Protocol):
    def execute(self, artifact_sha256: str, stdin_bytes: bytes,
                limits: ExecutionLimits) -> Observation: ...


def compare_observations(binary: Observation, candidate: Observation, *,
                         stdin_bytes: bytes) -> PairOutcome:
    from bbr.contracts import PairOutcome

    if any(o.status == "infrastructure_error" for o in (binary, candidate)):
        status, reason = "infrastructure_error", "runner_fault"
    elif any(o.timed_out for o in (binary, candidate)):
        status, reason = "timeout", "timeout"
    elif any(o.output_limited for o in (binary, candidate)):
        status, reason = "output_cap", "output_cap"
    elif any(o.signal is not None for o in (binary, candidate)):
        status, reason = "signal", "signal"
    elif any(o.exit_code is None for o in (binary, candidate)):
        status, reason = "infrastructure_error", "missing_exit_status"
    elif binary.exit_code != candidate.exit_code:
        status, reason = "wrong_exit", "wrong_exit"
    elif any(o.exit_code not in (0, 2) for o in (binary, candidate)):
        status, reason = "wrong_exit", "subject_exception"
    elif any(o.status == "subject_failure" and o.exit_code != 2
             for o in (binary, candidate)):
        status, reason = "wrong_exit", "subject_exception"
    elif binary.stdout_bytes != candidate.stdout_bytes:
        status, reason = "wrong_output", "wrong_output"
    else:
        status, reason = "equal", "exact"
    return PairOutcome(input_sha256=sha256(stdin_bytes).hexdigest(), binary=binary,
                       candidate=candidate, status=status, reason=reason)


def compare(binary_ref: str, candidate_ref: str, input_ref: bytes, *,
            oracle: Executor, candidate: Executor, limits: ExecutionLimits) -> PairOutcome:
    """Worker adapters are explicitly separate; no artifact path is executed here."""
    if oracle is candidate:
        raise ValueError("oracle and candidate require separate worker adapters")
    return compare_observations(oracle.execute(binary_ref, input_ref, limits),
                                candidate.execute(candidate_ref, input_ref, limits),
                                stdin_bytes=input_ref)


def run_pair(binary_ref: str, candidate_ref: str, inputs: tuple[bytes, ...], *,
             oracle: Executor, candidate: Executor,
             limits: ExecutionLimits) -> tuple[PairOutcome, ...]:
    return tuple(compare(binary_ref, candidate_ref, raw, oracle=oracle,
                         candidate=candidate, limits=limits) for raw in inputs)
