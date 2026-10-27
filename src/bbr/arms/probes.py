"""Adapt DL2's isolated pair port to the public-pool broker; no host fallback."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Mapping

if TYPE_CHECKING:
    from bbr.contracts import ExecutionLimits
    from bbr.differential.compare import Executor
    from .interventions import Submission


class RunnerProbeAdapter:
    """Candidate registration must return an admitted isolated worker artifact.

    The callback must register exact submitted source without executing it on the
    host. No such backend is provided here; absent registration is unknown and
    prevents even oracle execution. Construct oracle/candidate as separate workers.
    """

    def __init__(self, binary_ref: str, *, oracle: Executor, candidate: Executor,
                 limits: ExecutionLimits,
                 candidate_ref: Callable[[Submission], str] | None = None):
        if oracle is candidate:
            raise ValueError("separate oracle/candidate workers required")
        self.binary_ref, self.oracle, self.candidate = binary_ref, oracle, candidate
        self.limits, self.candidate_ref = limits, candidate_ref

    def __call__(self, submission: Submission, raw: bytes) -> Mapping[str, Any]:
        from bbr.differential import compare

        if self.candidate_ref is None:
            return {"status": "infrastructure_error"}
        if not submission.parse_valid or submission.abstain:
            raise ValueError("probe requires an isolated-valid candidate")
        reference = self.candidate_ref(submission)
        outcome = compare(self.binary_ref, reference, raw, oracle=self.oracle,
                          candidate=self.candidate, limits=self.limits)
        return {"status": outcome.status, "oracle": outcome.binary.model_dump(mode="json"),
                "candidate": outcome.candidate.model_dump(mode="json"),
                "diverged": outcome.status not in {"equal", "infrastructure_error"}}
