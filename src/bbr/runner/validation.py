"""Candidate diagnostics belong inside the future isolated worker, never host."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING, Protocol

from .policy import SandboxPolicy

if TYPE_CHECKING:
    from bbr.contracts import ExecutionLimits


@dataclass(frozen=True)
class CandidateValidationRequest:
    code_bytes: bytes
    candidate_sha256: str
    policy: SandboxPolicy
    limits: ExecutionLimits


class CandidateValidationBackend(Protocol):
    """Trusted adapter must compile/check imports ONLY inside candidate sandbox."""

    def validate(self, request: CandidateValidationRequest) -> tuple[bool | None, str]: ...


class CandidateValidator:
    """callable(code)->(parse_valid, diagnostic); None means infrastructure unknown.

    A false result is a checked subject syntax/import failure. No backend is an
    unavailable result, never false parse failure or fabricated success. The arm
    broker must preserve unknowns and defer all scoring until real validation.
    """

    def __init__(self, policy: SandboxPolicy, limits: ExecutionLimits, *,
                 backend: CandidateValidationBackend | None = None) -> None:
        from bbr.contracts import ExecutionLimits

        if policy.worker_kind != "candidate":
            raise ValueError("candidate validation requires candidate worker")
        self.policy = policy
        self.limits = ExecutionLimits.model_validate(limits)
        self.backend = backend

    def __call__(self, code: str) -> tuple[bool | None, str]:
        if type(code) is not str or not code.strip():
            return False, "candidate source must be a nonempty string"
        try:
            raw = code.encode("utf-8")
        except UnicodeEncodeError:
            return False, "candidate source is not UTF-8 encodable"
        if len(raw) > 32768:
            return False, "candidate source exceeds 32 KiB"
        if self.backend is None:
            return None, "infrastructure_error: isolated_candidate_validation_unavailable"
        request = CandidateValidationRequest(raw, sha256(raw).hexdigest(),
                                             self.policy, self.limits)
        try:
            result = self.backend.validate(request)
            if (type(result) is not tuple or len(result) != 2 or
                    (result[0] is not None and type(result[0]) is not bool) or
                    type(result[1]) is not str or len(result[1]) > 4096):
                raise ValueError("invalid validation adapter response")
            if result[0] is None and not result[1]:
                raise ValueError("unknown validation requires diagnostic")
            return result
        except Exception:
            return None, "infrastructure_error: isolated_candidate_validation_fault"
