"""Build requests for a separately admitted isolated worker; fail closed by default.

The backend is a trusted deployment seam, not an isolation proof. This module never
imports candidates, invokes subprocesses, mounts paths or starts containers.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from bbr.contracts import ExecutionLimits, Observation


def require_digest(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("expected lowercase SHA256 digest")
    return value


@dataclass(frozen=True)
class SandboxPolicy:
    """Required worker controls; activation must validate them outside this source."""

    image_sha256: str
    toolchain_sha256: str
    worker_kind: str = "oracle"
    network: bool = False
    read_only_root: bool = True
    fresh_process: bool = True
    process_limit: int = 1
    user: str = "unprivileged"

    def __post_init__(self) -> None:
        require_digest(self.image_sha256)
        require_digest(self.toolchain_sha256)
        if self.worker_kind not in {"oracle", "candidate"}:
            raise ValueError("unknown worker kind")
        if (self.network or not self.read_only_root or not self.fresh_process
                or self.process_limit != 1 or self.user != "unprivileged"):
            raise ValueError("worker isolation policy cannot be weakened")


@dataclass(frozen=True)
class ExecutionRequest:
    artifact_sha256: str
    stdin_bytes: bytes
    limits: ExecutionLimits
    policy: SandboxPolicy
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]


class IsolatedBackend(Protocol):
    """Trusted offline worker adapter, never a host subprocess fallback."""

    def execute(self, request: ExecutionRequest) -> Observation: ...


class Runner:
    def __init__(self, policy: SandboxPolicy, *, backend: IsolatedBackend | None = None,
                 argv: tuple[str, ...] = (),
                 environment: tuple[tuple[str, str], ...] = ()) -> None:
        if len(set(k for k, _ in environment)) != len(environment):
            raise ValueError("duplicate environment key")
        if any("\x00" in item for item in argv):
            raise ValueError("invalid argv")
        if any(not key or "=" in key or "\x00" in key + value
               for key, value in environment):
            raise ValueError("invalid environment")
        self.policy = policy
        self.backend = backend
        self.argv = tuple(argv)
        self.environment = tuple(sorted(environment))

    def execute(self, artifact_sha256: str, stdin_bytes: bytes,
                limits: ExecutionLimits) -> Observation:
        from bbr.contracts import Observation
        from bbr.contracts import ExecutionLimits

        require_digest(artifact_sha256)
        limits = ExecutionLimits.model_validate(limits)
        if type(stdin_bytes) is not bytes or len(stdin_bytes) > limits.stdin_bytes:
            raise ValueError("stdin must be bytes with length <=64")
        if self.backend is None:
            return Observation(stdout_bytes=b"", exit_code=None, signal=None,
                               timed_out=False, output_limited=False, elapsed=0.0,
                               status="infrastructure_error", reason="isolated_backend_unavailable")
        request = ExecutionRequest(artifact_sha256, stdin_bytes, limits, self.policy,
                                   self.argv, self.environment)
        try:
            observation = self.backend.execute(request)
            # A malformed adapter result is infrastructure unknown, never success.
            observation = Observation.model_validate(observation)
            if (len(observation.stdout_bytes) > limits.stdout_bytes
                    or len(observation.stderr_bytes) > limits.stderr_bytes
                    or (observation.elapsed > limits.wall_seconds
                        and not observation.timed_out)):
                raise ValueError("backend violated retained output/wall limits")
            # A reported timeout can include worker termination/cleanup time.
            # Other wall overruns remain malformed adapter results.
            return observation
        except Exception:
            return Observation(stdout_bytes=b"", exit_code=None, signal=None,
                               timed_out=False, output_limited=False, elapsed=0.0,
                               status="infrastructure_error", reason="isolated_backend_fault")
