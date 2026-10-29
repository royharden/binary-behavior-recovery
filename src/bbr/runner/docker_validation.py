"""Candidate diagnostics through an explicitly admitted isolated execution port.

Host work is limited to bytes, hashes, UTF-8 and closed JSON. The generated trusted
wrapper parses/compiles candidate syntax inside the container; it never runs it.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Callable

from bbr.contracts import ExecutionLimits, Observation
from .policy import ExecutionRequest, IsolatedBackend, SandboxPolicy
from .validation import CandidateValidationRequest

IMPORT_POLICY_ID = "bbr-stdlib-diagnostics-v1"
ALLOWED_IMPORTS = (
    "array", "bisect", "collections", "decimal", "fractions", "functools",
    "heapq", "itertools", "json", "math", "operator", "re", "statistics",
    "string", "sys",
)
_DYNAMIC_NAMES = (
    "__builtins__", "__import__", "breakpoint", "compile", "delattr", "eval", "exec", "getattr",
    "globals", "locals", "open", "setattr", "vars",
)


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


IMPORT_POLICY_SHA256 = sha256(_json({
    "id": IMPORT_POLICY_ID, "imports": ALLOWED_IMPORTS,
    "dynamic_names": _DYNAMIC_NAMES,
    "rules": "absolute-single-module;no-star-private-or-dunder;no-direct-dynamic",
})).hexdigest()


@dataclass(frozen=True)
class ValidationArtifactRegistration:
    """Exact bytes/identity the trusted registrar must admit as read-only."""

    wrapper_bytes: bytes
    wrapper_sha256: str
    candidate_sha256: str
    binding_sha256: str
    policy: SandboxPolicy
    limits: ExecutionLimits


@dataclass(frozen=True)
class ValidationArtifactReceipt:
    registration: ValidationArtifactRegistration
    artifact_sha256: str
    read_only: bool


# This literal is trusted program source, not candidate source. Substitution is
# restricted to base64 and canonical JSON string literals; neither is executable.
_WRAPPER = '''import ast, base64, hashlib, json
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
raw = base64.b64decode(CANDIDATE_B64, validate=True)
binding = json.loads(BINDING_JSON)
allowed = ALLOWED
dynamic = DYNAMIC
valid, reason = True, "valid"
try:
    if hashlib.sha256(raw).hexdigest() != binding["candidate_sha256"]:
        raise ValueError("candidate binding")
    tree = ast.parse(raw.decode("utf-8", errors="strict"), filename="<candidate>", mode="exec")
    # Compile catches contextual syntax errors (e.g. return outside a function).
    # The resulting code object is discarded; candidate body is never executed.
    compile(tree, "<candidate>", "exec", dont_inherit=True)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(item.name not in allowed or (item.asname and item.asname.startswith("_")) for item in node.names):
                valid, reason = False, "denied_import"
        elif isinstance(node, ast.ImportFrom):
            if node.level or node.module not in allowed or any(item.name == "*" or item.name.startswith("_") or (item.asname and item.asname.startswith("_")) for item in node.names):
                valid, reason = False, "denied_import"
        elif isinstance(node, ast.Name) and node.id in dynamic:
            valid, reason = False, "denied_dynamic"
        elif isinstance(node, ast.Attribute) and (node.attr.startswith("__") or node.attr in dynamic or node.attr in ("import_module", "load_module", "exec_module")):
            valid, reason = False, "denied_dynamic"
except (SyntaxError, UnicodeError, ValueError, RecursionError):
    valid, reason = False, "syntax_invalid"
with open(__file__, "rb") as artifact:
    wrapper_sha = hashlib.sha256(artifact.read()).hexdigest()
payload = {"schema": 1, "candidate_sha256": binding["candidate_sha256"], "binding_sha256": hashlib.sha256(canonical(binding)).hexdigest(), "wrapper_sha256": wrapper_sha, "valid": valid, "reason": reason}
payload["response_sha256"] = hashlib.sha256(canonical(payload)).hexdigest()
print(canonical(payload).decode("ascii"))
'''


def build_validation_artifact(request: CandidateValidationRequest) -> ValidationArtifactRegistration:
    """Pure packaging only: never parse or compile candidate source on the host."""
    raw = request.code_bytes
    if type(raw) is not bytes or not 0 < len(raw) <= 32768:
        raise ValueError("candidate source must contain 1..32768 bytes")
    text = raw.decode("utf-8", errors="strict")
    if not text.strip() or sha256(raw).hexdigest() != request.candidate_sha256:
        raise ValueError("candidate bytes/hash mismatch or empty source")
    policy = SandboxPolicy(**asdict(request.policy))
    if policy.worker_kind != "candidate":
        raise ValueError("candidate worker required")
    # Reconstruct rather than trusting model_validate's existing-instance fast
    # path; a caller can otherwise hand over an unchecked model_copy(update=...).
    limits = ExecutionLimits.model_validate(request.limits.model_dump(mode="python"))
    binding = {"schema": 1, "candidate_sha256": request.candidate_sha256,
               "import_policy_sha256": IMPORT_POLICY_SHA256,
               "policy": asdict(policy), "limits": limits.model_dump(mode="json")}
    prefix = ("CANDIDATE_B64 = " + repr(base64.b64encode(raw).decode("ascii")) + "\n"
              + "BINDING_JSON = " + repr(_json(binding).decode("ascii")) + "\n"
              + "ALLOWED = " + repr(ALLOWED_IMPORTS) + "\n"
              + "DYNAMIC = " + repr(_DYNAMIC_NAMES) + "\n")
    wrapper = (prefix + _WRAPPER).encode("utf-8")
    return ValidationArtifactRegistration(wrapper, sha256(wrapper).hexdigest(),
                                          request.candidate_sha256,
                                          sha256(_json(binding)).hexdigest(), policy, limits)


def _artifact_snapshot(artifact: ValidationArtifactRegistration) -> tuple[bytes, bytes]:
    """Detached bytes: frozen records/models do not freeze nested __dict__ state."""
    if (type(artifact) is not ValidationArtifactRegistration
            or type(artifact.wrapper_bytes) is not bytes
            or type(artifact.policy) is not SandboxPolicy
            or type(artifact.limits) is not ExecutionLimits):
        raise ValueError("invalid registration shape")
    return artifact.wrapper_bytes, _json({
        "wrapper_sha256": artifact.wrapper_sha256,
        "candidate_sha256": artifact.candidate_sha256,
        "binding_sha256": artifact.binding_sha256,
        "policy": asdict(artifact.policy),
        "limits": artifact.limits.model_dump(mode="json"),
    })


def _execution_snapshot(execution: ExecutionRequest) -> bytes:
    if (type(execution) is not ExecutionRequest
            or type(execution.stdin_bytes) is not bytes
            or type(execution.argv) is not tuple
            or type(execution.environment) is not tuple
            or type(execution.policy) is not SandboxPolicy
            or type(execution.limits) is not ExecutionLimits):
        raise ValueError("invalid execution shape")
    return _json({"artifact_sha256": execution.artifact_sha256,
                  "stdin_b64": base64.b64encode(execution.stdin_bytes).decode("ascii"),
                  "policy": asdict(execution.policy),
                  "limits": execution.limits.model_dump(mode="json"),
                  "argv": execution.argv, "environment": execution.environment})


def _check_registration(artifact: ValidationArtifactRegistration,
                        receipt: ValidationArtifactReceipt,
                        baseline: tuple[bytes, bytes], wrapper_sha256: str) -> None:
    if (type(receipt) is not ValidationArtifactReceipt
            or _artifact_snapshot(artifact) != baseline
            or _artifact_snapshot(receipt.registration) != baseline
            or receipt.read_only is not True
            or receipt.artifact_sha256 != wrapper_sha256):
        raise ValueError("unbound or mutated registration receipt")


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


class DockerCandidateValidationBackend:
    """Uses the caller's real admitted DockerBackend; never starts a host fallback.

    Registrar authority and transport honesty are trusted deployment boundaries.
    A receipt asserts real immutable artifact registration, not authorization alone.
    """

    def __init__(self, *, transport: IsolatedBackend | None = None,
                 registrar: Callable[[ValidationArtifactRegistration],
                                     ValidationArtifactReceipt] | None = None) -> None:
        self.transport = transport
        self.registrar = registrar

    def validate(self, request: CandidateValidationRequest) -> tuple[bool | None, str]:
        if self.transport is None or self.registrar is None:
            return None, "infrastructure_error: isolated_validation_admission_unavailable"
        try:
            artifact = build_validation_artifact(request)
            # Capture immutable values before crossing either trusted callback.
            # Equality against the same shallow-frozen object is insufficient.
            baseline = _artifact_snapshot(artifact)
            wrapper_sha256 = artifact.wrapper_sha256
            candidate_sha256 = artifact.candidate_sha256
            binding_sha256 = artifact.binding_sha256
            wall_seconds, stdout_bytes = artifact.limits.wall_seconds, artifact.limits.stdout_bytes
            receipt = self.registrar(artifact)
            _check_registration(artifact, receipt, baseline, wrapper_sha256)
            # The transport gets detached copies too, so mutation of its request
            # cannot silently change the registered artifact's constraints.
            execution = ExecutionRequest(
                wrapper_sha256, b"",
                ExecutionLimits.model_validate(artifact.limits.model_dump(mode="python")),
                SandboxPolicy(**asdict(artifact.policy)), (), ())
            execution_baseline = _execution_snapshot(execution)
            reported = self.transport.execute(execution)
            _check_registration(artifact, receipt, baseline, wrapper_sha256)
            if _execution_snapshot(execution) != execution_baseline:
                raise ValueError("mutated execution request")
            result = Observation.model_validate(
                reported.model_dump(mode="python") if isinstance(reported, Observation)
                else reported)
            if (result.status != "ok" or result.exit_code != 0 or result.signal is not None
                    or result.timed_out or result.output_limited or result.stderr_bytes
                    or result.reason is not None or result.elapsed > wall_seconds
                    or len(result.stdout_bytes) > stdout_bytes):
                raise ValueError("diagnostic execution incomplete")
            response = json.loads(result.stdout_bytes.decode("utf-8", errors="strict"),
                                  object_pairs_hook=_closed_object)
            keys = {"schema", "candidate_sha256", "binding_sha256", "wrapper_sha256",
                    "valid", "reason", "response_sha256"}
            if type(response) is not dict or set(response) != keys:
                raise ValueError("diagnostic schema mismatch")
            response_sha = response.pop("response_sha256")
            if (type(response_sha) is not str or sha256(_json(response)).hexdigest() != response_sha
                    or type(response["schema"]) is not int or response["schema"] != 1
                    or response["candidate_sha256"] != candidate_sha256
                    or response["binding_sha256"] != binding_sha256
                    or response["wrapper_sha256"] != wrapper_sha256
                    or type(response["valid"]) is not bool
                    or response["reason"] not in ("valid", "syntax_invalid", "denied_import", "denied_dynamic")
                    or response["valid"] != (response["reason"] == "valid")):
                raise ValueError("diagnostic binding mismatch")
            return response["valid"], str(response["reason"])
        except Exception:
            return None, "infrastructure_error: isolated_validation_fault_or_unbound_response"
