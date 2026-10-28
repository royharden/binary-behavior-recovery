"""Software units only: no container, candidate parsing, execution or custody claims."""

import base64
from dataclasses import replace
from hashlib import sha256
import json

import pytest

from bbr.contracts import ExecutionLimits, Observation
from bbr.runner.docker_validation import (
    DockerCandidateValidationBackend, ValidationArtifactReceipt,
    _DYNAMIC_NAMES, build_validation_artifact,
)
from bbr.runner.policy import SandboxPolicy
from bbr.runner.validation import CandidateValidationRequest


def request(raw=b"import sys\nsys.stdout.write(sys.stdin.read())\n"):
    return CandidateValidationRequest(raw, sha256(raw).hexdigest(),
                                      SandboxPolicy("a" * 64, "b" * 64, "candidate"),
                                      ExecutionLimits())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


class FakePort:
    def __init__(self, *, valid=True, reason="valid", change=None, observation=None):
        self.valid, self.reason = valid, reason
        self.change, self.observation = change, observation
        self.artifact = None
        self.executions = []

    def register(self, artifact):
        self.artifact = artifact
        return ValidationArtifactReceipt(artifact, artifact.wrapper_sha256, True)

    def execute(self, execution):
        self.executions.append(execution)
        if self.observation is not None:
            return self.observation
        artifact = self.artifact
        payload = {"schema": 1, "candidate_sha256": artifact.candidate_sha256,
                   "binding_sha256": artifact.binding_sha256,
                   "wrapper_sha256": artifact.wrapper_sha256,
                   "valid": self.valid, "reason": self.reason}
        if self.change:
            self.change(payload)
        payload["response_sha256"] = sha256(canonical(payload)).hexdigest()
        return Observation(stdout_bytes=canonical(payload), exit_code=0, status="ok")

    def backend(self):
        return DockerCandidateValidationBackend(transport=self, registrar=self.register)


@pytest.mark.parametrize("raw", [
    b"import sys\nsys.stdout.write(sys.stdin.read())\n",
    b"def broken(:\n",
    b"import subprocess\n",
    b"while True: pass\n",
    b"open('/tmp/validation-must-not-write', 'w').write('bad')\n",
])
def test_candidate_is_only_inert_packaged_data(raw):
    # These strings are controlled software specimens, never host parsed/run.
    artifact = build_validation_artifact(request(raw))
    assert base64.b64encode(raw) in artifact.wrapper_bytes
    assert artifact.candidate_sha256 == sha256(raw).hexdigest()
    assert artifact.wrapper_sha256 == sha256(artifact.wrapper_bytes).hexdigest()
    assert artifact.wrapper_bytes.count(b"CANDIDATE_B64 = ") == 1


@pytest.mark.parametrize("raw", [
    b'__builtins__["__import__"]("os")\n',
    b'__builtins__["eval"]("1 + 1")\n',
    b'namespace = __builtins__\nnamespace["__import__"]("os")\n',
])
def test_builtin_namespace_bypasses_are_inert_and_embedded_policy_denies_name(raw):
    # A packaging/policy regression only, not an executed candidate AST verdict.
    # Real denied_dynamic results require the separately admitted wrapper run.
    artifact = build_validation_artifact(request(raw))
    assert base64.b64encode(raw) in artifact.wrapper_bytes
    assert "__builtins__" in _DYNAMIC_NAMES
    assert ("DYNAMIC = " + repr(_DYNAMIC_NAMES) + "\n").encode("ascii") in artifact.wrapper_bytes
    assert b"isinstance(node, ast.Name) and node.id in dynamic:" in artifact.wrapper_bytes


@pytest.mark.parametrize("valid,reason", [
    (True, "valid"), (False, "syntax_invalid"),
    (False, "denied_import"), (False, "denied_dynamic"),
])
def test_bound_response_maps_checked_results(valid, reason):
    port = FakePort(valid=valid, reason=reason)
    assert port.backend().validate(request()) == (valid, reason)
    execution, = port.executions
    assert execution.artifact_sha256 == port.artifact.wrapper_sha256
    assert execution.stdin_bytes == b"" and execution.argv == execution.environment == ()
    assert execution.policy == request().policy and execution.limits == request().limits


def test_unavailable_admission_never_fabricates_success():
    port = FakePort()
    for backend in (DockerCandidateValidationBackend(),
                    DockerCandidateValidationBackend(transport=port),
                    DockerCandidateValidationBackend(registrar=port.register)):
        assert backend.validate(request())[0] is None
    assert not port.executions


@pytest.mark.parametrize("kind", ["digest", "readonly", "registration", "absent"])
def test_registrar_receipt_is_exact_and_mandatory(kind):
    port = FakePort()
    def registrar(artifact):
        if kind == "absent":
            return None
        return ValidationArtifactReceipt(
            replace(artifact, binding_sha256="f" * 64) if kind == "registration" else artifact,
            "f" * 64 if kind == "digest" else artifact.wrapper_sha256,
            False if kind == "readonly" else True)
    backend = DockerCandidateValidationBackend(transport=port, registrar=registrar)
    assert backend.validate(request())[0] is None
    assert not port.executions


def mutate_artifact(artifact, field):
    if field == "limits":
        # Pydantic frozen=True does not deeply freeze the instance dictionary.
        artifact.limits.__dict__["wall_seconds"] = 99.0
    elif field == "policy":
        artifact.policy.__dict__["image_sha256"] = "f" * 64
    else:
        artifact.__dict__[field] = b"changed wrapper" if field == "wrapper_bytes" else "f" * 64


@pytest.mark.parametrize("field", [
    "wrapper_bytes", "wrapper_sha256", "candidate_sha256", "binding_sha256", "policy", "limits",
])
def test_registrar_cannot_mutate_shared_artifact_and_receipt(field):
    port = FakePort()
    def registrar(artifact):
        receipt = port.register(artifact)
        binding_sha256 = artifact.binding_sha256
        mutate_artifact(artifact, field)
        if field == "limits":
            assert artifact.binding_sha256 == binding_sha256
            assert receipt.registration is artifact
        return receipt
    backend = DockerCandidateValidationBackend(transport=port, registrar=registrar)
    assert backend.validate(request())[0] is None
    assert not port.executions


@pytest.mark.parametrize("field", [
    "wrapper_bytes", "wrapper_sha256", "candidate_sha256", "binding_sha256", "policy", "limits",
])
def test_transport_cannot_mutate_retained_registration(field):
    port = FakePort()
    original_execute = port.execute
    def mutate(execution):
        mutate_artifact(port.artifact, field)
        return original_execute(execution)
    port.execute = mutate
    assert port.backend().validate(request())[0] is None


@pytest.mark.parametrize("field", [
    "artifact_sha256", "stdin_bytes", "argv", "environment", "policy", "limits",
])
def test_transport_cannot_mutate_execution_request(field):
    port = FakePort()
    original_execute = port.execute
    def mutate(execution):
        if field == "limits":
            assert execution.limits is not port.artifact.limits
            execution.limits.__dict__["wall_seconds"] = 99.0
        elif field == "policy":
            assert execution.policy is not port.artifact.policy
            execution.policy.__dict__["image_sha256"] = "f" * 64
        else:
            values = {"artifact_sha256": "f" * 64, "stdin_bytes": b"changed",
                      "argv": ("changed",), "environment": (("CHANGED", "1"),)}
            execution.__dict__[field] = values[field]
        return original_execute(execution)
    port.execute = mutate
    assert port.backend().validate(request())[0] is None


@pytest.mark.parametrize("field", ["artifact_sha256", "read_only", "registration"])
def test_transport_cannot_mutate_retained_receipt(field):
    port = FakePort()
    receipts = []
    def registrar(artifact):
        receipt = port.register(artifact)
        receipts.append(receipt)
        return receipt
    original_execute = port.execute
    def mutate(execution):
        receipt, = receipts
        values = {"artifact_sha256": "f" * 64, "read_only": False,
                  "registration": replace(port.artifact, candidate_sha256="f" * 64)}
        receipt.__dict__[field] = values[field]
        return original_execute(execution)
    port.execute = mutate
    backend = DockerCandidateValidationBackend(transport=port, registrar=registrar)
    assert backend.validate(request())[0] is None


@pytest.mark.parametrize("field,value", [
    ("schema", True), ("candidate_sha256", "c" * 64),
    ("binding_sha256", "c" * 64), ("wrapper_sha256", "c" * 64),
    ("valid", 1), ("reason", "invented"), ("valid", False), ("extra", "field"),
])
def test_even_rehashed_response_cannot_change_binding_or_schema(field, value):
    port = FakePort(change=lambda payload: payload.update({field: value}))
    assert port.backend().validate(request())[0] is None


@pytest.mark.parametrize("changes", [
    {"status": "subject_failure", "exit_code": 1},
    {"status": "subject_failure", "exit_code": None, "signal": 9},
    {"status": "subject_failure", "exit_code": None, "timed_out": True},
    {"status": "subject_failure", "exit_code": None, "output_limited": True},
    {"stderr_bytes": b"unexpected"}, {"elapsed": 2.01},
    {"stdout_bytes": b"not-json"}, {"stdout_bytes": b"\xff"},
    {"stdout_bytes": b'{"schema":1,"schema":1}'},
    {"stdout_bytes": b"{}"},
])
def test_execution_faults_or_malformed_json_are_unknown(changes):
    args = {"status": "ok", "exit_code": 0, "stdout_bytes": b"{}"}
    args.update(changes)
    port = FakePort(observation=Observation(**args))
    assert port.backend().validate(request())[0] is None


def test_response_digest_tampering_is_unknown():
    port = FakePort()
    original_execute = port.execute
    def tamper(execution):
        result = original_execute(execution)
        data = json.loads(result.stdout_bytes)
        data["response_sha256"] = "0" * 64
        return Observation(status="ok", exit_code=0, stdout_bytes=canonical(data))
    port.execute = tamper
    assert port.backend().validate(request())[0] is None


@pytest.mark.parametrize("raw", [b"", b" " * 20, b"x" * 32769, b"\xff"])
def test_invalid_byte_contract_never_reaches_registrar(raw):
    port = FakePort()
    assert port.backend().validate(request(raw))[0] is None
    assert port.artifact is None and not port.executions


def test_identity_changes_change_binding_and_wrapper():
    original = request()
    baseline = build_validation_artifact(original)
    for changed in (replace(original, code_bytes=b"pass", candidate_sha256=sha256(b"pass").hexdigest()),
                    replace(original, policy=SandboxPolicy("c" * 64, "b" * 64, "candidate")),
                    replace(original, policy=SandboxPolicy("a" * 64, "c" * 64, "candidate")),
                    replace(original, limits=ExecutionLimits(stdout_bytes=2048))):
        artifact = build_validation_artifact(changed)
        assert artifact.binding_sha256 != baseline.binding_sha256
        assert artifact.wrapper_sha256 != baseline.wrapper_sha256


def test_hash_mismatch_and_unchecked_limit_copies_fail_closed():
    original = request()
    for changed in (replace(original, candidate_sha256="f" * 64),
                    replace(original, limits=original.limits.model_copy(
                        update={"wall_seconds": 3.0}))):
        port = FakePort()
        assert port.backend().validate(changed)[0] is None
        assert port.artifact is None and not port.executions


def test_unchecked_observation_copy_cannot_bypass_output_caps():
    result = Observation(status="ok", exit_code=0).model_copy(
        update={"stdout_bytes": b"x" * 4097})
    assert FakePort(observation=result).backend().validate(request())[0] is None


@pytest.mark.parametrize("which", ["registrar", "transport"])
def test_callback_faults_are_unknown(which):
    port = FakePort()
    def fault(*args):
        raise RuntimeError("controlled software fault")
    if which == "registrar":
        backend = DockerCandidateValidationBackend(transport=port, registrar=fault)
    else:
        port.execute = fault
        backend = port.backend()
    assert backend.validate(request())[0] is None
