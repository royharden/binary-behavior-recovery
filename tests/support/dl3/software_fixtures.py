"""Authored SOFTWARE TEST fixtures, fixture origin, never ELF/held-out evidence.

Fake worker ports return scripted observations and validation acknowledgments.
They NEVER compile, import, execute or analyze candidate source. Their digests
identify software-test strings, not real images/toolchains or admitted workers.
"""
from dataclasses import dataclass
from hashlib import sha256

from bbr.contracts import CandidateResponse, Domain, ExecutionLimits, Observation, VisibleExample, VisibleTask
from bbr.evidence import (EvidenceBundle, EXTRACTOR_VERSION, ImportMetadata,
                          PublicEvidenceEnvelope, SectionSlice, _EVIDENCE_LIMITATIONS)
from bbr.providers.mock import ModelConfig, prepare_request, request_digest
from bbr.runner import CandidateValidator, Runner, SandboxPolicy

SOFTWARE_FIXTURE_ID = "dl3-authored-software-regression-v1-not-benchmark"
SOURCE_A = "# authored software-test source A; DATA ONLY\npass\n"
SOURCE_B = "# authored software-test source B; DATA ONLY\npass\n"
VALIDATION_DIAGNOSTIC = "authored software port acknowledgment; not syntax/isolation proof"
CAMPAIGN_ID = "authored-software-regression-campaign"
# Hand-authored SOFTWARE I/O for the search controller, not task/reference truth.
SOFTWARE_IDENTITY_IO = (
    (b"0\n", b"0\n"), (b"1\n", b"1\n"), (b"2\n", b"2\n"), (b"3\n", b"3\n"),
    (b"4\n", b"4\n"), (b"5\n", b"5\n"), (b"6\n", b"6\n"), (b"7\n", b"7\n"),
)
SOFTWARE_INCREMENT_IO = (
    (b"0\n", b"1\n"), (b"1\n", b"2\n"), (b"2\n", b"3\n"), (b"3\n", b"4\n"),
    (b"4\n", b"5\n"), (b"5\n", b"6\n"), (b"6\n", b"7\n"), (b"7\n", b"8\n"),
)


@dataclass(frozen=True)
class SoftwareCase:
    task: VisibleTask
    evidence_json: bytes
    artifact_sha256: str
    config: ModelConfig

    @property
    def fixed(self):
        return tuple(tuple(self.task.probe_inputs[i:i + 8]) for i in (0, 8, 16))


def software_case(*, task_id="authored-software-test-task", config=None,
                  text_bytes=b"\x01\x02\x03\x04"):
    """Structural envelope and tiny public parser cases, NOT an actual ELF task."""
    artifact = sha256(b"authored software-test identifier; NOT AN ELF").hexdigest()
    # Tiny authored bytes exercise full-envelope identity, never ELF extraction.
    raw = text_bytes
    bundle = EvidenceBundle(artifact, EXTRACTOR_VERSION,
        (SectionSlice(".text", 4096, 128, len(raw), sha256(raw).hexdigest(), raw.hex(), len(raw)),),
        (), ImportMetadata(False, None, 0, None, (), 0, 0, ("dynamic_table_absent",)),
        False, _EVIDENCE_LIMITATIONS)
    envelope = PublicEvidenceEnvelope.from_bundle(bundle, expected_artifact_sha256=artifact)
    examples = tuple(VisibleExample(stdin_bytes=f"{i}\n".encode(),
                                    stdout_bytes=f"{i}\n".encode()) for i in range(8))
    pool = tuple(f"{i}\n".encode() for i in range(8, 72)) + tuple(
        f"software-invalid-{i}\n".encode() for i in range(16))
    task = VisibleTask(task_id=task_id, evidence_sha256=envelope.evidence_sha256,
        codec="dec", domain=Domain(width=8, input_arity=1, output_arity=1, maximum=255),
        probe_inputs=pool, examples=examples)
    return SoftwareCase(task, envelope.canonical_json(), artifact, config or ModelConfig())


class SoftwareClock:
    """Scripted monotonic readings for SOFTWARE control flow, not timing evidence.

    Repeat the final reading after the explicit timeline is consumed. A single
    zero freezes S's search clock independently of host load/RAM pressure.
    """
    def __init__(self, readings=(0.0,)):
        self.readings = readings
        self.calls = 0

    def __call__(self):
        reading = self.readings[min(self.calls, len(self.readings) - 1)]
        self.calls += 1
        return reading


def response(code=SOURCE_A, *, probes=(), abstain=False):
    return CandidateResponse(code=None if abstain else code, abstain=abstain,
                             probe_inputs=tuple(probes), hypothesis=SOFTWARE_FIXTURE_ID).model_dump(mode="json")


def fixture_row(case, payload=None, *, history=()):
    request = prepare_request(case.task, history, case.config,
        evidence_json=case.evidence_json, artifact_sha256=case.artifact_sha256)
    return {"request": request, "request_sha256": request_digest(request),
            "response": response() if payload is None else payload,
            "usage": {"input_tokens": 0, "output_tokens": 0, "usd": "0"}, "origin": "fixture"}


def seven_scripted_rows(case):
    """Explicit software-port transcript: no probes, equal fixed observations.

    These are authored harness expectations, not recovered programs or independent
    expected answers. No product intervention engine generates this transcript.
    """
    payload = response()
    rows = [fixture_row(case, payload)]
    for arm in ("R", "P"):
        history = []
        for stage in (1, 2, 3):
            history.append({"response": payload, "format_diagnostic": VALIDATION_DIAGNOSTIC})
            if arm == "P":
                history.append({"public_feedback": {"stage": stage, "chosen": [],
                    "first_fixed_divergence": None, "slots_used": stage * 8}})
            rows.append(fixture_row(case, payload, history=history))
    return rows


class SoftwareValidationPort:
    """Acknowledges DATA without compiling/importing/executing any source."""
    def __init__(self):
        self.sources = []

    def validate(self, request):
        self.sources.append(request.code_bytes)
        return True, VALIDATION_DIAGNOSTIC


class SoftwareExecutionPort:
    """Returns one authored observation without inspecting candidate artifacts."""
    def __init__(self):
        self.inputs = []

    def execute(self, request):
        self.inputs.append(request.stdin_bytes)
        return Observation(stdout_bytes=b"authored-software-port-output", exit_code=0,
                           elapsed=0.0, status="ok")


def software_ports():
    # Opaque SOFTWARE identifiers only. No real image/toolchain is admitted here.
    image = sha256(b"SOFTWARE TEST NOT A REAL IMAGE PIN").hexdigest()
    tool = sha256(b"SOFTWARE TEST NOT A REAL TOOLCHAIN PIN").hexdigest()
    limits = ExecutionLimits()
    oracle_port, candidate_port, validation_port = SoftwareExecutionPort(), SoftwareExecutionPort(), SoftwareValidationPort()
    oracle_policy = SandboxPolicy(image, tool, worker_kind="oracle")
    candidate_policy = SandboxPolicy(image, tool, worker_kind="candidate")
    oracle = Runner(oracle_policy, backend=oracle_port)
    candidate = Runner(candidate_policy, backend=candidate_port)
    validator = CandidateValidator(candidate_policy, limits, backend=validation_port)

    def register(submission):
        # A test artifact ID only; source remains data, no artifact is executed.
        return sha256(submission.response["code"].encode()).hexdigest()

    return dict(oracle=oracle, candidate=candidate, validator=validator,
                candidate_ref=register, limits=limits), (oracle_port, candidate_port, validation_port)
