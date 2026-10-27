"""Closed shared wire contracts. Bytes are lowercase hex in JSON, never text-decoded."""
from __future__ import annotations

from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Codec = Literal["dec", "hex", "bin"]

class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True,
                              ser_json_bytes="hex", val_json_bytes="hex", allow_inf_nan=False)

class ExecutionLimits(Contract):
    wall_seconds: float = Field(default=2.0, gt=0, le=2)
    cpu_seconds: int = Field(default=1, gt=0, le=1)
    memory_bytes: int = Field(default=268435456, gt=0, le=268435456)
    stdout_bytes: int = Field(default=4096, gt=0, le=4096)
    stderr_bytes: int = Field(default=4096, gt=0, le=4096)
    stdin_bytes: int = Field(default=64, gt=0, le=64)
    processes: int = Field(default=1, ge=1, le=1)

class Observation(Contract):
    stdout_bytes: bytes = b""
    stderr_bytes: bytes = b""
    exit_code: int | None = Field(default=None, ge=0, le=255)
    signal: int | None = Field(default=None, gt=0)
    timed_out: bool = False
    output_limited: bool = False
    elapsed: float = Field(default=0.0, ge=0)
    status: Literal["ok", "subject_failure", "infrastructure_error"]
    reason: str | None = None

    @model_validator(mode="after")
    def coherent(self):
        if self.exit_code is not None and self.signal is not None:
            raise ValueError("exit_code and signal are mutually exclusive")
        if self.status == "ok" and (self.exit_code != 0 or self.signal or self.timed_out or self.output_limited):
            raise ValueError("ok requires clean exit zero")
        if self.status == "infrastructure_error" and not self.reason:
            raise ValueError("infrastructure error requires reason")
        if len(self.stdout_bytes) > 4096 or len(self.stderr_bytes) > 4096:
            raise ValueError("observation exceeds retained output cap")
        return self

class Domain(Contract):
    width: Literal[8, 16]
    input_arity: int = Field(ge=0, le=8)
    output_arity: int = Field(ge=0, le=8)
    minimum: int = Field(default=0, ge=0)
    maximum: int = Field(ge=0, le=65535)

    @model_validator(mode="after")
    def bounds(self):
        if not self.minimum <= self.maximum < 2 ** self.width:
            raise ValueError("invalid unsigned domain bounds")
        return self

class FamilySpec(Domain):
    family_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    semantic_fingerprint: str
    finite_domain_size: int | None = Field(default=None, gt=0)
    author: str
    created: str
    rights_status: Literal["pending", "approved", "rejected"] = "pending"
    split: Literal["dev"] = "dev"

    @model_validator(mode="after")
    def finite_domain(self):
        if self.finite_domain_size is not None and self.finite_domain_size != (self.maximum-self.minimum+1)**self.input_arity:
            raise ValueError("finite domain capacity does not match public domain")
        return self

class Instance(Contract):
    instance_id: str
    family_id: str
    spec_sha256: Sha256
    source_sha256: Sha256
    reference_sha256: Sha256
    rights_status: Literal["pending", "approved", "rejected"] = "pending"

class BuildArtifact(Contract):
    task_id: str
    family_id: str
    codec: Codec
    compiler: Literal["gcc", "clang"]
    optimization: Literal["O0", "O2"]
    artifact_sha256: Sha256
    text_sha256: Sha256 | None = None
    execution_contract_sha256: Sha256
    source_sha256: Sha256
    toolchain_sha256: Sha256
    size_bytes: int = Field(gt=0)

class Manifest(Contract):
    edition: str
    artifacts: tuple[BuildArtifact, ...]
    source_commit: str
    admission_status: Literal["pending", "accepted", "rejected"] = "pending"

class EvidencePointer(Contract):
    section: str
    offset: int = Field(ge=0)
    length: int = Field(ge=0)
    sha256: Sha256
    boundary_uncertain: bool = True

class EvidenceString(Contract):
    section: str
    offset: int = Field(ge=0)
    length: int = Field(ge=0)
    text: str
    flags: tuple[str, ...] = ()

class Evidence(Contract):
    artifact_sha256: Sha256
    extractor_version: str
    sections: tuple[EvidencePointer, ...] = ()
    strings: tuple[EvidenceString, ...] = ()
    truncated: bool = False
    limitations: tuple[str, ...] = ()

class VisibleExample(Contract):
    stdin_bytes: bytes = Field(max_length=64)
    stdout_bytes: bytes = Field(max_length=4096)
    exit_code: int = Field(default=0, ge=0, le=255)

class VisibleTask(Contract):
    task_id: str
    evidence_sha256: Sha256
    codec: Codec
    domain: Domain
    # Frozen public pool: 64 valid + 16 malformed; admission proves that partition.
    probe_inputs: tuple[bytes, ...] = Field(min_length=80, max_length=80)
    examples: tuple[VisibleExample, ...] = Field(min_length=8, max_length=8)

    @field_validator("probe_inputs")
    @classmethod
    def bounded_probes(cls, value):
        if len(value) > 80 or any(len(item)>64 for item in value):
            raise ValueError("probe inputs exceed public caps")
        if len(set(value)) != len(value):
            raise ValueError("duplicate raw public probe input")
        return value

    @model_validator(mode="after")
    def public_partition(self):
        # Deferred import avoids a module-definition cycle with corpus FamilySpec.
        from bbr.corpus.codecs import decode

        def valid_input(raw: bytes) -> bool:
            try:
                values = decode(raw, self.codec, self.domain.width)
            except ValueError:
                return False
            return (len(values) == self.domain.input_arity and
                    all(self.domain.minimum <= v <= self.domain.maximum for v in values))

        if sum(valid_input(raw) for raw in self.probe_inputs) != 64:
            raise ValueError("public pool requires 64 valid and 16 malformed inputs")
        visible = {example.stdin_bytes for example in self.examples}
        if len(visible) != 8 or visible.intersection(self.probe_inputs):
            raise ValueError("visible examples must be unique and disjoint from public pool")
        for example in self.examples:
            if not valid_input(example.stdin_bytes) or example.exit_code != 0:
                raise ValueError("visible examples require valid canonical input and exit zero")
            outputs = decode(example.stdout_bytes, self.codec, self.domain.width,
                             max_elements=self.domain.output_arity)
            if len(outputs) != self.domain.output_arity:
                raise ValueError("visible examples require exact output arity")
        return self

class CandidateResponse(Contract):
    code: str | None = Field(default=None, max_length=32768)
    abstain: bool = False
    probe_inputs: tuple[bytes, ...] = Field(default=(), max_length=8)
    hypothesis: str = Field(default="", max_length=4096)

    @model_validator(mode="after")
    def choice(self):
        if self.abstain == bool(self.code and self.code.strip()):
            raise ValueError("choose nonempty code or abstain")
        if self.code is not None and len(self.code.encode("utf-8")) > 32768:
            raise ValueError("candidate code exceeds 32 KiB")
        if any(len(item)>64 for item in self.probe_inputs):
            raise ValueError("probe input exceeds 64 bytes")
        return self

class PairOutcome(Contract):
    input_sha256: Sha256
    binary: Observation
    candidate: Observation
    status: Literal["equal", "wrong_output", "wrong_exit", "timeout", "signal", "output_cap", "infrastructure_error"]
    reason: str | None = None

class Counterexample(Contract):
    stdin_bytes: bytes = Field(max_length=64)
    outcome: PairOutcome
    input_sha256: Sha256

class ReplayBundle(Contract):
    bundle_version: Literal[1] = 1
    artifact_sha256: Sha256
    candidate_sha256: Sha256
    execution_contract_sha256: Sha256
    toolchain_sha256: Sha256
    original: Counterexample
    reduced: Counterexample
    attempts: int = Field(ge=0, le=256)
    minimality: Literal["locally_minimal", "budget_exhausted", "not_shrunk"]
    limits: ExecutionLimits
    # Absent only on legacy retained-data bundles; replay must call the guard below.
    image_sha256: Sha256 | None = None
    argv: tuple[str, ...] | None = None
    environment: tuple[tuple[str, str], ...] | None = None
    comparator_version: str | None = Field(default=None, min_length=1)
    move_policy: str | None = Field(default=None, min_length=1)
    trace: tuple[Counterexample, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def replay_pins(self):
        pins = (self.image_sha256, self.argv, self.environment,
                self.comparator_version, self.move_policy)
        if any(item is not None for item in pins) or self.trace:
            self.require_replay_pins()
        return self

    def require_replay_pins(self) -> None:
        """Reject legacy/incomplete bundles before executable replay.

        Pinned claims still require a separately trusted record digest and runner.
        This validates retained structure, never that these executions occurred.
        """
        if (self.image_sha256 is None or self.argv is None or
                self.environment is None or self.comparator_version is None or
                self.move_policy is None or not self.trace):
            raise ValueError("replay pins or retained trace missing")
        if any("\x00" in item for item in self.argv):
            raise ValueError("invalid replay argv")
        if (len({key for key, _ in self.environment}) != len(self.environment) or
                any(not key or "=" in key or "\x00" in key + value
                    for key, value in self.environment)):
            raise ValueError("invalid replay environment")
        if (len(self.trace) != self.attempts or self.trace[0] != self.original or
                self.reduced not in self.trace):
            raise ValueError("retained trace does not match shrink result")

class Verdict(Contract):
    status: Literal["pending", "accepted", "rejected", "not_qualified"]
    reasons: tuple[str, ...]
    evidence_sha256: Sha256 | None = None

Candidate = CandidateResponse
