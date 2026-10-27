"""Fail-closed dev build schedule and whole-instance validity gate.

Receipts must be supplied by the future isolated runner/custodian. These routines
validate recorded claims, and do not independently establish their truth.
"""
from __future__ import annotations
from collections import defaultdict
from typing import Literal
from pydantic import Field, model_validator
from bbr.contracts import BuildArtifact, Contract, FamilySpec, Sha256, Verdict

class ToolchainPin(Contract):
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    gcc_version: str = Field(min_length=1)
    clang_version: str = Field(min_length=1)
    binutils_version: str = Field(min_length=1)
    package_snapshot: str = Field(min_length=1)
    source_date_epoch: int = Field(ge=0)
    manifest_sha256: Sha256
    rights_receipt_sha256: Sha256

class BuildCell(Contract):
    task_id: str
    family_id: str
    codec: Literal["dec", "hex", "bin"]
    compiler: Literal["gcc", "clang"]
    optimization: Literal["O0", "O2"]
    argv: tuple[str, ...]
    strip_argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    toolchain_sha256: Sha256

def build_plan(specs: tuple[FamilySpec, ...], pin: ToolchainPin) -> tuple[BuildCell, ...]:
    """All 96 nominal cells, retained even if later binaries coincide."""
    if len(specs) != 8 or len({s.family_id for s in specs}) != 8:
        raise ValueError("exactly eight distinct dev families required")
    if sum(s.finite_domain_size == 256 for s in specs) != 2:
        raise ValueError("exactly two finite-domain families required")
    rows = []
    for spec in sorted(specs, key=lambda s: s.family_id):
        for codec in ("dec", "hex", "bin"):
            for compiler in ("gcc", "clang"):
                for opt in ("O0", "O2"):
                    task = f"{spec.family_id}-{codec}-{compiler}-{opt}"
                    rows.append(BuildCell(task_id=task, family_id=spec.family_id,
                        codec=codec, compiler=compiler, optimization=opt,
                        argv=(compiler, "-std=c17", f"-{opt}", "-Wall", "-Wextra", "-Werror",
                              "-fno-ident", "-ffile-prefix-map=/work=.", "-Wl,--build-id=none",
                              "/work/source.c", "-o", "/work/program"),
                        strip_argv=("strip", "--strip-all", "/work/program"),
                        environment=(("LC_ALL", "C"), ("TZ", "UTC"),
                                     ("SOURCE_DATE_EPOCH", str(pin.source_date_epoch))),
                        toolchain_sha256=pin.manifest_sha256))
    return tuple(rows)

class ValidityReceipt(Contract):
    task_id: str
    artifact_sha256: Sha256
    source_sha256: Sha256
    toolchain_sha256: Sha256
    reference_sha256: Sha256
    independent_reviewer: str = Field(min_length=1)
    independent_review_receipt_sha256: Sha256
    rights_receipt_sha256: Sha256
    public_domain_sha256: Sha256
    rebuild_sha256: Sha256
    valid_cases: int = Field(gt=0)
    malformed_cases: int = Field(gt=0)
    full_domain_cases: int = Field(ge=0)
    stability_repeats: int = Field(ge=2)
    reference_agrees: bool
    manual_traps_agree: bool
    sanitized_clean: bool
    unsigned_bounds_reviewed: bool
    cross_variants_agree: bool
    deterministic: bool
    ub_negative_control_rejected: bool

def validate_instance(spec: FamilySpec, artifacts: tuple[BuildArtifact, ...],
                      receipts: tuple[ValidityReceipt, ...]) -> Verdict:
    """One missing/failing variant rejects the complete semantic instance."""
    reasons = []
    expected = {(c, p, o) for c in ("dec", "hex", "bin")
                for p in ("gcc", "clang") for o in ("O0", "O2")}
    cells = {(a.codec, a.compiler, a.optimization) for a in artifacts}
    if len(artifacts) != 12 or cells != expected:
        reasons.append("missing_or_duplicate_variant")
    expected_tasks = {f"{spec.family_id}-{c}-{p}-{o}" for c, p, o in expected}
    task_ids = {a.task_id for a in artifacts}
    if (len(task_ids) != 12 or task_ids != expected_tasks or
            any(a.task_id != f"{a.family_id}-{a.codec}-{a.compiler}-{a.optimization}"
                for a in artifacts)):
        reasons.append("invalid_or_duplicate_scheduled_task")
    if any(a.family_id != spec.family_id for a in artifacts):
        reasons.append("family_mismatch")
    if spec.rights_status != "approved":
        reasons.append("rights_pending_or_rejected")
    by_task = {r.task_id: r for r in receipts}
    if len(receipts) != 12 or len(by_task) != 12 or set(by_task) != expected_tasks:
        reasons.append("missing_duplicate_or_extra_receipt")
    if len({a.toolchain_sha256 for a in artifacts}) != 1:
        reasons.append("mixed_artifact_toolchain")
    # Source wrappers vary by codec, but compiler/optimization variants must share it.
    for codec in ("dec", "hex", "bin"):
        if len({a.source_sha256 for a in artifacts if a.codec == codec}) != 1:
            reasons.append(f"mixed_source:{codec}")
    # These are consistency checks on externally supplied claims, not authentication.
    for field in ("toolchain_sha256", "reference_sha256", "public_domain_sha256",
                  "rights_receipt_sha256"):
        if len({getattr(r, field) for r in receipts}) != 1:
            reasons.append(f"mixed_receipt_identity:{field}")
    for artifact in artifacts:
        r = by_task.get(artifact.task_id)
        if r is None:
            continue
        if (r.artifact_sha256 != artifact.artifact_sha256 or
            r.rebuild_sha256 != artifact.artifact_sha256 or
            r.toolchain_sha256 != artifact.toolchain_sha256 or
            r.source_sha256 != artifact.source_sha256):
            reasons.append(f"pin_or_rebuild_mismatch:{artifact.task_id}")
        checks = (r.reference_agrees, r.manual_traps_agree, r.sanitized_clean,
                  r.unsigned_bounds_reviewed, r.cross_variants_agree, r.deterministic,
                  r.ub_negative_control_rejected)
        if not all(checks):
            reasons.append(f"validity_failed:{artifact.task_id}")
        if spec.finite_domain_size is not None and r.full_domain_cases != spec.finite_domain_size:
            reasons.append(f"incomplete_finite_domain:{artifact.task_id}")
    return Verdict(status="rejected" if reasons else "accepted", reasons=tuple(reasons))

def group_execution_identities(artifacts: tuple[BuildArtifact, ...]) -> tuple[tuple[str, ...], ...]:
    """Complete stripped ELF + execution contract, only within family and codec.

    .text coincidences intentionally do not affect analytic weight.
    """
    if len({a.task_id for a in artifacts}) != len(artifacts):
        raise ValueError("duplicate scheduled task ID")
    grouped = defaultdict(list)
    for a in artifacts:
        key = (a.family_id, a.codec, a.artifact_sha256, a.execution_contract_sha256)
        grouped[key].append(a.task_id)
    return tuple(tuple(sorted(grouped[key])) for key in sorted(grouped))
