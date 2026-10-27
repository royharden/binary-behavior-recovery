"""Custodian-supplied metadata admission, not held-out content generation."""
from __future__ import annotations

from dataclasses import dataclass
from .admission import Admission
from .preregister import Registration, require_digest


@dataclass(frozen=True)
class FamilyReceipt:
    family_id: str
    semantic_fingerprint: str
    tier: str
    source_sha256: str
    reference_sha256: str
    grammar_sha256: str
    trap_sha256: str
    original_rights_receipt: str
    independent_validity_receipt: str
    finite_capacity: int | None


def admit_metadata(registration: Registration, admission: Admission, families: tuple[FamilyReceipt, ...], dev_semantic_fingerprints: tuple[str, ...]) -> dict:
    registration.validate()
    admission.validate(registration.edition)
    if len(families) != 8 or {f.family_id for f in families} != {c.family_id for c in registration.cells}:
        raise ValueError("all eight sealed family receipts required; no replacement")
    fingerprints = [f.semantic_fingerprint for f in families]
    if len(set(fingerprints)) != 8 or set(fingerprints) & set(dev_semantic_fingerprints):
        raise ValueError("semantic duplicates/relabeling fail admission")
    if len(dev_semantic_fingerprints) != 8 or len(set(dev_semantic_fingerprints)) != 8:
        raise ValueError("complete dev semantic roster required")
    for f in families:
        for value in (f.semantic_fingerprint, f.source_sha256, f.reference_sha256, f.grammar_sha256, f.trap_sha256, f.original_rights_receipt, f.independent_validity_receipt):
            require_digest(value)
        if {c.tier for c in registration.cells if c.family_id == f.family_id} != {f.tier}:
            raise ValueError("family tier differs from preregistration")
        if f.tier == "finite" and f.finite_capacity != 256:
            raise ValueError("finite tier must certify exactly 256 canonical values")
        if f.tier == "ordinary" and (type(f.finite_capacity) is not int or f.finite_capacity < 328):
            raise ValueError("ordinary capacity must fit disjoint 8+64+256 values")
    return {"status": "metadata_receipts_present", "registration_sha256": registration.sha256, "independence_proven_by_code": False, "runtime_validity": "requires_independent_receipt_verification"}
