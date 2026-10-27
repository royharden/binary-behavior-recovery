"""Receipt checks only: supplied claims do not establish human independence."""
from __future__ import annotations

from dataclasses import dataclass
from .preregister import closed, require_digest, text


@dataclass(frozen=True)
class Admission:
    edition: str
    author: str
    custodian: str
    evaluator: str
    builder_identities: tuple[str, ...]
    roy_appointment_receipt: str
    rights_receipt: str
    independence_history_receipt: str
    validity_receipt: str
    disjointness_receipt: str
    source_commitment: str
    partition_commitment: str
    canary_commitment: str
    freeze_receipt: str
    heldout_creation_after_freeze_receipt: str
    mount_isolation_receipt: str
    sample_admission_receipt: str
    release_rights_receipt: str
    accepted_by_roy: bool = False

    def validate(self, edition: str) -> None:
        if self.edition != edition or self.accepted_by_roy is not True:
            raise ValueError("PENDING — needs Roy: independent appointment/rights/admission")
        for name in ("author", "custodian", "evaluator"):
            text(getattr(self, name), name)
        if not isinstance(self.builder_identities, tuple) or any(not isinstance(x, str) or not x for x in self.builder_identities):
            raise ValueError("builder identity tuple required")
        if self.evaluator == self.author or any(x in self.builder_identities for x in (self.author, self.custodian, self.evaluator)):
            raise ValueError("independent author/custodian and separate evaluator required")
        if not self.builder_identities:
            raise ValueError("builder exposure roster required")
        for name, value in vars(self).items():
            if name.endswith("receipt") or name.endswith("commitment"):
                require_digest(value)


def admission_from_dict(raw: dict) -> Admission:
    closed(raw, set(Admission.__dataclass_fields__), "admission")
    if not isinstance(raw["builder_identities"], list):
        raise ValueError("builder identity list required")
    result = Admission(**{**raw, "builder_identities": tuple(raw["builder_identities"])})
    result.validate(result.edition)
    return result
