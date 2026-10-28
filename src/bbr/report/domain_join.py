"""Inventory-backed retained domain/certificate source composition.

Only the independent retained-analysis producer decides qualification. This
module opens no worker, provider, generator or database, and enumerates no domain.
Inventory consistency and a supplied binding commitment are not custody proof.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def recompute_domains(root: Path, sources: dict, *, files: dict[str, Path],
                      inventory: dict[str, dict], registration: Any,
                      partitions: dict, campaign_receipt: dict) -> dict:
    """Delegate each bounded source descriptor to ``summarize_domain``.

    ``expected_binding_sha256`` is supplied separately from the binding file.
    It is never inferred from the binding body or the raw inventory file hash.
    Missing inputs remain None; malformed supplied source fails closed. The
    caller must have verified global scoring and ALL-final-campaign locks first.
    """
    # Local imports keep archive -> domain join composition free of import cycles.
    from .archive import MAX_FILE, ReportError, _file_hash
    from .archive import canonical, digest, read_json, safe_file

    def closed(value: object, fields: set[str], label: str) -> dict:
        if not isinstance(value, dict) or set(value) != fields:
            raise ReportError(f"closed {label} shape required")
        return value

    def sha256(value: object) -> str:
        if (not isinstance(value, str) or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)):
            raise ReportError("canonical domain binding SHA256 required")
        return value

    source_entries: dict[str, dict] = {}

    def supplied(relative: object) -> Any:
        if relative is None:
            return None
        if not isinstance(relative, str) or relative not in files or relative not in inventory:
            raise ReportError("domain source must be a retained data inventory path")
        entry = closed(inventory[relative],
            {"path", "kind", "sha256", "replay_record_sha256"}, "domain inventory entry")
        if (entry["path"] != relative or entry["kind"] != "data"
                or entry["replay_record_sha256"] is not None):
            raise ReportError("domain sources require bounded data entries, not replay entries")
        expected_raw = sha256(entry["sha256"])
        path = safe_file(root, relative)  # Default16 MiB; no replay exception.
        retained = files[relative]
        if not isinstance(retained, Path) or retained.resolve(strict=True) != path:
            raise ReportError("domain source differs from validated inventory path")
        if _file_hash(path, MAX_FILE) != expected_raw:
            raise ReportError("domain source differs from retained raw file hash")
        source_entries[relative] = {"path": relative, "sha256": expected_raw}
        return read_json(path)

    registration.validate()
    closed(sources, {"schema", "entries"}, "domain source manifest")
    if sources["schema"] != "bbr.domain-sources.v1":
        raise ReportError("unsupported domain source schema")
    descriptors = sources["entries"]
    if not isinstance(descriptors, list) or len(descriptors) > len(registration.final_keys):
        raise ReportError("bounded nominal domain source entry list required")
    if not descriptors:
        return {"status": "not_supplied", "reason": "retained domain source entries unavailable",
                "source_recomputed": False, "summaries": [], "source_entries": [],
                "population_rate": None, "population_rate_reason": "no population rate inferred"}

    try:
        from bbr.contracts import Domain
        from evaluation.domain_certificate import summarize_domain
    except ImportError as error:
        raise ReportError("retained domain certificate producer unavailable") from error

    descriptor_fields = {"domain", "domain_policy", "binding", "expected_binding_sha256",
                         "observed_probes", "records"}
    summaries = []
    bound_identities = set()
    binding_commitments = []
    for descriptor in descriptors:
        closed(descriptor, descriptor_fields, "domain source descriptor")
        expected_binding = descriptor["expected_binding_sha256"]
        if expected_binding is not None:
            sha256(expected_binding)
        domain_wire = supplied(descriptor["domain"])
        domain = None
        if descriptor["domain"] is not None:
            if not isinstance(domain_wire, dict):
                raise ReportError("supplied public Domain source must be an object")
            domain = Domain.model_validate_json(canonical(domain_wire))
        policy = supplied(descriptor["domain_policy"])
        binding = supplied(descriptor["binding"])
        observed = supplied(descriptor["observed_probes"])
        records = supplied(descriptor["records"])
        for field, value in (("domain_policy", policy), ("binding", binding),
                             ("observed_probes", observed)):
            if descriptor[field] is not None and not isinstance(value, dict):
                raise ReportError(f"supplied {field} source must be an object")
        if descriptor["records"] is not None and (
            not isinstance(records, list) or len(records) > 256
            or any(not isinstance(record, dict) for record in records)
        ):
            raise ReportError("supplied retained domain records must be a bounded object array")
        # Check the present public wire envelopes even when another source is
        # unavailable. Deep qualification/identity analysis remains the producer.
        if policy is not None:
            closed(policy, {"schema", "tasks"}, "domain policy source")
            if policy["schema"] != "bbr.domain-policy.v1" or not isinstance(policy["tasks"], list):
                raise ReportError("unsupported domain policy source")
        if observed is not None:
            closed(observed, {"schema", "task_id", "model", "arm", "candidate_sha256",
                              "lock_sha256", "public_input_hex"}, "observed probe source")
            if (observed["schema"] != "bbr.observed-probes.v1"
                    or not isinstance(observed["public_input_hex"], list)
                    or len(observed["public_input_hex"]) > 48):
                raise ReportError("unsupported or oversized observed probe source")
        if binding is not None:
            closed(binding, {"schema", "task_id", "model", "arm", "candidate_sha256",
                "artifact_sha256", "execution_contract_sha256", "comparator_version",
                "registration_sha256", "lock_sha256", "partition_sha256", "domain_policy_sha256",
                "canonical_plan_sha256", "observed_probes_sha256", "records_sha256"}, "domain binding source")
            if binding["schema"] != "bbr.domain-binding.v1":
                raise ReportError("unsupported domain binding source")
            # Check the separately retained commitment even if another input is
            # absent. Do not let the producer's unavailable path hide a mismatch.
            if expected_binding is not None and digest(canonical(binding)) != expected_binding:
                raise ReportError("domain binding differs from separate trusted canonical commitment")
            names = ("task_id", "model", "arm", "candidate_sha256")
            if all(isinstance(binding.get(name), str) for name in names):
                identity = tuple(binding[name] for name in names)
                if identity in bound_identities:
                    raise ReportError("duplicate retained domain candidate identity")
                bound_identities.add(identity)
        summary = summarize_domain(registration, domain=domain, partitions=partitions,
            campaign_receipt=campaign_receipt, domain_policy=policy, binding=binding,
            expected_binding_sha256=expected_binding, observed_probes=observed, records=records)
        if not isinstance(summary, dict) or summary.get("schema") != "bbr.domain-summary.v1":
            raise ReportError("domain producer returned an unsupported summary")
        canonical(summary)
        summaries.append(summary)
        binding_commitments.append(expected_binding)
    return {"status": "retained_domain_summaries", "reason": None,
            "source_recomputed": True, "summaries": summaries,
            "source_entries": [source_entries[path] for path in sorted(source_entries)],
            "expected_binding_sha256": binding_commitments,
            "population_rate": None, "population_rate_reason": "single-row events are not a population rate",
            "verification_scope": "retained consistency only; not execution, admission or custody authenticity"}
