"""Authored SOFTWARE REGRESSION checks, never an independent corpus.

All finite values and literal observations below are software parser/bookkeeping
fixtures. No executable, model result, admitted campaign or real authority is
represented. Factory/product calls occur only during later authorized tests.
Candidate source is never compiled, imported or executed by this module.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json

import pytest


def domain_case(matrix, *, fail_at: int | None = 200, sample_size: int = 8) -> dict:
    """Create a hand-computable constant-output software comparison fixture.

    This is a direct domain-analyzer fixture; a fail_at observation must also be
    applied to primary row observations before composing a whole archive. The
    all-pass variant is consistent with the supplied matrix P row by construction.
    """
    from bbr.contracts import Observation
    from bbr.corpus.codecs import encode
    from bbr.differential import COMPARATOR_VERSION, compare_observations
    from evaluation.preregister import digest

    cell = next(c for c in matrix.registration.cells if c.tier == "finite" and c.codec == "dec")
    model, arm = matrix.registration.models[0], "P"
    final = next(f for f in matrix.receipt["finals"]
                 if (f["task_id"], f["model"], f["arm"]) == (cell.task_id, model, arm))
    assert final["status"] == "candidate", "domain fixture needs patterned software matrix"
    domain = matrix.domains[cell.family_id]
    policy = deepcopy(matrix.domain_policy)
    # All variants of this software family inherit the same authored recipe.
    for entry in policy["tasks"]:
        if entry["task_id"].startswith(cell.family_id + "-"):
            entry["sampling"] = {
                "recipe_id": "AUTHORED_SOFTWARE_REGRESSION_FIXED_SAMPLE",
                "size": sample_size,
                "canonical_keys": [json.dumps([v], separators=(",", ":"))
                                   for v in range(72, 72 + min(sample_size, 184))],
            }
    pins = dict(matrix.registration.pins)
    pins["domain_policy"] = digest(policy)
    registration = replace(matrix.registration, pins=tuple(sorted(pins.items())))
    receipt = deepcopy(matrix.receipt)
    receipt["registration_sha256"] = registration.sha256
    receipt.pop("lock_sha256")
    receipt["lock_sha256"] = digest(receipt)
    observed = {
        "schema": "bbr.observed-probes.v1", "task_id": cell.task_id,
        "model": model, "arm": arm, "candidate_sha256": final["candidate_sha256"],
        "lock_sha256": receipt["lock_sha256"],
        "public_input_hex": [encode((8,), cell.codec, domain.width).hex(),
                             encode((9,), cell.codec, domain.width).hex(),
                             b"software-public-invalid-00".hex()],
    }
    records = []
    for value in range(256):
        raw = encode((value,), cell.codec, domain.width)
        oracle = Observation(stdout_bytes=encode((0,), cell.codec, domain.width),
                             exit_code=0, status="ok")
        candidate = Observation(stdout_bytes=encode((1 if value == fail_at else 0,),
                                                     cell.codec, domain.width),
                                exit_code=0, status="ok")
        pair = compare_observations(oracle, candidate, stdin_bytes=raw)
        records.append({
            "task_id": cell.task_id, "model": model, "arm": arm,
            "candidate_sha256": final["candidate_sha256"],
            "artifact_sha256": cell.artifact_sha256,
            "execution_contract_sha256": cell.execution_contract_sha256,
            "comparator_version": COMPARATOR_VERSION, "stdin_hex": raw.hex(),
            "outcome": pair.model_dump(mode="json"),
        })
    target_policy = next(entry for entry in policy["tasks"] if entry["task_id"] == cell.task_id)
    binding = {
        "schema": "bbr.domain-binding.v1", "task_id": cell.task_id,
        "model": model, "arm": arm, "candidate_sha256": final["candidate_sha256"],
        "artifact_sha256": cell.artifact_sha256,
        "execution_contract_sha256": cell.execution_contract_sha256,
        "comparator_version": COMPARATOR_VERSION,
        "registration_sha256": registration.sha256,
        "lock_sha256": receipt["lock_sha256"],
        "partition_sha256": pins["partitions"], "domain_policy_sha256": pins["domain_policy"],
        "canonical_plan_sha256": target_policy["canonical_plan_sha256"],
        "observed_probes_sha256": digest(observed), "records_sha256": digest(records),
    }
    return {"registration": registration, "cell": cell, "kwargs": {
        "domain": domain, "partitions": matrix.partitions, "campaign_receipt": receipt,
        "domain_policy": policy, "binding": binding,
        "expected_binding_sha256": digest(binding), "observed_probes": observed,
        "records": records}}


def _summarize(case: dict, **changes) -> dict:
    from evaluation.domain_certificate import summarize_domain

    return summarize_domain(case["registration"], **{**case["kwargs"], **changes})


def test_domain_software_false_pass_calibration(patterned_matrix):
    case = domain_case(patterned_matrix)
    result = _summarize(case)
    assert result["status"] == "qualified"
    certificate, calibration = result["certificate"], result["calibration"]
    assert certificate["label"] == "exhaustive_on_declared_domain"
    assert certificate["canonical_total"] == 256
    assert certificate["primary184_denominator"] == 184
    assert certificate["all256_agreement"] is False
    assert certificate["primary184_private_agreement"] is False
    assert (certificate["probe_observed_count"], certificate["public_but_unobserved_count"],
            certificate["observed_malformed_probe_count"]) == (2, 62, 1)
    assert calibration["sample_agreement"] is True
    assert calibration["false_pass_vs256"] is True
    assert calibration["false_pass_vs184"] is True
    assert calibration["effective_size"] == 8
    assert calibration["unseen_private_count"] == 176
    assert "not a population rate" in calibration["interpretation"]


def test_domain_private_sample_exhaustion_is_disclosed(patterned_matrix):
    result = _summarize(domain_case(patterned_matrix, sample_size=256))
    calibration = result["calibration"]
    assert calibration["requested_size"] == 256
    assert calibration["effective_size"] == 184
    assert calibration["exhausts_private_pool"] is True
    assert calibration["unseen_private_count"] == 0
    assert calibration["sample_agreement"] is False
    assert calibration["false_pass_vs256"] is False
    assert "no additional unseen private coverage" in calibration["coverage_note"]


def test_domain_valid_partial_preserves_unavailable_disclosures(patterned_matrix):
    case = domain_case(patterned_matrix, fail_at=None)
    result = _summarize(case, domain=None)
    assert result["status"] == "not_qualified"
    assert result["reason"] == "domain_truth_unavailable"
    assert result["certificate"] is None and result["calibration"] is None
    assert result["provenance"] is None
    assert any("Domain" in check for check in result["unavailable_checks"])


def test_domain_missing_truth_cannot_mask_present_corruption(patterned_matrix):
    case = domain_case(patterned_matrix)
    bad_policy = deepcopy(case["kwargs"]["domain_policy"])
    bad_policy["tasks"].pop()
    with pytest.raises(ValueError, match="policy.*commitment|roster"):
        _summarize(case, domain=None, domain_policy=bad_policy)
    bad_records = deepcopy(case["kwargs"]["records"])
    bad_records[0]["outcome"]["input_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="input digest"):
        _summarize(case, binding=None, expected_binding_sha256=None, records=bad_records)
    with pytest.raises(ValueError, match="SHA256"):
        _summarize(case, binding=None, expected_binding_sha256="NOT_A_SOFTWARE_SHA256")


def test_domain_canonical_binding_is_not_raw_pretty_json_hash(patterned_matrix):
    case = domain_case(patterned_matrix)
    pretty = json.dumps(case["kwargs"]["binding"], indent=2).encode("utf-8")
    raw_hash = sha256(pretty).hexdigest()
    assert raw_hash != case["kwargs"]["expected_binding_sha256"]
    with pytest.raises(ValueError, match="separate trusted commitment"):
        _summarize(case, expected_binding_sha256=raw_hash)


def test_domain_oracle_fault_is_not_comparison_success(patterned_matrix):
    from bbr.contracts import Observation
    from bbr.corpus.codecs import encode
    from bbr.differential import compare_observations
    from evaluation.preregister import digest

    case = domain_case(patterned_matrix, fail_at=None)
    records = deepcopy(case["kwargs"]["records"])
    raw = bytes.fromhex(records[0]["stdin_hex"])
    # This is known software observation data, not worker/candidate execution.
    bad_arity = Observation(stdout_bytes=encode((0, 0), "dec", 8), exit_code=0, status="ok")
    records[0]["outcome"] = compare_observations(bad_arity, bad_arity,
                                               stdin_bytes=raw).model_dump(mode="json")
    binding = {**case["kwargs"]["binding"], "records_sha256": digest(records)}
    result = _summarize(case, records=records, binding=binding,
                        expected_binding_sha256=digest(binding))
    assert result["status"] == "not_qualified"
    assert result["certificate"]["invalid_oracle_count"] == 1
    assert result["certificate"]["all256_agreement"] is None
    assert result["calibration"]["sample_agreement"] is None


def domain_inventory(tmp_path, case: dict) -> dict:
    """Persist only software-test sidecars inside the caller test temporary root."""
    from bbr.report.archive import canonical, digest

    files, inventory = {}, {}
    descriptor = {}
    for field in ("domain", "domain_policy", "binding", "observed_probes", "records"):
        value = case["kwargs"][field]
        if field == "domain":
            value = value.model_dump(mode="json")
        relative = f"software-only-{field}.json"
        path = tmp_path / relative
        raw = canonical(value)
        path.write_bytes(raw)
        files[relative] = path
        inventory[relative] = {"path": relative, "kind": "data", "sha256": digest(raw),
                               "replay_record_sha256": None}
        descriptor[field] = relative
    descriptor["expected_binding_sha256"] = case["kwargs"]["expected_binding_sha256"]
    return {"files": files, "inventory": inventory,
            "sources": {"schema": "bbr.domain-sources.v1", "entries": [descriptor]}}


def test_domain_inventory_join_retains_authority_limits(patterned_matrix, tmp_path):
    from bbr.report.domain_join import recompute_domains

    case = domain_case(patterned_matrix, fail_at=None)
    retained = domain_inventory(tmp_path, case)
    result = recompute_domains(tmp_path, retained["sources"], files=retained["files"],
        inventory=retained["inventory"], registration=case["registration"],
        partitions=case["kwargs"]["partitions"],
        campaign_receipt=case["kwargs"]["campaign_receipt"])
    assert result["source_recomputed"] is True
    assert result["summaries"][0]["certificate"]["all256_agreement"] is True
    assert result["population_rate"] is None
    assert result["expected_binding_sha256"] == [case["kwargs"]["expected_binding_sha256"]]
    assert "not execution" in result["verification_scope"]


def test_domain_inventory_rejects_tamper_and_replay_type(patterned_matrix, tmp_path):
    from bbr.report.archive import ReportError
    from bbr.report.domain_join import recompute_domains

    case = domain_case(patterned_matrix, fail_at=None)
    retained = domain_inventory(tmp_path, case)
    arguments = {"files": retained["files"], "inventory": retained["inventory"],
                 "registration": case["registration"],
                 "partitions": case["kwargs"]["partitions"],
                 "campaign_receipt": case["kwargs"]["campaign_receipt"]}
    relative = retained["sources"]["entries"][0]["records"]
    retained["inventory"][relative]["kind"] = "replay"
    with pytest.raises(ReportError, match="bounded data"):
        recompute_domains(tmp_path, retained["sources"], **arguments)
    retained["inventory"][relative]["kind"] = "data"
    retained["files"][relative].write_bytes(b"[]")
    with pytest.raises(ReportError, match="raw file hash"):
        recompute_domains(tmp_path, retained["sources"], **arguments)
