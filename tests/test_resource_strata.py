"""Authored software-regression arithmetic/projection tests, fixture origin only.

No provider, database, independent author/custodian or benchmark corpus is used.
The strata scorer stub tests projection only, not scoring/admission correctness.
"""

from copy import deepcopy
from decimal import Decimal

import pytest

from bbr.report.resource_metrics import ResourceSummaryError, summarize_resources
from evaluation import strata
from evaluation.preregister import digest
from support.dl2.fixtures import canonical_digest, fixture_sha, pass_references
from support.dl2.fixtures import projection_fixture, resource_inputs


def resources(ledger, receipts, **kwargs):
    return summarize_resources(ledger, receipts, campaign_id="software-no-campaign",
                               origin="fixture", **kwargs)


def test_unique_and_incremental_shared_m_money_not_double_charged():
    ledger, receipts = resource_inputs((("M:0", "settled", "0.03", "0.03"),
        ("R:1", "settled", "0.02", "0.02"), ("P:1", "settled", "0.04", "0.04")))
    result = resources(ledger, receipts, pass_counts=pass_references())
    assert Decimal(result["campaign_unique"]["settled_spend_usd"]) == Decimal("0.09")
    groups = {g["arm"]: g for g in result["groups"]}
    assert Decimal(groups["R"]["incremental"]["settled_spend_usd"]) == Decimal("0.02")
    assert Decimal(groups["P"]["usd_per_pass"]) == Decimal("0.07")
    assert groups["R"]["shared_m_reuse"][0]["new_charge_usd"] == "0"
    assert result["campaign_unique"]["measurements"]["input_tokens"] is None


@pytest.mark.parametrize("reserve,charge,expected_charge,expected_reserve", [
    ("0.10", None, "0", "0.10"), ("0.10", "0.20", "0.20", "0")])
def test_unknown_bill_or_reserve_is_preserved_but_not_settled(reserve, charge, expected_charge, expected_reserve):
    ledger, receipts = resource_inputs((("M:0", "unknown", reserve, charge),))
    result = resources(ledger, receipts, pass_counts=pass_references())
    costs = result["campaign_unique"]
    assert Decimal(costs["settled_spend_usd"]) == 0
    assert Decimal(costs["unresolved_recorded_charge_usd"]) == Decimal(expected_charge)
    assert Decimal(costs["unpriced_reserved_liability_usd"]) == Decimal(expected_reserve)
    assert all(g["usd_per_pass"] is None for g in result["groups"])


def test_exact_never_sent_retry_is_retained():
    ledger, receipts = resource_inputs((("M:0", "never_sent", "0.03", "0"),
                                       ("M:0", "settled", "0.03", "0.02")))
    result = resources(ledger, receipts)
    assert result["campaign_unique"]["unique_attempts"] == 2
    assert Decimal(result["campaign_unique"]["settled_spend_usd"]) == Decimal("0.02")
    assert result["attempts"][0]["status"] == "never_sent"


@pytest.mark.parametrize("mutation", ["duplicate", "missing", "request_digest", "origin", "config", "ledger_total"])
def test_resource_join_refuses_conflicting_lineage(mutation):
    ledger, receipts = resource_inputs()
    if mutation == "duplicate":
        receipts.append(deepcopy(receipts[0]))
    elif mutation == "missing":
        receipts.clear()
    elif mutation == "request_digest":
        receipts[0]["request_sha256"] = fixture_sha("wrong request")
    elif mutation == "origin":
        receipts[0]["origin"] = "live"
    elif mutation == "config":
        receipts[0]["request"]["model_config"]["seed"] = 99
    else:
        ledger["committed_usd"] = "0"
    with pytest.raises(ResourceSummaryError):
        resources(ledger, receipts)


def test_token_source_hash_and_known_usage_match_ledger():
    ledger, receipts = resource_inputs()
    row = receipts[0]
    source = {"request_sha256": row["request_sha256"], "origin": "fixture",
              "usage": {"input_tokens": 7, "output_tokens": 3, "usd": "0.03"}}
    row.update(provider_record=source, provider_record_sha256=canonical_digest(source),
               provider_record_reason=None)
    result = resources(ledger, receipts)
    assert result["campaign_unique"]["measurements"]["input_tokens"] == 7
    assert result["campaign_unique"]["measurements"]["peak_memory_bytes"] is None
    row["provider_record"]["usage"]["usd"] = "0.04"
    row["provider_record_sha256"] = canonical_digest(row["provider_record"])
    with pytest.raises(ResourceSummaryError, match="USD differs"):
        resources(ledger, receipts)


def test_zero_pass_and_partial_usage_remain_null():
    ledger, receipts = resource_inputs()
    result = resources(ledger, receipts, pass_counts=pass_references(passes=0))
    assert all(g["usd_per_pass"] is None and g["usd_per_pass_reason"] == "zero passes" for g in result["groups"])
    assert result["campaign_unique"]["measurements"]["wall_seconds"] is None


def project(monkeypatch, score, registration, *, expected=None):
    calls = []
    def trusted_software_score_stub(reg, rows, **kwargs):
        # Stub ONLY the scorer boundary; no custody receipt or oracle is invented.
        calls.append((reg, rows, kwargs))
        return deepcopy(score)
    monkeypatch.setattr(strata, "score_rows", trusted_software_score_stub)
    result = strata.summarize_strata(registration, [], partitions={"software-unit-stub": True},
        campaign_receipt={"software-unit-stub": True},
        expected_score_sha256=digest(score) if expected is None else expected)
    assert len(calls) == 1 and calls[0][0] is registration
    return result


def test_strata_fixed_denominators_and_primary_nominal_difference(monkeypatch):
    registration, score = projection_fixture()
    result = project(monkeypatch, score, registration)
    assert result["scheduled_rows"] == 1344
    for entry in result["tables"]["by_model_arm"]:
        assert entry["nominal_valid_pass"] == {"n": 72, "N": 96, "value": 0.75, "reason": None}
        assert entry["primary_identity_group_estimate"] == 0.5
    assert all(row["scheduled"] == 12 for row in result["tables"]["by_family"])
    assert all(row["scheduled"] == 32 and row["primary_identity_group_estimate"] is None
               for row in result["tables"]["by_codec"])
    assert {row["scheduled"] for row in result["tables"]["by_tier"]} == {24, 72}
    assert result["unsupported_metrics"]["paired_bootstrap"]["value"] is None


def test_missing_row_status_stays_in_nominal_denominator(monkeypatch):
    registration, score = projection_fixture()
    row = next(r for r in score["rows"] if r["model"] == "software-model-a" and r["arm"] == "M")
    row.update(status="not_run", complete=False, unknown_reason="authored software missing-row fixture",
               passes={k: False for k in row["passes"]}, case_counts={k: 0 for k in row["case_counts"]})
    summary = next(s for s in score["summaries"] if s["model"] == row["model"] and s["arm"] == row["arm"])
    summary.update(primary=None, reason="incomplete_fixed_population", complete=False)
    summary["family_estimates"][row["family_id"]] = None
    score["complete"] = False
    result = project(monkeypatch, score, registration)
    table = next(r for r in result["tables"]["by_model_arm"] if r["model"] == row["model"] and r["arm"] == row["arm"])
    assert table["nominal_valid_pass"]["N"] == 96 and table["nominal_valid_pass"]["value"] is None
    assert table["status_counts"]["not_run"] == 1 and table["unknown_rows"] == 1


@pytest.mark.parametrize("mutation", ["duplicate", "missing", "dimension", "identity", "origin"])
def test_strata_refuses_untrusted_roster_or_provenance(monkeypatch, mutation):
    registration, score = projection_fixture()
    if mutation == "duplicate":
        score["rows"][1] = deepcopy(score["rows"][0])
    elif mutation == "missing":
        score["rows"].pop()
    elif mutation == "dimension":
        score["rows"][0]["codec"] = "not-a-codec"
    elif mutation == "identity":
        score["rows"][0]["identity"][2] = fixture_sha("wrong symbolic artifact")
    else:
        score["origin"] = "live"
    with pytest.raises(ValueError):
        project(monkeypatch, score, registration)


def test_strata_checks_canonical_commitment_before_projection(monkeypatch):
    registration, score = projection_fixture()
    with pytest.raises(ValueError, match="commitment"):
        project(monkeypatch, score, registration, expected=fixture_sha("unrelated software score"))
