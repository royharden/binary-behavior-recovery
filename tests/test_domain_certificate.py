"""AUTHORED SOFTWARE TEST FIXTURE; origin=fixture; builder-lineage/nonindependent.

Software regression coverage only, not heldout/benchmark or independent admission.
"""
from copy import deepcopy

import pytest

from bbr.contracts import Domain, Observation
from evaluation.domain_certificate import summarize_domain
from evaluation.preregister import digest
from support.dl1.domain_fixtures import change_outcome, fixture_digest, make_domain_fixture


def summarize(fixture, **overrides):
    return summarize_domain(fixture.registration, **{**fixture.arguments, **overrides})


def assert_partial(result, reason):
    assert result["status"] == "not_qualified"
    assert result["reason"] == reason
    assert result["provenance"] is result["certificate"] is result["calibration"] is None
    assert result["unavailable_checks"]


@pytest.mark.parametrize("codec", ["dec", "hex", "bin"])
def test_complete256_counts_and_scope_preserve_private184(codec):
    f = make_domain_fixture(codec=codec)
    result = summarize(f)
    cert = result["certificate"]
    assert f.registration.origin == "fixture"
    assert result["status"] == "qualified"
    assert "unavailable_checks" not in result
    assert cert["canonical_total"] == 256
    assert cert["visible_count"] == 8
    assert cert["probe_observed_count"] == 1
    assert cert["public_but_unobserved_count"] == 63
    assert cert["observed_malformed_probe_count"] == 1
    assert cert["private_count"] == cert["primary184_denominator"] == 184
    assert cert["all256_agreement"] is cert["primary184_private_agreement"] is True
    assert cert["label"] == "exhaustive_on_declared_domain"
    assert "not arbitrary stdin" in cert["scope"]
    assert result["identity"] == {k: f.arguments["binding"][k] for k in ("task_id", "model", "arm", "candidate_sha256")}


@pytest.mark.parametrize("failure,private,vs184", [(0, True, False), (8, True, False), (100, False, True)])
def test_sample_false_pass_is_separate_from_full_and_private_agreement(failure, private, vs184):
    f = make_domain_fixture()
    change_outcome(f, failure, candidate=Observation(stdout_bytes=b"0,0\n", status="ok", exit_code=0))
    r = summarize(f)
    assert r["certificate"]["all256_agreement"] is False
    assert r["certificate"]["primary184_private_agreement"] is private
    assert r["calibration"]["sample_agreement"] is True
    assert r["calibration"]["false_pass_vs256"] is True
    assert r["calibration"]["false_pass_vs184"] is vs184


def test_sample_failure_is_not_false_pass():
    f = make_domain_fixture()
    change_outcome(f, 72, candidate=Observation(stdout_bytes=b"0\n", status="ok", exit_code=0))
    cal = summarize(f)["calibration"]
    assert cal["sample_agreement"] is False
    assert cal["false_pass_vs256"] is cal["false_pass_vs184"] is False


@pytest.mark.parametrize("size", [184, 200, 256])
def test_private_sample_exhaustion_adds_no_unseen_coverage(size):
    cal = summarize(make_domain_fixture(sample_size=size))["calibration"]
    assert cal["requested_size"] == size
    assert cal["effective_size"] == 184
    assert cal["exhausts_private_pool"] is True
    assert cal["unseen_private_count"] == 0
    assert cal["coverage_note"] == "no additional unseen private coverage"


def test_missing_sample_preserves_certificate_but_cannot_calibrate():
    r = summarize(make_domain_fixture(sample_size=None))
    assert r["certificate"]["all256_agreement"] is True
    assert r["calibration"]["reason"] == "precommitted_sample_unavailable"
    assert r["calibration"]["sample_agreement"] is None


@pytest.mark.parametrize("size", [0, 257, True])
def test_invalid_sample_size_fails_even_without_domain(size):
    f = make_domain_fixture()
    f.arguments["domain_policy"]["tasks"][0]["sampling"]["size"] = size
    f.refresh(policy=True)
    with pytest.raises(ValueError, match="sample size"):
        summarize(f, domain=None)


@pytest.mark.parametrize("corruption", ["malformed", "duplicate", "outside"])
def test_deferred1_missing_domain_does_not_hide_repinned_bad_policy(corruption):
    f = make_domain_fixture()
    tasks = f.arguments["domain_policy"]["tasks"]
    if corruption == "malformed":
        tasks[0]["unexpected"] = "fixture"
    elif corruption == "duplicate":
        tasks[1] = deepcopy(tasks[0])
    else:
        tasks[0]["task_id"] = "outside-fixture-roster"
    f.refresh(policy=True)
    with pytest.raises(ValueError):
        summarize(f, domain=None)


@pytest.mark.parametrize("field,value", [("extra", 1), ("outcome", []),
    ("candidate_sha256", "0" * 64), ("execution_contract_sha256", "0" * 64),
    ("comparator_version", "wrong-comparator"), ("model", "outside-model")])
def test_deferred2_missing_policy_keeps_record_local_and_identity_checks(field, value):
    f = make_domain_fixture()
    f.arguments["records"][1][field] = value
    f.refresh()
    with pytest.raises(ValueError):
        summarize(f, domain_policy=None)


@pytest.mark.parametrize("field,value", [("input_sha256", "0" * 64), ("status", "wrong_output"), ("reason", "fabricated")])
def test_deferred3_missing_binding_still_recomputes_pair(field, value):
    f = make_domain_fixture()
    f.arguments["records"][0]["outcome"][field] = value
    with pytest.raises(ValueError):
        summarize(f, binding=None)


def test_deferred3_invalid_trusted_digest_fails_without_binding():
    with pytest.raises(ValueError, match="SHA256"):
        summarize(make_domain_fixture(), binding=None, expected_binding_sha256="malformed")


@pytest.mark.parametrize("missing,reason", [("domain", "domain_truth_unavailable"),
    ("partitions", "frozen_partitions_unavailable"), ("campaign_receipt", "post_final_lock_receipt_unavailable"),
    ("domain_policy", "domain_sampling_policy_unavailable"), ("binding", "paired_identity_binding_unavailable"),
    ("expected_binding_sha256", "trusted_binding_commitment_unavailable"),
    ("observed_probes", "observed_probe_commitment_unavailable"), ("records", "retained_records_unavailable")])
def test_deferred4_each_missing_source_is_explicit_and_never_qualified(missing, reason):
    f = make_domain_fixture()
    result = summarize(f, **{missing: None})
    assert_partial(result, reason)
    assert result["identity"]["candidate_sha256"] == f.arguments["binding"]["candidate_sha256"]


def test_no_paired_sources_invent_no_target_identity():
    result = summarize(make_domain_fixture(), binding=None, observed_probes=None, records=None)
    assert result["identity"] is None
    assert any("no paired identity" in check for check in result["unavailable_checks"])


@pytest.mark.parametrize("missing", ["domain", "binding", "expected_binding_sha256"])
def test_available_partition_joins_reject_private_probe_even_in_partial_result(missing):
    f = make_domain_fixture()
    f.arguments["observed_probes"]["public_input_hex"] = [b"72\n".hex()]
    f.refresh()
    with pytest.raises(ValueError, match="escape frozen public"):
        summarize(f, **{missing: None})


def test_policy_domain_still_decodes_records_when_caller_domain_missing():
    f = make_domain_fixture()
    # Keep 256 distinct records and coherent comparator hashes; only grammar is bad.
    record = f.arguments["records"][0]
    record["stdin_hex"] = b"00\n".hex()
    change_outcome(f, 0)
    with pytest.raises(ValueError, match="outside-frozen"):
        summarize(f, domain=None)
    with pytest.raises(ValueError, match="noncanonical decimal"):
        summarize(f, domain=None, partitions=None)


@pytest.mark.parametrize("missing", [None, "expected_binding_sha256"])
@pytest.mark.parametrize("bad_oracle", [b"", b"0,1\n", b"garbage\n"])
def test_deferred6_bad_oracle_output_is_unknown_not_validation_exception(missing, bad_oracle):
    f = make_domain_fixture()
    change_outcome(f, 1, binary=Observation(stdout_bytes=bad_oracle, status="ok", exit_code=0))
    if missing:
        assert_partial(summarize(f, **{missing: None}), "trusted_binding_commitment_unavailable")
    else:
        r = summarize(f)
        assert r["certificate"]["invalid_oracle_count"] == 1
        assert r["certificate"]["all256_agreement"] is None
        assert r["calibration"]["sample_agreement"] is None


def test_missing_domain_and_policy_discloses_unchecked_oracle_arity():
    r = summarize(make_domain_fixture(), domain=None, domain_policy=None)
    assert any("oracle-output arity" in check for check in r["unavailable_checks"])


def test_deferred6_partial_path_actually_checks_oracle_arity_before_return(monkeypatch):
    import evaluation.domain_certificate as module
    f = make_domain_fixture()
    bad_output = b"0,1,2\n"
    change_outcome(f, 1, binary=Observation(stdout_bytes=bad_output, status="ok", exit_code=0))
    original_decode = module.decode
    attempted_bad_output = []

    def observing_decode(raw, codec, width, **kwargs):
        if raw == bad_output and kwargs.get("max_elements") == 1:
            attempted_bad_output.append(raw)
        return original_decode(raw, codec, width, **kwargs)

    monkeypatch.setattr(module, "decode", observing_decode)
    assert_partial(summarize(f, expected_binding_sha256=None), "trusted_binding_commitment_unavailable")
    assert attempted_bad_output == [bad_output]


@pytest.mark.parametrize("side", ["binary", "candidate"])
def test_infrastructure_faults_are_unknown_and_never_sample_pass(side):
    f = make_domain_fixture()
    change_outcome(f, 0, **{side: Observation(status="infrastructure_error", reason="fixture-backend-unavailable")})
    r = summarize(f)
    assert r["status"] == "not_qualified"
    assert r["certificate"]["infrastructure_unknown_count"] == 1
    assert r["certificate"]["all256_agreement"] is None
    assert r["certificate"]["primary184_private_agreement"] is None
    assert r["calibration"]["sample_agreement"] is None
    assert r["calibration"]["false_pass_vs256"] is None


@pytest.mark.parametrize("field", ["registration_sha256", "partition_sha256", "domain_policy_sha256",
    "canonical_plan_sha256", "lock_sha256", "records_sha256", "observed_probes_sha256"])
def test_binding_pin_corruption_fails_with_recommitted_body(field):
    f = make_domain_fixture()
    f.arguments["binding"][field] = fixture_digest("wrong-pin")
    f.arguments["expected_binding_sha256"] = digest(f.arguments["binding"])
    expected_cause = (
        r"^observed probe identity/lock mismatch$" if field == "lock_sha256" else "pins mismatch"
    )
    with pytest.raises(ValueError, match=expected_cause):
        summarize(f)


def test_binding_requires_separate_matching_commitment():
    with pytest.raises(ValueError, match="separate trusted commitment"):
        summarize(make_domain_fixture(), expected_binding_sha256=fixture_digest("wrong-authority"))


@pytest.mark.parametrize("corruption", ["missing", "repeated", "outside"])
def test_record_coverage_cannot_be_reduced_repeated_or_substituted(corruption):
    f = make_domain_fixture()
    records = f.arguments["records"]
    if corruption == "missing":
        records.pop()
    elif corruption == "repeated":
        records[-1] = deepcopy(records[0])
    else:
        records[-1]["stdin_hex"] = b"1,2\n".hex()
        change_outcome(f, 255)
    f.refresh()
    with pytest.raises(ValueError):
        summarize(f)


@pytest.mark.parametrize("source", ["binding", "observed_probes", "records"])
def test_noncandidate_final_conflicts_with_each_present_candidate_source(source):
    f = make_domain_fixture()
    target = f.arguments["binding"]
    final = next(x for x in f.arguments["campaign_receipt"]["finals"]
                 if all(x[k] == target[k] for k in ("task_id", "model", "arm")))
    final.update(status="abstain", candidate_sha256=None)
    f.refresh()
    overrides = {name: None for name in ("binding", "observed_probes", "records") if name != source}
    with pytest.raises(ValueError, match="noncandidate final"):
        summarize(f, **overrides)


def test_wrong_locked_candidate_cannot_hide_behind_missing_domain():
    f = make_domain_fixture()
    f.arguments["observed_probes"]["candidate_sha256"] = fixture_digest("other-candidate")
    f.refresh()
    with pytest.raises(ValueError, match="locked final"):
        summarize(f, domain=None)


@pytest.mark.parametrize("source", ["observed_probes", "records"])
def test_paired_identity_join_survives_missing_receipt(source):
    f = make_domain_fixture()
    if source == "records":
        f.arguments[source][1]["candidate_sha256"] = fixture_digest("different-record-candidate")
    else:
        f.arguments[source]["candidate_sha256"] = fixture_digest("different-probe-candidate")
    f.refresh()
    with pytest.raises(ValueError, match="identity"):
        summarize(f, campaign_receipt=None)


def test_receipt_lock_tamper_is_rejected_before_partial_return():
    f = make_domain_fixture()
    f.arguments["campaign_receipt"]["lease_id"] = "tampered-fixture-lease"
    with pytest.raises(ValueError, match="lock receipt digest"):
        summarize(f, domain=None)


def test_probe_lock_and_repetition_corruption_are_rejected():
    f = make_domain_fixture()
    f.arguments["observed_probes"]["lock_sha256"] = fixture_digest("other-lock")
    with pytest.raises(ValueError, match="lock mismatch"):
        summarize(f, binding=None)
    f = make_domain_fixture()
    probes = f.arguments["observed_probes"]["public_input_hex"]
    probes.append(probes[0])
    f.refresh()
    with pytest.raises(ValueError, match="probes repeat"):
        summarize(f)


def test_nonprobing_arm_cannot_claim_observations():
    f = make_domain_fixture(arm="S")
    f.arguments["observed_probes"]["public_input_hex"] = [b"8\n".hex()]
    f.refresh()
    with pytest.raises(ValueError, match="non-probing arm"):
        summarize(f)


def test_caller_domain_must_equal_committed_domain():
    with pytest.raises(ValueError, match="differs from precommitted"):
        summarize(make_domain_fixture(), domain=Domain(width=16, input_arity=1, output_arity=1, maximum=255))


def test_sample_membership_is_checked_with_missing_caller_domain():
    f = make_domain_fixture()
    # Change every finite variant consistently to isolate private membership.
    for task in f.arguments["domain_policy"]["tasks"]:
        if task["sampling"] is not None:
            task["sampling"]["canonical_keys"][0] = "value-8"
    f.refresh(policy=True)
    with pytest.raises(ValueError, match="escapes frozen private184"):
        summarize(f, domain=None)
