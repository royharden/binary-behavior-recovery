"""BUILDER-AUTHORED SOFTWARE REGRESSION CHECKS ONLY.

Not an admitted corpus, independent author/custodian, model campaign or execution
of candidate code. Structural receipt positive controls are explicitly fictional
software fixtures. All actual worker/live/data-admission gates remain separate.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from support.dl4.elf import metadata_only_elf
from support.dl4.matrix import make_matrix, summary_for


@pytest.fixture(scope="module")
def software_matrix():
    return make_matrix(patterned=False)


@pytest.fixture(scope="module")
def bound_matrix():
    return make_matrix(patterned=False, model_bindings=True)


@pytest.fixture(scope="module")
def patterned_matrix():
    return make_matrix(patterned=True)


def _score(matrix, rows=None):
    from evaluation.score import score_rows
    return score_rows(matrix.registration, matrix.rows if rows is None else rows,
                      partitions=matrix.partitions, campaign_receipt=matrix.receipt)


@pytest.fixture(scope="module")
def patterned_score(patterned_matrix):
    return _score(patterned_matrix)


def _index(matrix, arm="M"):
    key = (matrix.registration.cells[0].task_id, matrix.registration.models[0], arm)
    return next(i for i, row in enumerate(matrix.rows)
                if (row["task_id"], row["model"], row["arm"]) == key)


def _changed_case(matrix, *, side="candidate", **changes):
    rows = list(matrix.rows)
    index = _index(matrix)
    row = dict(rows[index])
    row["cases"] = list(row["cases"])
    case_index = next(i for i, case in enumerate(row["cases"])
                      if case["partition"] == "private_valid")
    case = dict(row["cases"][case_index])
    case[side] = {**case[side], **changes}
    row["cases"][case_index] = case
    rows[index] = row
    return rows


def test_closed_registration_and_software_authority_controls(software_matrix):
    reg = software_matrix.registration
    assert reg.origin == "fixture"
    assert "SOFTWARE_REGRESSION_ONLY" in reg.edition
    with pytest.raises(ValueError, match="96"):
        replace(reg, cells=reg.cells[:-1]).validate()
    with pytest.raises(ValueError, match="closed preregistration"):
        replace(reg, pins=reg.pins + (("unrecognized_pin", "0" * 64),)).validate()
    with pytest.raises(ValueError, match="independent"):
        replace(software_matrix.admission,
                author=software_matrix.admission.builder_identities[0]).validate(reg.edition)
    with pytest.raises(ValueError, match="PENDING"):
        replace(software_matrix.admission, accepted_by_roy=False).validate(reg.edition)


def _lock_software_campaign(path, matrix):
    from evaluation.exposure import Campaign
    campaign = Campaign(path)
    campaign.seal(matrix.registration, matrix.admission)
    campaign.dispatch()
    for final in matrix.receipt["finals"]:
        campaign.lock_final(final["task_id"], final["model"], final["arm"],
                            final["candidate_sha256"], final["status"])
    return campaign


def test_durable_all_final_barrier_and_single_campaign(tmp_path, software_matrix):
    from evaluation.exposure import Campaign, validate_open_receipt
    path = tmp_path / "SOFTWARE_ONLY_campaign.sqlite"
    campaign = Campaign(path)
    try:
        campaign.seal(software_matrix.registration, software_matrix.admission)
        campaign.dispatch()
        with pytest.raises(ValueError, match="second campaign"):
            campaign.dispatch()
        with pytest.raises(ValueError, match="all campaign final"):
            campaign.open_hidden(software_matrix.admission.evaluator, "software-only-lease")
        for final in software_matrix.receipt["finals"]:
            campaign.lock_final(final["task_id"], final["model"], final["arm"],
                                final["candidate_sha256"], final["status"])
        first = software_matrix.receipt["finals"][0]
        with pytest.raises(sqlite3.IntegrityError):
            campaign.lock_final(first["task_id"], first["model"], first["arm"], None, "abstain")
        with pytest.raises(ValueError, match="appointed evaluator"):
            campaign.open_hidden("SOFTWARE_ONLY_WRONG_EVALUATOR", "software-only-lease")
        locked = campaign.open_hidden(software_matrix.admission.evaluator, "software-only-lease")
        receipt = campaign.retained_open_receipt()
        assert receipt["lock_sha256"] == locked
        assert len(validate_open_receipt(software_matrix.registration, receipt)) == 1344
        with pytest.raises(ValueError, match="once only"):
            campaign.open_hidden(software_matrix.admission.evaluator, "second-software-lease")
        campaign.retire()
        with pytest.raises(ValueError, match="second campaign"):
            campaign.dispatch()
        with pytest.raises(sqlite3.IntegrityError):
            campaign.seal(software_matrix.registration, software_matrix.admission)
    finally:
        campaign.close()


def test_concurrent_hidden_open_has_one_winner(tmp_path, software_matrix):
    from evaluation.exposure import Campaign
    path = tmp_path / "SOFTWARE_ONLY_concurrent.sqlite"
    campaign = _lock_software_campaign(path, software_matrix)
    campaign.close()

    def open_once(number):
        connection = Campaign(path)
        try:
            connection.open_hidden(software_matrix.admission.evaluator, f"software-only-lease-{number}")
            return "opened"
        except ValueError:
            return "refused"
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(open_once, (1, 2)))
    assert sorted(outcomes) == ["opened", "refused"]


def test_retained_open_receipt_rejects_database_tamper(tmp_path, software_matrix):
    campaign = _lock_software_campaign(tmp_path / "SOFTWARE_ONLY_tamper.sqlite", software_matrix)
    try:
        campaign.open_hidden(software_matrix.admission.evaluator, "software-only-lease")
        campaign.db.execute("UPDATE finals SET status='syntax_failure' WHERE rowid=(SELECT MIN(rowid) FROM finals)")
        with pytest.raises(ValueError, match="durable campaign differs"):
            campaign.retained_open_receipt()
    finally:
        campaign.close()


def test_primary_unequal_groups_and_nominal_denominators(patterned_matrix, patterned_score):
    model = patterned_matrix.registration.models[0]
    m = summary_for(patterned_score, model, "M")
    assert m["nominal_valid_pass"] == {"n": 24, "N": 96}
    assert m["primary"] == pytest.approx(1 / 6)
    assert m["grouped"] == 72
    assert all(value == pytest.approx(1 / 6) for value in m["family_estimates"].values())
    assert summary_for(patterned_score, model, "R")["primary"] == 0
    assert summary_for(patterned_score, model, "P")["primary"] == 1
    overfit = summary_for(patterned_score, model, "lookup")
    assert overfit["visible_pass"] == {"n": 96, "N": 96}
    assert overfit["hidden_fail_given_visible"]["value"] == 1
    assert len(patterned_score["rows"]) == 1344 and patterned_score["complete"]


def test_missing_nominal_row_is_unknown_not_filtered(patterned_matrix):
    rows = list(patterned_matrix.rows)
    rows.pop(_index(patterned_matrix, "P"))
    result = _score(patterned_matrix, rows)
    p = summary_for(result, patterned_matrix.registration.models[0], "P")
    assert p["scheduled"] == 96 and p["nominal_valid_pass"] == {"n": 95, "N": 96}
    assert p["unknown"] == 1 and p["primary"] is None and not result["complete"]


@pytest.mark.parametrize("side", ["candidate", "oracle"])
def test_subject_failure_exit_zero_never_becomes_pass(patterned_matrix, side):
    result = _score(patterned_matrix, _changed_case(patterned_matrix, side=side, status="subject_failure"))
    row = next(row for row in result["rows"] if row["task_id"] == patterned_matrix.registration.cells[0].task_id
               and row["model"] == patterned_matrix.registration.models[0] and row["arm"] == "M")
    assert not row["passes"]["private_valid"]
    assert row["complete"] is (side == "candidate")


@pytest.mark.parametrize("fault,unknown", [
    ({"status": "infrastructure_error", "exit_code": None}, True),
    ({"status": "subject_failure", "exit_code": None}, True),
    ({"status": "subject_failure", "exit_code": None, "timed_out": True}, False),
    ({"status": "subject_failure", "exit_code": None, "signal": 9}, False),
    ({"status": "subject_failure", "output_limited": True}, False),
])
def test_resource_faults_and_infrastructure_unknowns_are_distinct(patterned_matrix, fault, unknown):
    result = _score(patterned_matrix, _changed_case(patterned_matrix, **fault))
    m = summary_for(result, patterned_matrix.registration.models[0], "M")
    assert m["unknown"] == int(unknown)
    assert m["nominal_valid_pass"]["n"] == 23
    assert (m["primary"] is None) is unknown


def test_candidate_identity_and_frozen_input_substitution_refuse(patterned_matrix):
    rows = list(patterned_matrix.rows)
    index = _index(patterned_matrix)
    row = deepcopy(rows[index])
    row["candidate_sha256"] = "f" * 64
    rows[index] = row
    with pytest.raises(ValueError, match="final lock"):
        _score(patterned_matrix, rows)
    row["candidate_sha256"] = patterned_matrix.rows[index]["candidate_sha256"]
    row["cases"][0]["canonical_key"] = "software-key-not-in-frozen-pool"
    with pytest.raises(ValueError, match="frozen"):
        _score(patterned_matrix, rows)


def test_paired_bootstrap_retains_family_pairs_and_is_order_invariant(patterned_matrix, patterned_score):
    from evaluation.statistics import paired_bootstrap
    first = paired_bootstrap(patterned_matrix.registration, patterned_score)
    reordered = _score(patterned_matrix, list(reversed(patterned_matrix.rows)))
    assert first == paired_bootstrap(patterned_matrix.registration, reordered)
    for result in first:
        assert result["draws"] == 2000 and len(result["draw_digest"]) == 64
        expected = {"P-R": 1, "P-M": 5 / 6, "M-S": 1 / 6}[result["difference"]]
        assert result["estimate"] == pytest.approx(expected)
        assert result["interval95"] == pytest.approx([expected, expected])
        assert len(result["raw_family_differences"]) == 8 and result["exploratory"]


def _pair(case):
    from bbr.contracts import Observation
    from bbr.differential import compare_observations

    def observation(raw):
        return Observation(stdout_bytes=bytes.fromhex(raw["stdout_hex"]),
            exit_code=raw["exit_code"], signal=raw["signal"], timed_out=raw["timed_out"],
            output_limited=raw["output_limited"], status=raw["status"],
            reason="SOFTWARE_ONLY_INFRASTRUCTURE_CONTROL" if raw["status"] == "infrastructure_error" else None)
    return compare_observations(observation(case["oracle"]), observation(case["candidate"]),
                                stdin_bytes=bytes.fromhex(case["input_hex"]))


def test_retained_collector_uses_shared_pair_and_rejects_duplicates_public_and_hash_drift(patterned_matrix):
    from evaluation.producer import RetainedCollector
    collector = RetainedCollector(patterned_matrix.registration, partitions=patterned_matrix.partitions,
                                  campaign_receipt=patterned_matrix.receipt)
    row = patterned_matrix.rows[_index(patterned_matrix)]
    case = row["cases"][0]
    args = (row["task_id"], row["model"], row["arm"])
    kwargs = {"candidate_sha256": row["candidate_sha256"],
              "stdin_bytes": bytes.fromhex(case["input_hex"]), "outcome": _pair(case)}
    collector.add(*args, **kwargs)
    with pytest.raises(ValueError, match="duplicate"):
        collector.add(*args, **kwargs)
    with pytest.raises(ValueError, match="final lock"):
        collector.add(*args, **{**kwargs, "candidate_sha256": "f" * 64})
    public = next(task for task in patterned_matrix.partitions["tasks"]
                  if task["task_id"] == row["task_id"])["partitions"]["public_valid"][0]
    outside = {**case, "input_hex": public["raw_hex"], "canonical_key": public["canonical_key"]}
    with pytest.raises(ValueError, match="absent from frozen scoring"):
        collector.add(*args, **{**kwargs, "stdin_bytes": bytes.fromhex(outside["input_hex"]),
                               "outcome": _pair(outside)})
    detached = collector.rows()
    next(result for result in detached if result["cases"])["cases"].clear()
    assert any(result["cases"] for result in collector.rows())


# These imported checks are collected once in this authorized test entrypoint.
# Support modules are trusted authored test source, never model candidate code.
from support.dl4.archive_checks import (  # noqa: E402,F401
    test_report_versions_roundtrip,
    test_partial_domain_inventory_keeps_unqualified_disclosures,
    test_report_render_escapes_hostile_strings,
    test_report_tampering_refuses,
    test_archive_path_aliases_refuse,
    test_archive_symlink_refuses_when_host_permits_links,
    test_archive_declared_data_and_replay_size_ceilings,
    test_archive_replay_raw_hash_is_not_body_commitment,
    test_replay_type_cannot_expand_scoring_source_cap,
    test_bound_resource_counts_require_full_population,
    test_resource_binding_pin_refuses_self_consistent_tamper,
    test_resource_unknown_liability_does_not_become_zero,
    test_resource_join_requires_each_ledger_attempt_and_single_origin,
    test_resource_shared_m_views_are_nonadditive,
)
from support.dl4.domain_checks import (  # noqa: E402,F401
    test_domain_software_false_pass_calibration,
    test_domain_private_sample_exhaustion_is_disclosed,
    test_domain_valid_partial_preserves_unavailable_disclosures,
    test_domain_missing_truth_cannot_mask_present_corruption,
    test_domain_canonical_binding_is_not_raw_pretty_json_hash,
    test_domain_oracle_fault_is_not_comparison_success,
    test_domain_inventory_join_retains_authority_limits,
    test_domain_inventory_rejects_tamper_and_replay_type,
)


@pytest.mark.parametrize("fail_at", [None, 0, 200])
def test_archive_joins_domain_observations_to_primary_rows(
        tmp_path, software_matrix, patterned_matrix, fail_at):
    """One source cannot pass while the same candidate/input fails in another."""
    from support.dl4.archive_checks import make_archive
    from support.dl4.domain_checks import domain_case, domain_inventory
    from bbr.report.archive import ReportError, build_report, canonical, read_json
    from evaluation.preregister import digest

    # Keep the archive small: one software candidate, every other row abstains.
    selected = deepcopy(patterned_matrix.rows[_index(patterned_matrix, "P")])
    rows = list(software_matrix.rows)
    key = (selected["task_id"], selected["model"], selected["arm"])
    rows[_index(software_matrix, "P")] = selected
    receipt = deepcopy(software_matrix.receipt)
    for final in receipt["finals"]:
        if (final["task_id"], final["model"], final["arm"]) == key:
            final.update(status="candidate", candidate_sha256=selected["candidate_sha256"])
    receipt.pop("lock_sha256")
    receipt["lock_sha256"] = digest(receipt)
    compact = replace(software_matrix, rows=rows, receipt=receipt)
    case = domain_case(compact, fail_at=fail_at)
    compact = replace(compact, registration=case["registration"],
                      receipt=case["kwargs"]["campaign_receipt"],
                      domain_policy=case["kwargs"]["domain_policy"])
    root = tmp_path / "SOFTWARE_ONLY_conflicting_sources"
    _, paths, score = make_archive(root, compact, version=4)
    retained = domain_inventory(root, case)
    descriptor_path = "domain-sources.json"
    (root / descriptor_path).write_bytes(canonical(retained["sources"]))
    paths += list(retained["files"]) + [descriptor_path]
    bundle = read_json(root / "bundle.json")
    bundle["domain_sources"] = descriptor_path
    (root / "bundle.json").write_bytes(canonical(bundle))
    if fail_at is None:
        joined = build_report(root, paths, score, origin="fixture",
            campaign_id=compact.registration.edition, scoring_bundle="bundle.json")
        assert joined["domains"]["primary_observation_join"]["checked_observations"] == 192
        assert joined["domains"]["summaries"][0]["certificate"]["all256_agreement"] is True
    else:
        with pytest.raises(ReportError, match="contradict|primary observation"):
            build_report(root, paths, score, origin="fixture",
                         campaign_id=compact.registration.edition, scoring_bundle="bundle.json")


def _public_config(tmp_path):
    from bbr.contracts import Domain, VisibleExample, VisibleTask
    from bbr.corpus import encode
    from bbr.evidence import extract
    from bbr.report.archive import canonical
    artifact = metadata_only_elf()
    path = tmp_path / "SOFTWARE_METADATA_ONLY_NEVER_EXECUTED.elf"
    path.write_bytes(artifact)
    envelope_source = extract(artifact)
    domain = Domain(width=8, input_arity=1, output_arity=1, minimum=0, maximum=255)
    public = tuple(encode((value,), "dec", 8) for value in range(8, 72))
    public += tuple(f"software-invalid-public-{value:02}".encode() for value in range(16))
    task = VisibleTask(task_id="software-public-task", evidence_sha256=envelope_source.digest(),
        codec="dec", domain=domain, probe_inputs=public,
        examples=tuple(VisibleExample(stdin_bytes=encode((value,), "dec", 8),
                                     stdout_bytes=b"0\n", exit_code=0) for value in range(8)))
    policy_pin = sha256(b"SOFTWARE_ONLY_WORKER_POLICY_NOT_AN_ADMITTED_IMAGE").hexdigest()
    config = {"schema": "bbr.fixture-preflight.v1", "origin": "fixture", "artifact": path.name,
        "artifact_sha256": sha256(artifact).hexdigest(), "visible_task": task.model_dump(mode="json"),
        "candidate_source": "raise AssertionError('software test candidate must remain inert')",
        "image_sha256": policy_pin, "toolchain_sha256": policy_pin, "limits": {}}
    config_path = tmp_path / "SOFTWARE_ONLY_preflight.json"
    config_path.write_bytes(canonical(config))
    return config_path, config, task


def test_cli_default_mock_is_labeled_pending(capsys):
    from bbr.cli import main
    assert main(["demo", "--mock"]) == 2
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "SCRIPTED FIXTURE / NO LIVE MODEL RESULT"
    assert json.loads(lines[-1])["status"] == "configuration_required"


def test_real_cli_module_entrypoint_remains_keyless_and_pending():
    result = subprocess.run([sys.executable, "-m", "bbr.cli", "demo", "--mock"],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == 2, result.stderr
    assert "SCRIPTED FIXTURE / NO LIVE MODEL RESULT" in result.stdout
    assert json.loads(result.stdout.splitlines()[-1])["live_status"] == "not_run"


def test_cli_preflight_actual_imports_preserve_none_and_zero_dispatch(tmp_path, capsys, monkeypatch):
    from bbr.cli import main
    from bbr.providers.dispatch import FixtureDispatch
    config_path, _, _ = _public_config(tmp_path)

    def never_dispatch(*args, **kwargs):
        raise AssertionError("software preflight must never construct a dispatcher")
    monkeypatch.setattr(FixtureDispatch, "__init__", never_dispatch)
    assert main(["run", "--arm", "P", "--config", str(config_path)]) == 2
    output = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert output["status"] == "preflight_blocked"
    assert output["candidate_validation"]["valid"] is None
    assert output["runner"]["status"] == "infrastructure_error"
    assert output["provider_dispatched"] is False
    assert len(output["prepared_request_sha256"]) == 64
    assert output["public_probe_inputs"] == 80


def test_cli_journey_without_dependencies_never_claims_campaign_locks(tmp_path, capsys):
    from bbr.cli import main
    from bbr.report.archive import canonical
    _, preflight, task = _public_config(tmp_path)
    config = {key: preflight[key] for key in ("origin", "artifact", "artifact_sha256", "visible_task", "limits")}
    config.update(schema="bbr.fixture-journey.v1", campaign_id="SOFTWARE_ONLY_NO_REAL_CAMPAIGN",
        fixed_batches=[[value.hex() for value in task.probe_inputs[start:start+8]] for start in (0, 8, 16)],
        fixture_records=None, model_config=None)
    path = tmp_path / "SOFTWARE_ONLY_journey.json"
    path.write_bytes(canonical(config))
    assert main(["demo", "--mock", "--journey-config", str(path)]) == 2
    output = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert output["scope"] == "one_task_fixture"
    assert output["driver"]["status"] == "unavailable"
    assert output["driver"]["attempted_provider_calls"] == 0
    assert output["hidden_scoring"] == "not_performed"
    assert output["campaign_lock_authorization"] == "not_supplied_by_task_driver"


def test_cli_refuses_live_placeholder_configuration_before_any_dispatch(tmp_path, capsys):
    from bbr.cli import main
    from bbr.report.archive import canonical
    _, preflight, task = _public_config(tmp_path)
    config = {key: preflight[key] for key in ("artifact", "artifact_sha256", "visible_task", "limits")}
    config.update(schema="bbr.fixture-journey.v1", origin="live",
        campaign_id="SOFTWARE_ONLY_NEGATIVE_PLACEHOLDER_CONTROL",
        fixed_batches=[[value.hex() for value in task.probe_inputs[start:start+8]] for start in (0, 8, 16)],
        fixture_records=None, model_config={"model_id": "<PLACEHOLDER_MODEL_PIN>",
            "config_id": "software-only-negative-control", "endpoint_id": "offline", "seed": 0, "origin": "live"})
    path = tmp_path / "SOFTWARE_ONLY_live_refusal.json"
    path.write_bytes(canonical(config))
    assert main(["run", "--arm", "M", "--journey-config", str(path)]) == 2
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["status"] == "refused"
