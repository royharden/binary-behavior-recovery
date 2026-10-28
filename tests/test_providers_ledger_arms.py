"""Authored SOFTWARE regression tests, fixture origin, not independent corpus.

No candidate source is compiled/imported/executed. Scripted worker ports are
software-test doubles, not admitted sandbox, isolation or benchmark evidence.
"""
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from hashlib import sha256
import json
import sqlite3
from threading import Barrier

import pytest

from bbr.arms.fixture_journey import run_fixture_task
from bbr.arms.interventions import (ArmArchive, InfrastructureUnknown, ProbeBroker,
                                    Submission, run_interventions, validate_submission)
from bbr.ledger import BudgetStop, Ledger, read_report
from bbr.providers.dispatch import FixtureDispatch, ReceiptSinkError
from bbr.providers.mock import (MockProvider, ModelConfig, ProviderError,
                               ProviderUnavailable, canonical, live_provider)
from bbr.report.resource_metrics import summarize_resources
from support.dl3.software_fixtures import (CAMPAIGN_ID, SOURCE_A, SOURCE_B,
    VALIDATION_DIAGNOSTIC, fixture_row, response, seven_scripted_rows, software_case, software_ports)


def digest(label):
    return sha256(label.encode()).hexdigest()


def dispatcher(case, ledger, rows, **kwargs):
    return FixtureDispatch(case.task.task_id, case.task, MockProvider(rows), ledger, case.config,
        campaign_id=CAMPAIGN_ID, evidence_json=case.evidence_json,
        artifact_sha256=case.artifact_sha256, **kwargs)


def test_ledger_reopen_exact_decimal_and_idempotent_settlement(tmp_path):
    path = tmp_path / "software-ledger.sqlite"
    ledger = Ledger(path, cap_usd="0.30")
    first = ledger.reserve("software:one", digest("one"), "0.10")
    assert ledger.reserve("software:one", digest("one"), "0.10") == first
    Ledger(path, cap_usd="0.30").mark_sent(first)
    ledger.settle(first, "0.10", reason="authored software cost")
    ledger.settle(first, "0.10", reason="same settlement replay")
    reopened = Ledger(path, cap_usd="0.30")
    second = reopened.reserve("software:two", digest("two"), "0.20")
    reopened.mark_sent(second)
    reopened.settle(second, "0.20", reason="authored software cost")
    report = read_report(path)
    assert Decimal(report["committed_usd"]) == Decimal("0.30")
    assert report["available_usd"] == "0" and report["dispatch_blocked"]
    with pytest.raises(BudgetStop):
        reopened.reserve("software:three", digest("three"), "0")


def test_unknown_usage_survives_reopen_and_requires_reconcile(tmp_path):
    path = tmp_path / "unknown.sqlite"
    ledger = Ledger(path, cap_usd="1")
    reservation = ledger.reserve("unknown", digest("unknown"), "0.80")
    ledger.mark_sent(reservation)
    ledger.settle(reservation, None, reason="authored software unknown-usage case")
    reopened = Ledger(path, cap_usd="1")
    report = reopened.report()
    assert report["committed_usd"] == "0.80" and report["dispatch_blocked"]
    with pytest.raises(BudgetStop):
        reopened.reserve("next", digest("next"), "0.01")
    reopened.reconcile(reservation, billed_usd="0.25", evidence="authored software bill")
    assert read_report(path)["available_usd"] == "0.75"
    assert not read_report(path)["dispatch_blocked"]


def test_never_sent_retry_and_attempt_cap_are_durable(tmp_path):
    path = tmp_path / "retry.sqlite"
    ledger = Ledger(path, cap_usd="1", max_attempts=2)
    first = ledger.reserve("retry", digest("retry"), "0.50")
    ledger.reconcile(first, proven_never_sent=True, evidence="authored never-sent software case")
    second = ledger.reserve("retry", digest("retry"), "0.50", retry=True)
    assert second.attempt == 2
    ledger.mark_sent(second)
    ledger.settle(second, "0", reason="software zero-cost response")
    with pytest.raises(BudgetStop):
        ledger.reserve("retry", digest("retry"), "0.50", retry=True)
    with pytest.raises(BudgetStop):
        Ledger(path, cap_usd="1", max_attempts=2).reserve("another", digest("another"), "0")
    assert len(read_report(path)["attempts"]) == 2


def test_over_reserve_charge_stays_unknown_and_cap_is_not_rewritten(tmp_path):
    path = tmp_path / "over-reserve.sqlite"
    ledger = Ledger(path, cap_usd="1")
    reservation = ledger.reserve("over", digest("over"), "0.50")
    ledger.mark_sent(reservation)
    ledger.settle(reservation, "1.10", reason="authored software over-reserve case")
    report = read_report(path)
    assert report["attempts"][0]["status"] == "unknown"
    assert report["committed_usd"] == "1.10" and report["dispatch_blocked"]
    with pytest.raises(BudgetStop):
        Ledger(path, cap_usd="2")


def test_concurrent_reservations_cannot_oversubscribe_or_dispatch_twice(tmp_path):
    path = tmp_path / "concurrent.sqlite"
    ledger = Ledger(path, cap_usd="1")
    barrier = Barrier(2)

    def reserve(index):
        barrier.wait(timeout=10)
        try:
            return ledger.reserve(f"software:{index}", digest(str(index)), "0.75")
        except BudgetStop:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        attempts = list(pool.map(reserve, (1, 2)))
    winners = [item for item in attempts if item is not None]
    assert len(winners) == 1
    ledger.mark_sent(winners[0])
    with pytest.raises(BudgetStop):
        ledger.mark_sent(winners[0])
    assert read_report(path)["committed_usd"] == "0.75"


def test_read_report_never_initializes_missing_or_changes_existing_db(tmp_path, monkeypatch):
    missing = tmp_path / "missing.sqlite"
    with pytest.raises(FileNotFoundError):
        read_report(missing)
    assert not missing.exists()
    path = tmp_path / "existing.sqlite"
    Ledger(path)
    before = path.read_bytes()

    def forbidden_init(*args, **kwargs):
        raise AssertionError("read-only report must not initialize Ledger")

    monkeypatch.setattr(Ledger, "__init__", forbidden_init)
    report = read_report(path)
    assert report["attempts"] == [] and report["committed_usd"] == "0"
    assert path.read_bytes() == before
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT cap FROM config").fetchone()[0] == "40"


@pytest.mark.parametrize("amount", [0.1, "NaN", "Infinity", "-0.01", "0.0000000000001"])
def test_ledger_rejects_unsafe_amounts_before_reservation(tmp_path, amount):
    ledger = Ledger(tmp_path / "money.sqlite")
    with pytest.raises(ValueError):
        ledger.reserve("unsafe", digest("unsafe"), amount)
    assert ledger.report()["attempts"] == []


def test_exact_mock_request_and_resource_record_are_bound_and_detached(tmp_path):
    case = software_case()
    row = fixture_row(case)
    ledger = Ledger(tmp_path / "fixture.sqlite")
    call = dispatcher(case, ledger, [row])
    result = call("M:0", [])
    assert result.code == SOURCE_A
    receipts = call.receipt_snapshots()
    assert len(receipts) == 1 and receipts[0]["provider_record"] == row
    assert receipts[0]["request_sha256"] == digest_bytes(canonical(receipts[0]["request"]))
    assert receipts[0]["provider_record_sha256"] == digest_bytes(canonical(row))
    receipts[0]["provider_record"]["response"]["code"] = "mutated data"
    assert call.receipt_snapshots()[0]["provider_record"]["response"]["code"] == SOURCE_A
    assert json.loads(call.receipt_jsonl()) == call.receipt_snapshots()[0]
    assert ledger.report()["attempts"][0]["charge"] == "0"


def digest_bytes(raw):
    return sha256(raw).hexdigest()


@pytest.mark.parametrize("change", ["missing", "artifact", "noncanonical", "bundle_digest", "config"])
def test_mock_refuses_missing_changed_or_mismatched_full_evidence(change):
    case = software_case()
    provider = MockProvider([fixture_row(case)])
    evidence, artifact, task, config = case.evidence_json, case.artifact_sha256, case.task, case.config
    if change == "missing":
        evidence = None
    elif change == "artifact":
        artifact = digest("different authored artifact ID")
    elif change == "noncanonical":
        evidence += b"\n"
    elif change == "bundle_digest":
        task = task.model_copy(update={"evidence_sha256": digest("different bundle")})
    else:
        config = ModelConfig(seed=1)
    original = fixture_row(case)["request_sha256"]
    with pytest.raises(ProviderError):
        provider.propose(task, [], config, {"request_sha256": original},
                         evidence_json=evidence, artifact_sha256=artifact)


def test_schema_failure_retains_exact_record_and_missing_record_has_reason(tmp_path):
    case = software_case()
    malformed = fixture_row(case, {"unexpected_software_test_field": True})
    ledger = Ledger(tmp_path / "malformed.sqlite")
    call = dispatcher(case, ledger, [malformed])
    with pytest.raises(ProviderError):
        call("M:0", [])
    assert call.receipt_snapshots()[0]["provider_record"] == malformed
    assert ledger.report()["attempts"][0]["status"] == "settled"
    absent = dispatcher(case, Ledger(tmp_path / "absent.sqlite"), [])
    with pytest.raises(ProviderError):
        absent("M:0", [])
    receipt = absent.receipt_snapshots()[0]
    assert receipt["provider_record"] is None and receipt["provider_record_sha256"] is None
    assert receipt["provider_record_reason"]


def test_sink_failure_keeps_local_receipt_without_redispatch(tmp_path):
    case = software_case()
    ledger = Ledger(tmp_path / "sink.sqlite")

    def broken_sink(receipt):
        receipt["request"]["model_config"]["model_id"] = "sink mutation"
        raise RuntimeError("authored software sink failure")

    call = dispatcher(case, ledger, [fixture_row(case)], receipt_sink=broken_sink)
    with pytest.raises(ReceiptSinkError):
        call("M:0", [])
    assert call.receipt_snapshots()[0]["request"]["model_config"]["model_id"] == case.config.model_id
    with pytest.raises(ProviderError):
        call("M:0", [])
    assert len(ledger.report()["attempts"]) == len(call.receipt_snapshots()) == 1


def test_live_path_is_unavailable_without_sdk_or_model_call():
    with pytest.raises(ProviderUnavailable, match="live_not_run"):
        live_provider()


def test_interventions_share_m_seven_calls_last_valid_and_final_abstain():
    case = software_case()
    calls = []

    def dispatch(label, history):
        calls.append(label)
        if label == "R:3":
            return response(abstain=True)
        if label in {"R:2", "P:3"}:
            return {"unknown": "authored schema failure"}
        return response(SOURCE_B if label == "P:2" else SOURCE_A)

    broker = ProbeBroker.for_task(case.task, case.fixed,
        lambda submission, raw: {"status": "equal", "diverged": False})
    locks = run_interventions(dispatch,
        lambda raw, label: validate_submission(raw, label, lambda code: (True, VALIDATION_DIAGNOSTIC)), broker)
    assert calls == ["M:0", "R:1", "R:2", "R:3", "P:1", "P:2", "P:3"]
    assert locks["R"]["status"] == "abstain"
    assert locks["P"]["selected_call_id"] == "P:2"
    initial = locks["M"]["submissions"][0]
    assert locks["R"]["submissions"][0] == locks["P"]["submissions"][0] == initial


def test_probe_invalid_repeat_outside_and_fixed_slots_are_charged_without_fill():
    case = software_case()
    seen = []

    def run_pair(submission, raw):
        seen.append(raw)
        return {"status": "wrong_output", "diverged": True}

    broker = ProbeBroker.for_task(case.task, case.fixed, run_pair)
    # Deliberately malformed direct software submission exercises broker defense,
    # not CandidateResponse admission or independent model behavior.
    probes = ["invalid hex", "ff", case.task.probe_inputs[32].hex()] + [case.task.probe_inputs[32].hex()] * 5
    submission = Submission("M:0", {"code": SOURCE_A, "abstain": False, "probe_inputs": probes}, True, "software", "fixture")
    feedback = [broker.feedback(submission) for _ in range(3)]
    assert broker.slots == 48 and len(seen) == 25
    assert feedback[0]["chosen"][0]["status"] == "invalid"
    assert feedback[0]["chosen"][1]["status"] == "outside_public_pool"
    assert feedback[0]["chosen"][3]["status"] == "repeated"
    assert feedback[0]["first_fixed_divergence"]["input_hex"] == case.fixed[0][0].hex()
    with pytest.raises(ValueError):
        broker.feedback(submission)


def test_unknown_validation_retains_m_response_and_stops_calls():
    case, calls = software_case(), []

    def dispatch(label, history):
        calls.append(label)
        return response()

    broker = ProbeBroker.for_task(case.task, case.fixed, lambda submission, raw: {})
    with pytest.raises(InfrastructureUnknown) as error:
        run_interventions(dispatch,
            lambda raw, label: validate_submission(raw, label, lambda code: (None, "software unavailable")), broker)
    assert calls == ["M:0"]
    receipt = error.value.snapshot()
    assert receipt["attempted_response"]["code"] == SOURCE_A and receipt["calls_attempted"] == 1
    assert receipt["archive_snapshots"] == {}


def test_partial_probe_fault_keeps_prior_observations_locks_and_latches():
    case, calls, executions = software_case(), [], []

    def dispatch(label, history):
        calls.append(label)
        return response(probes=case.task.probe_inputs[32:35])

    def run_pair(submission, raw):
        executions.append(raw)
        return {"status": "infrastructure_error" if len(executions) == 3 else "equal", "diverged": False}

    broker = ProbeBroker.for_task(case.task, case.fixed, run_pair)
    with pytest.raises(InfrastructureUnknown) as error:
        run_interventions(dispatch,
            lambda raw, label: validate_submission(raw, label, lambda code: (True, "software acknowledgment")), broker)
    receipt = error.value.snapshot()
    assert calls == ["M:0", "R:1", "R:2", "R:3"]
    assert len(receipt["probe_progress"]["chosen"]) == 2
    assert receipt["probe_progress"]["stage_slots_used"] == 3
    assert receipt["probe_progress"]["attempted_input"] == case.task.probe_inputs[34].hex()
    assert receipt["archive_snapshots"]["R"]["selected_call_id"] == "R:3"
    with pytest.raises(InfrastructureUnknown):
        broker.feedback(Submission("P:1", response(), True, "software", "fixture"))
    assert len(executions) == 3


def test_lock_and_failure_receipts_are_recursively_immutable_and_exports_detached():
    payload = response()
    archive = ArmArchive("M", [Submission("M:0", payload, True, "software", "fixture")])
    lock = archive.lock()
    before = archive.lock_bytes()
    payload["code"] = "caller mutation"
    with pytest.raises(TypeError):
        lock["submissions"][0]["response"]["code"] = "lock mutation"
    detached = archive.lock_snapshot()
    detached["submissions"][0]["response"]["code"] = "detached mutation"
    with pytest.raises(ValueError):
        archive.append_submission(Submission("M:1", response(), True, "software", "fixture"))
    assert archive.lock_bytes() == before
    failure = InfrastructureUnknown("M:0", "software unknown", attempted_response=response())
    exported = failure.snapshot()
    exported["attempted_response"]["code"] = "mutation"
    assert failure.snapshot()["attempted_response"]["code"] == SOURCE_A


def task_kwargs(case, ledger=None, **extra):
    return dict(campaign_id=CAMPAIGN_ID, artifact_sha256=case.artifact_sha256,
        evidence_json=case.evidence_json, fixed_batches=case.fixed,
        fixture_records=seven_scripted_rows(case), ledger=ledger, model_config=case.config, **extra)


def test_orchestrator_defaults_unavailable_zero_dispatch_without_ledger_init(monkeypatch):
    case = software_case()

    def forbidden(*args, **kwargs):
        raise AssertionError("default unavailable path must not dispatch or initialize DB")

    monkeypatch.setattr(Ledger, "__init__", forbidden)
    monkeypatch.setattr(MockProvider, "propose", forbidden)
    result = run_fixture_task(case.task, **task_kwargs(case))
    assert result["status"] == "unavailable" and result["attempted_provider_calls"] == 0
    assert result["resource_receipts"] == [] and result["hidden_scoring"] == "not_performed"


def test_orchestrator_scripted_ports_join_all_receipts_without_candidate_execution(tmp_path):
    case = software_case()
    ledger = Ledger(tmp_path / "journey.sqlite")
    ports, doubles = software_ports()
    result = run_fixture_task(case.task, **task_kwargs(case, ledger, **ports))
    assert result["status"] == "fixture_candidates_locked"
    assert result["attempted_provider_calls"] == len(result["resource_receipts"]) == 7
    assert set(result["builder_locks"]) == {"S", "control:echo", "control:constant", "control:visible_lookup"}
    assert set(result["arm_locks"]) == {"M", "R", "P"}
    assert len(doubles[0].inputs) == len(doubles[1].inputs) == 24
    assert len(doubles[2].sources) == 11  # four builder-source + seven model DATA checks
    assert result["runtime_validation"] == "unverified" and result["hidden_scoring"] == "not_performed"
    summary = summarize_resources(ledger.report(), result["resource_receipts"],
                                  campaign_id=CAMPAIGN_ID, origin="fixture")
    assert summary["campaign_unique"]["unique_attempts"] == 7
    assert summary["campaign_unique"]["settled_spend_usd"] == "0"
    assert all(group["usd_per_pass"] is None for group in summary["groups"])


def test_orchestrator_ledger_configuration_failure_is_unknown_not_seven_parsefails(tmp_path):
    case = software_case(task_id="t" * 180, config=ModelConfig(config_id="c" * 100))
    ledger = Ledger(tmp_path / "long-id.sqlite")
    ports, _ = software_ports()
    result = run_fixture_task(case.task, **task_kwargs(case, ledger, **ports))
    assert result["status"] == "infrastructure_unknown" and result["attempted_provider_calls"] == 1
    assert result["arm_locks"] == {} and result["resource_receipts"] == []
    assert result["failure"]["receipt"]["call_id"] == "M:0"
    assert ledger.report()["attempts"] == []


def test_orchestrator_sink_fault_preserves_exact_response_resource_sidecar(tmp_path):
    case = software_case()
    ledger = Ledger(tmp_path / "journey-sink.sqlite")
    ports, _ = software_ports()

    def fail_sink(receipt):
        raise RuntimeError("authored software archive outage")

    result = run_fixture_task(case.task, **task_kwargs(case, ledger, receipt_sink=fail_sink, **ports))
    assert result["status"] == "infrastructure_unknown" and result["attempted_provider_calls"] == 1
    assert result["resource_receipts"][0]["provider_record"]["response"]["code"] == SOURCE_A
    assert ledger.report()["attempts"][0]["status"] == "settled"
