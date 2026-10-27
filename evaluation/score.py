"""Recompute exact retained-observation metrics; never execute either subject."""
from __future__ import annotations

from collections import defaultdict
from .preregister import Registration
from .exposure import validate_open_receipt
from .validate import canonical_hex, frozen_partitions


def _closed(value: dict, fields: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("closed retained row shape violated")


def _observation(raw: dict) -> tuple[bool, bool]:
    _closed(raw, {"stdout_hex", "exit_code", "signal", "timed_out", "output_limited", "status"})
    canonical_hex(raw["stdout_hex"], 4096)
    if raw["exit_code"] is not None and (type(raw["exit_code"]) is not int or not 0 <= raw["exit_code"] <= 255):
        raise ValueError("exit must be an integer from 0 through 255")
    if raw["signal"] is not None and (type(raw["signal"]) is not int or raw["signal"] <= 0):
        raise ValueError("signal must be a positive integer")
    if raw["exit_code"] is not None and raw["signal"] is not None:
        raise ValueError("exit and signal are mutually exclusive")
    if type(raw["timed_out"]) is not bool or type(raw["output_limited"]) is not bool:
        raise ValueError("boolean resource flags required")
    if not isinstance(raw["status"], str) or raw["status"] not in {"ok", "subject_failure", "infrastructure_error"}:
        raise ValueError("invalid observation status")
    clean = raw["signal"] is None and not raw["timed_out"] and not raw["output_limited"]
    # These are the comparable fields of the shared Observation contract. Its
    # diagnostic reason/stderr/elapsed fields stay in the producer archive.
    if raw["status"] == "ok" and (not clean or raw["exit_code"] != 0):
        raise ValueError("ok requires clean exit zero")
    # Match compare_observations: resource faults are known subject failures;
    # an otherwise unclassified missing exit is an infrastructure unknown.
    unknown = raw["status"] == "infrastructure_error" or (clean and raw["exit_code"] is None)
    # A clean subject_failure is comparable only for expected malformed exit 2.
    # In particular, identical stdout/exit 0 must not erase a subject exception.
    healthy = clean and ((raw["status"] == "ok" and raw["exit_code"] == 0) or
                         (raw["status"] == "subject_failure" and raw["exit_code"] == 2))
    return healthy, unknown


def _case(case: dict) -> tuple[str, bool, bool]:
    _closed(case, {"partition", "input_hex", "canonical_key", "oracle", "candidate"})
    if not isinstance(case["partition"], str) or case["partition"] not in {"visible", "private_valid", "private_malformed"}:
        raise ValueError("unknown scoring partition")
    canonical_hex(case["input_hex"], 64)
    if case["partition"] == "private_malformed":
        if case["canonical_key"] is not None:
            raise ValueError("malformed input cannot have canonical identity")
    elif not isinstance(case["canonical_key"], str) or not case["canonical_key"]:
        raise ValueError("decoded canonical identity required")
    oracle_ok, oracle_unknown = _observation(case["oracle"])
    candidate_ok, candidate_unknown = _observation(case["candidate"])
    if case["partition"] == "private_malformed":
        oracle_ok = oracle_ok and case["oracle"]["stdout_hex"] == "" and case["oracle"]["exit_code"] == 2
    else:
        oracle_ok = oracle_ok and case["oracle"]["exit_code"] == 0
    # Faulting oracle cannot validate a candidate, even with an identical fault.
    unknown = oracle_unknown or candidate_unknown or not oracle_ok
    matched = oracle_ok and candidate_ok and case["oracle"]["stdout_hex"] == case["candidate"]["stdout_hex"] and case["oracle"]["exit_code"] == case["candidate"]["exit_code"]
    return case["partition"], matched, unknown


def score_rows(registration: Registration, rows: list[dict], *, partitions: dict,
               campaign_receipt: dict) -> dict:
    registration.validate()
    finals = validate_open_receipt(registration, campaign_receipt)
    rosters = frozen_partitions(registration, partitions)
    if not isinstance(rows, list):
        raise ValueError("retained row list required")
    supplied = {}
    for row in rows:
        _closed(row, {"task_id", "model", "arm", "candidate_sha256", "status", "cases"})
        if any(not isinstance(row[n], str) for n in ("task_id", "model", "arm", "status")):
            raise ValueError("row identities/status must be strings")
        key = (row["task_id"], row["model"], row["arm"])
        if key not in registration.final_keys or key in supplied:
            raise ValueError("duplicate/outside-roster retained row")
        if row["status"] not in {"candidate", "abstain", "syntax_failure", "not_run", "infrastructure_error"}:
            raise ValueError("invalid candidate status")
        if row["status"] != finals[key]["status"] or row["candidate_sha256"] != finals[key]["candidate_sha256"]:
            raise ValueError("retained row differs from pre-hidden final candidate lock")
        if not isinstance(row["cases"], list):
            raise ValueError("case list required")
        if row["status"] != "candidate" and row["cases"]:
            raise ValueError("noncandidate status cannot carry execution observations")
        supplied[key] = row
    cellmap = {c.task_id: c for c in registration.cells}
    scored = []
    for key in sorted(registration.final_keys):
        cell = cellmap[key[0]]
        row = supplied.get(key, {"status": "not_run", "cases": []})
        groups = defaultdict(list)
        observed_inputs = defaultdict(set)
        raw_seen, canonical_seen = set(), set()
        for case in row["cases"]:
            partition, passed, unknown = _case(case)
            if case["input_hex"] in raw_seen:
                raise ValueError("raw input repeats/intersects partitions")
            raw_seen.add(case["input_hex"])
            canonical = case["canonical_key"]
            if canonical is not None:
                if canonical in canonical_seen:
                    raise ValueError("decoded input repeats/intersects partitions")
                canonical_seen.add(canonical)
            groups[partition].append((passed, unknown))
            observed_inputs[partition].add((case["input_hex"], canonical))
        required = {"visible": 8, "private_valid": 184 if cell.tier == "finite" else 256, "private_malformed": 32}
        candidate = row["status"] == "candidate"
        if candidate and any(observed_inputs[p] != rosters[key[0]][p] for p in required):
            raise ValueError("candidate observations must equal frozen visible/private input sets")
        counts_valid = all(len(groups[p]) == n if p != "private_valid" or cell.tier == "finite" else len(groups[p]) >= n for p, n in required.items())
        any_unknown = any(u for cases in groups.values() for _, u in cases)
        complete = row["status"] in {"abstain", "syntax_failure"} or (candidate and counts_valid and not any_unknown)
        passes = {p: (all(v for v, _ in groups[p]) if candidate and complete else False) for p in required}
        scored.append({"task_id": key[0], "model": key[1], "arm": key[2], "candidate_sha256": finals[key]["candidate_sha256"], "family_id": cell.family_id, "codec": cell.codec, "compiler": cell.compiler, "optimization": cell.optimization, "tier": cell.tier, "identity": list(cell.identity), "status": row["status"], "complete": complete, "unknown_reason": None if complete else "missing_cases_or_infrastructure_unknown", "passes": passes, "case_counts": {p: len(groups[p]) for p in required}})
    summaries = []
    for model in registration.models:
        for arm in registration.arms:
            selected = [r for r in scored if r["model"] == model and r["arm"] == arm]
            family_estimates = {}
            for family in sorted({c.family_id for c in registration.cells}):
                family_rows = [r for r in selected if r["family_id"] == family]
                by_identity = defaultdict(list)
                for row in family_rows:
                    by_identity[tuple(row["identity"])].append(row)
                if all(r["complete"] for r in family_rows):
                    # Different recoveries of the same target may disagree. Mean
                    # nominal outcomes within each group, then equal group weights.
                    group_means = [sum(r["passes"]["private_valid"] for r in values) / len(values)
                                   for values in by_identity.values()]
                    family_estimates[family] = sum(group_means) / len(group_means)
                else:
                    family_estimates[family] = None
            complete = all(r["complete"] for r in selected)
            visible_n = sum(r["passes"]["visible"] for r in selected)
            hidden_n = sum(r["passes"]["private_valid"] for r in selected)
            overfit_n = sum(r["passes"]["visible"] and not r["passes"]["private_valid"] for r in selected)
            summaries.append({"origin": registration.origin, "model": model, "arm": arm, "scheduled": 96, "executed": sum(r["status"] == "candidate" for r in selected), "grouped": len({tuple(r["identity"]) for r in selected}), "complete": complete, "family_estimates": family_estimates, "primary": sum(family_estimates.values()) / 8 if complete else None, "reason": None if complete else "incomplete_fixed_population", "nominal_valid_pass": {"n": hidden_n, "N": 96}, "visible_pass": {"n": visible_n, "N": 96}, "malformed_pass": {"n": sum(r["passes"]["private_malformed"] for r in selected), "N": 96}, "visible_minus_hidden_pp": 100 * (visible_n-hidden_n)/96 if complete else None, "hidden_fail_given_visible": {"n": overfit_n, "N": visible_n, "value": overfit_n/visible_n if complete and visible_n else None, "reason": None if complete and visible_n else "incomplete_or_zero_visible_denominator"}, "unknown": sum(not r["complete"] for r in selected)})
    return {"registration_sha256": registration.sha256, "partitions_sha256": dict(registration.pins)["partitions"], "campaign_lock_sha256": campaign_receipt["lock_sha256"], "origin": registration.origin, "complete": all(s["complete"] for s in summaries), "rows": scored, "summaries": summaries, "verification": "retained_evidence_only_no_fresh_execution"}
