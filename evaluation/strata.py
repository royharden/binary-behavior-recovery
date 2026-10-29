"""Project retained scorer output into nominal strata, never another scorer.

Only the existing score_rows function interprets observations or computes primary
identity/family estimates. No executable, private stream or database is opened.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .preregister import Registration, digest, require_digest
from .score import score_rows

_SCORE_KEYS = {"registration_sha256", "partitions_sha256", "campaign_lock_sha256",
               "origin", "complete", "rows", "summaries", "verification"}
_ROW_KEYS = {"task_id", "model", "arm", "candidate_sha256", "family_id", "codec",
             "compiler", "optimization", "tier", "identity", "status", "complete",
             "unknown_reason", "passes", "case_counts"}
_PARTITIONS = ("visible", "private_valid", "private_malformed")
_STATUSES = ("candidate", "abstain", "syntax_failure", "not_run", "infrastructure_error")
_TABLES = (("by_model_arm", None), ("by_family", "family_id"), ("by_codec", "codec"),
           ("by_compiler", "compiler"), ("by_optimization", "optimization"),
           ("by_tier", "tier"))


def _validated_source(registration: Registration, score: dict) -> dict[tuple[str, str], dict]:
    if type(score) is not dict or set(score) != _SCORE_KEYS:
        raise ValueError("base score_rows output required; no asserted aggregate input")
    if (score["registration_sha256"] != registration.sha256 or
            score["partitions_sha256"] != dict(registration.pins)["partitions"] or
            score["origin"] != registration.origin or
            score["verification"] != "retained_evidence_only_no_fresh_execution"):
        raise ValueError("score registration/origin/provenance mismatch")
    require_digest(score["campaign_lock_sha256"])
    cells = {cell.task_id: cell for cell in registration.cells}
    seen = set()
    if type(score["rows"]) is not list or len(score["rows"]) != len(registration.final_keys):
        raise ValueError("all scheduled nominal scored rows required")
    for row in score["rows"]:
        if type(row) is not dict or set(row) != _ROW_KEYS:
            raise ValueError("closed scored row required")
        key = (row["task_id"], row["model"], row["arm"])
        if key not in registration.final_keys or key in seen:
            raise ValueError("duplicate/outside-roster scored row")
        seen.add(key)
        cell = cells[row["task_id"]]
        if (any(row[name] != getattr(cell, name) for name in
                ("family_id", "codec", "compiler", "optimization", "tier")) or
                row["identity"] != list(cell.identity)):
            raise ValueError("scored task dimensions/complete ELF identity mismatch")
        if (row["status"] not in _STATUSES or type(row["complete"]) is not bool or
                type(row["passes"]) is not dict or set(row["passes"]) != set(_PARTITIONS) or
                any(type(v) is not bool for v in row["passes"].values()) or
                type(row["case_counts"]) is not dict or set(row["case_counts"]) != set(_PARTITIONS) or
                any(type(n) is not int or n < 0 for n in row["case_counts"].values())):
            raise ValueError("invalid scored status/pass/count fields")
        if (row["complete"] and row["unknown_reason"] is not None) or (
                not row["complete"] and
                (type(row["unknown_reason"]) is not str or not row["unknown_reason"])):
            raise ValueError("scored completeness reason mismatch")
        if not row["complete"] and any(row["passes"].values()):
            raise ValueError("incomplete scored row cannot count as passing")
    if seen != registration.final_keys:
        raise ValueError("scored nominal roster incomplete")
    summaries = {}
    families = {cell.family_id for cell in registration.cells}
    if type(score["summaries"]) is not list:
        raise ValueError("scorer summaries required")
    for summary in score["summaries"]:
        key = (summary["model"], summary["arm"])
        if (key in summaries or key[0] not in registration.models or key[1] not in registration.arms
                or summary["origin"] != registration.origin or summary["scheduled"] != 96 or
                set(summary["family_estimates"]) != families):
            raise ValueError("scorer summary roster/origin mismatch")
        summaries[key] = summary
    if set(summaries) != {(model, arm) for model in registration.models for arm in registration.arms}:
        raise ValueError("all model/arm summaries required")
    return summaries


def _nominal(rows: list[dict]) -> dict[str, Any]:
    """Count existing row booleans, retaining every scheduled status in N."""
    total = len(rows)
    complete = all(row["complete"] for row in rows)
    passing = {partition: sum(row["passes"][partition] for row in rows)
               for partition in _PARTITIONS}
    overfit = sum(row["passes"]["visible"] and not row["passes"]["private_valid"]
                  for row in rows)
    status_counts = Counter(row["status"] for row in rows)
    unknowns = Counter(row["unknown_reason"] for row in rows if not row["complete"])

    def rate(partition: str) -> dict:
        return {"n": passing[partition], "N": total,
                "value": passing[partition] / total if complete else None,
                "reason": None if complete else "incomplete_nominal_stratum"}

    return {"scheduled": total, "scheduled_task_ids": sorted(row["task_id"] for row in rows),
            "complete": complete, "unknown_rows": sum(not row["complete"] for row in rows),
            "unknown_reason_counts": dict(sorted(unknowns.items())),
            "status_counts": {status: status_counts[status] for status in _STATUSES},
            "identity_group_count": len({tuple(row["identity"]) for row in rows}),
            "family_count": len({row["family_id"] for row in rows}),
            "nominal_valid_pass": rate("private_valid"),
            "visible_pass": rate("visible"), "malformed_pass": rate("private_malformed"),
            "visible_minus_hidden_pp": 100 * (passing["visible"] - passing["private_valid"]) / total
                if complete else None,
            "visible_minus_hidden_reason": None if complete else "incomplete_nominal_stratum",
            "hidden_fail_given_visible": {"n": overfit, "N": passing["visible"],
                "value": overfit / passing["visible"] if complete and passing["visible"] else None,
                "reason": None if complete and passing["visible"] else
                    "incomplete_nominal_stratum" if not complete else "zero_visible_denominator"},
            "retained_case_counts": {partition: sum(row["case_counts"][partition] for row in rows)
                                     for partition in _PARTITIONS},
            "case_count_basis": "nominal task-case observations; not independent/deduplicated values"}


def summarize_strata(registration: Registration, retained_rows: list[dict], *,
                     partitions: dict, campaign_receipt: dict,
                     expected_score_sha256: str) -> dict:
    """Recompute through the sole scorer, verify source commitment, then project.

    expected_score_sha256 is the canonical base score_rows commitment from the
    caller's separately verified retained inputs; not a summary's embedded hash.
    No primary weighting, bootstrap or private-domain generation occurs here.
    """
    require_digest(expected_score_sha256)
    # This source call is the only observation/score interpretation. No alternate
    # boolean scorer or caller-asserted aggregate can bypass its full input gates.
    score = score_rows(registration, retained_rows, partitions=partitions,
                       campaign_receipt=campaign_receipt)
    actual_sha256 = digest(score)
    if actual_sha256 != expected_score_sha256:
        raise ValueError("recomputed canonical score-source commitment mismatch")
    summaries = _validated_source(registration, score)
    tables = {}
    for table, dimension in _TABLES:
        grouped: dict[tuple[str, ...], list[dict]] = defaultdict(list)
        for row in score["rows"]:
            key = (row["model"], row["arm"])
            if dimension is not None:
                key += (row[dimension],)
            grouped[key].append(row)
        output = []
        for key, rows in sorted(grouped.items()):
            summary = summaries[key[:2]]
            dimensions = {"origin": registration.origin, "model": key[0], "arm": key[1]}
            if dimension is not None:
                dimensions[dimension] = key[2]
            if table == "by_model_arm":
                primary = summary["primary"]
                reason = summary["reason"]
                basis = "existing scorer equal-family primary with its identity-group weights"
            elif table == "by_family":
                primary = summary["family_estimates"][key[2]]
                reason = None if primary is not None else "incomplete_family"
                basis = "existing scorer family estimate with its identity-group weights"
            else:
                primary = None
                reason = "no primary identity/family estimator defined for this nominal stratum"
                basis = "nominal table only; use existing full-family scorer primary separately"
            output.append({**dimensions, **_nominal(rows),
                "primary_identity_group_estimate": primary,
                "primary_identity_group_reason": reason, "primary_estimate_basis": basis,
                "nominal_estimate_basis": "equal scheduled nominal rows; distinct from primary weighting"})
        tables[table] = output
    return {"schema": "bbr.strata.v1", "origin": registration.origin,
            "edition": registration.edition, "registration_sha256": registration.sha256,
            "source_score_sha256": actual_sha256,
            "partitions_sha256": score["partitions_sha256"],
            "campaign_lock_sha256": score["campaign_lock_sha256"],
            "complete": score["complete"], "scheduled_rows": len(score["rows"]),
            "nominal_rows_per_model_arm": 96, "tables": tables,
            "unsupported_metrics": {
                "runtime_cause_categories": {"value": None,
                    "reason": "scored rows do not retain fault-cause observations"},
                "tokens_cost_resource_metrics": {"value": None,
                    "reason": "use separately joined retained resource sources, not score rows"},
                "finite_sample_calibration": {"value": None,
                    "reason": "no precommitted calibration sample observations in scored rows"},
                "paired_bootstrap": {"value": None,
                    "reason": "use existing evaluation.statistics paired bootstrap; no strata redraws"}},
            "verification_scope": "recomputed retained-score projection only; no fresh execution/authenticity",
            "limitations": ["incomplete strata rates stay null; passing n is a retained lower count",
                "abstain and syntax-failure rows remain complete denominator failures",
                "finite184 and ordinary256+ case counts are not pooled case-level pass rates",
                "marginal tables overlap and must not be added together",
                "fixture/live and models/arms are never pooled into a headline estimate"]}
