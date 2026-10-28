"""Authored software test data, NOT binary corpus/held-out/custody evidence.

All hashes identify symbolic test values; none denotes a real image or binary.
Nonzero money values are arithmetic fixtures, never actual spending.
"""

from copy import deepcopy
from hashlib import sha256
import json
from decimal import Decimal


def fixture_sha(label: str) -> str:
    return sha256(("authored-software-regression-fixture:" + label).encode()).hexdigest()


def canonical_digest(value) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def resource_inputs(calls=(("M:0", "settled", "0.03", "0.03"),)):
    """Symbolic accounting rows, no actual provider/API/SQLite operation."""
    attempts, receipts = [], []
    for label, status, reserve, charge in calls:
        attempt = 1 + sum(row["request_id"].endswith(":" + label) for row in attempts)
        request = {"visible_task": {"task_id": "software-task"}, "history": [label],
                   "model_config": {"model_id": "software-model", "config_id": "software-config",
                                    "endpoint_id": "offline", "seed": 0, "origin": "fixture"}}
        request_id = "software-task:software-config:" + label
        digest = canonical_digest(request)
        attempts.append({"request_id": request_id, "digest": digest, "attempt": attempt,
                         "reserve": reserve, "status": status, "charge": charge,
                         "reason": "authored software accounting fixture, not a real bill"})
        receipts.append({"schema": "bbr.call-resource.v1", "campaign_id": "software-no-campaign",
            "origin": "fixture", "task_id": "software-task", "model_id": "software-model",
            "config_id": "software-config", "call_id": label, "request_id": request_id,
            "attempt": attempt, "request_sha256": digest, "request": request,
            "provider_record": None, "provider_record_sha256": None,
            "provider_record_reason": "no provider dispatched; software regression fixture"})
    committed = sum((Decimal(a["reserve"] if a["charge"] is None else a["charge"])
                     for a in attempts), Decimal(0))
    ledger = {"cap_usd": "40", "committed_usd": str(committed),
              "available_usd": str(max(Decimal(0), Decimal(40) - committed)),
              "attempts": attempts, "max_attempts": 1344,
              "dispatch_blocked": any(a["status"] in {"reserved", "in_flight", "unknown"}
                                      for a in attempts) or committed >= 40 or len(attempts) >= 1344}
    return ledger, receipts


def pass_references(arms=("M", "R", "P"), passes=1):
    return [{"model_id": "software-model", "config_id": "software-config", "arm": arm,
             "passed_tasks": passes, "reason": None,
             "source_sha256": fixture_sha("software-score-reference-" + arm)} for arm in arms]


def projection_fixture():
    """Trusted-score UNIT stub only; no hidden-open/admission receipt is fabricated.

    In each codec 3 nominal variants share a passing identity and the remaining
    identity fails: nominal pass3/4, equal-identity pass1/2, equal-family pass1/2.
    This tests projection, NOT the scorer or any benchmark/campaign gate.
    """
    from evaluation.preregister import Cell, Registration
    cells = []
    for family in range(8):
        for codec in ("dec", "hex", "bin"):
            for variant, (compiler, optimization) in enumerate(
                    (("gcc", "O0"), ("gcc", "O2"), ("clang", "O0"), ("clang", "O2"))):
                cells.append(Cell(f"software-{family}-{codec}-{variant}", f"software-family-{family}",
                    codec, compiler, optimization, "finite" if family < 2 else "ordinary",
                    fixture_sha(f"symbolic-artifact-{family}-{codec}-{variant == 3}"),
                    fixture_sha(f"symbolic-contract-{family}-{codec}")))
    pin_names = ("engine", "scorer", "baselines", "prompts", "wrappers", "generators", "domain_policy",
                 "resources", "prices", "schedule", "partitions", "source", "canaries")
    registration = Registration("authored-software-projection-no-campaign", tuple(cells),
        ("software-model-a", "software-model-b"), ("S", "M", "R", "P", "echo", "constant", "lookup"),
        "fixture", tuple((name, fixture_sha("symbolic-pin-" + name)) for name in pin_names), 0)
    rows = []
    for task, model, arm in sorted(registration.final_keys):
        cell = next(c for c in cells if c.task_id == task)
        passed = not task.endswith("-3")
        rows.append({"task_id": task, "model": model, "arm": arm,
            "candidate_sha256": fixture_sha("symbolic-software-candidate"),
            "family_id": cell.family_id, "codec": cell.codec, "compiler": cell.compiler,
            "optimization": cell.optimization, "tier": cell.tier, "identity": list(cell.identity),
            "status": "candidate", "complete": True, "unknown_reason": None,
            "passes": {"visible": True, "private_valid": passed, "private_malformed": passed},
            "case_counts": {"visible": 8, "private_valid": 184 if cell.tier == "finite" else 256,
                            "private_malformed": 32}})
    summaries = [{"origin": "fixture", "model": model, "arm": arm, "scheduled": 96,
        "family_estimates": {f"software-family-{i}": 0.5 for i in range(8)},
        "primary": 0.5, "reason": None, "complete": True}
        for model in registration.models for arm in registration.arms]
    score = {"registration_sha256": registration.sha256,
             "partitions_sha256": dict(registration.pins)["partitions"],
             "campaign_lock_sha256": fixture_sha("symbolic-score-lock-not-a-receipt"),
             "origin": "fixture", "complete": True, "rows": rows, "summaries": summaries,
             "verification": "retained_evidence_only_no_fresh_execution"}
    return registration, deepcopy(score)
