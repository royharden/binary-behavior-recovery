"""Pure retained-resource joins. Ledger snapshots remain the cost authority.

No database, provider, scorer or candidate code is opened/imported/executed here.
Digest consistency is not proof of dispatch, usage authenticity or independence.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN, localcontext
from hashlib import sha256
import json
import re
from typing import Any, Mapping, Sequence

_REPORT = {"cap_usd", "committed_usd", "available_usd", "attempts",
           "max_attempts", "dispatch_blocked"}
_ATTEMPT = {"request_id", "digest", "attempt", "reserve", "status", "charge", "reason"}
_RECEIPT = {"schema", "campaign_id", "origin", "task_id", "model_id", "config_id",
            "call_id", "request_id", "attempt", "request_sha256", "request",
            "provider_record", "provider_record_sha256", "provider_record_reason"}
_PASS = {"model_id", "config_id", "arm", "passed_tasks", "reason", "source_sha256"}
_LABELS = {"M:0", "R:1", "R:2", "R:3", "P:1", "P:2", "P:3"}
_UNRESOLVED = {"reserved", "in_flight", "unknown"}


class ResourceSummaryError(ValueError):
    """Inconsistent, incomplete or mixed retained resource input."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ResourceSummaryError("retained JSON data required") from exc


def _digest(value: Any) -> str:
    return sha256(_canonical(value)).hexdigest()


def _closed(value: Any, keys: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise ResourceSummaryError("unknown/missing retained fields")
    return value


def _text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise ResourceSummaryError("nonempty bounded identity/reason required")
    return value


def _sha(value: Any) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ResourceSummaryError("lowercase SHA256 required")
    return value


def _integer(value: Any, maximum: int = 10**15) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ResourceSummaryError("bounded nonnegative integer required")
    return value


def _decimal(value: Any, maximum: int = 1000000) -> Decimal:
    if type(value) is not str or len(value) > 64:
        raise ResourceSummaryError("decimal string required; floats forbidden")
    try:
        number = Decimal(value)
    except InvalidOperation as exc:
        raise ResourceSummaryError("invalid decimal") from exc
    if (not number.is_finite() or number < 0 or number > maximum
            or number.as_tuple().exponent < -12):
        raise ResourceSummaryError("decimal exceeds ledger precision/range")
    return Decimal(0) if number == 0 else number


def _number(number: Decimal) -> str:
    return format(number, "f")


def _ledger(snapshot: dict[str, Any]) -> dict[tuple[str, int], dict[str, Any]]:
    _closed(snapshot, _REPORT)
    cap = _decimal(snapshot["cap_usd"])
    maximum = _integer(snapshot["max_attempts"], 1344)
    if not 0 < cap <= 40 or maximum == 0 or type(snapshot["dispatch_blocked"]) is not bool:
        raise ResourceSummaryError("invalid persistent ledger configuration")
    rows = snapshot["attempts"]
    if type(rows) is not list or len(rows) > maximum:
        raise ResourceSummaryError("ledger attempt ceiling exceeded")
    index = {}
    committed = Decimal(0)
    for row in rows:
        _closed(row, _ATTEMPT)
        request_id, attempt = _text(row["request_id"]), _integer(row["attempt"], 2)
        _sha(row["digest"])
        if attempt == 0 or (request_id, attempt) in index:
            raise ResourceSummaryError("duplicate/invalid ledger attempt")
        reserve = _decimal(row["reserve"])
        charge = None if row["charge"] is None else _decimal(row["charge"])
        status = row["status"]
        if type(row["reason"]) is not str or status not in _UNRESOLVED | {"settled", "never_sent"}:
            raise ResourceSummaryError("invalid ledger status/reason")
        if ((status in {"settled", "never_sent"} and charge is None)
                or (status in {"reserved", "in_flight"} and charge is not None)
                or (status == "never_sent" and charge != 0)
                or (status == "unknown" and charge is not None and charge <= reserve)):
            raise ResourceSummaryError("ledger charge/status disagreement")
        if status in {"settled", "never_sent", "unknown"} and not row["reason"].strip():
            raise ResourceSummaryError("settlement/reconciliation reason missing")
        index[request_id, attempt] = row
        committed += reserve if charge is None else charge
    for (request_id, attempt), row in index.items():
        if attempt == 2:
            prior = index.get((request_id, 1))
            if (prior is None or prior["status"] != "never_sent" or
                    prior["digest"] != row["digest"] or
                    _decimal(prior["reserve"]) != _decimal(row["reserve"])):
                raise ResourceSummaryError("retry lacks exact never-sent lineage")
    blocked = (any(row["status"] in _UNRESOLVED for row in rows) or
               committed >= cap or len(rows) >= maximum)
    if (_decimal(snapshot["committed_usd"], 1344000000) != committed or
            _decimal(snapshot["available_usd"]) != max(Decimal(0), cap - committed) or
            snapshot["dispatch_blocked"] != blocked):
        raise ResourceSummaryError("ledger aggregate/configuration drift")
    return index


def _measurements(source: dict[str, Any] | None, charge: Decimal | None) -> dict[str, Any]:
    usage = None if source is None else source.get("usage")
    tokens: dict[str, Any] = {"input_tokens": None, "output_tokens": None}
    if usage is not None:
        _closed(usage, {"input_tokens", "output_tokens", "usd"})
        for name in tokens:
            if usage[name] is not None:
                tokens[name] = _integer(usage[name])
        if usage["usd"] is not None and (charge is None or _decimal(usage["usd"]) != charge):
            raise ResourceSummaryError("provider usage USD differs from ledger charge")
    resources = None if source is None else source.get("resources")
    metrics: dict[str, Any] = {"wall_seconds": None, "cpu_seconds": None,
                               "peak_memory_bytes": None}
    if resources is not None:
        _closed(resources, set(metrics))
        for name in ("wall_seconds", "cpu_seconds"):
            if resources[name] is not None:
                metrics[name] = _number(_decimal(resources[name]))
        if resources["peak_memory_bytes"] is not None:
            metrics["peak_memory_bytes"] = _integer(resources["peak_memory_bytes"])
    return {**tokens, **metrics,
            "unavailable_reasons": {name: "not available in retained provider record"
                                     for name, value in {**tokens, **metrics}.items()
                                     if value is None}}


def _attempt(receipt: dict[str, Any], ledger: dict[str, Any], *,
             campaign_id: str, origin: str) -> dict[str, Any]:
    _closed(receipt, _RECEIPT)
    if (receipt["schema"] != "bbr.call-resource.v1" or
            receipt["campaign_id"] != campaign_id or receipt["origin"] != origin):
        raise ResourceSummaryError("campaign/origin/schema mismatch")
    task, model, config = (_text(receipt[k]) for k in ("task_id", "model_id", "config_id"))
    label = receipt["call_id"]
    if label not in _LABELS or receipt["request_id"] != f"{task}:{config}:{label}":
        raise ResourceSummaryError("call/request identity mismatch")
    if (receipt["request_sha256"] != ledger["digest"] or
            receipt["request_id"] != ledger["request_id"] or
            receipt["attempt"] != ledger["attempt"]):
        raise ResourceSummaryError("ledger request/attempt identity mismatch")
    request = receipt["request"]
    if type(request) is not dict or _digest(request) != _sha(receipt["request_sha256"]):
        raise ResourceSummaryError("exact request digest mismatch")
    cfg, visible = request.get("model_config"), request.get("visible_task")
    if (type(cfg) is not dict or type(visible) is not dict or visible.get("task_id") != task
            or any(cfg.get(k) != v for k, v in
                   (("model_id", model), ("config_id", config), ("origin", origin)))):
        raise ResourceSummaryError("request task/model/config/origin mismatch")
    _closed(cfg, {"model_id", "config_id", "endpoint_id", "seed", "origin"})
    _text(cfg["endpoint_id"])
    if type(cfg["seed"]) is not int:
        raise ResourceSummaryError("model seed must be retained integer")
    source = receipt["provider_record"]
    if source is None:
        if receipt["provider_record_sha256"] is not None:
            raise ResourceSummaryError("missing source cannot carry digest")
        _text(receipt["provider_record_reason"])
    else:
        if (type(source) is not dict or _digest(source) != _sha(receipt["provider_record_sha256"])
                or source.get("origin") != origin or
                source.get("request_sha256") != receipt["request_sha256"]):
            raise ResourceSummaryError("provider-record identity/digest mismatch")
        if "request" in source and _digest(source["request"]) != receipt["request_sha256"]:
            raise ResourceSummaryError("provider-record request drift")
        if receipt["provider_record_reason"] is not None:
            raise ResourceSummaryError("present source must use null unavailable reason")
    charge = None if ledger["charge"] is None else _decimal(ledger["charge"])
    measurements = _measurements(source, charge)
    if ledger["status"] == "never_sent" and any(
            measurements[name] not in (None, 0) for name in ("input_tokens", "output_tokens")):
        raise ResourceSummaryError("never-sent attempt cannot have provider token usage")
    return {"task_id": task, "model_id": model, "config_id": config, "arm": label[0],
            "call_id": label, "request_id": receipt["request_id"],
            "attempt": receipt["attempt"], "request_sha256": receipt["request_sha256"],
            "model_config_sha256": _digest(cfg), "receipt_sha256": _digest(receipt),
            "provider_record_sha256": receipt["provider_record_sha256"],
            "provider_record_reason": receipt["provider_record_reason"],
            "origin": origin, "status": ledger["status"], "reason": ledger["reason"],
            "reserved_usd": _number(_decimal(ledger["reserve"])),
            "recorded_charge_usd": None if charge is None else _number(charge),
            "measurements": measurements}


def _totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    settled, unresolved_charge, reserve = Decimal(0), Decimal(0), Decimal(0)
    for row in rows:
        charge = row["recorded_charge_usd"]
        if row["status"] in {"settled", "never_sent"}:
            settled += _decimal(charge)
        elif charge is None:
            reserve += _decimal(row["reserved_usd"])
        else:
            unresolved_charge += _decimal(charge)
    measurements = {}
    reasons = {}
    for name in ("input_tokens", "output_tokens", "wall_seconds", "cpu_seconds", "peak_memory_bytes"):
        values = [row["measurements"][name] for row in rows]
        if not values or any(value is None for value in values):
            measurements[name] = None
            reasons[name] = "one or more retained attempt measurements unavailable" if rows else "no retained attempts"
        elif name in {"wall_seconds", "cpu_seconds"}:
            measurements[name] = _number(sum((_decimal(v) for v in values), Decimal(0)))
        elif name == "peak_memory_bytes":
            measurements[name] = max(values)
        else:
            measurements[name] = sum(values)
    return {"unique_attempts": len(rows), "settled_spend_usd": _number(settled),
            "unresolved_recorded_charge_usd": _number(unresolved_charge),
            "unpriced_reserved_liability_usd": _number(reserve),
            "committed_usd": _number(settled + unresolved_charge + reserve),
            "cost_complete": all(row["status"] not in _UNRESOLVED for row in rows),
            "measurements": measurements, "unavailable_reasons": reasons}


def summarize_resources(ledger_report: Mapping[str, Any], receipts: Sequence[Mapping[str, Any]], *,
                        campaign_id: str, origin: str,
                        pass_counts: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Join a complete ledger snapshot, retained call receipts and score references.

    pass_counts references are caller-verified scoring inputs, not a second scorer.
    The caller must retain all inputs under independently pinned archive digests.
    """
    _text(campaign_id)
    if origin not in {"fixture", "live"}:
        raise ResourceSummaryError("explicit fixture/live origin required")
    # Detach ordinary retained JSON only; never call methods on live producer objects.
    snapshot = json.loads(_canonical(ledger_report))
    supplied = json.loads(_canonical(receipts))
    scores = json.loads(_canonical(pass_counts))
    if (type(supplied) is not list or len(supplied) > 1344 or
            type(scores) is not list or len(scores) > 4032):
        raise ResourceSummaryError("bounded retained receipt/score arrays required")
    with localcontext() as context:
        context.prec = 50
        context.rounding = ROUND_HALF_EVEN
        index = _ledger(snapshot)
        joined = {}
        configs = {}
        identities = {}
        for receipt in supplied:
            _closed(receipt, _RECEIPT)
            key = (_text(receipt["request_id"]), _integer(receipt["attempt"], 2))
            if key not in index or key in joined:
                raise ResourceSummaryError("missing ledger row or duplicate/conflicting call receipt")
            row = _attempt(receipt, index[key], campaign_id=campaign_id, origin=origin)
            config = row["config_id"]
            if config in configs and configs[config] != row["model_config_sha256"]:
                raise ResourceSummaryError("model/config identity drift")
            configs[config] = row["model_config_sha256"]
            identity = (row["task_id"], row["model_id"], config, row["call_id"])
            if key[0] in identities and identities[key[0]] != identity:
                raise ResourceSummaryError("request ID reused across conflicting identities")
            identities[key[0]] = identity
            joined[key] = row
        if set(joined) != set(index):
            raise ResourceSummaryError("every ledger attempt must have exactly one identity receipt")
        rows = [joined[key] for key in sorted(joined)]
        scores_by_group = {}
        for score in scores:
            _closed(score, _PASS)
            key = (_text(score["model_id"]), _text(score["config_id"]), score["arm"])
            if score["arm"] not in {"M", "R", "P"} or key in scores_by_group:
                raise ResourceSummaryError("duplicate/invalid pass-count group")
            _sha(score["source_sha256"])
            if score["passed_tasks"] is None:
                _text(score["reason"])
            elif score["reason"] is not None:
                raise ResourceSummaryError("known pass count must use null unavailable reason")
            else:
                _integer(score["passed_tasks"])
            scores_by_group[key] = score
        groups = []
        group_keys = sorted({(r["model_id"], r["config_id"], arm)
                             for r in rows for arm in ("M", "R", "P")})
        if not set(scores_by_group).issubset(group_keys):
            raise ResourceSummaryError("pass count has no retained model/config group")
        for model, config, arm in group_keys:
            own = [r for r in rows if (r["model_id"], r["config_id"], r["arm"]) == (model, config, arm)]
            initial = [r for r in rows if (r["model_id"], r["config_id"], r["arm"]) == (model, config, "M")]
            initial_tasks = {r["task_id"] for r in initial}
            if any(r["task_id"] not in initial_tasks for r in own):
                raise ResourceSummaryError("arm calls lack retained shared M lineage")
            totals = _totals(own)
            inclusive = totals if arm == "M" else _totals(own + initial)
            score = scores_by_group.get((model, config, arm))
            passes = None if score is None else score["passed_tasks"]
            if passes is not None and passes > len(initial_tasks):
                raise ResourceSummaryError("pass count exceeds retained task count")
            reason = ("pass count unavailable" if passes is None else "zero passes" if passes == 0
                      else "unresolved costs including shared M" if not inclusive["cost_complete"] else None)
            groups.append({"model_id": model, "config_id": config, "arm": arm,
                "incremental": totals, "including_shared_m_nonadditive": inclusive,
                "passed_tasks": passes,
                "pass_count_reason": "score reference unavailable" if score is None else score["reason"],
                "pass_count_source_sha256": None if score is None else score["source_sha256"],
                "usd_per_pass": None if reason else _number(
                    _decimal(inclusive["settled_spend_usd"], 1344000000) / passes),
                "usd_per_pass_basis": "arm costs including shared M; nonadditive across arms",
                "usd_per_pass_reason": reason,
                "shared_m_reuse": [] if arm == "M" else [
                    {"task_id": r["task_id"], "request_id": r["request_id"], "attempt": r["attempt"],
                     "request_sha256": r["request_sha256"], "receipt_sha256": r["receipt_sha256"],
                     "original_recorded_charge_usd": r["recorded_charge_usd"],
                     "original_status": r["status"], "new_charge_usd": "0"} for r in initial]})
        return {"schema": "bbr.resource-summary.v1", "campaign_id": campaign_id, "origin": origin,
            "verification_scope": "retained structural consistency only; not execution/authenticity",
            "ledger_report_sha256": _digest(snapshot), "receipts_sha256": _digest(supplied),
            "pass_counts_sha256": _digest(scores), "campaign_unique": _totals(rows),
            "ratio_decimal_precision": 50, "ratio_rounding": "ROUND_HALF_EVEN",
            "ledger_dispatch_blocked": snapshot["dispatch_blocked"],
            "attempts": rows, "groups": groups}
