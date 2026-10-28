"""Builder-authored SOFTWARE-ONLY resource inputs, never dispatch receipts.

Factories run only during authorized software tests. Literal usage/charges below
are arithmetic regression inputs, not measured provider usage or actual spending.
No database, provider, candidate program or independent corpus is accessed.
"""

from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
from hashlib import sha256
import json
from typing import Any

SCOPE = "BUILDER_AUTHORED_SOFTWARE_ONLY_NOT_DISPATCH_OR_INDEPENDENT_CORPUS"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def commitment(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def make_resource_inputs(matrix: Any, *, task_count: int | None = None,
                         labels: tuple[str, ...] = ("M:0",),
                         charge: str = "0", unknown_first: bool = False) -> tuple[dict, list[dict]]:
    """Return detached closed dictionaries for resource join regression tests.

    ``task_count=None`` covers all 96 nominal software tasks for each model. An
    optional nonzero charge is an authored arithmetic example only. The helper
    deliberately does not claim these mappings were emitted by FixtureDispatch.
    """
    cells = list(matrix.registration.cells)
    if task_count is not None:
        cells = cells[:task_count]
    if not labels or labels[0] != "M:0" or any(
        label not in {"M:0", "R:1", "R:2", "R:3", "P:1", "P:2", "P:3"}
        for label in labels
    ):
        raise ValueError("software resource labels need shared M first")
    attempts: list[dict] = []
    receipts: list[dict] = []
    for score_model in matrix.registration.models:
        config = deepcopy(matrix.model_configs[score_model])
        for cell in cells:
            for label in labels:
                # This is a minimal retained opaque request identity for the
                # resource parser, not an admitted VisibleTask/provider fixture.
                request = {"visible_task": {"task_id": cell.task_id},
                           "model_config": config, "software_test_scope": SCOPE,
                           "history": [], "evidence": {"software_only": True}}
                request_sha = commitment(request)
                request_id = f"{cell.task_id}:{config['config_id']}:{label}"
                unknown = unknown_first and not attempts
                record = None if unknown else {
                    "request": request, "request_sha256": request_sha,
                    "origin": "fixture", "response": {"abstain": True},
                    "usage": {"input_tokens": 0, "output_tokens": 0, "usd": charge}}
                attempts.append({"request_id": request_id, "digest": request_sha,
                    "attempt": 1, "reserve": "1" if unknown else charge,
                    "status": "unknown" if unknown else "settled",
                    "charge": None if unknown else charge,
                    "reason": "SOFTWARE_ONLY unknown-liability example" if unknown else
                              "SOFTWARE_ONLY authored arithmetic example; no actual charge"})
                receipts.append({"schema": "bbr.call-resource.v1",
                    "campaign_id": matrix.registration.edition, "origin": "fixture",
                    "task_id": cell.task_id, "model_id": config["model_id"],
                    "config_id": config["config_id"], "call_id": label,
                    "request_id": request_id, "attempt": 1,
                    "request_sha256": request_sha, "request": request,
                    "provider_record": record,
                    "provider_record_sha256": None if unknown else commitment(record),
                    "provider_record_reason": "SOFTWARE_ONLY source unavailable example" if unknown else None})
    committed = sum((Decimal(row["reserve"] if row["charge"] is None else row["charge"])
                     for row in attempts), Decimal(0))
    if committed > 40:
        raise ValueError("software example exceeds supported ledger cap")
    snapshot = {"cap_usd": "40", "committed_usd": format(committed, "f"),
        "available_usd": format(Decimal(40) - committed, "f"),
        "attempts": attempts, "max_attempts": 1344,
        "dispatch_blocked": unknown_first and bool(attempts) or committed >= 40 or len(attempts) >= 1344}
    return snapshot, receipts
