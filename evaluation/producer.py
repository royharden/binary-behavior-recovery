"""Adapt retained shared producer contracts to frozen evaluation rows.

This collector opens no streams, dispatches no calls and executes no subjects.
It consumes already-retained PairOutcome values under a supplied post-lock receipt.
Authentic custody and the original execution remain external requirements.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .exposure import validate_open_receipt
from .preregister import Registration, require_digest
from .run import retained_report
from .validate import frozen_partitions


def observation_row(observation: Any) -> dict:
    """Use the shared Observation producer, retaining infrastructure unknowns."""
    from bbr.contracts import Observation

    value = Observation.model_validate(observation)
    return {"stdout_hex": value.stdout_bytes.hex(), "exit_code": value.exit_code,
            "signal": value.signal, "timed_out": value.timed_out,
            "output_limited": value.output_limited, "status": value.status}


class RetainedCollector:
    """Collect exact nominal task/model/arm observations, with no worker access."""

    def __init__(self, registration: Registration, *, partitions: dict,
                 campaign_receipt: dict):
        self.registration = registration
        # Caller mutation must not replace frozen manifests or final identities.
        self.partitions = deepcopy(partitions)
        self.receipt = deepcopy(campaign_receipt)
        self.rosters = frozen_partitions(registration, self.partitions)
        self.finals = validate_open_receipt(registration, self.receipt)
        self._rows: dict[tuple[str, str, str], dict] = {}
        for key, final in self.finals.items():
            if final["status"] != "candidate":
                self._rows[key] = {**deepcopy(final), "cases": []}

    def add(self, task_id: str, model: str, arm: str, *, candidate_sha256: str,
            stdin_bytes: bytes, outcome: Any) -> None:
        """Add a retained pair for an exact frozen visible/private input.

        The same opaque input can appear across arms and models; each nominal row
        retains it once. Public feedback cannot enter the hidden primary score.
        """
        from bbr.contracts import PairOutcome
        from bbr.differential import compare_observations
        from hashlib import sha256

        if any(not isinstance(x, str) or not x for x in (task_id, model, arm)):
            raise ValueError("explicit task/model/arm identities required")
        key = (task_id, model, arm)
        final = self.finals.get(key)
        if final is None or final["status"] != "candidate":
            raise ValueError("retained execution has no locked candidate")
        if require_digest(candidate_sha256) != final["candidate_sha256"]:
            raise ValueError("retained candidate differs from final lock")
        if type(stdin_bytes) is not bytes or len(stdin_bytes) > 64:
            raise ValueError("bounded input bytes required")
        value = PairOutcome.model_validate(outcome)
        if value.input_sha256 != sha256(stdin_bytes).hexdigest():
            raise ValueError("retained pair input hash differs from bytes")
        recomputed = compare_observations(value.binary, value.candidate,
                                          stdin_bytes=stdin_bytes)
        if (recomputed.status, recomputed.reason) != (value.status, value.reason):
            raise ValueError("retained comparator status or reason drift")
        raw_hex = stdin_bytes.hex()
        matches = [(partition, canonical) for partition, roster in self.rosters[task_id].items()
                   if partition in {"visible", "private_valid", "private_malformed"}
                   for raw, canonical in roster if raw == raw_hex]
        if len(matches) != 1:
            raise ValueError("retained input absent from frozen scoring partitions")
        partition, canonical = matches[0]
        row = self._rows.setdefault(key, {**deepcopy(final), "cases": []})
        if any(case["input_hex"] == raw_hex for case in row["cases"]):
            raise ValueError("duplicate retained observation for nominal row")
        row["cases"].append({"partition": partition, "input_hex": raw_hex,
                             "canonical_key": canonical,
                             "oracle": observation_row(value.binary),
                             "candidate": observation_row(value.candidate)})

    def rows(self) -> list[dict]:
        """Detached canonical row order; missing nominal rows remain missing."""
        rows = deepcopy([self._rows[key] for key in sorted(self._rows)])
        for row in rows:
            row["cases"].sort(key=lambda c: (c["partition"], c["input_hex"]))
        return rows

    def summary(self) -> dict:
        """Use the sole scorer; partial candidate input sets still refuse scoring."""
        return retained_report(self.registration, self.rows(), partitions=self.partitions,
                               campaign_receipt=self.receipt)
