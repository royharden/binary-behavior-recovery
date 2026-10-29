"""M/R/P source controller. Only injected isolated ports may inspect candidates."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence


class InfrastructureUnknown(RuntimeError):
    """Stop dispatch with a detached, recursively immutable failure receipt."""

    def __init__(self, call_id: str, diagnostic: str, *,
                 attempted_response: Mapping[str, Any] | None = None,
                 origin: str | None = None, probe_progress: Mapping[str, Any] | None = None,
                 calls_attempted: int = 0,
                 archive_snapshots: Mapping[str, Mapping[str, Any]] | None = None):
        super().__init__(diagnostic)
        self._receipt = _snapshot({
            "call_id": call_id, "status": "infrastructure_error", "diagnostic": diagnostic,
            "attempted_response": attempted_response, "origin": origin,
            "probe_progress": probe_progress, "calls_attempted": calls_attempted,
            "archive_snapshots": archive_snapshots if archive_snapshots is not None else {}})

    @property
    def receipt(self) -> Mapping[str, Any]:
        return self._receipt

    @property
    def call_id(self) -> str:
        return self._receipt["call_id"]

    @property
    def status(self) -> str:
        return self._receipt["status"]

    @property
    def diagnostic(self) -> str:
        return self._receipt["diagnostic"]

    @property
    def calls_attempted(self) -> int:
        return self._receipt["calls_attempted"]

    @property
    def archive_snapshots(self) -> Mapping[str, Mapping[str, Any]]:
        return self._receipt["archive_snapshots"]

    def snapshot(self) -> dict[str, Any]:
        """Detached ordinary JSON export; edits cannot change the receipt."""
        return _json_value(self._receipt)

    def with_controller_context(self, calls_attempted: int,
                                archives: Mapping[str, Mapping[str, Any]]) -> InfrastructureUnknown:
        return InfrastructureUnknown(
            self.call_id, self.diagnostic,
            attempted_response=self._receipt["attempted_response"], origin=self._receipt["origin"],
            probe_progress=self._receipt["probe_progress"], calls_attempted=calls_attempted,
            archive_snapshots=archives)


def _json_value(value: Any) -> Any:
    """Detach JSON data, including our frozen mapping/array representations."""
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("JSON object keys must be strings")
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise TypeError("expected JSON data")


def _canonical(value: Any) -> bytes:
    return json.dumps(_json_value(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _snapshot(value: Any) -> Any:
    # Round-tripping severs every caller-owned container before it is frozen.
    return _freeze(json.loads(_canonical(value)))


@dataclass(frozen=True, slots=True)
class Submission:
    call_id: str
    response: Mapping[str, Any] | None
    parse_valid: bool
    diagnostic: str
    origin: str

    def __post_init__(self) -> None:
        if any(type(item) is not str for item in
               (self.call_id, self.diagnostic, self.origin)) or type(self.parse_valid) is not bool:
            raise TypeError("submission metadata must be strings and a boolean")
        if self.response is not None and not isinstance(self.response, Mapping):
            raise TypeError("submission response must be a JSON object or null")
        object.__setattr__(self, "response", _snapshot(self.response))

    def snapshot(self) -> dict[str, Any]:
        """Return detached ordinary JSON data for serialization/callbacks."""
        return {"call_id": self.call_id, "response": _json_value(self.response),
                "parse_valid": self.parse_valid, "diagnostic": self.diagnostic,
                "origin": self.origin}

    @property
    def abstain(self) -> bool:
        return self.parse_valid and self.response is not None and self.response.get("abstain") is True


def validate_submission(response: Any, call_id: str,
                        isolated_validate: Callable[[str], tuple[bool | None, str]],
                        origin: str = "fixture") -> Submission:
    """Validate structure here; delegate all candidate parsing to isolation.

    Canonical JSON mode preserves hexadecimal probe bytes for the broker. The
    callback must refuse unavailable sandbox execution, never use host exec/import.
    """
    from bbr.contracts import CandidateResponse

    try:
        if isinstance(response, CandidateResponse):
            checked = response
        elif isinstance(response, Mapping):
            checked = CandidateResponse.model_validate_json(_canonical(response))
        else:
            checked = CandidateResponse.model_validate_json(response)
    except (ValueError, TypeError) as exc:
        return Submission(call_id, None, False, f"response_schema: {exc}", origin)
    payload = checked.model_dump(mode="json")
    if checked.abstain:
        return Submission(call_id, payload, True, "explicit_abstain", origin)

    def unknown(diagnostic: str) -> InfrastructureUnknown:
        # An unvalidated attempt is retained separately from parse-valid/invalid
        # submissions. In particular, M:0 may fail before any archive exists.
        return InfrastructureUnknown(call_id, diagnostic, attempted_response=payload, origin=origin)

    try:
        verdict = isolated_validate(checked.code)
    except Exception as exc:
        raise unknown("infrastructure_error: candidate validator fault") from exc
    if not isinstance(verdict, tuple) or len(verdict) != 2:
        raise unknown("infrastructure_error: malformed candidate validator result")
    valid, diagnostic = verdict
    if (valid is not None and type(valid) is not bool) or type(diagnostic) is not str:
        raise unknown("infrastructure_error: malformed candidate validator result")
    if valid is None:
        raise unknown(diagnostic)
    return Submission(call_id, payload, valid, diagnostic, origin)


@dataclass(frozen=True, slots=True, init=False)
class ArmArchive:
    arm: str
    submissions: tuple[Submission, ...]
    feedback: tuple[Mapping[str, Any], ...]
    shared_m_call_id: str
    _locked_record: Mapping[str, Any] | None
    _locked_bytes: bytes | None

    def __init__(self, arm: str, submissions: Sequence[Submission] = (),
                 feedback: Sequence[Mapping[str, Any]] = (), shared_m_call_id: str = ""):
        if type(arm) is not str or type(shared_m_call_id) is not str:
            raise TypeError("archive identity must be strings")
        object.__setattr__(self, "arm", arm)
        object.__setattr__(self, "shared_m_call_id", shared_m_call_id)
        object.__setattr__(self, "submissions", tuple(self._submission(s) for s in submissions))
        object.__setattr__(self, "feedback", tuple(self._feedback(row) for row in feedback))
        object.__setattr__(self, "_locked_record", None)
        object.__setattr__(self, "_locked_bytes", None)

    @staticmethod
    def _submission(value: Submission) -> Submission:
        if not isinstance(value, Submission):
            raise TypeError("archive requires Submission records")
        return Submission(**value.snapshot())

    @staticmethod
    def _feedback(value: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            raise TypeError("archive feedback must be a JSON object")
        return _snapshot(value)

    @property
    def locked(self) -> bool:
        return self._locked_record is not None

    def append_submission(self, submission: Submission) -> None:
        if self.locked:
            raise ValueError("archive is locked")
        object.__setattr__(self, "submissions", self.submissions + (self._submission(submission),))

    def append_feedback(self, feedback: Mapping[str, Any]) -> None:
        if self.locked:
            raise ValueError("archive is locked")
        object.__setattr__(self, "feedback", self.feedback + (self._feedback(feedback),))

    def selected(self) -> Submission | None:
        # Explicit final abstention is a parse-valid selection. Neither observed
        # performance nor any hidden score participates in this choice.
        return next((s for s in reversed(self.submissions) if s.parse_valid), None)

    def lock(self) -> Mapping[str, Any]:
        if self._locked_record is not None:
            return self._locked_record
        selected = self.selected()
        payload = {"arm": self.arm, "shared_m_call_id": self.shared_m_call_id,
                   "selected_call_id": selected.call_id if selected else None,
                   "status": "abstain" if selected and selected.abstain else
                             "candidate" if selected else "parse_fail",
                   "submissions": [s.snapshot() for s in self.submissions],
                   "feedback": self.feedback}
        record = _snapshot({**payload, "sha256": sha256(_canonical(payload)).hexdigest()})
        object.__setattr__(self, "_locked_bytes", _canonical(record))
        object.__setattr__(self, "_locked_record", record)
        return record

    def lock_bytes(self) -> bytes:
        """Canonical JSON including sha256; the digest covers the record without sha256."""
        self.lock()
        assert self._locked_bytes is not None
        return self._locked_bytes

    def lock_snapshot(self) -> dict[str, Any]:
        """Detached mutable JSON export; editing it cannot alter the retained lock."""
        return json.loads(self.lock_bytes())


class ProbeBroker:
    """Only the frozen public pool can reach an isolated pair executor.

    `run_pair` returns a closed mapping with status, oracle and candidate
    observations and `diverged`. Infrastructure faults stop the intervention.
    Invalid/repeated/outside requests consume slots without a target run.
    """

    def __init__(self, public_pool: Sequence[bytes], fixed_batches: Sequence[Sequence[bytes]],
                 run_pair: Callable[[Submission, bytes], Mapping[str, Any]]):
        if len(fixed_batches) != 3 or any(len(batch) != 8 for batch in fixed_batches):
            raise ValueError("exactly three precommitted batches of eight required")
        if len(set(public_pool)) != len(public_pool):
            raise ValueError("public pool contains duplicates")
        fixed = [raw for batch in fixed_batches for raw in batch]
        if len(set(fixed)) != 24 or any(raw not in public_pool for raw in fixed):
            raise ValueError("fixed batches must be unique public-pool inputs")
        self.pool = frozenset(public_pool)
        self.fixed = tuple(tuple(batch) for batch in fixed_batches)
        self.run_pair = run_pair
        self.slots = 0
        self.stage = 0
        self.seen: set[bytes] = set()
        self._stopped: InfrastructureUnknown | None = None

    @classmethod
    def for_task(cls, visible_task: Any, fixed_batches: Sequence[Sequence[bytes]],
                 run_pair: Callable[[Submission, bytes], Mapping[str, Any]]) -> ProbeBroker:
        """Production binding uses exactly the shared validated public pool."""
        from bbr.contracts import VisibleTask

        task = VisibleTask.model_validate(visible_task)
        return cls(task.probe_inputs, fixed_batches, run_pair)

    def _query(self, submission: Submission, value: Any) -> Mapping[str, Any]:
        self.slots += 1
        if not isinstance(value, str):
            return {"status": "invalid"}
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            return {"status": "invalid"}
        if len(raw) > 64:
            return {"status": "invalid"}
        if raw in self.seen:
            return {"status": "repeated"}
        self.seen.add(raw)
        if raw not in self.pool:
            return {"status": "outside_public_pool"}
        if not submission.parse_valid or submission.abstain:
            return {"status": "candidate_unavailable"}
        try:
            outcome = _json_value(self.run_pair(ArmArchive._submission(submission), raw))
            if not isinstance(outcome, dict) or "status" not in outcome:
                raise TypeError("missing pair outcome status")
            # Freeze only allowlisted public data before returning or retaining it.
            public_outcome = _snapshot({
                key: outcome[key] for key in ("status", "oracle", "candidate", "diverged")
                if key in outcome} | {"input_hex": raw.hex()})
        except Exception as exc:
            raise InfrastructureUnknown(
                submission.call_id, "probe adapter fault: stop dispatch",
                probe_progress={"failed_observation": {
                    "status": "infrastructure_error", "input_hex": raw.hex()}}) from exc
        if outcome.get("status") == "infrastructure_error":
            raise InfrastructureUnknown(
                submission.call_id, "probe infrastructure fault: stop dispatch",
                probe_progress={"failed_observation": public_outcome})
        return public_outcome

    def feedback(self, submission: Submission) -> Mapping[str, Any]:
        if self._stopped is not None:
            raise self._stopped
        if self.stage >= 3:
            raise ValueError("three feedback stages exhausted")
        probes = submission.response.get("probe_inputs", []) if submission.response else []
        if not isinstance(probes, (tuple, list)) or len(probes) > 8:
            probes = [None] * 8
        chosen: list[Mapping[str, Any]] = []
        fixed: list[Mapping[str, Any]] = []
        slots_before_stage = self.slots
        phase = "chosen"
        value: Any = None
        try:
            for value in probes:
                chosen.append(_snapshot(self._query(submission, value)))
            # No replacement search for unused chosen slots. Fixed checks are
            # in precommitted order; successful feedback reveals first divergence.
            phase = "fixed"
            for raw in self.fixed[self.stage]:
                value = raw.hex()
                fixed.append(_snapshot(self._query(submission, value)))
        except InfrastructureUnknown as exc:
            progress = {"stage": self.stage + 1, "completed_stages": self.stage,
                        "phase": phase, "attempted_input": value,
                        "chosen": chosen, "fixed": fixed,
                        "failed_observation": exc.receipt["probe_progress"]["failed_observation"],
                        "slots_used": self.slots,
                        "stage_slots_used": self.slots - slots_before_stage}
            self._stopped = InfrastructureUnknown(
                exc.call_id, exc.diagnostic, attempted_response=submission.response,
                origin=submission.origin, probe_progress=progress)
            raise self._stopped from exc
        self.stage += 1
        return {"stage": self.stage, "chosen": chosen,
                "first_fixed_divergence": next((row for row in fixed if row.get("diverged")), None),
                "slots_used": self.slots}


def run_interventions(dispatch: Callable[[str, Sequence[Mapping[str, Any]]], Any],
                      validate: Callable[[Any, str], Submission], broker: ProbeBroker,
                      origin: str = "fixture") -> dict[str, Mapping[str, Any]]:
    """dispatch MUST reserve durably before transport and retain failed attempts.

    validate supplies closed-schema + isolated syntax/import/format diagnostics.
    Both branches receive the same validator diagnostics. No hidden scorer port
    exists. Shared M is dispatched once; each R/P branch adds at most three calls.
    """
    if origin != "fixture":
        raise ValueError("live dispatch disabled")
    calls = 0
    archives: dict[str, ArmArchive] = {}

    def interrupted(exc: InfrastructureUnknown) -> InfrastructureUnknown:
        return exc.with_controller_context(
            calls, {arm: archive.lock_snapshot() for arm, archive in archives.items()})

    def submit(label: str, history: Sequence[Mapping[str, Any]]) -> Submission:
        nonlocal calls
        calls += 1
        if calls > 7:
            raise ValueError("seven unique call ceiling")
        try:
            # Neither callback receives aliases into retained controller history.
            result = validate(dispatch(label, _json_value(history)), label)
            result = ArmArchive._submission(result)
        except InfrastructureUnknown as exc:
            raise interrupted(exc) from exc
        except (ValueError, TypeError) as exc:
            return Submission(label, None, False, str(exc), origin)
        if result.call_id != label or result.origin != origin:
            raise ValueError("submission identity/origin drift")
        return result

    initial = submit("M:0", [])
    archives = {arm: ArmArchive(arm, [initial], [], initial.call_id) for arm in ("M", "R", "P")}
    for arm in ("R", "P"):
        archive = archives[arm]
        history: list[Mapping[str, Any]] = []
        for stage in range(3):
            previous = archive.submissions[-1]
            if previous.abstain:
                break
            history.append({"response": _json_value(previous.response),
                            "format_diagnostic": previous.diagnostic})
            if arm == "P":
                try:
                    feedback = _snapshot(broker.feedback(previous))
                except InfrastructureUnknown as exc:
                    raise interrupted(exc) from exc
                archive.append_feedback(feedback)
                history.append({"public_feedback": _json_value(feedback)})
            archive.append_submission(submit(f"{arm}:{stage + 1}", history))
    # JSON-compatible exports are detached from the retained immutable locks.
    return {arm: archive.lock_snapshot() for arm, archive in archives.items()}
