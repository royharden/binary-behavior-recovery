"""SQLite durable, monotonic one-campaign barriers. No worker execution."""
from __future__ import annotations

from dataclasses import asdict
import json
import sqlite3
from pathlib import Path
from .admission import Admission, admission_from_dict
from .preregister import Registration, closed, digest, require_digest, text

FINAL_STATUSES = {"candidate", "abstain", "syntax_failure", "not_run", "infrastructure_error"}


def validate_open_receipt(registration: Registration, receipt: dict) -> dict[tuple[str, str, str], dict]:
    """Retained-byte linkage, not authentication of independent custody."""
    registration.validate()
    closed(receipt, {"schema", "registration_sha256", "admission", "admission_sha256", "evaluator", "lease_id", "finals", "lock_sha256"}, "hidden-open receipt")
    if receipt["schema"] != "bbr.hidden-open.v1" or receipt["registration_sha256"] != registration.sha256:
        raise ValueError("hidden-open receipt registration mismatch")
    admission = admission_from_dict(receipt["admission"])
    admission.validate(registration.edition)
    if digest(asdict(admission)) != receipt["admission_sha256"]:
        raise ValueError("admission receipt digest mismatch")
    for pin, commitment in (("partitions", admission.partition_commitment), ("source", admission.source_commitment), ("canaries", admission.canary_commitment)):
        if dict(registration.pins)[pin] != commitment:
            raise ValueError("admission differs from registration commitments")
    if receipt["evaluator"] != admission.evaluator:
        raise ValueError("hidden-open evaluator differs from appointment")
    text(receipt["lease_id"], "scorer lease")
    if not isinstance(receipt["finals"], list):
        raise ValueError("final-lock list required")
    finals = {}
    for final in receipt["finals"]:
        closed(final, {"task_id", "model", "arm", "candidate_sha256", "status"}, "final lock")
        for name in ("task_id", "model", "arm", "status"):
            text(final[name], name)
        key = (final["task_id"], final["model"], final["arm"])
        if key not in registration.final_keys or key in finals:
            raise ValueError("duplicate/outside-roster final lock")
        if final["status"] not in {"candidate", "abstain", "syntax_failure"}:
            raise ValueError("incomplete campaign cannot have a hidden-open receipt")
        if final["status"] == "candidate":
            require_digest(final["candidate_sha256"])
        elif final["candidate_sha256"] is not None:
            raise ValueError("noncandidate final cannot carry a candidate hash")
        finals[key] = final
    if set(finals) != registration.final_keys:
        raise ValueError("all final locks required before hidden observations")
    if receipt["finals"] != [finals[k] for k in sorted(finals)]:
        raise ValueError("final locks must use canonical schedule order")
    body = {k: v for k, v in receipt.items() if k != "lock_sha256"}
    if digest(body) != require_digest(receipt["lock_sha256"]):
        raise ValueError("hidden-open lock receipt digest mismatch")
    return finals


class Campaign:
    def __init__(self, path: Path):
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS campaign (
          singleton INTEGER PRIMARY KEY CHECK(singleton=1), edition TEXT NOT NULL,
          registration TEXT NOT NULL, registration_sha TEXT NOT NULL, admission_sha TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('sealed','dispatched','hidden_open','retired')),
          evaluator TEXT NOT NULL, hidden_owner TEXT, admission TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS finals (
          task TEXT NOT NULL, model TEXT NOT NULL, arm TEXT NOT NULL,
          candidate_sha TEXT, status TEXT NOT NULL,
          PRIMARY KEY(task,model,arm));
        CREATE TABLE IF NOT EXISTS hidden_receipt (
          singleton INTEGER PRIMARY KEY CHECK(singleton=1), receipt TEXT NOT NULL);
        """)
        if "admission" not in {r[1] for r in self.db.execute("PRAGMA table_info(campaign)")}:
            self.close()
            raise ValueError("legacy campaign schema lacks retained admission; new independently sealed campaign storage required")

    def close(self) -> None:
        self.db.close()

    def seal(self, registration: Registration, admission: Admission) -> None:
        registration.validate()
        admission.validate(registration.edition)
        if dict(registration.pins)["partitions"] != admission.partition_commitment or dict(registration.pins)["source"] != admission.source_commitment or dict(registration.pins)["canaries"] != admission.canary_commitment:
            raise ValueError("admission commitments differ from frozen pins")
        # INSERT, never replace: retired editions cannot silently restart.
        self.db.execute("INSERT INTO campaign VALUES(1,?,?,?,?,? ,?,NULL,?)", (
            registration.edition, json.dumps(asdict(registration), sort_keys=True), registration.sha256,
            digest(asdict(admission)), "sealed", admission.evaluator,
            json.dumps(asdict(admission), sort_keys=True)))

    def _state(self) -> tuple:
        row = self.db.execute("SELECT state,registration,registration_sha,evaluator FROM campaign WHERE singleton=1").fetchone()
        if row is None:
            raise ValueError("campaign has not been admitted/sealed")
        if digest(json.loads(row[1])) != row[2]:
            raise ValueError("registration tampered")
        return row

    def dispatch(self) -> None:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if self._state()[0] != "sealed":
                raise ValueError("second campaign/dispatch refused")
            self.db.execute("UPDATE campaign SET state='dispatched' WHERE singleton=1")
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def lock_final(self, task: str, model: str, arm: str, candidate_sha: str | None, status: str) -> None:
        for name, value in (("task", task), ("model", model), ("arm", arm), ("status", status)):
            text(value, name)
        if status not in FINAL_STATUSES:
            raise ValueError("invalid final status")
        if status == "candidate":
            require_digest(candidate_sha)
        elif candidate_sha is not None:
            raise ValueError("noncandidate final cannot carry candidate hash")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            state, raw, _, _ = self._state()
            if state != "dispatched":
                raise ValueError("final locks require dispatch and precede hidden opening")
            registration = json.loads(raw)
            keys = {(c["task_id"], m, a) for c in registration["cells"] for m in registration["models"] for a in registration["arms"]}
            if (task, model, arm) not in keys:
                raise ValueError("final outside frozen schedule")
            self.db.execute("INSERT INTO finals VALUES(?,?,?,?,?)", (task, model, arm, candidate_sha, status))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def open_hidden(self, evaluator: str, lease_id: str) -> str:
        text(lease_id, "trusted scorer lease identity")
        text(evaluator, "evaluator")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            state, raw, registration_sha, appointed = self._state()
            if state != "dispatched" or evaluator != appointed:
                raise ValueError("hidden opening requires appointed evaluator, once only")
            reg = json.loads(raw)
            expected = {(c["task_id"], m, a) for c in reg["cells"] for m in reg["models"] for a in reg["arms"]}
            rows = self.db.execute("SELECT task,model,arm,candidate_sha,status FROM finals ORDER BY task,model,arm").fetchall()
            if {(r[0], r[1], r[2]) for r in rows} != expected:
                raise ValueError("all campaign final candidates must be locked before any hidden opening")
            if any(r[4] in {"not_run", "infrastructure_error"} for r in rows):
                raise ValueError("incomplete campaign cannot open hidden streams")
            admission_raw, admission_sha = self.db.execute("SELECT admission,admission_sha FROM campaign WHERE singleton=1").fetchone()
            receipt = {"schema": "bbr.hidden-open.v1", "registration_sha256": registration_sha,
                       "admission": json.loads(admission_raw), "admission_sha256": admission_sha,
                       "evaluator": evaluator, "lease_id": lease_id,
                       "finals": [dict(zip(("task_id", "model", "arm", "candidate_sha256", "status"), r)) for r in rows]}
            receipt["lock_sha256"] = digest(receipt)
            from .preregister import registration_from_dict
            validate_open_receipt(registration_from_dict(reg), receipt)
            self.db.execute("INSERT INTO hidden_receipt VALUES(1,?)", (json.dumps(receipt, sort_keys=True),))
            self.db.execute("UPDATE campaign SET state='hidden_open',hidden_owner=? WHERE singleton=1", (lease_id,))
            self.db.execute("COMMIT")
            return receipt["lock_sha256"]
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def retained_open_receipt(self) -> dict:
        """Snapshot and verify the durable post-lock receipt without reopening."""
        self.db.execute("BEGIN")
        try:
            state, raw, _, evaluator = self._state()
            if state not in {"hidden_open", "retired"}:
                raise ValueError("hidden scoring requires durable hidden-open transition")
            stored = self.db.execute("SELECT receipt FROM hidden_receipt WHERE singleton=1").fetchone()
            if stored is None:
                raise ValueError("durable hidden-open receipt missing")
            receipt = json.loads(stored[0])
            from .preregister import registration_from_dict
            validate_open_receipt(registration_from_dict(json.loads(raw)), receipt)
            finals = self.db.execute("SELECT task,model,arm,candidate_sha,status FROM finals ORDER BY task,model,arm").fetchall()
            retained_finals = [dict(zip(("task_id", "model", "arm", "candidate_sha256", "status"), r)) for r in finals]
            owner, admission_sha = self.db.execute("SELECT hidden_owner,admission_sha FROM campaign WHERE singleton=1").fetchone()
            if receipt["finals"] != retained_finals or receipt["lease_id"] != owner or receipt["evaluator"] != evaluator or receipt["admission_sha256"] != admission_sha:
                raise ValueError("durable campaign differs from retained open receipt")
            self.db.execute("COMMIT")
            return receipt
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def retained_report(self, registration: Registration, rows: list[dict], *, partitions: dict) -> dict:
        from .run import retained_report
        return retained_report(registration, rows, partitions=partitions,
                               campaign_receipt=self.retained_open_receipt())

    def retire(self) -> None:
        self._state()
        self.db.execute("UPDATE campaign SET state='retired' WHERE singleton=1")
