"""Original SQLite ledger. Amounts are decimal strings, never SQL REAL values."""

from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
import sqlite3
from typing import Iterator


class BudgetStop(RuntimeError):
    """Dispatch is prohibited until the stated liability is resolved."""


def _money(value: Decimal | str) -> Decimal:
    if not isinstance(value, (Decimal, str)):
        raise ValueError("USD must be a Decimal or decimal string")
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("Invalid USD amount") from exc
    if not amount.is_finite() or amount < 0:
        raise ValueError("USD must be finite and nonnegative")
    # Bounded precision avoids Decimal context rounding during aggregation.
    if amount.as_tuple().exponent < -12 or amount > Decimal("1000000"):
        raise ValueError("USD precision/range exceeds ledger limits")
    return amount


@dataclass(frozen=True)
class Reservation:
    request_id: str
    request_sha256: str
    attempt: int
    reserved_usd: Decimal
    status: str
    charged_usd: Decimal | None


class Ledger:
    """One durable app budget and at most one outstanding transport attempt.

    Constructing opens/initializes a database at the caller-selected path. The
    caller must pin request SHA256 to the entire exact request, model/config and
    price identity. Live authorization and dated-price checks belong upstream.
    """

    def __init__(self, path: str | Path, cap_usd: Decimal | str = "40",
                 max_attempts: int = 1344) -> None:
        self.path = str(path)
        if self.path == ":memory:" or not self.path:
            raise ValueError("A durable file path is required")
        cap = _money(cap_usd)
        if cap > Decimal("40") or cap == 0:
            raise ValueError("App cap must be >0 and <=40 USD")
        if type(max_attempts) is not int or not 1 <= max_attempts <= 1344:
            raise ValueError("Attempt ceiling must be 1..1344")
        with self._transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY CHECK(id=1), cap TEXT NOT NULL, max_attempts INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS attempts (request_id TEXT NOT NULL, digest TEXT NOT NULL, attempt INTEGER NOT NULL, reserve TEXT NOT NULL, status TEXT NOT NULL, charge TEXT, reason TEXT NOT NULL DEFAULT '', PRIMARY KEY(request_id, attempt))")
            db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL, attempt INTEGER NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
            db.execute("INSERT OR IGNORE INTO config VALUES (1, ?, ?)", (str(cap), max_attempts))
            old = db.execute("SELECT cap, max_attempts FROM config WHERE id=1").fetchone()
            if Decimal(old[0]) != cap or old[1] != max_attempts:
                raise BudgetStop("Persistent cap/config differs; reconciliation required")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    @staticmethod
    def _reservation(row: sqlite3.Row) -> Reservation:
        return Reservation(row["request_id"], row["digest"], row["attempt"],
                           Decimal(row["reserve"]), row["status"],
                           None if row["charge"] is None else Decimal(row["charge"]))

    @staticmethod
    def _event(db: sqlite3.Connection, request_id: str, attempt: int,
               action: str, detail: str) -> None:
        db.execute("INSERT INTO events(request_id,attempt,action,detail) VALUES (?,?,?,?)",
                   (request_id, attempt, action, detail))

    @staticmethod
    def _committed(db: sqlite3.Connection) -> Decimal:
        return sum((Decimal(row["charge"] if row["charge"] is not None else row["reserve"])
                    for row in db.execute("SELECT reserve,charge FROM attempts")), Decimal(0))

    def reserve(self, request_id: str, request_sha256: str,
                worst_case_usd: Decimal | str, *, retry: bool = False) -> Reservation:
        """Idempotently reserve an exact request; explicit retry only after never_sent.

        A duplicate returns its recorded attempt and never creates/dispatches a
        new one. The caller must use mark_sent before any transport operation.
        """
        amount = _money(worst_case_usd)
        if not isinstance(request_id, str) or not request_id.strip() or len(request_id) > 256:
            raise ValueError("Nonempty bounded request ID required")
        if not isinstance(request_sha256, str) or len(request_sha256) != 64 or any(c not in "0123456789abcdef" for c in request_sha256):
            raise ValueError("Lowercase request SHA256 required")
        with self._transaction() as db:
            old = db.execute("SELECT * FROM attempts WHERE request_id=? ORDER BY attempt DESC LIMIT 1", (request_id,)).fetchone()
            if old is not None:
                if old["digest"] != request_sha256 or Decimal(old["reserve"]) != amount:
                    raise BudgetStop("Request ID/config/reservation drift")
                if not retry:
                    return self._reservation(old)
                if old["status"] != "never_sent" or old["attempt"] != 1:
                    raise BudgetStop("Only one proven-never-sent retry is allowed")
            elif retry:
                raise BudgetStop("Retry lacks a proven-never-sent original attempt")
            if db.execute("SELECT 1 FROM attempts WHERE status IN ('reserved','in_flight','unknown') LIMIT 1").fetchone():
                raise BudgetStop("Unresolved attempt: settle/reconcile before dispatch")
            config = db.execute("SELECT * FROM config WHERE id=1").fetchone()
            if db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] >= config["max_attempts"]:
                raise BudgetStop("Attempt ceiling exhausted")
            committed = self._committed(db)
            if committed >= Decimal(config["cap"]) or committed + amount > Decimal(config["cap"]):
                raise BudgetStop("App budget exhausted")
            attempt = 1 if old is None else 2
            db.execute("INSERT INTO attempts(request_id,digest,attempt,reserve,status) VALUES (?,?,?,?,'reserved')", (request_id, request_sha256, attempt, str(amount)))
            self._event(db, request_id, attempt, "reserve", str(amount))
            return Reservation(request_id, request_sha256, attempt, amount, "reserved", None)

    def mark_sent(self, reservation: Reservation) -> None:
        """Commit BEFORE transport. A crash thereafter retains the full liability."""
        with self._transaction() as db:
            row = self._get(db, reservation)
            if row["status"] != "reserved":
                raise BudgetStop("Attempt already dispatched or unavailable")
            db.execute("UPDATE attempts SET status='in_flight' WHERE request_id=? AND attempt=?", (reservation.request_id, reservation.attempt))
            self._event(db, reservation.request_id, reservation.attempt, "mark_sent", "transport may now start")

    def _get(self, db: sqlite3.Connection, reservation: Reservation) -> sqlite3.Row:
        row = db.execute("SELECT * FROM attempts WHERE request_id=? AND attempt=?", (reservation.request_id, reservation.attempt)).fetchone()
        if row is None or row["digest"] != reservation.request_sha256 or Decimal(row["reserve"]) != reservation.reserved_usd:
            raise BudgetStop("Unknown or changed reservation")
        return row

    def settle(self, reservation: Reservation, actual_usd: Decimal | str | None,
               *, reason: str) -> None:
        """Unknown usage keeps full reserve; actual charges may never exceed it."""
        amount = None if actual_usd is None else _money(actual_usd)
        if not reason.strip():
            raise ValueError("Settlement evidence/reason required")
        with self._transaction() as db:
            row = self._get(db, reservation)
            status = "unknown" if amount is None or amount > Decimal(row["reserve"]) else "settled"
            if row["status"] == "settled" and status == "settled" and Decimal(row["charge"]) == amount:
                return
            if row["status"] != "in_flight":
                raise BudgetStop("Only dispatched attempts can settle; unknown requires reconciliation")
            # An over-reserve bill is preserved, and blocks dispatch as unknown.
            db.execute("UPDATE attempts SET status=?,charge=?,reason=? WHERE request_id=? AND attempt=?", (status, None if amount is None else str(amount), reason, reservation.request_id, reservation.attempt))
            self._event(db, reservation.request_id, reservation.attempt, status, reason)

    def reconcile(self, reservation: Reservation, *, billed_usd: Decimal | str | None = None,
                  proven_never_sent: bool = False, evidence: str) -> None:
        """Operator reconciliation; missing evidence/ambiguous usage stays blocked."""
        if not evidence.strip() or (billed_usd is None) == (not proven_never_sent):
            raise ValueError("Choose exactly one: evidenced bill or proven never-sent")
        amount = Decimal(0) if proven_never_sent else _money(billed_usd)
        with self._transaction() as db:
            row = self._get(db, reservation)
            if row["status"] not in ("reserved", "in_flight", "unknown"):
                raise BudgetStop("Reconciliation requires unresolved attempt")
            status = "never_sent" if proven_never_sent else "settled"
            db.execute("UPDATE attempts SET status=?,charge=?,reason=? WHERE request_id=? AND attempt=?", (status, str(amount), evidence, reservation.request_id, reservation.attempt))
            self._event(db, reservation.request_id, reservation.attempt, "reconcile_" + status, evidence)

    def report(self) -> dict[str, object]:
        with self._transaction() as db:
            return _report_snapshot(db)


def _report_snapshot(db: sqlite3.Connection) -> dict[str, object]:
    """One accounting calculation for both existing and read-only consumers."""
    configs = db.execute("SELECT id,cap,max_attempts FROM config LIMIT 2").fetchall()
    if len(configs) != 1 or configs[0]["id"] != 1:
        raise BudgetStop("Invalid ledger configuration")
    config = configs[0]
    cap = _money(config["cap"])
    if not 0 < cap <= Decimal("40") or type(config["max_attempts"]) is not int or not 1 <= config["max_attempts"] <= 1344:
        raise BudgetStop("Invalid persisted ledger ceilings")
    # Bound text before materializing rows; do not silently truncate evidence.
    if db.execute("SELECT 1 FROM attempts WHERE length(request_id)>256 OR length(digest)!=64 OR length(reserve)>32 OR length(charge)>32 OR length(reason)>4096 LIMIT 1").fetchone():
        raise BudgetStop("Ledger report text bounds exceeded")
    attempts = [dict(row) for row in db.execute(
        "SELECT request_id,digest,attempt,reserve,status,charge,reason FROM attempts ORDER BY request_id,attempt LIMIT 1345")]
    if len(attempts) > config["max_attempts"]:
        raise BudgetStop("Ledger report attempt ceiling exceeded")
    for row in attempts:
        if (type(row["request_id"]) is not str or not row["request_id"].strip()
                or type(row["digest"]) is not str or len(row["digest"]) != 64
                or any(c not in "0123456789abcdef" for c in row["digest"])
                or type(row["attempt"]) is not int or row["attempt"] not in (1, 2)
                or type(row["reason"]) is not str
                or row["status"] not in {"reserved", "in_flight", "unknown", "settled", "never_sent"}):
            raise BudgetStop("Malformed ledger attempt")
        _money(row["reserve"])
        if row["charge"] is not None:
            _money(row["charge"])
        elif row["status"] in {"settled", "never_sent"}:
            raise BudgetStop("Closed attempt lacks billing disposition")
    committed = Ledger._committed(db)
    blocked = any(row["status"] in ("reserved", "in_flight", "unknown") for row in attempts)
    return {"cap_usd": str(cap), "committed_usd": str(committed),
            "available_usd": str(max(Decimal(0), cap - committed)),
            "attempts": attempts, "max_attempts": config["max_attempts"],
            "dispatch_blocked": blocked or committed >= cap or len(attempts) >= config["max_attempts"]}


def read_report(path: str | Path) -> dict[str, object]:
    """Read an existing ledger snapshot without initializing/configuring it.

    No Ledger instance is constructed, no schema statement is issued, and no
    reservation/settlement occurs. SQLite WAL snapshot behavior requires later
    runtime validation; immutable=1 is deliberately absent so WAL is not ignored.
    """
    source = Path(path)
    if source.is_symlink():
        raise BudgetStop("Ledger report refuses symlink path")
    source = source.resolve(strict=True)
    if not source.is_file() or source.stat().st_size > 64 * 1024 * 1024:
        raise BudgetStop("Existing bounded ledger file required")
    db = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=5, isolation_level=None)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        return _report_snapshot(db)
    finally:
        if db.in_transaction:
            db.execute("ROLLBACK")
        db.close()
