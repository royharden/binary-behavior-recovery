# Durable cost accounting

Construction only; runtime, crash/reopen and concurrency behavior have not run.
Live provider dispatch remains disabled and no keys are read. The app-wide ceiling
is USD 40, including failures, diagnostics, retries and unresolved liabilities.

`bbr.ledger.Ledger(path, cap_usd="40", max_attempts=1344)` uses a durable SQLite
file with immediate write transactions and FULL synchronous writes. Cap/config
changes on reopen refuse. Currency is bounded exact Decimal stored as text;
floats, negative, nonfinite and overprecision amounts refuse. No third-party
source or SDK is used. The caller supplies a canonical exact-request SHA256
including model/endpoint/config/price identity and a dated worst-case price.
The ledger does not approve models, prices, admission or live access.

API:

- `reserve(request_id, request_sha256, worst_case_usd, retry=False)` returns an
  immutable Reservation. Duplicate exact identity returns recorded state with
  no new charge. Changed identity/amount refuses. Only one outstanding attempt
  is permitted globally. Persist the reservation before transport.
- `mark_sent(reservation)` commits before transport and refuses repeated use.
  A crash before or after transport therefore leaves a blocking liability.
- `settle(reservation, actual_usd_or_None, reason=...)` retains unknown usage at
  full reserve. Over-reserve bills remain recorded and block dispatch pending
  reconciliation. Known ordinary charges release unused reserve.
- `reconcile(reservation, billed_usd=..., evidence=...)` records an evidenced
  final bill. Alternatively `proven_never_sent=True` releases the reservation
  and allows at most one explicit retry for that same request, still consuming
  the global attempt ceiling. A timeout is not proof of never sent.
- `report()` gives decimal strings, retained attempts, limits and blocked state.

Shared M branches and fixture replay reuse the original request/Reservation and
response archive; they do not call mark_sent again or create another ledger
entry. Mock/replay charges are zero with original request lineage retained.
The intervention controller separately enforces seven unique requests per task;
the global ceiling includes original attempts and retries. SDK retries must stay
disabled. No partial campaign or cheaper-model substitution is authorized here.

Deferred checks: concurrent boundary reservations; crash before/after transport;
restart and config drift; idempotent settlements/reuse; unknown and over-reserve
bills; evidenced reconciliation; retry/attempt exhaustion; Decimal precision and
cap edges; exact provider request/price identity; complete campaign preflight.
