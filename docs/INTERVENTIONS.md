# Recovery construction API

SEAM-005 retained resources: `FixtureDispatch(..., campaign_id=<opaque ID>,
receipt_sink=None)` now requires explicit campaign identity. After each successful
durable mark_sent, it retains exactly one closed `bbr.call-resource.v1` receipt on
success, schema refusal or unexpected failure. `receipt_snapshots()` returns detached
JSON mappings; `receipt_jsonl()` returns canonical JSON plus LF per receipt, in dispatch
order. Optional sink receives another detached snapshot after local retention. A sink
failure raises ReceiptSinkError, stops the flow, and must never trigger redispatch;
caller can recover local snapshots. FixtureDispatch does not write archive files.

Receipt keys are schema, campaign_id, origin, task_id, model_id, config_id, call_id,
request_id, attempt, request_sha256, request, provider_record,
provider_record_sha256 and provider_record_reason. The request is the exact detached
object used for reservation. MockProvider.propose's optional record_sink captures
the exact matched fixture before response validation; a malformed response retains
that row without claiming success. No exact row gives null record/hash and an
explicit reason. No exception text, inferred usage, resource timing, charge or status
is manufactured. Existing authored fixture usage is retained unchanged; absent wall,
CPU and memory measurements remain absent for the resource summarizer to label unknown.
Ledger report is authoritative for reserve, charge and status. If settlement fails,
receipt retention does not settle or reconcile the ledger. Dispatch refuses task-ID
drift; shared M reuse creates no new call/receipt. Failed mark_sent/reuse is not a new
owned dispatch. The archive owner must join exact full ledger attempt coverage and
reject duplicate/missing sidecars, then hash inventory sources for DL2 summarization.
No receipt proves real execution, token correctness, isolation or custody.

SEAM-003 consumer construction: `prepare_request`, `MockProvider.propose` and
`FixtureDispatch` now require full canonical public evidence bytes and the expected
source artifact digest. Full envelope content is included in request hashing; its
bundle digest is compared with VisibleTask.evidence_sha256, and its source artifact
is checked against the trusted expected artifact. Missing,
noncanonical, >48KiB, mismatched or changed content refuses; narrow `to_contract`
and digest-only requests have no fallback. Fixture files bind the same full object.
DL1 retains ownership of public-field/section/string/import validation. Consumer
imports `PublicEvidenceEnvelope` from `bbr.evidence`, calls `from_json` with both
expected digests, then `validate_for`, `canonical_json` and `to_dict`. No other
evidence model or permissive callback exists. Missing producer source raises
`ProviderUnavailable` before fixture transport. Producer source must be integrated
before joined execution; this source reconciliation is runtime-unverified.
Live transport always refuses because verified tokenizer,
budget and pre-dispatch leak controls are unavailable. No estimates are represented
as verified token counts. Existing SEAM-002 validator-unknown semantics remain.

Runtime unverified; independent admission pending. Original implementation with no
third-party source reuse. No candidate source is imported or executed by this code.

`baseline_for_task(VisibleTask, evidence_constants=...)` is the S entrypoint:
it pins input/output arity, width and admitted input range from shared Domain.
`enumerate_baseline` exposes the lower-level dev search (max 10,000/2 seconds),
fixed primitive order and first-fitting tie break; only visible examples and
allowlisted static constants are inputs. Host matching evaluates the original DSL,
never generated Python. Generated standalone parser duplicates public codec glue;
future parity checks must compare it with `bbr.corpus.codecs`. `controls` produces
echo, first-visible constant, and exact visible lookup with empty/exit2 default.
Oversized control source refuses explicitly rather than truncating visible pairs.
Coverage, wall-time caps, generated-code parity and actual lookup passes are unrun.

`MockProvider.propose(visible_task, history, model_config, reservation)` validates
the shared VisibleTask/CandidateResponse and exact full-request hash. It reads no
environment variables, keys or SDKs. `FixtureDispatch` binds it to `Ledger`, with
seven distinct labels, durable reserve/mark-sent before lookup, and zero-cost
settlement on fixture success/refusal. Unknown unexpected failures retain liability.
Live adapters always refuse. Public fixture schema is described beside the fixtures;
actual admitted scripted task data is pending and has not been invented here.

`run_interventions(dispatch, validate, broker)` makes one shared M call and up to
three additional calls for each of R/P. The injected validator must supply shared
closed-response and **isolated** syntax/import diagnostics as a `Submission`.
Never use a host import/exec to implement it. M is dispatched once; independently
owned snapshots of its exact submission values initialize M/R/P. Archive selection is last parse-valid, explicit final
abstention retained. All attempts, including malformed responses, count.

`Submission` is frozen and slotted. Initialization canonicalizes response JSON,
detaches caller containers, and recursively freezes objects/arrays as read-only
mappings/tuples. `Submission.snapshot()` produces an ordinary detached JSON object.
Controller histories passed to dispatch are fresh JSON copies on every call, and
validator results are snapshotted before retention. Executor observations and public
feedback are detached before entering retained history. A callback retaining or
editing its arguments cannot rewrite an earlier submission, feedback, or branch.

`ProbeBroker(public_pool, fixed_batches, run_pair)` requires three frozen batches
of eight unique public inputs. Chosen inputs are raw hex from CandidateResponse;
at most eight per stage, with no replacement search. Fixed checks execute in stable
order, reveal only first divergence, and infrastructure faults stop the flow.
Invalid/repeat/outside/timeouts consume slots; outside requests never reach executor.
The broker has no hidden-input port. Maximum 48 slots/three stages. No fourth batch.
Executor must use DL2 isolation and return status/oracle/candidate/diverged only.

`ArmArchive` snapshots initialization inputs into immutable tuples and records.
Use `append_submission()` / `append_feedback()` before locking; both refuse after
lock. Direct field/list mutation is unavailable. `lock()` caches a recursively
immutable content-digested record and returns that same record on repeated calls.
`lock_bytes()` returns its canonical ASCII JSON bytes, including `sha256`; that
digest covers the canonical record with the `sha256` field omitted. `lock_snapshot()`
returns a detached, mutable JSON export. `run_interventions()` retains its existing
JSON-compatible result shape using those detached exports; modifying one export
cannot alter another arm or the retained lock. Standard `json.dumps()` callers use
the snapshot, since the immutable mapping/tuple lock is not a plain JSON container.
This local lock is for evaluation's campaign-final lock barrier and is not
authorization to open hidden data. Evaluation owns durable campaign locking and
private post-lock scoring.

Static producer reconciliation: inspected DL1's `src/bbr/contracts/__init__.py`
and `src/bbr/corpus/codecs.py` without importing them. `CandidateResponse` is
exported by `bbr.contracts` with code/abstain, at most eight byte probes, hypothesis,
closed strict fields and hexadecimal JSON byte serialization. This consumer's
`model_validate_json()` / `model_dump(mode="json")` path preserves those probes
as hex for the broker. `VisibleTask` supplies eight examples and a public pool of
80 distinct raw inputs (64 valid, 16 malformed), disjoint from examples. The
broker checks unique public membership and its 24 fixed checks; carrying the committed
evidence envelope now follows the SEAM-003 API above; joined execution remains
unverified. `ProbeBroker.for_task`
now binds the broker to exactly the producer-validated 80-input pool; direct
construction remains a lower-level development API. Static inspection confirms
names and source contracts only; no import, schema round-trip, or producer/consumer
execution has been run.

Deferred: joined DL1 schema round-trips; DL2 isolated validator/probe adapter;
admitted exact-request public fixture; syntax/import denial, quotas, timeout/error,
archive lineage, byte-identical shared-M and keyless joined runtime checks. All K/L
acceptance and live model preflight remain unrun. No measured result is claimed.
Mutation/alias regression execution is also deferred by Dirty Mode: initialization
input edits, nested response/feedback edits, callback-retained history edits,
post-lock append/field edits, repeated-lock byte identity, detached export edits,
and JSON export compatibility require future executable checks. This repair has
only static source and syntax inspection.

SEAM-002 reconciliation: pass `bbr.runner.CandidateValidator(policy, limits,
backend=None)` to `validate_submission` as the isolated validator callback.
Its `(True|False|None, diagnostic)` result preserves `None` as
`InfrastructureUnknown`, which stops all subsequent calls and carries failed call
identity, attempted-call count and locked partial archive snapshots. Its `receipt`
is a detached recursively immutable mapping; `snapshot()` exports ordinary JSON
without exposing retained containers. Candidate-validator refusal, exception or
malformed result retains the entire closed response as `attempted_response` and
its origin. This attempt is separate from selected submissions: unknown validation
is neither parse failure nor parse success. A failure at M:0 therefore has an empty
prior archive set, its exact attempted response and one attempted call. A later
failure retains the response alongside all prior locked M/R/P records.

Probe infrastructure faults use the same stop path. `probe_progress` retains the
one-based attempted stage, count of completed stages, chosen/fixed phase, failing
input, completed chosen and fixed observations, and the failed public observation
when supplied by the executor. `slots_used` and `stage_slots_used` include the
failed slot. This partial stage is an interruption receipt, not feedback eligible
for a later model call; successful feedback still reveals only the first fixed
divergence. The broker latches the fault and refuses subsequent feedback without
consuming another slot. The controller adds its attempted-call count and frozen
prior archive records while retaining these failure details, then raises to stop
dispatch. No replacement request, hidden scoring or host execution follows.

`RunnerProbeAdapter` binds the broker to DL2's public isolated pair comparison port.
It requires separate oracle/candidate workers; its `candidate_ref` callback must
register the exact submitted source in an admitted isolated worker. Unavailable
candidate registration returns `infrastructure_error` before oracle execution.
There is no host fallback or admitted backend implementation in this adapter.

The caller must persist the interruption receipt and mark the campaign incomplete.
Offline fixture cost is already durably settled at zero before validation; any
transport liability remains owned by the ledger. No admitted backend/policy pins
exist, so the joined path remains unavailable. Regression execution for M:0 and
later validator unknowns, partial chosen/fixed faults, receipt mutation, slot
accounting and stopped-broker reuse remains deferred by Dirty Mode; only static
source and AST syntax inspection was performed for this repair.
