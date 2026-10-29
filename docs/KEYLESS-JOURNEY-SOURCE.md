# One-task fixture source driver

At the initial static construction checkpoint, this source was not invoked and no
fixtures, database, inputs, observations or backend pins were materialized.
Round 2's explicit software-test exception now exercises unavailable and scripted
worker-port paths using authored software fixtures and temporary SQLite databases.
These checks never execute candidate source or establish admitted sandbox, original
ELF/corpus truth, independence, live behavior or benchmark performance. Real isolated
worker validation and corpus admission remain pending. See the owned regression
suite in `tests/test_providers_ledger_arms.py`; fake-policy digests are test IDs only.

`from bbr.arms.fixture_journey import run_fixture_task`

Required: an actual shared VisibleTask, campaign_id, trusted manifest artifact_sha256,
canonical PublicEvidenceEnvelope bytes as evidence_json, and three precommitted
eight-input fixed_batches from that task's public pool. Fixture records are actual
caller-supplied exact request/response rows, never generated answers. ModelConfig
defaults to the existing offline fixture origin. Evidence constants, if supplied,
must come only from the admitted public static evidence bundle.

Optional injected ledger, oracle Runner, candidate Runner, CandidateValidator,
candidate_ref registration callback, ExecutionLimits and receipt_sink are required
for the complete future path. Defaults return explicit unavailable with zero provider
dispatch and no Ledger construction. Backend=None remains unavailable. Workers must
be separate shared Runner instances with oracle/candidate roles and distinct backend
instances. Validator policy and limits must match the candidate worker. These checks
do not establish real backend admission, isolation or source truth: caller supplies
those verified receipts and actual pins; the driver invents none.

The function reuses baseline_for_task and controls on the same eight visible/domain
examples, then validates their generated source only through CandidateValidator.
Code remains data; no host compile/import/exec or candidate subprocess exists here.
Builder-source locks are kept separately from existing M/R/P intervention locks.
FixtureDispatch uses the required campaign ID, full evidence and trusted artifact;
RunnerProbeAdapter and ProbeBroker.for_task restrict feedback to the fixed public
pool. run_interventions owns seven-call/48-slot limits, shared M initialization,
last-valid/abstain selection and immutable partial/complete arm locks.

Return is detached JSON data: status, origin=fixture, one-task scope, campaign/task IDs,
runtime_validation=unverified, hidden_scoring=not_performed, no campaign authorization,
fixed-batch digest, baseline metadata, builder_locks, arm_locks, attempted provider
call count, resource receipt snapshots and failure state. Possible statuses are
unavailable, refused, infrastructure_unknown and fixture_candidates_locked. That last
status means local candidate locks exist, not measured correctness or live success.
Controls, abstentions and parse failures remain explicit in their lock records.

Unavailable validation retains its attempted response and any completed source locks.
M/R/P unknowns retain existing prior locks, attempted response and partial probe
progress. Only the producer's explicit ProviderError refusals enter the controller's
parse-failure path. Other dispatch exceptions, including generic ValueError/TypeError
from ledger/config/pre-dispatch faults, enter the existing infrastructure stop path;
they do not become candidate parse failures or allow later calls. Prior locks and
retained resource snapshots remain available, including when no receipt exists yet
for the stopped attempt. Attempted calls are not inferred from
successful responses. Optional sink persistence belongs to the archive owner;
in-memory receipts do not establish crash durability or complete campaign coverage.

There is no hidden input, scorer, shrinker, exhaustive evaluator or hidden execution
callback in this API. Local task locks cannot authorize a hidden comparison. The
campaign/report owner must require the existing validated ALL-final-campaign lock
receipt and trusted scorer before any private/exhaustive scoring or shrinking, bind
all retained resource/scoring sources to archive inventory hashes and preserve
fixture/live separation. Do not interpret a driver result as a96-task benchmark,
custodian appointment or independent admission.

The initial deferred list below remains the broader activation scope; selected
software regression cases are now checked under the Round 2 exception, without
converting fake-worker acknowledgments into runtime isolation evidence.
Deferred: actual admitted fixture/backend/ledger invocation; malformed/public-pool
and evidence refusals; missing/default backend states; S/controls codec/validation
parity; seven-call/48-slot and last-valid behavior; pre-dispatch ledger/config faults
(including an overlong combined ledger request ID); partial failure/sink/ledger
receipt persistence; full campaign joins and all K/L/security/custody gates. No
runtime, token-budget, timing, cost-per-pass or correctness result is claimed here.
