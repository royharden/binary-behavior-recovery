# Local instrument runbook

Status: Dirty construction, runtime unverified. No dependency installation, app
execution, Docker launch, live/model call or tests have been performed by DL4.

The frozen CLI surface is available as `bbr.cli:main` (root packaging is owned by
INT/DL1). `python -m bbr.cli` is the module entrypoint after later authorized setup.

Commands: `corpus build --spec-dir DIR --toolchain-pin FILE`,
`corpus gate --receipts FILE`, `evidence --artifact FILE --artifact-sha256 HASH`,
`run --arm S|M|R|P --config FILE`, `replay --bundle FILE --record-sha256 HASH`,
`demo --mock [--config FILE]`,
`verify-report FILE --evidence-root DIR`, `ledger report --database FILE`.
Build constructs the actual producer's complete 96-cell pinned schedule and does
not compile. Supply an actual `ToolchainPin` JSON object; no versions or pins are
invented. Gate accepts a closed `bbr.instance-receipts.v1` object with `spec`,
`artifacts` and `receipts`, uses `validate_instance`, and labels its result as
retained consistency rather than authentic independent admission. Evidence reads
the expected-hash artifact, then constructs the actual producer's
`PublicEvidenceEnvelope.from_bundle` and validates artifact and bundle identities.
The `public_evidence` output contains the full canonical `EvidenceBundle`, preserving
section bytes and unknown-boundary notices. `evidence_sha256` is the bundle digest,
not the envelope digest; both byte counts are explicit. Missing/unaccepted producer
source returns unavailable rather than a substitute envelope.

Replay requires a record digest from a separately trusted manifest. It uses the
producer's record/path/hash/comparator checks and returns retained consistency
with exit 2 because no admitted isolated backend is configured for fresh execution.
Ledger reporting delegates to the actual `bbr.ledger.read_report(path)` producer:
existing database only, 64 MiB producer bound, read-only SQLite URI/query-only
snapshot. The CLI does not construct `Ledger`, initialize storage, duplicate SQL
accounting, settle charges or substitute an empty report for failure. Missing API
is unavailable; missing/schema/SQLite/BudgetStop errors return explicit refusal.
Output labels a successful read as a retained ledger snapshot with runtime still
unverified. Builders have not opened a database to validate this source.

Run and demo use closed `bbr.fixture-preflight.v1` configuration: `schema`, `origin`
(`fixture` only), relative `artifact`, `artifact_sha256`, `visible_task`, inert
`candidate_source`, `image_sha256`, `toolchain_sha256` and `limits`. All supplied
objects use producer contracts. The full evidence digest must match VisibleTask.
Preflight constructs and validates the same producer `PublicEvidenceEnvelope` as
extraction, retaining full inert content for the owned provider consumer. Structural
checks do not prove ELF provenance, token budgets or semantic/canary leak absence.
It uses the accepted provider `prepare_request` with the producer's public fixture
`ModelConfig` default and complete canonical envelope, returning the exact request
digest and byte count. This prepares data only: no reservation, fixture lookup,
provider dispatch, hidden stream or model call follows. No live model is selected.
The actual validator with no backend returns `None` (infrastructure unknown),
while the actual runner with no backend retains its infrastructure observation.
Neither binary nor candidate executes. Preflight exits 2 before provider dispatch,
pending independent admission, isolated backends and verified leak/token controls.
Demo always prints
**SCRIPTED FIXTURE / NO LIVE MODEL RESULT** and never invents observations.

`run --arm S|M|R|P --journey-config FILE` and `demo --mock --journey-config FILE`
use the actual `bbr.arms.fixture_journey.run_fixture_task` source driver. This is
mutually exclusive with the earlier `--config` preflight. Closed config schema
`bbr.fixture-journey.v1` requires `origin` (`fixture`), actual `campaign_id`, relative
`artifact` and `artifact_sha256`, public `visible_task`, three `fixed_batches` of eight
canonical public-pool hex inputs, `limits`, `fixture_records` and `model_config`.
The last two may be null. Supplied fixtures use a relative path/raw-SHA descriptor
to an actual authored public JSON array (1..7 records, <=4 MiB); no records are
invented. A supplied model config has exactly the producer's five fields and must
remain fixture/offline. No config string becomes a backend, import or callback.

The ordinary CLI supplies no `FixtureDependencies`; the producer returns unavailable
with zero dispatch and exit2. Later authorized trusted Python composition may supply
actual existing Ledger, separate admitted Runner objects, CandidateValidator,
candidate registration and receipt sink through the local composition dataclass.
The single driver owns S/controls/M/R/P logic and retains all task locks, partial
unknowns and resource receipts. `--arm` is a view label on this complete one-task
driver result; it does not filter costs or create separate model calls. A local
`fixture_candidates_locked` result can yield exit0 for that local source task only.
It never supplies ALL-final-campaign locks, hidden-scoring permission, a successful
benchmark or fresh binary parity. No driver or dependencies are invoked by builders.

Later activation order:

1. Obtain Roy's independent appointment/rights decisions and admission receipts.
2. Pin actual toolchain/dependencies and configure isolated runner backends.
3. Exercise deterministic codecs, validity, adversarial isolation and exact byte/exit
   comparison; reproduce a retained original public dev failure and bounded shrink.
4. Exercise S/M/R/P with exact-request mock responses, no keys, no hidden data.
5. Exercise fixed schedule, missing rows, unequal identity clusters, 2,000 paired
   bootstrap, concurrent campaign locks, leak rejection and report tampering.
6. Freeze instrument/preregistration before independent held-out creation and seal.
7. Obtain model/access and worst-case whole-schedule cost approval before live calls.
8. Lock every final candidate, score privately, archive all scheduled rows and costs.

Host report verification only reads retained evidence. It does not execute binaries,
candidate Python or Docker. Exit 0 means retained-byte consistency, never equivalence
or runtime acceptance. Paths are relative to an explicit evidence root; keep that
root immutable and custodian-controlled. CLI errors do not authorize a retry campaign.
