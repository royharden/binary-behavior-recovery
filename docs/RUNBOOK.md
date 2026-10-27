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
the expected-hash artifact, then returns the full canonical `EvidenceBundle`, its
digest and byte count, preserving section bytes and unknown-boundary notices.

Replay requires a record digest from a separately trusted manifest. It uses the
producer's record/path/hash/comparator checks and returns retained consistency
with exit 2 because no admitted isolated backend is configured for fresh execution.
Ledger reporting refuses without a read-only producer API and opens no database.

Run and demo use closed `bbr.fixture-preflight.v1` configuration: `schema`, `origin`
(`fixture` only), relative `artifact`, `artifact_sha256`, `visible_task`, inert
`candidate_source`, `image_sha256`, `toolchain_sha256` and `limits`. All supplied
objects use producer contracts. The full evidence digest must match VisibleTask.
The actual validator with no backend returns `None` (infrastructure unknown),
while the actual runner with no backend retains its infrastructure observation.
Neither binary nor candidate executes. Preflight exits 2 before provider dispatch,
pending independent admission, isolated backends, the closed full-content evidence
envelope and verified leak/token controls. Demo always prints
**SCRIPTED FIXTURE / NO LIVE MODEL RESULT** and never invents observations.

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
