# Local instrument runbook

Status: Dirty construction, runtime unverified. No dependency installation, app
execution, Docker launch, live/model call or tests have been performed by DL4.

The frozen CLI surface is available as `bbr.cli:main` (root packaging is owned by
INT/DL1). `python -m bbr.cli` is the module entrypoint after later authorized setup.

Commands: `corpus build`, `corpus gate`, `evidence --artifact HASH`,
`run --arm S|M|R|P --config FILE`, `replay --bundle FILE`, `demo --mock`,
`verify-report FILE --evidence-root DIR`, `ledger report --database FILE`.
Until producer integration and safe execution are configured, commands return
structured `unavailable`/pending status and exit 2. Demo always prints
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
