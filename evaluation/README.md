# Trusted evaluation source

This directory is outside the installed wheel. It defines no held-out corpus or expected answers. Gate 0 remains PENDING — needs Roy. All execution, independent custody and numerical examples are unverified during Dirty Mode.

The closed required pin set permits exactly one optional name, `model_bindings`.
It commits an inventory-backed `bbr.model-bindings.v1` mapping of both opaque score
model identities to exact model/config/full-request-config hashes. The extra pin
participates in the existing registration digest before dispatch and final locks.
Registrations lacking it retain their original digest and score-only semantics;
resource USD/pass remains unbound rather than inferring aliases or retrofitting
an exposed edition. No other extra pin names are accepted. The report consumer
validates the mapping against actual retained request.model_config bytes before
deriving pass counts from the already recomputed full-population scorer summary.

`preregister.registration_from_dict(raw)` loads a closed `Registration` mapping. Exact fields are the dataclass fields; cells are `Cell` mappings, pins are name/digest pairs. It fixes eight families, two finite tiers, 96 nominal cells per model, two model/config identities, seven arms, 2,000 draws and explicit seed. Execution groups use full stripped ELF + execution contract, inside family/codec only. Semantic independence is established by accepted receipts, never opaque labels alone.

`admission.Admission.validate(edition)` requires Roy's accepted independent appointments, release rights, source/partition/canary/freeze and validity receipts. Digests are references requiring operator verification, not signatures verified by this code. `heldout_intake.admit_metadata(...)` checks the entire family metadata roster, normalized semantic fingerprints and capacity receipts. It neither opens nor creates corpus files. Fingerprints must be computed and independently reviewed before seal; caller-controlled hashes do not prove absence of semantic overlap.

`validate.audit_partitions(partitions, tier)` checks fixed raw/canonical partitions supplied by custodian. Records contain `raw_hex` and `canonical_key`; malformed records use null canonical key. `validate.frozen_partitions(registration, manifest)` requires a closed `{schema, tasks}` manifest with schema `bbr.partitions.v1`. Each task is `{task_id, partitions}`; partitions has visible/public_valid/public_malformed/private_valid/private_malformed arrays. All 96 tasks are required, the whole manifest digest must equal the registration's `partitions` pin, compiler/optimization variants inherit identical raw/canonical sets within family/codec, and all codecs inherit identical valid canonical sets within family. Codec correctness still requires custodian validity checks. The builder supplies no input data or expected answers.

`exposure.Campaign(path)` persists one campaign in SQLite. `seal(registration, admission)` is insert-only, `dispatch()` can happen once, `lock_final(task, model, arm, candidate_sha, status)` is immutable, and `open_hidden(evaluator, lease_id)` requires every final across both models/all arms locked and refuses a second/concurrent opening. That transaction also persists the `bbr.hidden-open.v1` receipt, including retained admission bytes, registration/admission digests, appointed evaluator, lease, all canonically ordered final statuses/hashes and lock digest. `retained_open_receipt()` validates that receipt against durable state and finals without opening streams again; `Campaign.retained_report(registration, rows, partitions=manifest)` uses it. Legacy databases lacking retained admission refuse this API; do not bypass the independent edition registry by creating a replacement campaign. No hidden mount or execution is performed. A campaign database must reside under independently controlled storage; builder access to arbitrary SQLite writes invalidates custody. Retired campaigns cannot restart in that database. The independent edition registry must prevent using a different database to evade the one-campaign limit; this remains a deployment/custody gate, not an in-process guarantee.

`score.score_rows(registration, rows, *, partitions=manifest, campaign_receipt=receipt)` and `run.retained_report(...)` require both frozen inputs. The latter adds `statistics.paired_bootstrap`. They validate the entire post-lock receipt before consuming any observations; archive recomputation uses retained receipt bytes rather than reopening the campaign. A matching hash establishes retained consistency, not authentic independent custody or truth of the claimed transition. Input rows are closed mappings with `task_id`, `model`, `arm`, `candidate_sha256`, `status`, `cases`. Every supplied status/hash must match the corresponding pre-hidden final lock (noncandidates use null hashes). Each case has `partition` (visible/private_valid/private_malformed), `input_hex`, `canonical_key` (null for malformed), `oracle`, `candidate`. Every candidate must supply the exact frozen visible/private input sets; different models/arms cannot substitute inputs or omit cases. Observation fields are `stdout_hex`, `exit_code`, `signal`, `timed_out`, `output_limited`, `status` (ok/subject_failure/infrastructure_error). Hex is lowercase canonical; exact stdout bytes and numeric exit status are compared. Inputs/outputs remain bounded. No candidate code is loaded or run.

Missing rows remain in the 96 denominator and make primary estimates/intervals null. Abstention/syntax failure are denominator failures. A candidate needs the exact frozen 8 visible, 184 finite or >=256 ordinary private valid, and 32 malformed observations. Oracle faults and any infrastructure unknown make a row incomplete. Raw and canonical intersections fail. Distinct recoveries of identical execution identities may disagree: average nominal outcomes within each identity group, then equal-weight group means within each family, then equal-weight the eight families. Summaries retain all nominal rows, final candidate identities, frozen partition/lock digests, per-family estimates, nominal sensitivity, malformed/visible/hidden gap and zero-denominator reasons. The bootstrap resamples eight whole family indices with replacement using the frozen seed, 2,000 draws, percentile intervals, RNG/Python version, draw digest and raw paired family differences. Intervals are exploratory; generation variance and multiplicity are not estimated.

`leakscan.scan_prompt(prompt, canaries, private_inputs)` checks exact canary bytes and private raw/hex/hash encodings without reading files. It is supplementary and can flag short-byte coincidences; independent custody must adjudicate leaks. It rejects empty private inputs because empty substring scans are meaningless. Scan only committed private inputs; visible hashes are not secrets. Semantic leakage and arbitrary encodings are not proved absent.

Deferred K/L checks: hand-computable unequal-group paired matrix; missing/abstain/zero denominators; 2,000 reproducible draws and arm-order invariance; raw/canonical intersections; semantic relabel rejection; concurrent SQLite lock/open attempts; post-lock immutability; mount isolation; rights/receipt authenticity; fixture/live lineage; live model and cost approvals; independent corpus validity/admission. No tests or runtime execution were run for this source increment.

`producer.RetainedCollector(registration, partitions=..., campaign_receipt=...)`
adapts shared `bbr.contracts.PairOutcome` values using the actual
`bbr.differential.compare_observations` comparator. `add(task_id, model, arm,
candidate_sha256=..., stdin_bytes=..., outcome=...)` checks final source identity,
input hash, comparator status/reason and membership in the frozen scoring pool.
It rejects duplicate observations and public feedback inputs. `rows()` returns
detached, ordered scorer rows; `summary()` invokes the sole retained scorer.
No worker, source import, hidden stream opening or provider port is available to
the collector. Infrastructure observations keep their unknown status; a missing
row stays missing, and partial candidate input sets cannot become successful rows.
The producer bytes/exit/signal/resource fields map directly to score observation
fields; elapsed/stderr/reason stay in original producer archives, not invented
statistical equality criteria. Custodian validity must establish decoded canonical
identities; this adapter consumes their frozen commitment rather than generating
inputs or references.
