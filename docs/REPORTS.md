# Retained report API

`bbr.report.build_report(root, evidence_paths, summary, origin=..., campaign_id=..., scoring_bundle=..., replay_records=None)`
creates schema `bbr.report.v3`. Origin must be `fixture` or `live`. Evidence inventory
is nonempty, unique and SHA256-addressed. The inventory must contain a scoring bundle
with exactly `schema`, `registration`, `partitions`, `campaign_receipt`, `row_shards`.
Its schema is `bbr.scoring-bundle.v2`; registration is the closed registration object,
partitions and campaign_receipt are relative inventory paths, and row_shards is a
nonempty list of distinct inventory paths to JSON arrays of retained rows. All bundle
references must be distinct and included in the evidence inventory. Split rows across
files (for example one scheduled row per file) to retain a complete 1,344-row campaign
without an oversized monolithic JSON file. The frozen evaluation harness validates
the pinned 96-task input manifest, retained all-final-lock/hidden-open receipt and
every candidate hash, then recomputes the summary and refuses disagreement or
origin/edition mismatch. Missing rows retain fixed denominators with null primary
estimates; a candidate carrying partial or substituted input sets is refused.
`write_report(new_directory, report)` writes canonical
JSON and escaped HTML/Markdown; destination must not exist. Evidence stays under
the explicit separately retained root and is never silently copied from custody.

`verify_report(report_path, evidence_root)` checks the closed report shape, canonical
body digest, every evidence byte hash, provenance labels and byte-identical rendered
views, and recomputes summary statistics from the validated frozen bundle. The supplied
entrypoint must be `report.json` and passes the same path/link checks as evidence and
rendered views. Archive links, junctions (including root directory chains), absolute
paths, traversal and ambiguous Windows names are refused. Each closed inventory
entry has `path`, `kind`, `sha256`, `replay_record_sha256`. Default `data` entries
are capped at 16 MiB and have null replay commitment. Explicit `replay` entries
are capped at 32 MiB, matching the producer's full 256-pair nested/envelope trace
limit; records are never truncated. Declare these with `replay_records`, a mapping
from inventory path to separately trusted canonical replay-body SHA256.
The raw JSON file `sha256` and canonical body `replay_record_sha256` are distinct:
the latter excludes the envelope's `record_sha256` field. The actual
`bbr.replay.load_record(..., expected_record_sha256=...)` verifies that commitment,
nested pins, trace and comparator lineage without fresh execution. Declaring an
entry as replay cannot enlarge a scoring bundle, partition, receipt or row shard;
those must stay `data` entries. Oversize reads and unknown entry kinds refuse.
Other consumers of `safe_file` retain the default 16 MiB ceiling.

The inventory is bounded to 8,192 files and 16 GiB total; this supports a full campaign at
the minimum private set sizes even with both 4 KiB output caps reached on every case.
Larger ordinary manifests require appropriately bounded shard files and remain subject
to that total cap. Loading and numerical recomputation have not been measured at this
scale. Duplicate JSON keys and nonfinite numbers are refused. Verification does not
execute/import candidate code or establish authentic original provenance. Keep the
external preregistration/source pins outside a writable report archive. Receipt and
admission hashes verify retained bytes and linkage; they do not cryptographically
authenticate appointments, independent custody or an actual hidden-open event.
The durable SQLite API checks the stored transition when producing the receipt;
offline report verification consumes that frozen receipt without reopening streams.
JSON, HTML and Markdown views are written as UTF-8 bytes with LF newlines on Windows.
The v3 verifier refuses earlier untyped report schemas rather than silently
upgrading their commitment semantics. Preserve old archives with their frozen
verifier; no old archive is rewritten by this source change.

## Resource-bearing reports

Score-only `bbr.scoring-bundle.v2` continues to produce/verify typed
`bbr.report.v3` with no resource metrics. Verification explicitly returns
`resources_recomputed=false` and `resource_status=not_supplied_score_only`.
Resource joins use closed `bbr.scoring-bundle.v3`: the same scoring fields plus
`resource_sources`, an inventory path. The resulting `bbr.report.v4` adds exactly
one `resources` object. The verifier rebuilds it from source; callers cannot supply
detached costs, tokens or pass counts to `build_report`.

The closed resource source file has schema `bbr.resource-sources.v1`, `ledger_report`
(path to the actual retained read-only ledger report dictionary), and `receipts`
(distinct paths to individual call-resource receipt objects). It may additionally
name one `model_bindings` file. These must be bounded `data` inventory entries;
resource inputs cannot substitute for scoring inputs or use replay size exceptions.
The consumer opens no database, provider or worker. It calls the sole DL2
`summarize_resources` implementation with campaign/origin and complete retained
source objects. That producer validates exact attempt/request identity and coverage,
retains unknown liabilities and charges M once; no second ledger arithmetic lives
in the archive. Missing measurements stay null with reasons.

For USD/pass, the optional `model_bindings` registration pin must have been frozen
before dispatch/final locks. Its mapping has schema `bbr.model-bindings.v1`, exact
edition/origin, and two closed bindings covering the opaque score model identities
once each: `score_model`, `model_id`, `config_id`, `request_model_config_sha256`.
Canonical mapping bytes must hash to that pin; model/config pairs are unique. Every
joined request's full model configuration (including endpoint/seed/origin) must
match the binding hash. No aliases, model choices, signatures or live approvals are
inferred from a structural match. The builder supplies no populated live mapping.

Only already recomputed full-population M/R/P counts can become pass references.
Their `source_sha256` commits the verified registration, partition/lock/row-shard
inventory lineage and recomputed score. Incomplete fixed population, missing call
coverage, absent binding or absent pass data yields null USD/pass with an explicit
reason; zero passes also has an undefined ratio. An unpinned or invalid supplied
mapping is refused. Omission of a mapping artifact permits an otherwise useful
resource report without pass counts, including when a pin exists but no artifact
was supplied. No exposed registration is modified to add a mapping. Resource
output consistency does not authenticate dispatch, original usage or custody.

The canonical score aggregate has schema `bbr.score-input-commitment.v1`,
`registration_sha256`, `partitions_sha256`, `campaign_lock_sha256`, `partitions`
and `campaign_receipt` path/raw-SHA256 pairs, ordered `row_shards` path/raw-SHA256
pairs, and `score_sha256` of the already recomputed score. When a binding artifact
is supplied it adds its `model_bindings` path/raw-SHA256 pair and canonical
`model_bindings_sha256` pin. The source commitment is SHA256 of this sorted-key,
compact, ASCII-escaped JSON object; every pass reference uses that same digest.

## Strata and domain analyses

Closed `bbr.scoring-bundle.v4` has the original scoring fields plus
`resource_sources` and `domain_sources`, each an inventory path or null. It produces
`bbr.report.v5` with `strata` and `domains`; `resources` is present only when supplied.
Earlier bundle/report combinations retain their original score-only/resource behavior
and rendered bytes. The verifier recomputes every supplied extension and compares the
entire JSON authority and escaped views; absent domain data is explicitly not supplied.

Strata uses actual `evaluation.strata.summarize_strata` on the same retained rows,
partitions and ALL-final-campaign receipt as the verified score. Its expected hash is
`evaluation.preregister.digest` of exactly the base score fields:
`registration_sha256`, `partitions_sha256`, `campaign_lock_sha256`, `origin`,
`complete`, `rows`, `summaries`, `verification`. Later paired-difference and claim-limit
fields are excluded. Six tables preserve origin/model/arm and scheduled nominal rows:
model/arm, family, codec, compiler, optimization and tier. HTML/Markdown display only
producer values, including n/N, unknowns and scorer-owned primary estimates; no new
estimator, rate denominator or bootstrap is introduced by rendering.

The domain source manifest is closed `bbr.domain-sources.v1` with `entries` (at most
one per nominal final key). Each descriptor has exactly `domain`, `domain_policy`,
`binding`, `expected_binding_sha256`, `observed_probes`, `records`. All source fields
except the expected hash are bounded data inventory paths or null. The expected hash
is a separate trusted canonical binding commitment, supplied outside the binding
object; it is never inferred from its raw file SHA or an embedded self-assertion.
The raw inventory hash is retained independently. Shared policy/domain files may be
referenced by several descriptors; duplicate bound candidate identities refuse.

The consumer validates supplied file hashes/types and calls the actual
`evaluation.domain_certificate.summarize_domain` with explicit keywords and the same
verified partitions/lock receipt. Missing data stays null/not qualified; no values,
records, samples or expected outcomes are generated. That producer owns full-domain
qualification, observed/public-but-unobserved accounting and precommitted calibration.
`exhaustive_on_declared_domain` covers exactly 256 supplied canonical valid values,
not arbitrary stdin strings or the primary private184 score. Calibration events are
retained separately and never promoted to a population rate. Structural commitments
do not authenticate original execution, independent custody or admission.

Numeric authority is JSON. Do not populate live rows from fixtures, combine models
or drop scheduled failures. Unknown metrics must be null with a reason. Evaluation
owns denominator, identity grouping, family means and paired bootstrap; report code
must consume that API instead of inventing a second scorer. The evaluation source is
outside the installed wheel and must be present on the module path; missing frozen
harness source refuses verification. Recomputed retained evidence is not fresh parity.
