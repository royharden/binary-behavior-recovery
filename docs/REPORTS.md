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

Numeric authority is JSON. Do not populate live rows from fixtures, combine models
or drop scheduled failures. Unknown metrics must be null with a reason. Evaluation
owns denominator, identity grouping, family means and paired bootstrap; report code
must consume that API instead of inventing a second scorer. The evaluation source is
outside the installed wheel and must be present on the module path; missing frozen
harness source refuses verification. Recomputed retained evidence is not fresh parity.
