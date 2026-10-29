# Retained resource summary

`bbr.report.resource_metrics.summarize_resources(ledger_report, receipts, *,
campaign_id, origin, pass_counts=()) -> dict` is a pure JSON-data join. It never
opens a database, calls a provider/scorer, imports a candidate or executes an app.
DL4 owns its archive/render invocation; importing via report.__init__ is not
required. Source construction is runtime-unverified.

`ledger_report` is the complete, unfiltered retained output of `Ledger.report()`.
Exact keys: cap_usd,committed_usd,available_usd,attempts,max_attempts,dispatch_blocked.
Each attempt has request_id,digest,attempt,reserve,status,charge,reason. Status is
reserved,in_flight,unknown,settled or never_sent. Attempts1/2 join by the exact
request ID and attempt number. Retry2 requires original1 proven never_sent with
identical request hash and reserve. The consumer must snapshot ledger data through
its owner; this function never reads SQLite or alters a liability.

Each receipt has exactly these fields:

| Field | Meaning |
| --- | --- |
| schema | bbr.call-resource.v1 |
| campaign_id,origin | Exact requested campaign and fixture/live origin |
| task_id,model_id,config_id | Retained opaque identity strings |
| call_id | M:0,R:1,R:2,R:3,P:1,P:2,P:3 |
| request_id,attempt | FixtureDispatch task_id:config_id:call_id, attempt1/2 |
| request_sha256 | Canonical full request SHA256 equal to ledger digest |
| request | Complete original JSON request, not a reconstructed subset |
| provider_record | Complete retained source snapshot or null |
| provider_record_sha256 | Canonical source SHA256, null if source missing |
| provider_record_reason | Nonempty unavailable reason if source null; otherwise null |

Canonical hashes use JSON sorted keys, compact separators, ensure_ascii=True,
allow_nan=False and ASCII bytes, without newline. Exact identity strings are
bounded to256 characters. JSON arrays are bounded to1344 receipts and4032 score
references. Unknown/duplicate fields and duplicate/conflicting ledger/receipt
identities refuse the join, including identical duplicate receipts. Every ledger
attempt must have one identity receipt; extra/missing receipts refuse. A complete
ledger mixing fixture/live cannot be filtered into a false single-origin summary.

The full request is hashed as opaque producer-owned data, while identity is
checked against request.visible_task.task_id and request.model_config. The model
configuration has exact model_id,config_id,endpoint_id,seed,origin; all config
bytes are hashed, and one config_id cannot silently change model/endpoint/seed.
Additional producer request envelope fields remain part of the full digest.
This supports future evidence-envelope additions without another request schema.
Request IDs are compared to the producer format, never split on colons.

The source snapshot must carry matching origin and request_sha256. If it embeds
the request, that full hash must agree too. Current retained MockProvider fixture
rows already carry request,request_sha256,response,usage,origin. Receipt generation
must preserve the actual snapshot; a fixture declaration is not a live execution
receipt. Absent source data can still join a failure/unknown ledger attempt with
a reason; no provider success is synthesized. Hashing the receipt binds all its
identity/provenance values and is not proof the source or call is authentic.

Optional provider_record.usage has exact input_tokens,output_tokens,usd. Tokens
are nonnegative integers or null; USD is a decimal string or null. Known USD must
equal the actual ledger charge. Never-sent attempts cannot carry positive token
usage. Optional provider_record.resources has exact wall_seconds,cpu_seconds,
peak_memory_bytes, all nullable; times are nonnegative decimal strings and memory
is a nonnegative integer. Existing providers emit no execution-resource fields,
so these remain null. Missing individual measurements and partial aggregate
measurements carry unavailable_reasons, never inferred0. No empty campaign is
presented as a measured zero-token or zero-resource run.

Money/time strings follow the ledger's finite, nonnegative precision up to12
fractional digits and per-attempt1,000,000 ceiling. Source money floats are refused.
Aggregation uses Decimal precision50, exact for the bounded monetary population.
Ratios use precision50 ROUND_HALF_EVEN, disclosed in output; a repeating ratio is
a rounded Decimal representation, not an exact rational equivalence claim.

Cost authority is solely the ledger:
- settled_spend_usd sums settled/never_sent charges; never_sent requires charge0.
- unresolved_recorded_charge_usd preserves known over-reserve unknown charges.
- unpriced_reserved_liability_usd sums unresolved attempts without a charge.
- committed_usd sums the three, matching ledger committed/available/blocked state.
Unresolved charges and reserves are not labeled settled spend. Failure reasons,
all attempt IDs/hashes, provider source hashes and original status/charge lineage
remain in the output. A settled billed failure is retained like any other charge;
this seam does not infer a functional result from a ledger settlement reason.

campaign_unique counts and charges each actual ledger attempt once. Group keys
are model_id,config_id,arm within the single explicit origin/campaign. Each arm's
incremental object includes only its own actual attempts. R/P shared_m_reuse lists
every original M attempt/hash/status/charge with new_charge_usd="0". Their
including_shared_m_nonadditive view combines original M and own attempts; it is
useful for arm cost comparisons but MUST NOT be summed across arms. No new
reservation/charge is invented for a reuse link. R/P calls without M lineage
refuse. These links do not independently prove byte-identical M initialization.

`pass_counts` optionally supplies consumer-verified score references with exact
model_id,config_id,arm,passed_tasks,reason,source_sha256. Each group appears once;
passed_tasks is a nonnegative integer no greater than retained task count, or
null with a nonempty reason. A known count uses reason=null. source_sha256 must
bind the consumer's already-verified retained scoring input in its archive; this
module does not open that source, verify a scorer or compute pass counts. It
hashes the complete supplied score-reference array for retained linkage.
usd_per_pass uses the including-shared-M settled arm cost and supplied pass count;
its basis is labeled nonadditive across arms. Missing or zero passes give
null+reason. Any unresolved own/shared-M cost also gives null+reason. Source
pass-count references and input hashes remain in the summary.

DL4 must archive the full ledger snapshot, all receipts/source snapshots and
verified pass-count inputs under external trusted digests, then invoke this pure
join during report build and verification. A resource receipt is not another
accounting ledger. Closed data consistency cannot establish authentic provider
usage, actual execution, independent custody or coverage. No fixtures, outcomes
or held-out expected answers are authored by this module.

Deferred normal validation: persisted ledger snapshot consistency across crashes,
retry/unknown/over-reserve/failed-charge joins, duplicate and digest/config/origin
refusals, M reuse accounting and nonadditive arm costs, partial/null usage and
measurements, zero-pass/incomplete-cost ratios, Decimal precision boundaries,
consumer archive recomputation and resource limits at the maximum campaign size.
No runtime tests, imports of application code, database reads, dependencies,
Docker/CI or live/model calls were run for this construction package.
