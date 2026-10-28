# Retained finite-domain certificate and sample calibration

Source construction only; runtime/numerical/import checks remain deferred. This
module creates no inputs, seeds, manifests, expected answers or independent data.
It never invokes input_plan, a subject process, DB, model or generator. A trusted
post-lock evaluator supplies already-retained records and separately trusted pins.
Hashes/closed shapes establish retained consistency, not authentic custody or truth
of narrated execution. Independent admission/rights/appointments remain external.

Import `evaluation.domain_certificate.summarize_domain`. All keyword inputs are
explicit: domain, partitions, campaign_receipt, domain_policy, binding,
expected_binding_sha256, observed_probes and records, plus Registration positional.
Missing truth is null/not_qualified with reason. Present invalid/mismatched evidence
raises ValueError. No fallback sampling or inferred observations are permitted.

The same entrypoint supports partial validation; no second helper/API is needed.
Before any missing-source return, it validates Registration, every present source's
closed shape/types and local invariants, and every join with available dependencies:

- Receipt and partitions use the existing canonical validators against Registration.
  Policy checks its global registration pin, complete96-task roster, Domain integer
  fields/tier capacity, variant commitments and sample shape/distinctness even when
  caller Domain or partitions are absent. Sample membership needs partitions.
- Binding checks its own identity, digest fields, registered artifact/execution and
  comparator, and registration/partition/policy pins. A supplied trusted binding hash
  must have digest shape even without binding; matching its body needs both sources.
- Probes check identity, lock digest, unique bounded canonical hex and arm restrictions.
  Records check exactly256 closed comparisons, registered task/model/arm and execution
  pins, consistent candidate identity, unique bounded canonical input hex, strict shared
  PairOutcome JSON, each input digest and recomputed shared comparator status/reason.
  These record checks need neither Domain, policy, partitions nor binding.
- Available sources join their paired identities, receipt locks/final candidates and
  binding probe/record digests before returning unavailable. A candidate claim in any
  binding, probe receipt or record conflicts with an available noncandidate final;
  it raises ValueError rather than being hidden by an unavailable result. Partitions
  permit record coverage and public-probe membership checks; policy plus partitions
  permit private sample membership. A present policy Domain can validate retained
  input decoding/coverage when caller Domain is absent, without supplying that missing
  required argument or producing a certificate. Domain decoding also needs a registered
  codec, obtained from a present binding, probe receipt or coherent record identity.
- Retained oracle status/exit health is classified before a partial return. When a
  validation Domain and registered codec are available, the same pass also checks
  output decoding and arity; complete scoring reuses its cached result. Invalid oracle
  computation yields null/not_qualified rather than ValueError solely for that failure.
  Without a validation Domain, unavailable_checks explicitly discloses the missing
  oracle-output arity check, and partial provenance/certificate/calibration stay null.

Partial outputs retain the first missing-source reason in argument order, null
provenance/certificate/calibration, and any validated paired identity. They additionally
contain `unavailable_checks: list[str]` naming the joins/qualification that missing
dependencies prevent. No target identity is invented when all paired sources are absent.
Available checks establish retained consistency only; absent authority is never inferred
from a digest. Complete valid inputs keep the existing output shape and scoring behavior;
`unavailable_checks` is added only for missing-source outputs.

The existing validate_open_receipt gate verifies all campaign finals precede hidden
opening; the target task/model/arm/candidate must match that receipt. Existing
frozen_partitions validates the sole frozen population/variant/canonical identity.
The supplied public Domain must be committed in the registration's domain_policy
pin and have capacity exactly256. Decode256 supplied distinct canonical inputs
within that domain to establish coverage by cardinality; never enumerate/generate
domain values. Every retained record joins exact artifact/execution/comparator/
candidate pins, input digest and shared PairOutcome comparator semantics. Invalid
oracle outputs and infrastructure unknowns yield null agreement, never a pass.

Certificate `exhaustive_on_declared_domain` covers only256 declared canonical
values, never all possible stdin strings or general equivalence. Primary184 private
agreement and denominator stay separate. Counts disclose8 visible, actually observed
valid public probes,64-minus-observed public-but-unobserved,184 private, and observed
malformed probes separately. Probe exposure comes only from the supplied bound
observed-probe receipt; non-P arms cannot claim public observations.

Calibration accepts only the precommitted private subset in domain_policy. Requested
size1..256 has effective size min(requested,184); sizes>=184 must name all184 private
keys. Disclose private exhaustion and zero extra unseen coverage. Report separately
sample agreement versus all256 and private184 agreement, with exact paired identity.
An individual false-pass event is not a population rate. Missing sample policy or
unknown observations produce null/not_qualified; never select a subset after scores.

Closed wire schemas/API are frozen in the private run's producer request, not model
prompts. Policy schema bbr.domain-policy.v1 has exactly schema/tasks; each task has
task_id/domain/canonical_plan_sha256/sampling. The96-task roster is complete. Domain
is all five public Domain JSON fields or None. Sampling is finite-only and either
None or exactly recipe_id/size/canonical_keys. Same-family variants cannot change
domain, canonical plan commitment or non-null sample recipe/subset. Global policy
hash must equal Registration.pins[domain_policy]; global partition hash remains
Registration.pins[partitions]. No new registration/shared contract API is introduced.

Binding bbr.domain-binding.v1 joins exact task/model/arm/candidate, artifact and
execution contract, comparator, registration/lock/partition/domain-policy/canonical-
plan/observed-probes/records digests. expected_binding_sha256 must come separately
from trusted custody, never self-authorized by the same mutable record. Observation
records are shared PairOutcome JSON plus bounded raw input hex and identity pins.
Output contains only commitments, counts and agreement/events, no private values.

Later authorized validation must exercise absent/mismatched bindings, duplicate/
missing/outside-domain records, wrong locked candidates, codec widths/arity, oracle
and infrastructure failures, full-domain coverage, private-only versus full scoring,
zero/partial/exhausted sample policies, cross-variant identity and report recomputation.
No such functions or tests were invoked during this source task.

Deferred partial-input regressions (descriptions only; no data/fixtures authored or
functions/tests invoked):

1. Missing caller Domain with a malformed/duplicate/outside96 policy roster must
   raise ValueError, including when the policy hash itself matches its supplied pin.
2. Missing policy with malformed record shape/type, changed paired identity or
   wrong registered execution/comparator must raise ValueError.
3. Missing binding with a corrupt record input hash or comparator result must raise
   ValueError through record-local checks; a present malformed trusted binding hash
   must also fail without a body. Available receipt/noncandidate contradictions and
   record/probe/partition joins must still reject inconsistent supplied evidence.
4. Valid partial evidence must return not_qualified with null provenance/certificate/
   calibration and explicit unavailable_checks, while applying all available joins;
   omit different dependencies to cover policy/partition membership and Domain checks.
5. Complete valid evidence must retain the prior certificate, counts, private184 and
   sample calibration behavior, with no partial-only unavailable_checks field.
6. Present Domain and coherent retained records with a missing trusted binding pin
   and bad oracle output arity must still classify that oracle failure before returning
   partial not_qualified with null provenance/certificate/calibration. Invalid oracle
   computation alone must not raise ValueError; the complete-input counterpart must
   reuse the same classification and retain null agreements for invalid oracle truth.
