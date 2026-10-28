# Retained score strata

Public source API, outside the installed wheel:

```python
from evaluation.strata import summarize_strata

summarize_strata(registration, retained_rows, *, partitions,
                 campaign_receipt, expected_score_sha256) -> dict
```

`registration` is the existing validated Registration; other inputs are the same
retained rows, frozen partition manifest and post-lock hidden-open receipt passed
to evaluation.score.score_rows. This module calls that sole scorer, checks the
canonical source commitment, then projects its output. It is not a second scorer,
does not accept asserted aggregate input, and never executes/imports subjects or
opens private streams/databases. Source-only construction remains unverified.

The expected commitment uses evaluation.preregister.digest of the base score_rows
output, which has exactly registration_sha256,partitions_sha256,
campaign_lock_sha256,origin,complete,rows,summaries,verification. For integration,
DL4 selects those exact keys from its independently recomputed retained_report
result and commits that base object; paired_differences/claim_limits added later
by retained_report are excluded from this commitment. Supply that expected hash
and the same raw input shards/manifest/receipt to summarize_strata. The function
recomputes through the existing scorer and refuses any mismatch before projecting.
Digest consistency does not prove authenticity or that an execution happened.
Consumer archive verification must also bind these inputs to external trusted pins.

The existing scorer alone checks registration, final candidate locks, frozen input
sets, observations and pass/completeness semantics. Strata then verifies every
nominal task/model/arm key against registration.final_keys, every provenance
dimension and complete-ELF/contract identity against its registered Cell, all
summary model/arm/family identities and exact canonical score commitment. All
96 nominal task rows per model/arm remain present. Missing raw scored rows are
handled by the existing scorer as not_run; a missing row in its full output is
refused. Incomplete rows can never be counted as passing by the projector.

Output schema bbr.strata.v1 binds source_score_sha256,registration_sha256,
partitions_sha256,campaign_lock_sha256,edition and single explicit origin. Its
tables always include origin,model,arm and the indicated optional dimension:

| Table | Extra dimension | Scheduled denominator per entry |
| --- | --- | --- |
| by_model_arm | none | 96 |
| by_family | family_id | 12 |
| by_codec | codec | 32 |
| by_compiler | compiler | 48 |
| by_optimization | optimization | 48 |
| by_tier | tier | 24 finite / 72 ordinary |

No table pools two models, two arms or fixture/live origins into a headline.
Tables are overlapping margins; summing margins duplicates rows. Each entry lists
scheduled_task_ids and its nominal scheduled denominator. Status counts preserve
candidate,abstain,syntax_failure,not_run,infrastructure_error. These are retained
score statuses, not independently measured runtime-cause categories. Unknown row
counts and original unknown-reason counts remain explicit.

nominal_valid_pass,visible_pass,malformed_pass contain n,N,value,reason. N always
includes every scheduled status, including abstain and syntax failure. Known
passing n comes only from existing scored booleans. If any row is incomplete,
rates are null with incomplete_nominal_stratum reason; retained n is a lower
count, not a statement that unknown rows failed or were run. Gap percentage points
and hidden-fail-given-visible rates also stay null for incomplete strata. A zero
visible denominator produces null+zero_visible_denominator. Complete abstentions
and syntax failures remain denominator failures as the scorer defines them.

Primary and nominal estimates are deliberately separate:
- by_family copies the scorer's family_estimates value for that family, including
  its mean of nominal outcomes within complete-ELF execution-identity groups and
  equal group weights. Incomplete families preserve null.
- by_model_arm copies the scorer's primary value and reason, including equal
  weights across eight families. No estimate is recomputed by this module.
- codec/compiler/optimization/tier strata expose nominal rates only. Their
  primary_identity_group_estimate is null with a reason that no primary estimator
  is defined there. identity_group_count is descriptive, never a new weight.

retained_case_counts sums actual visible/private_valid/private_malformed counts
over nominal rows. It counts repeated inputs across variants and arms as retained
task-case observations; it is not independent sample size. Finite184 private
cases and ordinary256+ private cases are not pooled into case-level accuracy or
presented as equivalent case denominators. The available source reports all-input
pass booleans, not individual matching-case totals or an exhaustive256 certificate.

Unsupported metrics are explicit null/reason entries at top level: detailed
runtime causes, tokens/cost/resource measurements, finite-sample calibration and
paired bootstrap. Resource data belongs to the separate retained resource join;
bootstrap belongs to existing evaluation.statistics with its frozen paired draws.
This module does not redraw, infer significance, synthesize resource measurements,
recover fault causes from a False pass, or claim full declared-domain enumeration.

DL4 owns invoking this module during report creation and verification, committing
its canonical output, rendering escaped HTML/Markdown and presenting nominal and
primary columns with their distinct labels. Unsupported fields must remain null.
It must not imply a row's candidate status means fresh execution was verified.

Deferred validation: exact 96-cell/arm/model preservation, wrong source/roster/
dimension/identity rejection, complete/incomplete/abstain/syntax-failure margins,
unequal identity-group versus nominal sensitivity, finite/ordinary case counts,
zero visible denominator and origin isolation, deterministic canonical projection
and full report/archive recomputation. No sample outcomes, expected answers,
independent/held-out pools or fixtures were authored for this source package. No
application imports, runtime/tests/type tooling, dependencies, network/model,
database, CI or Docker execution performed under this Dirty construction grant.
