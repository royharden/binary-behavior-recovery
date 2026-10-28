# Authored software regression support

These files contain trusted, builder-authored software test fixtures. They are not
independent/held-out corpus, an admitted campaign, genuine authority/rights receipts,
model results, real executables or evidence that a worker ran. All identities use
software-only labels and every registration has `origin="fixture"`. The synthetic
`accepted_by_roy=True` flag is solely a parser positive-control; it does **not** claim
Roy approved data or appointed any stub author/custodian/evaluator.

Importing this package constructs no matrix or data files and opens no database.
`make_matrix(patterned=True, model_bindings=False)` constructs fixture data only when
an authorized software test explicitly calls it. The helper imports trusted product
contracts/codec functions inside that call; it never imports, compiles or executes
candidate code. It does not invoke corpus generators, providers or workers.

`SoftwareMatrix` exposes `registration`, `partitions`, `admission`, `receipt`, `rows`,
`domains` (keyed by family), `bindings`, `domain_policy`, `model_configs` (keyed by
opaque score model), and the explicit `scope` label. `bindings` is the exact
`bbr.model-bindings.v1` wire mapping; each corresponding `model_configs[score_model]`
contains all five `model_id/config_id/endpoint_id/seed/origin` fields whose canonical
hash is frozen in the binding.
Its exact roster has 8 software families, 12 cells/family and 2 fixture models, hence
96 tasks/model and 1,344 model/arm rows. Two software families have uint8 finite
domains; six use uint16 ordinary domains. API partition names such as `private_valid`
describe software test roles here, never actual hidden/independent benchmark data.

Patterned mode has target identity group sizes 2,1,1 within family/codec. M passes only
gcc/O0: nominal valid pass is 1/4 and primary equal-group/equal-family estimate is 1/6.
P passes all valid fixture rows; R passes none. Lookup passes visible fixture cases
but fails private-role cases. S/echo/constant abstain. These are hand-authored known
software outcomes, not measured recovery results. `patterned=False` makes every arm
abstain, preserving all complete denominator failures with zero case observations;
use it for small archive/lock fixtures. Both modes include matching malformed exit2
observations only where a candidate exists.

`model_bindings=True` freezes the exact two fixture config hashes before registration
identity is computed. Without the option, the returned binding artifact is unpinned
and cannot authorize resource USD/pass. Public finite sampling is fixed to eight
precommitted software keys, never selected by a candidate result.

Templates and pools are deliberately shared to reduce memory. Treat every returned
mapping/list as immutable unless a negative test makes appropriate copies: copy a
row, its cases list, and each case/observation being changed. A shallow copy of the
outer rows list alone does not isolate mutations. `summary_for(score, model, arm)`
selects an existing summary without implementing score arithmetic.

No fixture factory, product import or test was invoked while these source files were
written. Runtime validation awaits the parent environment grant; RAM blocks installs.
