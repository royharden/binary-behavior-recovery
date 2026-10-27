# Runner, differential, shrink and replay

Dirty Mode source construction only. Nothing here establishes sandbox isolation,
binary validity, fresh parity, independent admission or runtime acceptance.

`bbr.runner.Runner(policy, backend=None)` exposes
`execute(artifact_sha256, stdin_bytes, limits) -> bbr.contracts.Observation`.
Without an explicitly configured trusted `IsolatedBackend`, execution returns
`infrastructure_error` with reason `isolated_backend_unavailable`. There is no
subprocess fallback and no host candidate import. The worker must resolve hashes
in separate read-only oracle/candidate stores, verify bytes, use fresh unprivileged
processes, enforce CPU/wall/memory/output/process limits, deny network and mounts
of sources/references/private streams, and separate candidate and oracle workers.
SandboxPolicy describes these requirements; an arbitrary Python backend is trusted
code and cannot prove them. Activation requires hostile-control validation later.
An explicit validated subject timeout remains a timeout when elapsed time includes
worker termination/cleanup overhead. A wall overrun without `timed_out` is an
infrastructure fault; retained stdout/stderr caps still apply to every observation.

`bbr.runner.CandidateValidator(policy, limits, backend=None)` is callable as
`validator(code) -> tuple[bool | None, str]` for the SEAM-001 candidate-validation
adapter. `None` reports explicit infrastructure unavailability/unknown, including
an absent isolated backend; it must not become a syntax failure or scoring success.
Actual parse/import checks remain inside the isolated candidate sandbox.

`bbr.differential.compare(binary_ref, candidate_ref, input_ref, *, oracle,
candidate, limits)` executes separate adapters. `compare_observations(...,
stdin_bytes=...)` and `run_pair(..., inputs, ...)` return shared PairOutcome models.
stdout bytes and numeric exits are exact; stderr/timing do not affect equality.
Clean exits 0 and public malformed exit 2 may agree; signals, timeout, caps or
other exception exits always fail even when both subjects fault. Infrastructure
errors/missing exits remain unknown, never denominator successes.
A `subject_failure` observation can agree only at the deliberate malformed exit 2;
in particular, matching exit 0 and stdout cannot hide a reported subject failure.

`deterministic_partition(values, seed=..., visible=8, public=64, private=256)`
uses SHA256 order over canonical caller-owned values. For a declared 256-value
domain explicitly use private=184. Preserve commitments in independent custody.
`audit_partitions` audits both bytes and decoded values, duplicates and malformed
pool disjointness. Supply a strict domain-aware codec decoder; for finite-domain
certification provide the full domain and minimum_valid=(8,64,184). It verifies
coverage/counts and returns a commitment, never claims that inputs are independent.
Apply identical canonical partitions across every codec/compiler/optimization.
No held-out cases, expected answers or independent evaluation data are included.

`grammar_moves` uses canonical codec round trips, contiguous element deletion and
numeric boundaries under a caller-supplied domain predicate. `shrink(case,
move_policy, evaluate=..., final_locked=True)` caps pairs at 256 and launch time
at 30s, retaining all attempts. The synchronous callback MUST honor the remaining
wall deadline in its isolated worker: this source cannot interrupt arbitrary
Python callbacks. No feedback shrinking. Complete final move pass with no smaller
failure earns `one_minimal_under_moves`; interruption yields
`reduced_budget_limited` or `shrink_exhausted`. This is not global minimality.
Malformed inputs need a separately frozen grammar-preserving policy; this version
only provides valid-input moves. Unknown observations stop reduction.

`bbr.replay.make_record` wraps DL1's ReplayBundle in a closed envelope pinning
image/toolchain, policy/argv/environment/limits, exact input bytes, comparator,
trace and precise minimality label. Shared nested replay pins and trace must be
complete and identical to the envelope; legacy incomplete replay is refused.
Records are capped at 32 MiB, covering the duplicate retained hex traces.
Shared `locally_minimal` maps only to
`one_minimal_under_moves`; `budget_exhausted` maps to `reduced_budget_limited`.
`verify_record` recomputes hashes and comparator results from retained observations;
it does not prove execution or exhaustive final-pass coverage. Caller MUST pin the
record digest separately. `load_record` rejects duplicate JSON keys, oversized
records, traversal/drive/ADS paths, symlinks and reparse points. Read-only storage
is required to rule out hostile concurrent filesystem replacement. Artifact path
components ending in dots/spaces are refused, including Windows traversal aliases,
and resolved files must stay within the resolved storage root. `replay`
checks artifact bytes and worker pins, then compares a fresh isolated execution to
retained observations, with infrastructure faults returned as unknown. No backend
is shipped. The same argv/environment and image are required for both v1 workers.

Deferred K validation: all three codec integrations; clean/malformed/exception,
timeout/cap/infra distinctions; capacity and raw/canonical overlap audits;
deterministic move/final-pass certificates and deadlines; tamper/traversal/link
refusals including Windows junctions; candidate/oracle mount isolation and hostile
controls; real pinned builds and known-dev failure replay within 60 seconds in a
prebuilt offline image. All normal independent admission and live L gates remain
pending. No Docker, fixtures with expected answers, CI, installs or live calls
were run or provisioned by this package.
