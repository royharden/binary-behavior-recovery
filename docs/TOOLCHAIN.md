# Toolchain and validity

Runtime unverified. No toolchain version, image digest, compiler result or license approval
is fabricated. `ToolchainPin` requires an actual immutable image digest, exact GCC/Clang/
binutils versions, dated package snapshot and rights receipt before `build_plan` can
schedule the 96 dev cells. No compiler runs on the host through this package.

`build_plan(specs, pin)` yields fixed argv/environment for all three codecs, both
compilers and O0/O2. A future isolated build adapter must render each codec, stage
`/work/source.c`, enforce limits, compile, strip, hash and rebuild twice. It must record
the complete ELF and execution contract, inspect dynamic linkage/runtime obligations,
and supply receipts. No Docker or deployment scaffolding was created in Dirty Mode.

`validate_instance(spec, artifacts, receipts)` rejects a whole semantic instance on
missing variants, pending rights, hash/rebuild drift, incomplete finite tier or any
recorded disagreement/UB/stability/trap failure. This validates receipt structure and
claims; independent identities, receipt authenticity and actual execution remain the
custodian's gate. It is never independent corpus admission.

`group_execution_identities(artifacts)` groups complete identical ELF bytes under
identical execution contracts only within a family/codec. Every nominal task ID is
retained. O2/O3 .text coincidence diagnostic, independent reference comparison,
sanitizers, malformed cases, deterministic repeats and all compiler runs are deferred.

No uv lock exists yet: approved dependency resolution and lock verification are deferred.
pyproject ranges are compatibility constraints, not claimed reproducible pins.
