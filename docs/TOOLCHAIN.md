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

## Round2 offline compiler request

Trusted software regression tests may run in INT's pinned local Python environment
after its explicit handoff. No compiler/container step is authorized for DL1 yet.
INT must select an already-present KAISER-PRO offline image, record its actual digest,
GCC/Clang/binutils versions and package snapshot, and grant a bounded run under
`C:\agent-runs\m15`. No pull, host compiler installation, privileged mode, home,
credential or Docker socket mounts. Free RAM must exceed3GiB immediately before
each install/container run. A low reading blocks that operation, not a fabricated pass.

Pending image identity: `<PLACEHOLDER_M15_TOOLCHAIN_IMAGE_DIGEST>`; pending exact
snapshot/version receipt: `<PLACEHOLDER_M15_TOOLCHAIN_SNAPSHOT>`. These unresolved
sentinels are never executable configuration or asserted real pins. Source ToolchainPin
rejects unresolved digest syntax. INT retains selection/activation ownership.

Within a later approved read-only/offline toolchain run, required commands are:

```text
gcc --version
clang --version
strip --version
gcc -std=c17 -O0 -Wall -Wextra -Werror -fno-ident -ffile-prefix-map=/work=. -Wl,--build-id=none /work/source.c -o /work/program
gcc -std=c17 -O2 -Wall -Wextra -Werror -fno-ident -ffile-prefix-map=/work=. -Wl,--build-id=none /work/source.c -o /work/program
clang -std=c17 -O0 -Wall -Wextra -Werror -fno-ident -ffile-prefix-map=/work=. -Wl,--build-id=none /work/source.c -o /work/program
clang -std=c17 -O2 -Wall -Wextra -Werror -fno-ident -ffile-prefix-map=/work=. -Wl,--build-id=none /work/source.c -o /work/program
strip --strip-all /work/program
```

Pin locale/timezone/epoch and the actual argv/environment from build_plan. A separate
approved sanitizer build adds `-fsanitize=address,undefined -fno-sanitize-recover=all
-fno-omit-frame-pointer -g` using both compilers. It must not become an admitted
stripped artifact. Original trusted software fixtures may exercise the wrapper;
generated/untrusted candidate code still requires an admitted isolated worker and
is never compiled/imported/executed on the host. Preserve raw outputs/exits, twice-
rebuilt complete ELF hashes and source/toolchain identities. All compiler, sanitizer,
linkage, version, reproducibility and runtime parity checks remain unrun until granted.
