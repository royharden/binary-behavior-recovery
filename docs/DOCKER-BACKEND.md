# Offline Docker execution backend

`bbr.runner.docker_backend.DockerBackend(config)` implements
`IsolatedBackend.execute(ExecutionRequest)`. Importing it and calling
`build_create_argv(config, request, artifact_path)` do not invoke Docker. The
builder performs request/configuration checks and returns the exact create argv
for software review. No package export, CLI activation, image, Dockerfile,
deployment scaffold, or validation backend is installed by this module.

This is source construction, runtime unverified. Current RAM and image/ownership
admission blocks remain. No Docker command, container, image pull, candidate
execution, install or runtime acceptance was performed to construct this source.

## Required deployment configuration

Construct `DockerBackendConfig` with explicit immutable raw lowercase SHA256
`image_sha256` and `toolchain_sha256`, `worker_kind` (`oracle` or `candidate`),
agent-ports `project`, `instance`, reserved `container_name`, `owner_callsign`,
`owner_id`, actual `grant_id`, absolute trusted host `docker_executable` and
`python_executable` Paths, and a trusted `admission_guard`. Set `owner_id` to the
actual ledger ID, or the empty string when the ledger has only a callsign. The
owner label uses the ID when present and otherwise the callsign. Placeholder
grants and low-diversity dummy digest pins are refused. No actual pins or grant
are supplied here.

The image must already exist locally as `sha256:<image_sha256>`, be a Linux image,
have no declared image volumes, and, if `bbr.toolchain.sha256` is present, it must
equal the toolchain pin. This optional label is only a consistency check; no image
rebuild is required to add it. Mandatory trusted deployment
attestation must bind the actual executable/toolchain bytes, image configuration,
`env_executable` (default `/usr/bin/env`) and `candidate_python` (default
`/usr/local/bin/python3`) to the approved image. A self-asserted image label does
not prove that binding. Deployment attestation may be the INT's recorded grant
for bounded software testing of an exact already-present image; it does not
appoint an independent benchmark author/custodian or admit benchmark evidence.
There are no image pulls; create uses `--pull=never` and
all Docker calls select the local Windows named-pipe daemon explicitly.
Every Docker invocation also specifies `--config
C:\agent-runs\m15\docker-client-empty`; the ports diagnostic receives the same
directory through `DOCKER_CONFIG`. Deployment must provision that owned empty,
non-reparse directory and guard its immutability. No user Docker config,
credential helper or context is read implicitly. No config directory is created
by this source.

Use separate role-specific artifact stores and separate registered container
names for oracle and candidate. The only bind mount is the single file
`C:\agent-runs\m15\<role>\<artifact-sha256>` mounted read-only at
`/artifact/subject`. Files must be at most 16 MiB. Hashes and path components are
checked without importing or parsing candidates. Symlinks and Windows reparse
points are refused. The backend creates no host directories or artifact files.
Deployment must make the store immutable to untrusted/concurrent writers across
hash verification and Docker's bind resolution; read-only mounting alone does
not solve host replacement races. The guard must verify this property.

## Mandatory external admission guard

`admission_guard(AdmissionContext)` is a trusted deployment component, not a
candidate-controlled callback. No permissive implementation is included. It runs
before **each** create and start, receives phase, config, artifact path/hash and
the exact container ID for start, and must fail closed on missing authority,
unknown state, withdrawn grants, resource pressure or conflicting ownership.
It must verify all of the following against current authority and live state:

- The exact grant authorizes these image/toolchain/executable pins, role, artifact
  custody, resource bounds, owner and registered name; role names do not overlap.
- The immutable artifact store prevents replacement during the operation.
- The pinned image/toolchain has trusted deployment attestation as described above.
- The actual local daemon agrees with ledger ownership and the exact name. For
  create, the name must be absent, not merely absent from a running-only list;
  for start, inspect the exact created ID and its actual name and labels.
- Concurrent launchers cannot take over the instance/name or replace the
  artifact/configuration between this proof and the immediate operation. A
  deployment-wide exclusive lease is required; the Python instance lock covers
  only calls to that one backend object.

Return an `AdmissionProof` with matching `grant_id`, pins, container name,
owner label and phase; fresh `checked_at_monotonic`; and literal true values for
`live_ownership_checked`, `immutable_artifact_checked`, `toolchain_attested`.
Proof age must be between zero and one second. These fields are assertions from
trusted admission, not evidence generated by the backend. Runtime acceptance
must test the guard and its evidence separately. Raising or malformed/mismatched
proofs produce infrastructure unknown.
The guard is called before any control diagnostic and refreshed after the ports
check, so missing admission cannot trigger a Docker CLI call. Creation admission
also runs before local image inspection and is refreshed immediately before
create. Admission callbacks themselves are trusted code and must honor the same
bounded-control requirements; this adapter cannot interrupt arbitrary callbacks.

The backend additionally checks Windows hostname `KAISER-PRO` and strictly more
than 3 GiB available physical RAM before admission and again immediately before
create/start. Unsupported hosts or unknown RAM fail closed. It reads the exact
machine-local record `C:\agent-ports\instances\<project>--<instance>.json`,
verifies `names.containers`, `owner.callsign`, `owner.id` fallback, and active
status, and invokes the canonical `agent-ports/scripts/ports.py check
PROJECT/instance` using the explicitly configured Python. Nonzero, timeout or
unknown refuses launch. A record with no ports can make that tool exit zero
without live Docker checks, so it never replaces the mandatory live guard.
Checks use bounded output and a five-second control deadline; a slow or busy
machine refuses admission. The ports script can itself spawn bounded diagnostic
children; this adapter never kills unrelated processes to repair a slow check.

## Execution and observation

Each execution creates a fresh container with numeric user `65534:65534`,
network `none`, no published ports, read-only root, all capabilities dropped,
`no-new-privileges`, PID limit one, no healthcheck/restart, no persistent logs,
one CPU and CPU rlimit from `ExecutionLimits`. Memory and total memory-plus-swap
both equal the requested memory limit, never above 256 MiB. No home directory,
Docker socket, credentials, source trees or other artifacts are provided. The
only requested writable filesystem mount is the fixed 16 MiB `/tmp` tmpfs,
created with `rw,noexec,nosuid,size=16777216`; the root remains read-only and the
artifact bind remains read-only. This tmpfs has no configuration or subject-argv
override. Docker image-defined anonymous volumes are rejected.

The image entrypoint is replaced with the attested `env` executable and `-i`.
Only `request.environment` reaches the subject; image and host candidate
environment variables are cleared. `request.argv` contains subject arguments,
with identical semantics for both roles. The trusted role selects the command:

- Oracle: `/artifact/subject <args>`.
- Candidate: attested Python `-I -S -B /artifact/subject <args>`.

There is no host candidate execution, compilation, parsing or import. In
particular, there is no host subprocess fallback. Host subprocesses are trusted
Docker control/attach commands and the canonical ports check, invoked with argv
lists and `shell=False`, with a small host environment. Candidate syntax/import
validation remains unavailable: this backend intentionally has no `validate`
method and cannot produce a successful `CandidateValidationBackend` verdict.
An independent implementation must parse/compile/check an explicit standard
library allowlist entirely inside its separately admitted candidate container.

Attached stdout and stderr are drained concurrently into independently capped
buffers; overflow or the wall deadline kills only the owned attach CLI child,
then promptly kills the previously verified exact owned container ID before
diagnostic inspection. State must confirm a real start and stopped termination;
an attach error with a never-started container remains infrastructure unknown.
Final owned-ID removal follows. The deadline includes attach
startup. Captured elapsed time describes attach/subject execution; host
preflight/create/inspect/cleanup time is separately bounded control overhead,
not included in that observation. CPU time is enforced inside the container by
the rlimit. Clean termination must come from inspected Docker `State` (not
the CLI exit alone), including exit code and OOM state; a transport/subject exit
disagreement becomes infrastructure unknown. Numeric exits are retained as
numeric exits; `128+N` is not guessed to be a signal. Timeout/output caps are
subject failures; unavailable or malformed state is infrastructure unknown.
The inspected exit code must be an integer from 0 through 255 and OOM state must
be a boolean even after a timeout or output cap. An owned limit kill can change
the container exit after attach ends, so transport exit equality is required
only when neither limit fired.

Cleanup inspects the exact created 64-character ID and verifies its actual name,
project/instance/owner/role/grant labels before removing that ID. It never removes
by name, prunes resources, or performs broad process kills. Unconfirmed cleanup
overrides a subject result with infrastructure unknown. A create timeout or
malformed response can leave a container with no confirmed ID; the adapter does
not guess ownership or remove by name. An operator must reconcile that unknown
state before another admission. This is a deliberate fail-closed limitation.

Before runtime activation, independent review and hostile-control verification
must establish the image, grant, guard, ownership lease, filesystem custody,
Docker controls, real stdin/output/exit/OOM behavior and bounded cleanup on the
admitted host. Pure argv/static checks do not establish those properties.
