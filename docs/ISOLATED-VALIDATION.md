# Isolated candidate diagnostics

`DockerCandidateValidationBackend` implements the existing
`CandidateValidationBackend.validate(request) -> (bool | None, str)` port. Configure
it with `transport=<admitted candidate DockerBackend>` and
`registrar=<trusted callback>`, then pass it to
`CandidateValidator(policy=candidate_policy, limits=execution_limits, backend=backend)`.
The required `candidate_policy` is the admitted `SandboxPolicy` with
`worker_kind="candidate"`; `execution_limits` is the corresponding `ExecutionLimits`.
Imports and construction perform no Docker or subprocess operations.

The host only checks byte size, strict UTF-8, hashes and bounded closed JSON. It
does not parse, compile, import or execute candidate source. The wrapper embeds
base64 candidate bytes as inert data. Only inside the candidate container does
the wrapper parse and compile syntax, inspect imports and discard the code object.
Candidate bodies never execute during validation, including infinite loops and
body side effects. Resource exhaustion in diagnostics remains unknown.

## Public import policy v1

`IMPORT_POLICY_ID` and `IMPORT_POLICY_SHA256` in `docker_validation.py` identify
the frozen public policy. Allowed absolute module names are `array`, `bisect`,
`collections`, `decimal`, `fractions`, `functools`, `heapq`, `itertools`, `json`,
`math`, `operator`, `re`, `statistics`, `string`, and `sys`. No imports are
performed to check availability; admitted image/toolchain identity remains a
separate responsibility. Both import statements and from-imports are checked,
including nested or unreachable statements.

Relative imports, dotted module names, star imports, private from-import names
and private aliases are rejected. References to `__builtins__`, `__import__`, `breakpoint`,
`compile`, `delattr`, `eval`, `exec`, `getattr`, `globals`, `locals`, `open`,
`setattr`, and `vars` are rejected, as are dunder attributes and direct attribute
references named `import_module`, `load_module` or `exec_module`. This also
rejects direct builtins-dictionary forms such as
`__builtins__["__import__"]("os")`, including assigning that namespace to an alias.
This bounded policy can reject otherwise valid Python. It does not prove arbitrary
dynamic Python safe: general aliasing, data-dependent behavior and the capabilities of
allowed modules are outside this diagnostic claim. AST checks are not a security
proof. Real OS isolation and execution admission remain mandatory.

## Exact artifact admission and wire binding

`build_validation_artifact(request)` is a pure packager returning
`ValidationArtifactRegistration(wrapper_bytes, wrapper_sha256, candidate_sha256,
binding_sha256, policy, limits)`. The binding hashes the candidate digest, import
policy digest, complete sandbox policy (including image/toolchain), and complete
execution limits. The wrapper digest covers the exact trusted program and data.

The registrar must verify and register those exact bytes under the digest-addressed
candidate artifact store using the existing deployment's immutable/read-only
controls and exact whitelist grant. It returns
`ValidationArtifactReceipt(registration, artifact_sha256, read_only=True)` only
after those controls hold. Before callbacks, the backend captures independent
immutable byte snapshots of wrapper bytes and all registration identity, policy
and limit fields. After each registrar and transport callback, it checks both the
artifact and receipt registration against those snapshots, plus the original
receipt digest and read-only requirement. The transport receives detached policy
and limit copies; its complete execution request is also checked against a
pre-callback snapshot. Shallow-frozen dataclasses and models alone do not prevent
nested dictionary mutation. A callback returning a fabricated receipt is not real
admission;
the registrar and injected transport are explicit trusted boundaries. The module
never writes a file, broadens a mount grant or supplies a permissive registrar.

The transport receives an `ExecutionRequest` for the wrapper digest, empty stdin,
empty argv/environment and identical candidate policy/limits. Existing limits
remain at most two seconds wall, one second CPU, 4 KiB per output pipe, 256 MiB
memory and one process. No grant, image or resource allowance is changed here.

The wrapper returns one closed JSON object with schema 1, candidate digest,
binding digest, actual wrapper-file digest, boolean validity, reason, and response
SHA256 over the canonical object excluding that final hash. Reasons are exactly
`valid`, `syntax_invalid`, `denied_import`, `denied_dynamic`; true requires `valid`.
Host decoding rejects duplicate/extra/missing fields, altered identities, bad hash,
invalid types, malformed UTF-8/JSON and incoherent validity. Hashes detect binding
errors, not malicious behavior by a trusted transport. Clean exit zero, no signal,
timeout, output cap, stderr, reason or wall overrun is required. All faults and
unavailable registrar/transport return `None` with an infrastructure diagnostic.
Only checked container syntax/policy results return false; no fault fabricates true.

## Verification boundary

`tests/support/dl2/test_docker_validation.py` uses fake registrar/transport ports
and controlled authored candidate byte strings. It checks packaging, admission,
wire binding, callback mutation refusal and unknown propagation; it never parses
or executes candidates. Builtins-dictionary regression specimens check inert
packaging and embedded denied-name configuration only; they do not establish an
actual wrapper AST verdict.
These software units do not establish real isolated behavior, independent corpus
custody or campaign acceptance. Actual diagnostic checks require a new exact
whitelisted wrapper-artifact grant, fresh guard checks and the real admitted
Docker transport. They must separately demonstrate valid stdio, syntax failure,
denied import, and a nonexecuted loop/side-effect candidate body. No such live
validation is claimed by this source construction.
