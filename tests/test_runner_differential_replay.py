"""Authored software regression fixtures; no candidate host execution/campaign claim."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys

import pytest

from bbr.contracts import ExecutionLimits, Observation
from bbr.corpus.codecs import decode, encode
from bbr.differential import InputPartition, audit_partitions, deterministic_partition
from bbr.differential import compare_observations
from bbr.runner import CandidateValidator, Runner, SandboxPolicy
from bbr.replay import load_record, make_record, replay, verify_record
from bbr.shrink import grammar_moves, shrink
from support.dl2.fixtures import canonical_digest, fixture_sha


def policy(role="oracle"):
    return SandboxPolicy(fixture_sha("symbolic-image-not-real"), fixture_sha("symbolic-toolchain"),
                         worker_kind=role)


def pair(raw=b"", *, left=b"a", right=b"b", **candidate_flags):
    oracle = Observation(status="ok", stdout_bytes=left, exit_code=0)
    candidate = Observation(status="ok", stdout_bytes=right, exit_code=0)
    if candidate_flags:
        candidate = Observation(status="subject_failure", stdout_bytes=right, **candidate_flags)
    return compare_observations(oracle, candidate, stdin_bytes=raw)


def test_missing_backend_and_validator_fail_closed():
    assert Runner(policy()).execute(fixture_sha("symbolic-artifact"), b"", ExecutionLimits()).status == "infrastructure_error"
    verdict, diagnostic = CandidateValidator(policy("candidate"), ExecutionLimits())("inert source text, never compiled")
    assert verdict is None and "unavailable" in diagnostic


@pytest.mark.parametrize("flags,expected", [
    ({"timed_out": True, "exit_code": None}, "timeout"),
    ({"output_limited": True, "exit_code": None}, "output_cap"),
    ({"signal": 9, "exit_code": None}, "signal"),
    ({"exit_code": 1}, "wrong_exit"),
    ({"exit_code": 0}, "wrong_exit"),
])
def test_faults_never_become_equal(flags, expected):
    assert pair(left=b"same", right=b"same", **flags).status == expected


def test_exact_bytes_exit2_and_unknown_are_distinct():
    assert pair(left=b"x\n", right=b"x").status == "wrong_output"
    assert pair(left=b"x", right=b"x").status == "equal"
    malformed = Observation(status="subject_failure", stdout_bytes=b"", exit_code=2)
    assert compare_observations(malformed, malformed, stdin_bytes=b"bad").status == "equal"
    unknown = Observation(status="infrastructure_error", reason="software fake failure")
    assert compare_observations(malformed, unknown, stdin_bytes=b"bad").status == "infrastructure_error"


def test_runner_preserves_timeout_but_refuses_other_limit_overrun():
    class Fake:
        def __init__(self, observation):
            self.observation = observation
        def execute(self, request):
            return self.observation
    timeout = Observation(status="subject_failure", timed_out=True, elapsed=3.0)
    run = Runner(policy(), backend=Fake(timeout))
    assert run.execute(fixture_sha("symbolic-artifact"), b"", ExecutionLimits()).timed_out
    run.backend = Fake(Observation(status="ok", exit_code=0, elapsed=3.0))
    assert run.execute(fixture_sha("symbolic-artifact"), b"", ExecutionLimits()).status == "infrastructure_error"


def test_validator_does_not_parse_candidate_and_rejects_malformed_adapter():
    class Fake:
        def validate(self, request):
            assert request.code_bytes == b"invalid python, deliberately inert"
            return (1, "not a bool")
    validator = CandidateValidator(policy("candidate"), ExecutionLimits(), backend=Fake())
    assert validator("invalid python, deliberately inert")[0] is None


def test_finite_partition_exact_coverage_and_repeatability():
    values = tuple((v,) for v in range(256))  # authored software integer-domain fixture
    parts = deterministic_partition(values, seed=b"software-unit-seed", private=184)
    assert tuple(map(len, parts)) == (8, 64, 184)
    assert parts == deterministic_partition(values, seed=b"software-unit-seed", private=184)
    encoded = tuple(InputPartition(name, tuple(encode(v, "dec", 8) for v in group))
                    for name, group in zip(("visible", "public", "private"), parts))
    result = audit_partitions(encoded, decode=lambda raw: decode(raw, "dec", 8),
                              finite_domain=frozenset(values), minimum_valid=(8, 64, 184))
    assert len(result) == 64
    with pytest.raises(ValueError, match="insufficient"):
        deterministic_partition(values, seed=b"software-unit-seed")


def test_raw_and_canonical_overlap_and_malformed_validity_refused():
    with pytest.raises(ValueError, match="duplicate"):
        audit_partitions((InputPartition("a", (b"1",)), InputPartition("b", (b"1",))), decode=lambda raw: (int(raw),))
    with pytest.raises(ValueError, match="canonical"):
        audit_partitions((InputPartition("a", (b"1",)), InputPartition("b", (b"01",))), decode=lambda raw: (int(raw),))
    with pytest.raises(ValueError, match="contains valid"):
        audit_partitions((InputPartition("a", (), (b"1",)),), decode=lambda raw: (int(raw),))


def test_grammar_moves_preserve_codec_and_strict_order():
    raw = encode((7, 5), "bin", 8)
    moves = grammar_moves(raw, decode=lambda b: decode(b, "bin", 8),
        encode=lambda v: encode(v, "bin", 8), width=8, in_domain=lambda v: len(v) <= 2)
    assert moves and len(moves) == len(set(moves))
    assert all((len(m), m) < (len(raw), raw) and len(decode(m, "bin", 8)) <= 2 for m in moves)


def test_shrink_budget_unknown_and_complete_final_pass(monkeypatch):
    moves = lambda raw: (bytes([raw[0] - 1]),) if raw[0] else ()
    result = shrink(b"\x02", moves, evaluate=lambda raw: pair(raw), final_locked=True)
    assert result.reduced == b"\x00" and result.status == "one_minimal_under_moves"
    limited = shrink(b"\x02", moves, evaluate=lambda raw: pair(raw), final_locked=True, max_pairs=1)
    assert limited.status == "reduced_budget_limited" and limited.paired_executions == 1
    import bbr.shrink.reduce as module
    times = iter((0.0, 31.0, 31.0))
    monkeypatch.setattr(module, "monotonic", lambda: next(times))
    deadline = shrink(b"\x02", moves, evaluate=lambda raw: pair(raw), final_locked=True)
    assert deadline.status == "reduced_budget_limited" and deadline.paired_executions == 1


def test_shrink_unknown_prevents_minimality():
    calls = []
    def evaluate(raw):
        calls.append(raw)
        if len(calls) == 1:
            return pair(raw)
        unknown = Observation(status="infrastructure_error", reason="software fake unavailable")
        return compare_observations(unknown, unknown, stdin_bytes=raw)
    result = shrink(b"\x02", lambda raw: (b"\x01",), evaluate=evaluate, final_locked=True)
    assert result.status == "shrink_exhausted" and result.reduced == b"\x02"
    with pytest.raises(ValueError, match="feedback"):
        shrink(b"x", lambda raw: (), evaluate=lambda raw: pair(raw), final_locked=False)


def retained_record(tmp_path):
    oracle_bytes, candidate_bytes = b"software symbolic oracle bytes", b"software inert candidate bytes"
    artifact, candidate_hash = sha256(oracle_bytes).hexdigest(), sha256(candidate_bytes).hexdigest()
    (tmp_path / "oracle.bin").write_bytes(oracle_bytes)
    (tmp_path / "candidate.txt").write_bytes(candidate_bytes)
    result = shrink(b"\x01", lambda raw: (), evaluate=lambda raw: pair(raw), final_locked=True)
    oracle, candidate = Runner(policy()), Runner(policy("candidate"))
    record = make_record(result, artifact_sha256=artifact, candidate_sha256=candidate_hash,
                         oracle=oracle, candidate=candidate, limits=ExecutionLimits())
    return record, oracle, candidate


def test_replay_retained_checks_and_unavailable_execution(tmp_path):
    record, oracle, candidate = retained_record(tmp_path)
    expected = record["record_sha256"]
    assert verify_record(record, expected_record_sha256=expected).attempts == 1
    assert replay(record, expected_record_sha256=expected, root=tmp_path,
                  artifact_path="oracle.bin", candidate_path="candidate.txt",
                  oracle=oracle, candidate=candidate).status == "infrastructure_error"
    (tmp_path / "record.json").write_text(json.dumps(record), encoding="utf-8")
    assert load_record(tmp_path, "record.json", expected_record_sha256=expected) == record


def test_replay_tamper_and_nested_pin_drift(tmp_path):
    record, _, _ = retained_record(tmp_path)
    changed = deepcopy(record)
    changed["image_sha256"] = fixture_sha("changed symbolic image")
    with pytest.raises(ValueError, match="digest"):
        verify_record(changed, expected_record_sha256=record["record_sha256"])
    changed["record_sha256"] = canonical_digest({k: v for k, v in changed.items() if k != "record_sha256"})
    with pytest.raises(ValueError, match="nested"):
        verify_record(changed, expected_record_sha256=changed["record_sha256"])


@pytest.mark.parametrize("relative", ["../record.json", ".. /record.json", "a./record.json", "x:stream", "a\\record.json", "/record.json"])
def test_replay_path_aliases_refused(tmp_path, relative):
    with pytest.raises((ValueError, OSError)):
        load_record(tmp_path, relative, expected_record_sha256=fixture_sha("record"))


def test_replay_symlink_refused(tmp_path):
    record, _, _ = retained_record(tmp_path)
    target = tmp_path / "record.json"
    target.write_text(json.dumps(record), encoding="utf-8")
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"symlink creation unavailable on this host: {error}")
    with pytest.raises(ValueError, match="symlink|reparse"):
        load_record(tmp_path, "linked.json", expected_record_sha256=record["record_sha256"])


def test_replay_duplicate_json_key_refused(tmp_path):
    record, _, _ = retained_record(tmp_path)
    target = tmp_path / "record.json"
    target.write_text('{"duplicate": 1, "duplicate": 2}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON"):
        load_record(tmp_path, "record.json", expected_record_sha256=record["record_sha256"])


def software_docker_config(tmp_path, role="oracle", **changes):
    from bbr.runner.docker_backend import DockerBackendConfig
    def no_runtime_guard(context):
        raise AssertionError("pure software argv tests must never invoke runtime admission")
    values = dict(image_sha256=fixture_sha("symbolic-image-not-real"),
        toolchain_sha256=fixture_sha("symbolic-toolchain"), worker_kind=role,
        project="m15-software-fixture", instance="source-only",
        container_name="m15-software-fixture-source-only-" + role,
        owner_callsign="authored-software-fixture-not-runtime-owner", owner_id="",
        grant_id="software-regression-not-an-activation-grant",
        docker_executable=tmp_path / "never-executed-docker.exe",
        python_executable=tmp_path / "never-executed-python.exe",
        admission_guard=no_runtime_guard)
    return DockerBackendConfig(**(values | changes))


@pytest.mark.parametrize("role", ["oracle", "candidate"])
def test_docker_argv_is_offline_bounded_and_role_separate_without_start(tmp_path, role):
    from bbr.runner.docker_backend import ARTIFACT, RUN_ROOT, build_create_argv
    from bbr.runner.policy import ExecutionRequest
    config = software_docker_config(tmp_path, role)
    request = ExecutionRequest(fixture_sha("symbolic-artifact"), b"", ExecutionLimits(),
                               policy(role), (), ())
    args = build_create_argv(config, request, RUN_ROOT / role / request.artifact_sha256)
    for required in ("--pull=never", "--network=none", "--read-only", "--user=65534:65534",
                     "--cap-drop=ALL", "--pids-limit=1", "--log-driver=none"):
        assert required in args
    assert "--privileged" not in args and "-p" not in args and "--publish" not in args
    assert "readonly" in args[args.index("--mount") + 1]
    assert ARTIFACT in args
    assert ("-I" in args) is (role == "candidate")


@pytest.mark.parametrize("role", ["oracle", "candidate"])
def test_docker_argv_has_one_frozen_tmpfs_and_readonly_artifact_without_overrides(tmp_path, role):
    # Regression: /tmp must remain the exact bounded writable mount while
    # Docker-looking subject arguments cannot override create-time controls.
    from bbr.runner.docker_backend import ARTIFACT, RUN_ROOT, build_create_argv
    from bbr.runner.policy import ExecutionRequest
    config = software_docker_config(tmp_path, role)
    subject_args = ("--tmpfs", "/tmp:rw,exec,size=33554432", "--mount",
                    "type=tmpfs,target=/tmp", "--read-only=false")
    request = ExecutionRequest(fixture_sha("symbolic-artifact"), b"", ExecutionLimits(),
                               policy(role), subject_args, ())
    artifact_path = RUN_ROOT / role / request.artifact_sha256
    args = build_create_argv(config, request, artifact_path)
    create_args = args[:args.index(f"sha256:{config.image_sha256}")]
    tmpfs_mounts = [create_args[index + 1] for index, arg in enumerate(create_args)
                    if arg == "--tmpfs"]
    bind_mounts = [create_args[index + 1] for index, arg in enumerate(create_args)
                   if arg == "--mount"]
    assert tmpfs_mounts == ["/tmp:rw,noexec,nosuid,size=16777216"]
    assert bind_mounts == [f"type=bind,source={artifact_path},target={ARTIFACT},readonly"]
    assert create_args.count("--read-only") == 1
    assert "--read-only=false" not in create_args
    assert not any(arg == "-v" or arg.startswith(("--volume", "--tmpfs=", "--mount="))
                   for arg in create_args)
    assert args[-len(subject_args) - 1:] == (ARTIFACT, *subject_args)


def test_docker_config_placeholders_and_role_path_drift_refused(tmp_path):
    from bbr.runner.docker_backend import RUN_ROOT, build_create_argv
    from bbr.runner.policy import ExecutionRequest
    with pytest.raises(ValueError):
        software_docker_config(tmp_path, image_sha256="<PLACEHOLDER_IMAGE>")
    config = software_docker_config(tmp_path)
    request = ExecutionRequest(fixture_sha("symbolic-artifact"), b"", ExecutionLimits(), policy(), (), ())
    with pytest.raises(ValueError, match="role-local"):
        build_create_argv(config, request, RUN_ROOT / "candidate" / request.artifact_sha256)


def software_terminated_docker_state():
    # Authored software state only; no daemon/container/runtime evidence.
    return {"StartedAt": "2026-10-27T12:00:00Z", "Running": False,
            "Status": "exited", "Error": "", "ExitCode": 137, "OOMKilled": False}


@pytest.mark.parametrize("limit_flag", ["timed_out", "limited"])
@pytest.mark.parametrize("field,value,missing", [
    ("ExitCode", None, True),
    ("ExitCode", None, False),
    ("ExitCode", "137", False),
    ("ExitCode", True, False),
    ("ExitCode", -1, False),
    ("ExitCode", 256, False),
    ("OOMKilled", None, True),
    ("OOMKilled", None, False),
    ("OOMKilled", "false", False),
    ("OOMKilled", 0, False),
])
def test_authored_software_docker_limits_require_complete_termination_metadata(
        limit_flag, field, value, missing):
    # Regression: a limit must not bypass mandatory inspected metadata checks.
    # execute maps this classifier's rejection to infrastructure_error.
    from bbr.runner.docker_backend import _Capture, _termination_observation
    state = software_terminated_docker_state()
    if missing:
        del state[field]
    else:
        state[field] = value
    captured = _Capture(1, b"software stdout", b"software stderr",
                        limit_flag == "timed_out", limit_flag == "limited", 0.1)
    with pytest.raises(RuntimeError, match="state unknown"):
        _termination_observation(state, captured, timed_out=captured.timed_out)


@pytest.mark.parametrize("limit_flag,reason", [
    ("timed_out", "wall_timeout"), ("limited", "output_limit"),
])
def test_authored_software_docker_owned_limit_kill_allows_attach_exit_difference(limit_flag, reason):
    from bbr.runner.docker_backend import _Capture, _termination_observation
    captured = _Capture(1, b"software stdout", b"software stderr",
                        limit_flag == "timed_out", limit_flag == "limited", 0.1)
    observation = _termination_observation(software_terminated_docker_state(), captured,
                                          timed_out=captured.timed_out)
    assert observation.status == "subject_failure" and observation.reason == reason
    assert observation.timed_out is captured.timed_out
    assert observation.output_limited is captured.limited
    assert observation.stdout_bytes == captured.stdout and observation.stderr_bytes == captured.stderr


def test_authored_software_docker_unlimited_exit_requires_attach_agreement():
    from bbr.runner.docker_backend import _Capture, _termination_observation
    state = software_terminated_docker_state()
    with pytest.raises(RuntimeError, match="transport exit differs"):
        _termination_observation(state, _Capture(1, b"", b"", False, False, 0.1), timed_out=False)
    observation = _termination_observation(state, _Capture(137, b"", b"", False, False, 0.1),
                                          timed_out=False)
    assert observation.status == "subject_failure" and observation.exit_code == 137
    assert observation.signal is None


@pytest.mark.parametrize("mode", ["echo", "burst", "sleep"])
def test_bounded_transport_with_known_software_child_only(mode):
    # This fixed checked-in harness fixture is NOT a generated recovery candidate.
    # No shell, eval, candidate text, image or container is involved.
    from bbr.runner.docker_backend import _capture
    fixture = Path(__file__).parent / "support" / "dl2" / "trusted_transport_fixture.py"
    result = _capture((sys.executable, "-I", "-S", str(fixture), mode), stdin=b"\x00a\xff",
                       seconds=0.1 if mode == "sleep" else 2.0,
                       stdout_cap=32, stderr_cap=1024)
    if mode == "echo":
        assert result.returncode == 0 and result.stdout == b"\x00a\xff"
        assert not result.timed_out and not result.limited
    elif mode == "burst":
        assert result.limited and len(result.stdout) <= 32
    else:
        assert result.timed_out
