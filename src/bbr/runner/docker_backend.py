"""Offline Docker execution source. Deployment admission remains a trusted seam.

Importing this module never invokes Docker. No candidate parsing, compilation or
import happens on the host. See docs/DOCKER-BACKEND.md before activation.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import threading
import time
from typing import Callable, Literal

from bbr.contracts import ExecutionLimits, Observation
from .policy import ExecutionRequest, SandboxPolicy, require_digest

RUN_ROOT = Path(r"C:\agent-runs\m15")
PORTS_SCRIPT = Path(r"C:\Users\Roy Harden\OneDrive\PJ-OD\skills\skills-bts\agent-ports\scripts\ports.py")
LEDGER_ROOT = Path(r"C:\agent-ports\instances")
ARTIFACT = "/artifact/subject"
CLIENT_CONFIG = RUN_ROOT / "docker-client-empty"


def _pin(value: str) -> str:
    require_digest(value)
    if len(set(value)) < 4:
        raise ValueError("placeholder pin refused")
    return value


@dataclass(frozen=True)
class AdmissionContext:
    phase: Literal["create", "start"]
    config: DockerBackendConfig
    artifact_path: Path
    artifact_sha256: str
    container_id: str | None


@dataclass(frozen=True)
class AdmissionProof:
    """Trusted guard's fresh external assertions, never inferred from config."""

    grant_id: str
    image_sha256: str
    toolchain_sha256: str
    container_name: str
    owner: str
    phase: Literal["create", "start"]
    checked_at_monotonic: float
    live_ownership_checked: bool
    immutable_artifact_checked: bool
    toolchain_attested: bool


@dataclass(frozen=True)
class DockerBackendConfig:
    image_sha256: str
    toolchain_sha256: str
    worker_kind: Literal["oracle", "candidate"]
    project: str
    instance: str
    container_name: str
    owner_callsign: str
    owner_id: str
    grant_id: str
    docker_executable: Path
    python_executable: Path
    admission_guard: Callable[[AdmissionContext], AdmissionProof]
    candidate_python: str = "/usr/local/bin/python3"
    env_executable: str = "/usr/bin/env"

    def __post_init__(self) -> None:
        _pin(self.image_sha256)
        _pin(self.toolchain_sha256)
        if self.worker_kind not in {"oracle", "candidate"}:
            raise ValueError("invalid worker role")
        for value in (self.project, self.instance, self.container_name):
            if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,100}", value) is None:
                raise ValueError("invalid ledger name")
        if (not self.owner_callsign or (self.owner_id
                and re.fullmatch(r"[0-9A-Z]{2}[0-9]{2}", self.owner_id) is None)):
            raise ValueError("explicit owner identity required")
        if (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,159}", self.grant_id) is None
                or any(s in self.grant_id.lower()
                for s in ("placeholder", "pending", "todo", "changeme"))):
            raise ValueError("explicit admitted grant required")
        if not callable(self.admission_guard):
            raise ValueError("trusted deployment admission guard required")
        for executable in (self.docker_executable, self.python_executable):
            if not isinstance(executable, Path) or not executable.is_absolute():
                raise ValueError("trusted absolute host CLI paths required")
        for executable in (self.candidate_python, self.env_executable):
            if re.fullmatch(r"/[A-Za-z0-9_./-]+", executable) is None or ".." in executable:
                raise ValueError("trusted absolute image executable required")


def _labels(config: DockerBackendConfig) -> dict[str, str]:
    return {"agentports.project": config.project, "agentports.instance": config.instance,
            "agentports.owner": config.owner_id or config.owner_callsign,
            "bbr.role": config.worker_kind,
            "bbr.grant": config.grant_id}


def _validate_request(config: DockerBackendConfig, request: ExecutionRequest) -> ExecutionLimits:
    if not isinstance(request.policy, SandboxPolicy):
        raise ValueError("sandbox policy required")
    # Reconstruct to reject a policy modified outside its frozen API.
    policy = SandboxPolicy(**vars(request.policy))
    if (policy.image_sha256 != config.image_sha256
            or policy.toolchain_sha256 != config.toolchain_sha256
            or policy.worker_kind != config.worker_kind):
        raise ValueError("request pins/role differ from admitted worker")
    _pin(request.artifact_sha256)
    limits = ExecutionLimits.model_validate(request.limits)
    if type(request.stdin_bytes) is not bytes or len(request.stdin_bytes) > limits.stdin_bytes:
        raise ValueError("invalid bounded stdin")
    if (type(request.argv) is not tuple or len(request.argv) > 64
            or any(type(arg) is not str or "\x00" in arg or len(arg) > 4096 for arg in request.argv)):
        raise ValueError("invalid subject arguments")
    if (type(request.environment) is not tuple or len(request.environment) > 32
            or any(type(pair) is not tuple or len(pair) != 2 for pair in request.environment)):
        raise ValueError("invalid explicit environment")
    keys: set[str] = set()
    for key, value in request.environment:
        if (type(key) is not str or type(value) is not str
                or re.fullmatch(r"[A-Z_][A-Z0-9_]{0,63}", key) is None
                or key in keys or len(value) > 4096 or "\x00" in value):
            raise ValueError("invalid explicit environment")
        keys.add(key)
    return limits


def build_create_argv(config: DockerBackendConfig, request: ExecutionRequest,
                      artifact_path: Path) -> tuple[str, ...]:
    """Pure argv builder for static/software review; performs no CLI operations."""
    limits = _validate_request(config, request)
    expected = RUN_ROOT / config.worker_kind / request.artifact_sha256
    if artifact_path != expected:
        raise ValueError("artifact binding must be role-local and digest-addressed")
    args = [str(config.docker_executable), "--config", str(CLIENT_CONFIG),
            "--host", "npipe:////./pipe/docker_engine",
            "create", "--pull=never", "--name", config.container_name,
            "--network=none", "--read-only", "--user=65534:65534",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--pids-limit=1", "--memory", str(limits.memory_bytes),
            "--memory-swap", str(limits.memory_bytes), "--cpus=1",
            "--ulimit", f"cpu={limits.cpu_seconds}:{limits.cpu_seconds}",
            "--ulimit", "core=0:0", "--no-healthcheck", "--restart=no",
            "--log-driver=none", "--workdir=/", "--interactive",
            "--mount", f"type=bind,source={artifact_path},target={ARTIFACT},readonly",
            "--entrypoint", config.env_executable]
    for key, value in _labels(config).items():
        args.extend(("--label", f"{key}={value}"))
    args.extend((f"sha256:{config.image_sha256}", "-i", "--"))
    # env -i removes even image-defined variables. Subject argv never selects a
    # host command or a different image executable.
    args.extend(f"{key}={value}" for key, value in request.environment)
    if config.worker_kind == "candidate":
        args.extend((config.candidate_python, "-I", "-S", "-B"))
    args.extend((ARTIFACT, *request.argv))
    return tuple(args)


@dataclass(frozen=True)
class _Capture:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    limited: bool
    elapsed: float


def _termination_observation(state: dict, captured: _Capture, *, timed_out: bool) -> Observation:
    """Classify inspected termination only; performs no host or Docker operations."""
    started_at = state.get("StartedAt")
    if (not isinstance(started_at, str) or started_at.startswith("0001-")
            or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T.+Z", started_at) is None
            or state.get("Running") is not False or state.get("Status") != "exited"
            or state.get("Error")):
        raise RuntimeError("subject never started or stopped state unknown")
    if type(state.get("ExitCode")) is not int or not 0 <= state["ExitCode"] <= 255:
        raise RuntimeError("subject termination state unknown")
    oom = state.get("OOMKilled")
    if type(oom) is not bool:
        raise RuntimeError("OOM state unknown")
    if captured.limited or timed_out:
        # The owned limit kill can change the inspected container exit after
        # attach was killed. Require complete state, not transport exit equality.
        return Observation(stdout_bytes=captured.stdout, stderr_bytes=captured.stderr,
                           timed_out=timed_out, output_limited=captured.limited,
                           elapsed=captured.elapsed, status="subject_failure",
                           reason="output_limit" if captured.limited else "wall_timeout")
    exit_code = state["ExitCode"]
    if captured.returncode != exit_code:
        raise RuntimeError("attach transport exit differs from inspected subject exit")
    # Docker reports numeric exits; do not invent a POSIX signal
    # from 128+N, which is also a valid intentional subject exit.
    return Observation(stdout_bytes=captured.stdout, stderr_bytes=captured.stderr,
                       exit_code=exit_code, elapsed=captured.elapsed,
                       status="ok" if exit_code == 0 and not oom else "subject_failure",
                       reason="oom_killed" if oom else None)


def _capture(argv: tuple[str, ...], *, stdin: bytes = b"", seconds: float = 5.0,
             stdout_cap: int = 65536, stderr_cap: int = 65536,
             host_env: dict[str, str] | None = None) -> _Capture:
    """Bound both pipes while running; kill only this owned CLI child on limits."""
    started = time.monotonic()
    # Docker daemon endpoint is explicit; no DOCKER_*, Python or candidate env
    # variables are inherited. Host CLI system discovery still needs SYSTEMROOT.
    env = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
    if host_env is not None:
        env.update(host_env)
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, shell=False)
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    failed = threading.Event()

    def drain(stream: object, slot: int, cap: int) -> None:
        try:
            while True:
                chunk = stream.read(1024)  # type: ignore[attr-defined]
                if not chunk:
                    break
                remaining = cap - len(buffers[slot])
                buffers[slot].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()
                    break
        except (OSError, ValueError):
            failed.set()

    threads = [threading.Thread(target=drain, args=(stream, i, cap), daemon=True)
               for i, (stream, cap) in enumerate(((process.stdout, stdout_cap),
                                                  (process.stderr, stderr_cap)))]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        assert process.stdin is not None
        try:
            process.stdin.write(stdin)
            process.stdin.close()
        except BrokenPipeError:
            pass
        while process.poll() is None:
            if overflow.is_set() or failed.is_set():
                process.kill()
                break
            if time.monotonic() - started >= seconds:
                timed_out = True
                process.kill()
                break
            time.sleep(min(0.005, seconds))
        process.wait(timeout=2)
        for thread in threads:
            thread.join(timeout=2)
        if any(thread.is_alive() for thread in threads) or failed.is_set():
            raise RuntimeError("CLI pipe capture incomplete")
        return _Capture(process.returncode, bytes(buffers[0]), bytes(buffers[1]),
                        timed_out, overflow.is_set(), time.monotonic() - started)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def _host_ready() -> None:
    if os.name != "nt" or platform.node().upper() != "KAISER-PRO":
        raise RuntimeError("admitted Windows host is KAISER-PRO only")

    class MemoryStatus(ctypes.Structure):
        _fields_ = [("length", ctypes.c_uint32), ("load", ctypes.c_uint32),
                    *[(name, ctypes.c_uint64) for name in
                      ("total", "available", "page_total", "page_available",
                       "virtual_total", "virtual_available", "extended")]]

    memory = MemoryStatus()
    memory.length = ctypes.sizeof(memory)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
        raise RuntimeError("free RAM unknown")
    if memory.available <= 3 * 1024 ** 3:
        raise RuntimeError("strictly more than 3 GiB free RAM required")


def _artifact_path(config: DockerBackendConfig, digest: str) -> Path:
    path = RUN_ROOT / config.worker_kind / digest
    # No directories are created here. An externally admitted, read-only store
    # must prevent replacement between these checks and the daemon bind mount.
    for component in (RUN_ROOT.parent, RUN_ROOT, path.parent, path):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("artifact link/reparse path refused")
    if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("missing or oversized artifact")
    with path.open("rb") as source:
        if sha256(source.read(16 * 1024 * 1024 + 1)).hexdigest() != digest:
            raise ValueError("artifact digest mismatch")
    return path


class DockerBackend:
    """Concrete IsolatedBackend. Does NOT implement candidate validation."""

    def __init__(self, config: DockerBackendConfig) -> None:
        self.config = config
        # A role's ledger name is exclusive for the entire execution/cleanup.
        self._lock = threading.Lock()

    def _docker(self, *args: str) -> _Capture:
        result = _capture((str(self.config.docker_executable), "--config", str(CLIENT_CONFIG), "--host",
                           "npipe:////./pipe/docker_engine", *args))
        if result.returncode != 0 or result.timed_out or result.limited:
            raise RuntimeError("Docker control operation failed or unknown")
        return result

    def _inspect(self, container_id: str) -> dict:
        if re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
            raise RuntimeError("invalid owned container ID")
        data = json.loads(self._docker("container", "inspect", container_id).stdout)
        if not isinstance(data, list) or len(data) != 1:
            raise RuntimeError("container state unknown")
        item = data[0]
        if (item.get("Id") != container_id or item.get("Name") != "/" + self.config.container_name
                or any(item.get("Config", {}).get("Labels", {}).get(k) != v
                       for k, v in _labels(self.config).items())):
            raise RuntimeError("container ownership/role mismatch")
        return item

    def _admit(self, request: ExecutionRequest, path: Path,
               phase: Literal["create", "start"], container_id: str | None) -> None:
        config = self.config
        _host_ready()
        config_info = CLIENT_CONFIG.lstat()
        if (not stat.S_ISDIR(config_info.st_mode) or stat.S_ISLNK(config_info.st_mode)
                or getattr(config_info, "st_file_attributes", 0) & 0x400
                or any(CLIENT_CONFIG.iterdir())):
            raise RuntimeError("owned empty Docker client config required")
        record_path = LEDGER_ROOT / f"{config.project}--{config.instance}.json"
        if record_path.stat().st_size > 65536:
            raise RuntimeError("ledger record oversized")
        record = json.loads(record_path.read_text(encoding="utf-8"))
        owner = record.get("owner") or {}
        if (record.get("project") != config.project or record.get("instance") != config.instance
                or owner.get("callsign") != config.owner_callsign
                or (owner.get("id") or owner.get("callsign")) != (config.owner_id or config.owner_callsign)
                or config.container_name not in (record.get("names") or {}).get("containers", [])
                or record.get("status") not in {"reserved", "stopped", "up"}):
            raise RuntimeError("ledger ownership/name/status not admitted")
        # agent-ports check can return 0 for an empty ports record without live
        # Docker checks. The mandatory guard must verify real names/ownership.
        context = AdmissionContext(phase, config, path, request.artifact_sha256, container_id)
        self._verify_proof(config.admission_guard(context), phase)
        check = _capture((str(config.python_executable), str(PORTS_SCRIPT), "check",
                          f"{config.project}/{config.instance}"), host_env={
                              "PATH": str(config.docker_executable.parent) + ";"
                              + str(Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"),
                              "DOCKER_HOST": "npipe:////./pipe/docker_engine",
                              "DOCKER_CONFIG": str(CLIENT_CONFIG)})
        if check.returncode != 0 or check.timed_out or check.limited:
            raise RuntimeError("agent-ports check blocked or unknown")
        # The diagnostic may be slow. Refresh the proof rather than treating
        # the pre-diagnostic admission as current ownership/resource evidence.
        self._verify_proof(config.admission_guard(context), phase)
        _host_ready()  # recheck RAM immediately before each create/start

    def _verify_proof(self, proof: AdmissionProof,
                      phase: Literal["create", "start"]) -> None:
        config = self.config
        if (not isinstance(proof, AdmissionProof) or proof.grant_id != config.grant_id
                or proof.image_sha256 != config.image_sha256
                or proof.toolchain_sha256 != config.toolchain_sha256
                or proof.container_name != config.container_name
                or proof.owner != (config.owner_id or config.owner_callsign)
                or proof.phase != phase or not math.isfinite(proof.checked_at_monotonic)
                or not 0 <= time.monotonic() - proof.checked_at_monotonic <= 1.0
                or proof.live_ownership_checked is not True
                or proof.immutable_artifact_checked is not True
                or proof.toolchain_attested is not True):
            raise RuntimeError("external deployment admission missing/stale/unknown")

    def execute(self, request: ExecutionRequest) -> Observation:
        if not self._lock.acquire(blocking=False):
            return self._unknown("docker_worker_busy")
        container_id: str | None = None
        result: Observation | None = None
        try:
            limits = _validate_request(self.config, request)
            path = _artifact_path(self.config, request.artifact_sha256)
            create_argv = build_create_argv(self.config, request, path)
            self._admit(request, path, "create", None)
            image = json.loads(self._docker("image", "inspect",
                               f"sha256:{self.config.image_sha256}").stdout)
            if (not isinstance(image, list) or len(image) != 1
                    or image[0].get("Id") != f"sha256:{self.config.image_sha256}"
                    or image[0].get("Os") != "linux"
                    or image[0].get("Config", {}).get("Volumes")
                    or (image[0].get("Config", {}).get("Labels") or {}).get("bbr.toolchain.sha256")
                    not in (None, self.config.toolchain_sha256)):
                raise RuntimeError("already-local image pins/metadata not admitted")
            self._admit(request, path, "create", None)
            created = _capture(create_argv)
            # Never guess an ID from a failed/ambiguous create or clean by name.
            if created.returncode != 0 or created.timed_out or created.limited:
                raise RuntimeError("container creation unknown; operator reconciliation required")
            container_id = created.stdout.decode("ascii").strip()
            item = self._inspect(container_id)
            if item.get("Image") != f"sha256:{self.config.image_sha256}":
                raise RuntimeError("container image differs from pin")
            self._admit(request, path, "start", container_id)
            captured = _capture((str(self.config.docker_executable), "--config", str(CLIENT_CONFIG), "--host",
                                "npipe:////./pipe/docker_engine", "start", "--attach",
                                "--interactive", container_id), stdin=request.stdin_bytes,
                                seconds=limits.wall_seconds, stdout_cap=limits.stdout_bytes,
                                stderr_cap=limits.stderr_bytes)
            timed_out = captured.timed_out or captured.elapsed > limits.wall_seconds
            if captured.limited or timed_out:
                # This exact immutable ID was already inspected as ours before
                # start. Stop it before any potentially slow diagnostic inspect;
                # never turn an attach disconnect into continuing subject work.
                try:
                    self._docker("container", "kill", container_id)
                except Exception:
                    # It may have exited concurrently. Only subsequent inspected
                    # stopped state can resolve that ambiguity.
                    pass
            state = self._inspect(container_id).get("State", {})
            result = _termination_observation(state, captured, timed_out=timed_out)
        except Exception:
            result = self._unknown("docker_backend_fault_or_admission_unavailable")
        finally:
            try:
                if container_id is not None:
                    self._inspect(container_id)  # fail closed before owned-ID removal
                    self._docker("container", "rm", "--force", container_id)
            except Exception:
                result = self._unknown("owned_container_cleanup_unconfirmed")
            self._lock.release()
        return result if result is not None else self._unknown("docker_result_unavailable")

    @staticmethod
    def _unknown(reason: str) -> Observation:
        return Observation(status="infrastructure_error", reason=reason)
