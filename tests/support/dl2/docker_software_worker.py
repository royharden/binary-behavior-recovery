"""Exact-grant real Docker SOFTWARE checks; never a recovery-candidate adapter.

Running requires the reviewed source, INT's fixed grant and live checks below.
Importing performs no Docker operation or fixture creation. No secret/config/home
files are read. Only literal scripts in SCRIPTS can reach the candidate worker.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import stat
import threading
import time

from bbr.contracts import ExecutionLimits
from bbr.runner.policy import ExecutionRequest, SandboxPolicy
from bbr.runner import docker_backend as db

IMAGE = "6e13e65c55e33adf203d77ee371cf8bf5d81bd4902ef07565721f46bf44917af"
MANIFEST_SHA = "3a0a617da520f844bddf809bd3769ac4836f6b90b54841c84ebef74c801a7532"
ENGINE = "59286557-c44a-4a4d-a428-cf81cadd61c4"
GRANT = "M15-R2-PYTHON-SOFTWARE-20261027"
OWNER = "0928_Codex_gpt-61-sol_N20M15TEAMDL2_M15-TEAM-DL2"
NAME = "m15-r2-candidate-worker"
DOCKER = Path(r"C:\Users\Roy Harden\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe")
APP = Path(r"C:\Users\Roy Harden\OneDrive\PJ-OD\PortfolioBuilder\binary-behavior-recovery")
RECEIPTS = APP / "agentops/runs/M15-DIRTY-20261027/round2/receipts"
RUNTIME_MANIFEST = RECEIPTS / "python-runtime-manifest.json"
LEDGER = Path(r"C:\agent-ports\instances\m15--r2-candidate.json")

# Original fixed SOFTWARE probes only. No supplied text/code/module/command input.
SCRIPTS = {
    "echo": b"import sys\nsys.stdout.buffer.write(sys.stdin.buffer.read(64))\n",
    "exit2": b"raise SystemExit(2)\n",
    "output_cap": b"import sys\nsys.stdout.buffer.write(b'x'*8192)\nsys.stdout.buffer.flush()\n",
    "timeout": b"import time\ntime.sleep(10)\n",
    "basic_bounds": b'''import errno,json,os
r={"uid":os.getuid(),"gid":os.getgid(),"pid":os.getpid()}
try:
    with open("/m15-dl2-root-write", "wb") as f: f.write(b"software")
    r["root_readonly"]=False
except OSError as e:
    r["root_readonly"]=e.errno==errno.EROFS
with open("/tmp/m15-dl2-software", "wb") as f: f.write(b"software")
r["tmp_writable"]=True
try:
    p=os.fork()
    if p==0: os._exit(0)
    os.waitpid(p,0)
    r["fork_refused"]=False
except OSError as e:
    r["fork_refused"]=e.errno==errno.EAGAIN
with open("/proc/mounts") as f:
    r["tmp_mount_options"]=[l.split()[3] for l in f if l.split()[1]=="/tmp"]
print(json.dumps(r,sort_keys=True))
''',
}


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def no_links(path: Path) -> None:
    absolute = path.absolute()
    for part in (*reversed(absolute.parents), absolute):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("link/reparse path refused")


def memory_gib() -> float:
    db._host_ready()  # actual host + strict RAM threshold, not a supplied assertion
    class Memory(ctypes.Structure):
        _fields_ = [("length", ctypes.c_uint32), ("load", ctypes.c_uint32),
                    *[(n, ctypes.c_uint64) for n in ("total", "available", "pt", "pa", "vt", "va", "ex")]]
    value = Memory()
    value.length = ctypes.sizeof(value)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(value)):
        raise RuntimeError("RAM observation unavailable")
    if value.available <= 3 * 1024**3:
        raise RuntimeError("RAM at/below3GiB; operation stopped")
    return value.available / 1024**3


class SoftwareGrant:
    def __init__(self, output: Path, python: Path):
        self.output, self.python = output, python
        self.events = []
        self.capture = db._capture
        self.mutex = None
        self.thread = None
        self.whitelist = {sha256(code).hexdigest(): name for name, code in SCRIPTS.items()}

    def lease(self) -> None:
        if os.name != "nt":
            raise RuntimeError("Windows software grant only")
        api = ctypes.windll.kernel32
        api.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        api.CreateMutexW.restype = ctypes.c_void_p
        api.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        api.ReleaseMutex.argtypes = [ctypes.c_void_p]
        api.CloseHandle.argtypes = [ctypes.c_void_p]
        self.mutex = api.CreateMutexW(None, False, "Local\\M15-R2-DL2-0928-candidate")
        acquired = api.WaitForSingleObject(self.mutex, 0) if self.mutex else -1
        if not self.mutex or acquired != 0:
            if self.mutex:
                if acquired == 0x80:  # abandoned is acquired, but requires operator review
                    api.ReleaseMutex(self.mutex)
                api.CloseHandle(self.mutex)
                self.mutex = None
            raise RuntimeError("exclusive software-worker lease unavailable")
        self.thread = threading.get_ident()

    def release(self) -> None:
        if self.mutex:
            ctypes.windll.kernel32.ReleaseMutex(self.mutex)
            ctypes.windll.kernel32.CloseHandle(self.mutex)
            self.mutex = None

    def ledger(self) -> dict:
        no_links(LEDGER)
        record = json.loads(LEDGER.read_bytes())
        if (record.get("project") != "m15" or record.get("instance") != "r2-candidate" or
                record.get("owner", {}).get("id") != "0928" or
                record.get("owner", {}).get("callsign") != OWNER or
                record.get("names", {}).get("containers") != [NAME] or
                record.get("status") not in {"reserved", "up", "stopped"}):
            raise RuntimeError("actual worker ledger owner/name/status differs")
        return record

    def control(self, *args: str, absent_ok=False):
        self.empty_client_config()
        argv = (str(DOCKER), "--config", str(db.CLIENT_CONFIG), "--host",
                "npipe:////./pipe/docker_engine", *args)
        result = self.capture(argv)
        self.events.append({"kind": "guard_control", "argv": argv, **asdict(result)})
        # Binary fields are encoded only in save/record_capture, below.
        if result.timed_out or result.limited:
            raise RuntimeError("bounded Docker diagnostic unknown")
        if result.returncode != 0:
            text = result.stderr.decode("utf-8", "replace").lower()
            if absent_ok and result.returncode == 1 and ("no such container" in text or "no such object" in text):
                return None
            raise RuntimeError("Docker diagnostic refused/unknown")
        return result.stdout

    def empty_client_config(self) -> None:
        no_links(db.CLIENT_CONFIG)
        if not db.CLIENT_CONFIG.is_dir() or any(db.CLIENT_CONFIG.iterdir()):
            raise RuntimeError("owned Docker client config is not empty; no credential files read")

    def inspect_container(self, identifier: str):
        raw = self.control("container", "inspect", identifier, absent_ok=True)
        if raw is None:
            return None
        data = json.loads(raw)
        if type(data) is not list or len(data) != 1:
            raise RuntimeError("container identity unknown")
        return data[0]

    def check_host_config(self, item: dict, context: db.AdmissionContext) -> None:
        labels = item.get("Config", {}).get("Labels") or {}
        expected = {"agentports.project": "m15", "agentports.instance": "r2-candidate",
                    "agentports.owner": "0928", "bbr.role": "candidate", "bbr.grant": GRANT}
        hc, config = item.get("HostConfig", {}), item.get("Config", {})
        if (item.get("Id") != context.container_id or item.get("Name") != "/" + NAME or
                item.get("Image") != "sha256:" + IMAGE or
                any(labels.get(k) != v for k, v in expected.items()) or
                config.get("User") != "65534:65534" or
                config.get("Entrypoint") != ["/usr/bin/env"] or
                config.get("Cmd") != ["-i", "--", "/usr/local/bin/python3", "-I", "-S", "-B", db.ARTIFACT]):
            raise RuntimeError("actual container identity/command/role mismatch")
        if (hc.get("NetworkMode") != "none" or hc.get("ReadonlyRootfs") is not True or
                hc.get("Privileged") is not False or hc.get("CapDrop") != ["ALL"] or
                hc.get("SecurityOpt") != ["no-new-privileges:true"] or
                hc.get("PidsLimit") != 1 or hc.get("Memory") != 268435456 or
                hc.get("MemorySwap") != 268435456 or hc.get("NanoCpus") != 1000000000 or
                hc.get("PortBindings") not in ({}, None) or hc.get("PublishAllPorts") is not False or
                hc.get("Tmpfs") != {"/tmp": "rw,noexec,nosuid,size=16777216"} or
                hc.get("Binds") not in (None, [])):
            raise RuntimeError("actual HostConfig violates granted software envelope")
        ulimits = {u["Name"]: (u["Soft"], u["Hard"]) for u in hc.get("Ulimits", [])}
        if ulimits.get("cpu") != (1, 1) or ulimits.get("core") != (0, 0):
            raise RuntimeError("actual CPU/core limit unknown")
        mounts = hc.get("Mounts")
        if (type(mounts) is not list or len(mounts) != 1 or
                mounts[0].get("Type") != "bind" or mounts[0].get("Target") != db.ARTIFACT or
                mounts[0].get("ReadOnly") is not True):
            raise RuntimeError("actual mount scope unknown")
        permitted = {str(context.artifact_path).lower().replace("\\", "/"),
            "/run/desktop/mnt/host/c/agent-runs/m15/candidate/" + context.artifact_sha256,
            "/host_mnt/c/agent-runs/m15/candidate/" + context.artifact_sha256}
        actual_source = str(mounts[0].get("Source", "")).lower().replace("\\", "/")
        if actual_source not in permitted:
            raise RuntimeError("actual bind source differs from exact granted artifact")
        if item.get("State", {}).get("Status") != "created" or item.get("State", {}).get("Running") is not False:
            raise RuntimeError("start guard requires exact unstarted owned container")

    def __call__(self, context: db.AdmissionContext) -> db.AdmissionProof:
        if not self.mutex or self.thread != threading.get_ident():
            raise RuntimeError("exclusive grant lease not held by this thread")
        cfg = context.config
        if (cfg.image_sha256 != IMAGE or cfg.toolchain_sha256 != MANIFEST_SHA or
                cfg.worker_kind != "candidate" or cfg.project != "m15" or
                cfg.instance != "r2-candidate" or cfg.container_name != NAME or
                cfg.owner_callsign != OWNER or cfg.owner_id != "0928" or cfg.grant_id != GRANT or
                cfg.docker_executable != DOCKER or cfg.python_executable != self.python):
            raise RuntimeError("actual source configuration outside exact software grant")
        no_links(RUNTIME_MANIFEST)
        raw = RUNTIME_MANIFEST.read_bytes()
        manifest = json.loads(raw)
        if (sha256(raw).hexdigest() != MANIFEST_SHA or manifest.get("image_sha256") != IMAGE or
                manifest.get("scope") != "trusted-python-software-regression-only-not-C-corpus" or
                manifest.get("python") != "3.12.13" or manifest.get("architecture") != "x86_64" or
                manifest.get("docker_engine_id") != ENGINE or manifest.get("machine") != "KAISER-PRO"):
            raise RuntimeError("actual runtime-only manifest commitment differs")
        digest = context.artifact_sha256
        name = self.whitelist.get(digest)
        path = db.RUN_ROOT / "candidate" / digest
        if name is None or context.artifact_path != path:
            raise RuntimeError("artifact absent from exact software source whitelist")
        no_links(path)
        info = path.stat()
        if (not stat.S_ISREG(info.st_mode) or not getattr(info, "st_file_attributes", 0) & 1 or
                path.read_bytes() != SCRIPTS[name] or sha256(path.read_bytes()).hexdigest() != digest):
            raise RuntimeError("whitelisted artifact is not exact frozen read-only bytes")
        whitelist_file = self.output / "fixtures.json"
        no_links(whitelist_file)
        frozen = json.loads(whitelist_file.read_bytes())
        if (not getattr(whitelist_file.stat(), "st_file_attributes", 0) & 1 or frozen != {
                "scope": "authored SOFTWARE fixtures only", "grant_id": GRANT,
                "image_sha256": IMAGE, "runtime_manifest_sha256": MANIFEST_SHA,
                "fixtures": {n: {"sha256": sha256(code).hexdigest(),
                    "path": str(db.RUN_ROOT / "candidate" / sha256(code).hexdigest())}
                    for n, code in SCRIPTS.items()}}):
            raise RuntimeError("retained software fixture whitelist changed")
        self.ledger()
        engine = self.control("info", "--format", "{{.ID}}")
        if engine.decode("ascii").strip() != ENGINE:
            raise RuntimeError("actual local Docker engine identity differs")
        images = json.loads(self.control("image", "inspect", "sha256:" + IMAGE))
        if (type(images) is not list or len(images) != 1 or images[0].get("Id") != "sha256:" + IMAGE or
                images[0].get("Os") != "linux" or images[0].get("Architecture") != "amd64" or
                images[0].get("Config", {}).get("Volumes")):
            raise RuntimeError("actual present Linux image/no-volumes identity differs")
        item = self.inspect_container(NAME if context.phase == "create" else context.container_id)
        if context.phase == "create":
            if context.container_id is not None or item is not None:
                raise RuntimeError("exact worker name already occupied; no deletion by name")
        elif context.phase == "start":
            if item is None:
                raise RuntimeError("created owned container not present")
            self.check_host_config(item, context)
        else:
            raise RuntimeError("unknown admission phase")
        ram = memory_gib()
        self.events.append({"kind": "actual_admission", "phase": context.phase, "fixture": name,
            "container_id": context.container_id, "free_ram_gib": ram,
            "ledger_sha256": sha256(LEDGER.read_bytes()).hexdigest(), "host": platform.node(),
            "manifest_sha256": MANIFEST_SHA, "image_sha256": IMAGE,
            "actual_host_config": None if item is None else item.get("HostConfig"),
            "checked_monotonic": time.monotonic()})
        return db.AdmissionProof(GRANT, IMAGE, MANIFEST_SHA, NAME, "0928", context.phase,
                                 time.monotonic(), True, True, True)

    def record_capture(self, argv, **kwargs):
        # Record, never replace/fake any transport result or invocation arguments.
        self.empty_client_config()
        if "create" in argv or "start" in argv:
            self.ledger()
            self.events.append({"kind": "immediate_preoperation_ram", "argv": argv,
                                "free_ram_gib": memory_gib(), "monotonic": time.monotonic()})
        result = self.capture(argv, **kwargs)
        self.events.append({"kind": "actual_transport", "argv": argv, **asdict(result)})
        return result


def serialize(value):
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, dict):
        return {k: serialize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [serialize(v) for v in value]
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.out.absolute()
    if output.exists() or output.parent.resolve(strict=True) != RECEIPTS.resolve(strict=True):
        raise RuntimeError("new unique direct phase-receipt directory required")
    output.mkdir()
    import sys
    expected_python = APP / ".venv-round2/Scripts/python.exe"
    if Path(sys.executable) != expected_python:
        raise RuntimeError("actual approved app-local target interpreter required")
    guard = SoftwareGrant(output, expected_python)
    observations = []
    try:
        guard.lease()
        memory_gib()
        no_links(db.RUN_ROOT)
        target = db.RUN_ROOT / "candidate"
        target.mkdir(exist_ok=True)
        no_links(target)
        for code in SCRIPTS.values():
            path = target / sha256(code).hexdigest()
            if path.exists():
                no_links(path)
                if path.read_bytes() != code or not getattr(path.stat(), "st_file_attributes", 0) & 1:
                    raise RuntimeError("existing artifact is not admitted frozen software bytes")
            else:
                with path.open("xb") as stream:
                    stream.write(code)
                path.chmod(stat.S_IREAD)
        fixtures = {n: {"sha256": sha256(code).hexdigest(), "path": str(target / sha256(code).hexdigest())}
                    for n, code in SCRIPTS.items()}
        (output / "fixtures.json").write_bytes(canonical({"scope": "authored SOFTWARE fixtures only",
            "grant_id": GRANT, "image_sha256": IMAGE, "runtime_manifest_sha256": MANIFEST_SHA,
            "fixtures": fixtures}))
        (output / "fixtures.json").chmod(stat.S_IREAD)
        config = db.DockerBackendConfig(IMAGE, MANIFEST_SHA, "candidate", "m15", "r2-candidate", NAME,
            OWNER, "0928", GRANT, DOCKER, expected_python, guard)
        backend = db.DockerBackend(config)
        policy = SandboxPolicy(IMAGE, MANIFEST_SHA, worker_kind="candidate")
        db._capture = guard.record_capture
        for name, code in SCRIPTS.items():
            raw = b"software\x00\xff" if name == "echo" else b""
            digest = sha256(code).hexdigest()
            limits = ExecutionLimits()
            request = ExecutionRequest(digest, raw, limits, policy, (), ())
            actual = backend.execute(request)
            result = {"fixture": name, "request": {"artifact_sha256": digest, "stdin_hex": raw.hex(),
                "limits": limits.model_dump(mode="json"), "policy": asdict(policy), "argv": [], "environment": []},
                "create_argv": db.build_create_argv(config, request, target / digest),
                "observation": actual.model_dump(mode="json"), "fresh_trusted_software_execution": True}
            # A returned infrastructure error is NOT evidence a subject started.
            result["fresh_trusted_software_execution"] = actual.status != "infrastructure_error"
            if name == "echo":
                result["expected_behavior_observed"] = actual.status == "ok" and actual.stdout_bytes == raw
            elif name == "exit2":
                result["expected_behavior_observed"] = actual.exit_code == 2 and actual.stdout_bytes == b""
            elif name == "output_cap":
                result["expected_behavior_observed"] = actual.output_limited and len(actual.stdout_bytes) <= 4096
            elif name == "timeout":
                result["expected_behavior_observed"] = actual.timed_out
            else:
                probe = json.loads(actual.stdout_bytes) if actual.status == "ok" else None
                result["probe"] = probe
                result["expected_behavior_observed"] = (probe is not None and
                    all(probe.get(k) is True for k in ("root_readonly", "tmp_writable", "fork_refused")) and
                    probe.get("uid") == 65534 and probe.get("gid") == 65534 and probe.get("pid") == 1 and
                    len(probe.get("tmp_mount_options", [])) == 1 and
                    {"rw", "noexec", "nosuid"}.issubset(probe["tmp_mount_options"][0].split(",")))
            observations.append(result)
            (output / "observations.json").write_bytes(canonical(serialize(observations)))
            (output / "events.json").write_bytes(canonical(serialize(guard.events)))
            if actual.status == "infrastructure_error":
                break  # do not keep creating subjects after unresolved infrastructure
        leftover = guard.inspect_container(NAME)
        if leftover is not None:
            raise RuntimeError("owned worker remains; preserve for exact-ID operator reconciliation")
        passed = len(observations) == len(SCRIPTS) and all(r["expected_behavior_observed"] for r in observations)
        (output / "result.json").write_bytes(canonical({"software_checks_passed": passed,
            "checks_observed": len(observations), "owned_container_absent": True,
            "scope": "trusted authored software only; no candidate/corpus/independence claim",
            "image_sha256": IMAGE, "runtime_manifest_sha256": MANIFEST_SHA, "grant_id": GRANT,
            "network_probe": "not_attempted; configuration proof only", "spend_usd": "0"}))
        return 0 if passed else 2
    except Exception as error:
        (output / "blocked.json").write_bytes(canonical({"status": "blocked_or_unknown", "reason": str(error),
            "grant_id": GRANT, "image_sha256": IMAGE, "runtime_manifest_sha256": MANIFEST_SHA,
            "checks_observed": len(observations), "no_broad_sandbox_pass": True}))
        return 3
    finally:
        db._capture = guard.capture
        try:
            (output / "events.json").write_bytes(canonical(serialize(guard.events)))
        finally:
            guard.release()


if __name__ == "__main__":
    raise SystemExit(main())
