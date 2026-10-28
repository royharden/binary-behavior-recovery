"""Proposed exact four-wrapper guard/registrar. No default operational grant.

This module preserves docker_software_worker.SCRIPTS and its five-script guard.
Only explicit externally pinned authorization can register these four wrappers.
Host processing is bytes/base64/hash/JSON, never candidate syntax or execution.
"""

from __future__ import annotations

import base64
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import re
import stat
import threading
import time

from bbr.contracts import ExecutionLimits
from bbr.runner.policy import SandboxPolicy
from bbr.runner.validation import CandidateValidationRequest
from bbr.runner.docker_validation import (IMPORT_POLICY_ID, IMPORT_POLICY_SHA256,
    ValidationArtifactRegistration, ValidationArtifactReceipt, build_validation_artifact)
from . import docker_software_worker as original

ROOT = Path(__file__).resolve().parents[3]
SOURCES = {"validator": "src/bbr/runner/docker_validation.py",
           "guard_registrar": "tests/support/dl2/docker_validation_software.py",
           "existing_worker_guard": "tests/support/dl2/docker_software_worker.py",
           "transport": "src/bbr/runner/docker_backend.py"}
CASES = (
    ("valid_stdio", b"import sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n", True, "valid",
     "Ordinary allowed stdio syntax is checked, without executing its body."),
    ("syntax_invalid", b"def broken(:\n", False, "syntax_invalid",
     "The container parser must reject a deliberately invalid software specimen."),
    ("denied_import", b"import os\n", False, "denied_import",
     "The declared public import policy must reject os before any candidate execution."),
    ("body_must_not_execute", b"print('BODY_MUST_NOT_RUN')\nwhile True:\n    pass\n", True, "valid",
     "Valid syntax must return promptly without printing the marker or entering the loop."),
)


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def sources() -> dict:
    return {name: {"path": path, "sha256": sha256((ROOT / path).read_bytes()).hexdigest()}
            for name, path in SOURCES.items()}


def fixed_policy() -> SandboxPolicy:
    return SandboxPolicy(original.IMAGE, original.MANIFEST_SHA, worker_kind="candidate")


def registrations() -> dict[str, ValidationArtifactRegistration]:
    return {name: build_validation_artifact(CandidateValidationRequest(
        raw, sha256(raw).hexdigest(), fixed_policy(), ExecutionLimits()))
        for name, raw, _, _, _ in CASES}


def build_manifest(source_commit: str) -> dict:
    """Pure source hashing/byte packaging. Does not write or admit any artifact."""
    if type(source_commit) is not str or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("exact candidate commit required")
    artifacts = registrations()
    cases = []
    for name, raw, valid, reason, demonstrates in CASES:
        artifact = artifacts[name]
        cases.append({"name": name, "candidate_base64": base64.b64encode(raw).decode("ascii"),
            "candidate_sha256": artifact.candidate_sha256,
            "wrapper_base64": base64.b64encode(artifact.wrapper_bytes).decode("ascii"),
            "wrapper_sha256": artifact.wrapper_sha256, "binding_sha256": artifact.binding_sha256,
            "expected_valid": valid, "expected_reason": reason, "demonstrates": demonstrates})
    return {"schema": "bbr.dl2.validation-manifest.v2", "source_commit": source_commit,
        "scope": "four authored software diagnostics; candidate bodies never execute",
        "sources": sources(), "image_sha256": original.IMAGE,
        "runtime_manifest_sha256": original.MANIFEST_SHA, "policy": asdict(fixed_policy()),
        "limits": ExecutionLimits().model_dump(mode="json"),
        "import_policy_id": IMPORT_POLICY_ID, "import_policy_sha256": IMPORT_POLICY_SHA256,
        "cases": cases}


def check_manifest(value: dict) -> dict[str, ValidationArtifactRegistration]:
    if type(value) is not dict:
        raise ValueError("closed manifest object required")
    # A byte-exact comparison rejects type coercion, extras, altered diagnostics,
    # arbitrary source strings and any mismatch in either literal wrapper.
    expected = build_manifest(value.get("source_commit"))
    if canonical(value) != canonical(expected):
        raise ValueError("manifest differs from the four fixed source/binding records")
    return registrations()


def load_pinned(path: Path, expected_sha256: str) -> tuple[bytes, dict]:
    original.db.require_digest(expected_sha256)
    original.no_links(path)
    if path.suffix != ".json" or path.stat().st_size > 65536:
        raise ValueError("bounded explicit JSON record required")
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("external file-byte commitment mismatch")
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate record key")
            result[key] = item
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if type(value) is not dict:
        raise ValueError("JSON object required")
    return raw, value


class ExactValidationAdmission:
    """Real guard + registrar, dormant without INT's external authorization pin.

    The authorization SHA must arrive from INT, not be derived from an untrusted
    request or the approval file itself. These checks do not authenticate Roy.
    """

    def __init__(self, proposal_path: Path, proposal_sha256: str, *, output: Path,
                 python: Path, authorization_path: Path | None = None,
                 authorization_sha256: str | None = None):
        if python != original.APP / ".venv-round2/Scripts/python.exe":
            raise ValueError("exact approved app-local Python required")
        if not output.absolute().is_relative_to(original.RECEIPTS.absolute()):
            raise ValueError("phase-owned output location required")
        self.proposal_path, self.proposal_sha256 = proposal_path, proposal_sha256
        _, proposal = load_pinned(proposal_path, proposal_sha256)
        check_manifest(proposal)
        self.authorization_path, self.authorization_sha256 = authorization_path, authorization_sha256
        self.base = original.SoftwareGrant(output, python)
        self.registered: set[str] = set()

    def _authorize(self):
        if self.authorization_path is None or self.authorization_sha256 is None:
            raise RuntimeError("explicit validation-wrapper authorization is unavailable")
        _, proposal = load_pinned(self.proposal_path, self.proposal_sha256)
        artifacts = check_manifest(proposal)
        _, auth = load_pinned(self.authorization_path, self.authorization_sha256)
        keys = {"schema", "decision", "extension_id", "base_grant_id", "proposal_sha256",
                "guard_registrar_sha256", "image_sha256", "runtime_manifest_sha256",
                "project", "instance", "container_name", "owner_id", "wrapper_sha256", "limits"}
        extension = auth.get("extension_id")
        if (set(auth) != keys or auth.get("schema") != "bbr.dl2.validation-admission.v1" or
                auth.get("decision") != "approved" or type(extension) is not str or
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,159}", extension) is None or
                any(word in extension.lower() for word in ("placeholder", "pending", "todo"))):
            raise RuntimeError("closed concrete approval record required")
        fixed = {"base_grant_id": original.GRANT, "proposal_sha256": self.proposal_sha256,
            "guard_registrar_sha256": proposal["sources"]["guard_registrar"]["sha256"],
            "image_sha256": original.IMAGE, "runtime_manifest_sha256": original.MANIFEST_SHA,
            "project": "m15", "instance": "r2-candidate", "container_name": original.NAME,
            "owner_id": "0928", "wrapper_sha256": sorted(a.wrapper_sha256 for a in artifacts.values()),
            "limits": ExecutionLimits().model_dump(mode="json")}
        if canonical({key: auth[key] for key in fixed}) != canonical(fixed):
            raise RuntimeError("approval does not bind the exact proposal/source/scope")
        if not self.base.mutex or self.base.thread != threading.get_ident():
            raise RuntimeError("exclusive owned software-worker lease required")
        return proposal, artifacts, auth

    def register(self, artifact: ValidationArtifactRegistration) -> ValidationArtifactReceipt:
        """Never approve arbitrary wrappers or return a receipt before real checks."""
        _, artifacts, auth = self._authorize()
        expected = next((a for a in artifacts.values() if a.wrapper_sha256 == artifact.wrapper_sha256), None)
        if (expected is None or type(artifact) is not ValidationArtifactRegistration or
                artifact.wrapper_bytes != expected.wrapper_bytes or
                canonical({"candidate": artifact.candidate_sha256, "binding": artifact.binding_sha256,
                    "policy": asdict(artifact.policy), "limits": artifact.limits.model_dump(mode="json")}) !=
                canonical({"candidate": expected.candidate_sha256, "binding": expected.binding_sha256,
                    "policy": asdict(expected.policy), "limits": expected.limits.model_dump(mode="json")})):
            raise RuntimeError("artifact is not an exact frozen diagnostic wrapper")
        path = original.db.RUN_ROOT / "candidate" / artifact.wrapper_sha256
        original.no_links(path.parent)
        if path.exists():
            original.no_links(path)
            if path.read_bytes() != expected.wrapper_bytes or not getattr(path.stat(), "st_file_attributes", 0) & 1:
                raise RuntimeError("existing wrapper is mismatching or not readonly; no overwrite")
        else:
            with path.open("xb") as stream:
                stream.write(expected.wrapper_bytes)
            path.chmod(stat.S_IREAD)
        self._check_file(path, expected)
        self.registered.add(artifact.wrapper_sha256)
        self.base.events.append({"kind": "actual_validation_registration", "wrapper_sha256": artifact.wrapper_sha256,
            "candidate_sha256": artifact.candidate_sha256, "binding_sha256": artifact.binding_sha256,
            "extension_id": auth["extension_id"], "path": str(path), "read_only_checked": True})
        return ValidationArtifactReceipt(artifact, artifact.wrapper_sha256, True)

    @staticmethod
    def _check_file(path: Path, artifact: ValidationArtifactRegistration):
        original.no_links(path)
        if (not stat.S_ISREG(path.stat().st_mode) or not getattr(path.stat(), "st_file_attributes", 0) & 1 or
                path.read_bytes() != artifact.wrapper_bytes or
                sha256(path.read_bytes()).hexdigest() != artifact.wrapper_sha256):
            raise RuntimeError("exact readonly wrapper file not verified")

    def __call__(self, context: original.db.AdmissionContext) -> original.db.AdmissionProof:
        _, artifacts, auth = self._authorize()
        cfg = context.config
        if (cfg.image_sha256 != original.IMAGE or cfg.toolchain_sha256 != original.MANIFEST_SHA or
                cfg.worker_kind != "candidate" or cfg.project != "m15" or cfg.instance != "r2-candidate" or
                cfg.container_name != original.NAME or cfg.owner_callsign != original.OWNER or
                cfg.owner_id != "0928" or cfg.grant_id != original.GRANT or
                cfg.docker_executable != original.DOCKER or cfg.python_executable != self.base.python or
                cfg.admission_guard is not self):
            raise RuntimeError("worker configuration outside exact software scope")
        artifact = next((a for a in artifacts.values() if a.wrapper_sha256 == context.artifact_sha256), None)
        path = original.db.RUN_ROOT / "candidate" / context.artifact_sha256
        if artifact is None or context.artifact_path != path or context.artifact_sha256 not in self.registered:
            raise RuntimeError("wrapper was not explicitly registered under this grant")
        self._check_file(path, artifact)
        original.no_links(original.RUNTIME_MANIFEST)
        if sha256(original.RUNTIME_MANIFEST.read_bytes()).hexdigest() != original.MANIFEST_SHA:
            raise RuntimeError("runtime-only manifest changed")
        self.base.ledger()
        if self.base.control("info", "--format", "{{.ID}}").decode("ascii").strip() != original.ENGINE:
            raise RuntimeError("actual daemon identity differs")
        images = json.loads(self.base.control("image", "inspect", "sha256:" + original.IMAGE))
        if (type(images) is not list or len(images) != 1 or images[0].get("Id") != "sha256:" + original.IMAGE or
                images[0].get("Os") != "linux" or images[0].get("Architecture") != "amd64" or
                images[0].get("Config", {}).get("Volumes")):
            raise RuntimeError("actual existing image identity/no-volumes unverified")
        item = self.base.inspect_container(original.NAME if context.phase == "create" else context.container_id)
        if context.phase == "create":
            if context.container_id is not None or item is not None:
                raise RuntimeError("exact worker name is occupied; no removal by name")
        elif context.phase == "start":
            if item is None:
                raise RuntimeError("exact created container missing")
            self.base.check_host_config(item, context)
        else:
            raise RuntimeError("invalid operation phase")
        ram = original.memory_gib()
        self.base.events.append({"kind": "actual_validation_admission", "phase": context.phase,
            "wrapper_sha256": context.artifact_sha256, "container_id": context.container_id,
            "extension_id": auth["extension_id"], "proposal_sha256": self.proposal_sha256,
            "authorization_sha256": self.authorization_sha256, "free_ram_gib": ram,
            "actual_host_config": None if item is None else item.get("HostConfig")})
        return original.db.AdmissionProof(original.GRANT, original.IMAGE, original.MANIFEST_SHA,
            original.NAME, "0928", context.phase, time.monotonic(), True, True, True)
