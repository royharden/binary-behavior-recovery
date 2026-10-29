"""INT's exact four diagnostics; real transport, no host candidate execution."""
from __future__ import annotations

import argparse
import base64
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import sys
import threading

from bbr.contracts import ExecutionLimits
from bbr.runner.docker_validation import DockerCandidateValidationBackend
from bbr.runner.validation import CandidateValidationRequest
from . import docker_validation_software as frozen

old = frozen.original
PHASE = old.RECEIPTS.parent
GRANT_PATH = PHASE / "assignments/DL2-FOUR-DIAGNOSTICS-GRANT.md"
GRANT_SHA = "c561062d946b8fe8ec87011c2077a3498dd0212351152e9ef8c8ba849a185c25"
EXTENSION = "M15-R2-FOUR-DIAGNOSTICS-20261027"
PROPOSAL_PATH = old.RECEIPTS / "DL2-validation-wrapper-proposal-ae3a6c1.json"
PROPOSAL_SHA = "91b980a2b5c81e5a6c1b2038e7298253c0d9ea4f3dfafd5909bcd0f9dd979692"
MANIFEST_PATH = old.RECEIPTS / "DL2-validation-manifest-00b2922.json"
MANIFEST_SHA = "27329e673cf61bd536dd229380001f501c28b1f983d741f416e0843b4ee1531a"


def check_original_proposal(proposal: dict, artifacts: dict) -> None:
    """Compare original pinned bytes/bindings; never parse candidate syntax."""
    if (proposal.get("source_commit") != "ae3a6c13e78ecd387f2c6729f2082b3d78402da5" or
            proposal.get("module_sha256") != frozen.sources()["validator"]["sha256"] or
            proposal.get("import_policy_sha256") != frozen.IMPORT_POLICY_SHA256 or
            frozen.canonical(proposal.get("policy")) != frozen.canonical(asdict(frozen.fixed_policy())) or
            frozen.canonical(proposal.get("limits")) != frozen.canonical(ExecutionLimits().model_dump(mode="json"))):
        raise RuntimeError("original grant proposal policy/source differs")
    rows = proposal.get("wrappers")
    if type(rows) is not list or len(rows) != 4:
        raise RuntimeError("exactly four original wrappers required")
    for row, (name, raw, valid, reason, _) in zip(rows, frozen.CASES, strict=True):
        artifact = artifacts[name]
        expected = {"software_fixture": name, "candidate_utf8": raw.decode("utf-8"),
            "candidate_sha256": artifact.candidate_sha256, "wrapper_sha256": artifact.wrapper_sha256,
            "wrapper_base64": base64.b64encode(artifact.wrapper_bytes).decode("ascii"),
            "wrapper_size": len(artifact.wrapper_bytes), "binding_sha256": artifact.binding_sha256,
            "expected_software_valid": valid, "expected_reason": reason,
            "expected_no_body_marker": "BODY_MUST_NOT_RUN"}
        if frozen.canonical(row) != frozen.canonical(expected):
            raise RuntimeError("original granted wrapper differs")


class GrantedAdmission(frozen.ExactValidationAdmission):
    """Adapter for actual pinned Markdown grant, not a fabricated JSON approval."""
    def __init__(self, output: Path, source_sha256: str):
        old.db.require_digest(source_sha256)
        if output.parent.resolve(strict=True) != old.RECEIPTS.resolve(strict=True):
            raise RuntimeError("direct phase receipt output required")
        old.no_links(output)
        self.source_sha256 = source_sha256
        super().__init__(MANIFEST_PATH, MANIFEST_SHA, output=output,
            python=old.APP / ".venv-round2/Scripts/python.exe")
        self.authorization_sha256 = GRANT_SHA

    def _authorize(self):
        old.no_links(Path(__file__))
        if sha256(Path(__file__).read_bytes()).hexdigest() != self.source_sha256:
            raise RuntimeError("reviewed operator source changed")
        old.no_links(GRANT_PATH)
        if sha256(GRANT_PATH.read_bytes()).hexdigest() != GRANT_SHA:
            raise RuntimeError("actual INT grant changed or unavailable")
        _, manifest = frozen.load_pinned(MANIFEST_PATH, MANIFEST_SHA)
        artifacts = frozen.check_manifest(manifest)
        _, proposal = frozen.load_pinned(PROPOSAL_PATH, PROPOSAL_SHA)
        check_original_proposal(proposal, artifacts)
        if not self.base.mutex or self.base.thread != threading.get_ident():
            raise RuntimeError("exclusive owned software-worker lease required")
        return manifest, artifacts, {"extension_id": EXTENSION}


class RecordingTransport:
    """Delegates every request to the actual DockerBackend, retaining result bytes."""
    def __init__(self, backend):
        self.backend = backend
        self.records = []

    def execute(self, request):
        observation = self.backend.execute(request)
        self.records.append({"request": {"artifact_sha256": request.artifact_sha256,
            "stdin_hex": request.stdin_bytes.hex(), "argv": request.argv,
            "environment": request.environment, "policy": asdict(request.policy),
            "limits": request.limits.model_dump(mode="json")},
            "create_argv": old.db.build_create_argv(self.backend.config, request,
                old.db.RUN_ROOT / "candidate" / request.artifact_sha256),
            "observation": observation.model_dump(mode="python")})
        return observation


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    args = parser.parse_args(argv)
    output = args.out.absolute()
    if output.exists() or output.parent.resolve(strict=True) != old.RECEIPTS.resolve(strict=True):
        raise RuntimeError("new unique direct phase receipt directory required")
    old.no_links(output.parent)
    output.mkdir()
    admission = GrantedAdmission(output, args.source_sha256)
    guard = admission.base
    observations = []
    transport = None
    try:
        if Path(sys.executable) != guard.python:
            raise RuntimeError("approved target Python required")
        guard.lease()
        admission._authorize()
        old.memory_gib()
        old.no_links(old.db.RUN_ROOT)
        target = old.db.RUN_ROOT / "candidate"
        target.mkdir(exist_ok=True)
        old.no_links(target)
        config = old.db.DockerBackendConfig(old.IMAGE, old.MANIFEST_SHA, "candidate", "m15",
            "r2-candidate", old.NAME, old.OWNER, "0928", old.GRANT, old.DOCKER,
            guard.python, admission)
        transport = RecordingTransport(old.db.DockerBackend(config))
        validator = DockerCandidateValidationBackend(transport=transport, registrar=admission.register)
        old.db._capture = guard.record_capture
        for name, raw, expected_valid, expected_reason, _ in frozen.CASES:
            before = len(transport.records)
            valid, reason = validator.validate(CandidateValidationRequest(raw, sha256(raw).hexdigest(),
                frozen.fixed_policy(), ExecutionLimits()))
            recorded = transport.records[before:]
            marker_absent = len(recorded) == 1 and all(b"BODY_MUST_NOT_RUN" not in
                recorded[0]["observation"][pipe] for pipe in ("stdout_bytes", "stderr_bytes"))
            observations.append({"fixture": name, "valid": valid, "reason": reason,
                "expected_valid": expected_valid, "expected_reason": expected_reason,
                "body_marker_absent": marker_absent,
                "expected_behavior_observed": valid is expected_valid and reason == expected_reason and marker_absent,
                "actual_transport": recorded})
            (output / "observations.json").write_bytes(frozen.canonical(old.serialize(observations)))
            (output / "events.json").write_bytes(frozen.canonical(old.serialize(guard.events)))
            if valid is None:
                break  # infrastructure unknown: no further create/start attempts
        leftover = guard.inspect_container(old.NAME)
        if leftover is not None:
            raise RuntimeError("owned worker remains; exact-ID operator reconciliation required")
        passed = len(observations) == 4 and all(row["expected_behavior_observed"] for row in observations)
        (output / "result.json").write_bytes(frozen.canonical({"four_diagnostics_passed": passed,
            "checks_observed": len(observations), "owned_container_absent": True,
            "extension_id": EXTENSION, "grant_sha256": GRANT_SHA, "proposal_sha256": PROPOSAL_SHA,
            "manifest_sha256": MANIFEST_SHA, "operator_source_sha256": args.source_sha256,
            "image_sha256": old.IMAGE, "runtime_manifest_sha256": old.MANIFEST_SHA,
            "scope": "four authored software diagnostics only; candidate bodies never execute",
            "network_attempted": False, "spend_usd": "0"}))
        return 0 if passed else 2
    except Exception as error:
        (output / "blocked.json").write_bytes(frozen.canonical({"status": "blocked_or_unknown",
            "reason": str(error), "checks_observed": len(observations), "extension_id": EXTENSION}))
        return 3
    finally:
        old.db._capture = guard.capture
        try:
            (output / "events.json").write_bytes(frozen.canonical(old.serialize(guard.events)))
        finally:
            guard.release()


if __name__ == "__main__":
    raise SystemExit(main())
