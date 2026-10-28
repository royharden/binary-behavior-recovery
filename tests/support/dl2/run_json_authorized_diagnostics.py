"""Four original diagnostics through the unchanged JSON-authorized real guard."""
from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import sys

from bbr.contracts import ExecutionLimits
from bbr.runner.docker_validation import DockerCandidateValidationBackend
from bbr.runner.validation import CandidateValidationRequest
from . import docker_validation_software as frozen
from .run_four_diagnostics import RecordingTransport

old = frozen.original
AUTHORIZATION_PATH = old.RECEIPTS.parent / "assignments/INT-FOUR-DIAGNOSTICS-AUTHORIZATION.json"
AUTHORIZATION_SHA = "bef12fde5250a93f7b9e47701843b477bea5f1a20202c77d24b4e85c746423a3"
MANIFEST_PATH = old.RECEIPTS / "DL2-validation-manifest-00b2922.json"
MANIFEST_SHA = "27329e673cf61bd536dd229380001f501c28b1f983d741f416e0843b4ee1531a"
EXTENSION = "M15-R2-FOUR-DIAGNOSTICS-20261027"
RECORDING_SOURCE_SHA = "e8701835caa4576997ab94b40bf83aad70f90d944ced268a2c9fd4bb35dd651d"


def prepare_output(requested: Path) -> Path:
    """Resolve/reject escapes before mkdir or any recorder writes."""
    if ".." in requested.parts:
        raise RuntimeError("parent traversal refused")
    old.no_links(old.RECEIPTS)
    old.no_links(requested.absolute().parent)
    try:
        requested.lstat()
    except FileNotFoundError:
        pass
    else:
        old.no_links(requested)
    output = requested.resolve(strict=False)
    if output.parent != old.RECEIPTS.resolve(strict=True) or output.exists():
        raise RuntimeError("new unique direct resolved phase receipt required")
    output.mkdir()  # exclusive; never reuse an existing record directory
    old.no_links(output)
    return output


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    args = parser.parse_args(argv)
    old.db.require_digest(args.source_sha256)
    old.no_links(Path(__file__))
    if sha256(Path(__file__).read_bytes()).hexdigest() != args.source_sha256:
        raise RuntimeError("reviewed driver source changed")
    recording_source = Path(__file__).with_name("run_four_diagnostics.py")
    old.no_links(recording_source)
    if sha256(recording_source.read_bytes()).hexdigest() != RECORDING_SOURCE_SHA:
        raise RuntimeError("reviewed recording delegate changed")
    output = prepare_output(args.out)
    admission = frozen.ExactValidationAdmission(MANIFEST_PATH, MANIFEST_SHA,
        output=output, python=old.APP / ".venv-round2/Scripts/python.exe",
        authorization_path=AUTHORIZATION_PATH, authorization_sha256=AUTHORIZATION_SHA)
    guard = admission.base
    observations = []
    try:
        if Path(sys.executable) != guard.python:
            raise RuntimeError("approved target Python required")
        guard.lease()
        _, _, auth = admission._authorize()
        if auth["extension_id"] != EXTENSION:
            raise RuntimeError("exact extension required")
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
                break
        if guard.inspect_container(old.NAME) is not None:
            raise RuntimeError("owned worker remains; exact-ID reconciliation required")
        passed = len(observations) == 4 and all(row["expected_behavior_observed"] for row in observations)
        (output / "result.json").write_bytes(frozen.canonical({"four_diagnostics_passed": passed,
            "checks_observed": len(observations), "owned_container_absent": True,
            "extension_id": EXTENSION, "authorization_sha256": AUTHORIZATION_SHA,
            "manifest_sha256": MANIFEST_SHA, "operator_source_sha256": args.source_sha256,
            "image_sha256": old.IMAGE, "runtime_manifest_sha256": old.MANIFEST_SHA,
            "guard_type": "unchanged ExactValidationAdmission; external JSON authorization",
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
