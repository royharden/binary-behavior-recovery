"""Authored software units: byte proposal checks and unavailable-grant refusal.

No authorization is fabricated, no wrapper/candidate is parsed or executed, and
no mutex/agent-ports/Docker runtime operation occurs in these tests.
"""

from copy import deepcopy
from hashlib import sha256

import pytest

from support.dl2 import docker_validation_software as proposed


def proposal():
    # A symbolic source-commit identity for this UNIT, not an actual admission.
    return proposed.build_manifest("0" * 40)


def test_manifest_binds_literal_bytes_and_exact_sources():
    body = proposal()
    artifacts = proposed.check_manifest(body)
    assert tuple(artifacts) == tuple(case[0] for case in proposed.CASES)
    assert len(artifacts) == 4
    assert body["sources"] == proposed.sources()
    for case in body["cases"]:
        artifact = artifacts[case["name"]]
        assert artifact.wrapper_sha256 == case["wrapper_sha256"]
        assert artifact.candidate_sha256 == case["candidate_sha256"]


@pytest.mark.parametrize("mutation", ["candidate", "wrapper", "binding", "policy", "limits", "source", "expected", "extra"])
def test_manifest_rejects_rehashed_or_asserted_substitutions(mutation):
    body = deepcopy(proposal())
    if mutation == "candidate":
        body["cases"][0]["candidate_base64"] = "cGFzcw=="
    elif mutation == "wrapper":
        body["cases"][0]["wrapper_base64"] = "cGFzcw=="
    elif mutation == "binding":
        body["cases"][0]["binding_sha256"] = "0" * 64
    elif mutation == "policy":
        body["policy"]["network"] = True
    elif mutation == "limits":
        body["limits"]["wall_seconds"] = 3.0
    elif mutation == "source":
        body["sources"]["guard_registrar"]["sha256"] = "0" * 64
    elif mutation == "expected":
        body["cases"][0]["expected_valid"] = 1  # bool/int coercion must not pass
    else:
        body["extra"] = "not declared"
    with pytest.raises(ValueError):
        proposed.check_manifest(body)


def test_missing_actual_grant_cannot_register_or_grant_proof(tmp_path, monkeypatch):
    body = proposal()
    raw = proposed.canonical(body)
    path = tmp_path / "proposal.json"
    path.write_bytes(raw)
    # Tests use phase basetemp under the receipt root; no run-root artifact path.
    admission = proposed.ExactValidationAdmission(path, sha256(raw).hexdigest(),
        output=tmp_path / "output", python=proposed.original.APP / ".venv-round2/Scripts/python.exe")
    def forbidden(*args, **kwargs):
        raise AssertionError("missing grant must not invoke Docker or create a file")
    monkeypatch.setattr(admission.base, "control", forbidden)
    artifact = next(iter(proposed.check_manifest(body).values()))
    with pytest.raises(RuntimeError, match="authorization is unavailable"):
        admission.register(artifact)
    with pytest.raises(RuntimeError, match="authorization is unavailable"):
        admission(None)
    assert not admission.registered and admission.base.mutex is None
    assert not (tmp_path / "output").exists()


def test_proposal_pin_and_duplicate_keys_refuse_before_activation(tmp_path):
    path = tmp_path / "proposal.json"
    raw = proposed.canonical(proposal())
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="commitment"):
        proposed.load_pinned(path, "0" * 64)
    raw = b'{"same":1,"same":2}'
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="duplicate"):
        proposed.load_pinned(path, sha256(raw).hexdigest())


def test_original_five_script_whitelist_is_unchanged():
    before = {key: bytes(value) for key, value in proposed.original.SCRIPTS.items()}
    proposal()
    assert proposed.original.SCRIPTS == before
    assert set(before) == {"echo", "exit2", "output_cap", "timeout", "basic_bounds"}
