"""Binding/refusal units only; no wrapper parse/compile or Docker operation."""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from support.dl2 import run_four_diagnostics as run


def proposal():
    return run.frozen.load_pinned(run.PROPOSAL_PATH, run.PROPOSAL_SHA)[1]


def test_actual_granted_proposal_matches_fixed_packaged_artifacts():
    run.check_original_proposal(proposal(), run.frozen.registrations())
    assert sha256(run.GRANT_PATH.read_bytes()).hexdigest() == run.GRANT_SHA


@pytest.mark.parametrize("field", ["candidate_utf8", "wrapper_sha256", "binding_sha256",
    "expected_software_valid", "extra", "count", "policy", "module"])
def test_original_binding_substitutions_refused(field):
    changed = deepcopy(proposal())
    if field == "count":
        changed["wrappers"].pop()
    elif field == "policy":
        changed["policy"]["network"] = True
    elif field == "module":
        changed["module_sha256"] = "0" * 64
    elif field == "extra":
        changed["wrappers"][0]["extra"] = True
    elif field == "expected_software_valid":
        changed["wrappers"][0][field] = 1
    else:
        changed["wrappers"][0][field] = "substitution"
    with pytest.raises(RuntimeError):
        run.check_original_proposal(changed, run.frozen.registrations())


def test_real_grant_without_lease_refuses_registration_before_writes(tmp_path, monkeypatch):
    operator_sha = sha256(Path(run.__file__).read_bytes()).hexdigest()
    # Basetemp is under the phase receipt root; constructor requires direct child.
    admission = run.GrantedAdmission(next(p for p in tmp_path.parents if p.parent == run.old.RECEIPTS), operator_sha)
    monkeypatch.setattr(admission.base, "control", lambda *a, **k: pytest.fail("no Docker permitted"))
    artifact = next(iter(run.frozen.registrations().values()))
    with pytest.raises(RuntimeError, match="lease required"):
        admission.register(artifact)
    assert not admission.registered


def test_source_pin_mismatch_refuses_before_lease(tmp_path):
    admission = run.GrantedAdmission(next(p for p in tmp_path.parents if p.parent == run.old.RECEIPTS), "0" * 64)
    with pytest.raises(RuntimeError, match="operator source changed"):
        admission._authorize()

