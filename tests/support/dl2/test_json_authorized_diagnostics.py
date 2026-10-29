"""Recorder containment and externally pinned bytes; no Docker/candidate parsing."""
import pytest

from support.dl2 import run_json_authorized_diagnostics as run


def test_actual_external_authorization_pin_matches_manifest():
    _, auth = run.frozen.load_pinned(run.AUTHORIZATION_PATH, run.AUTHORIZATION_SHA)
    _, manifest = run.frozen.load_pinned(run.MANIFEST_PATH, run.MANIFEST_SHA)
    run.frozen.check_manifest(manifest)
    assert auth["proposal_sha256"] == run.MANIFEST_SHA
    assert auth["extension_id"] == run.EXTENSION


def test_output_is_exclusive_resolved_child(tmp_path, monkeypatch):
    monkeypatch.setattr(run.old, "RECEIPTS", tmp_path)
    output = run.prepare_output(tmp_path / "new")
    assert output == tmp_path.resolve() / "new"
    with pytest.raises(RuntimeError, match="new unique"):
        run.prepare_output(output)


def test_parent_traversal_refused_before_writes(tmp_path, monkeypatch):
    monkeypatch.setattr(run.old, "RECEIPTS", tmp_path)
    with pytest.raises(RuntimeError, match="traversal"):
        run.prepare_output(tmp_path / ".." / "escape")


def test_outside_or_nested_output_refused(tmp_path, monkeypatch):
    root = tmp_path / "receipts"
    root.mkdir()
    monkeypatch.setattr(run.old, "RECEIPTS", root)
    with pytest.raises(RuntimeError, match="new unique"):
        run.prepare_output(tmp_path / "outside")
    child = root / "child"
    child.mkdir()
    with pytest.raises(RuntimeError, match="new unique"):
        run.prepare_output(child / "nested")
