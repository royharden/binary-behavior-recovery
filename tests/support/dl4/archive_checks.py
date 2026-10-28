"""Actual report/resource software checks, with no candidate code execution.

All source artifacts written by these tests are BUILDER_AUTHORED_SOFTWARE_ONLY.
No positive control claims independent custody, real dispatch or benchmark data.
The parent imports test functions into its single authorized pytest entrypoint.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path

import pytest

from .resources import make_resource_inputs


def _write(root: Path, relative: str, value: object) -> str:
    from bbr.report.archive import canonical

    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value) + b"\n")
    return relative


def make_archive(root: Path, matrix, *, version: int = 2,
                 resource_task_count: int | None = 0, unknown_first: bool = False,
                 partial_domain: bool = False, replay_record: dict | None = None):
    """Create later-test-only source files and a real recomputed report."""
    from bbr.report.archive import build_report
    from evaluation.run import retained_report

    root.mkdir(parents=True, exist_ok=True)
    paths = [
        _write(root, "partitions.json", matrix.partitions),
        _write(root, "locks.json", matrix.receipt),
        _write(root, "rows.json", matrix.rows)]
    bundle = {"schema": f"bbr.scoring-bundle.v{version}",
        "registration": asdict(matrix.registration), "partitions": paths[0],
        "campaign_receipt": paths[1], "row_shards": [paths[2]]}
    if version in (3, 4):
        snapshot, receipts = make_resource_inputs(matrix, task_count=resource_task_count,
                                                  unknown_first=unknown_first)
        ledger_path = _write(root, "ledger.json", snapshot)
        receipt_paths = [_write(root, f"receipts/{index:04d}.json", receipt)
                         for index, receipt in enumerate(receipts)]
        sources = {"schema": "bbr.resource-sources.v1", "ledger_report": ledger_path,
                   "receipts": receipt_paths}
        paths.extend([ledger_path, *receipt_paths])
        if "model_bindings" in dict(matrix.registration.pins):
            sources["model_bindings"] = _write(root, "model-bindings.json", matrix.bindings)
            paths.append(sources["model_bindings"])
        bundle["resource_sources"] = _write(root, "resources.json", sources)
        paths.append(bundle["resource_sources"])
    if version == 4:
        bundle["domain_sources"] = None
        if partial_domain:
            domain_sources = {"schema": "bbr.domain-sources.v1", "entries": [{
                "domain": None, "domain_policy": None, "binding": None,
                "expected_binding_sha256": None, "observed_probes": None, "records": None}]}
            bundle["domain_sources"] = _write(root, "domains.json", domain_sources)
            paths.append(bundle["domain_sources"])
    paths.append(_write(root, "bundle.json", bundle))
    replay_records = None
    if replay_record is not None:
        # Intentional pretty JSON: file bytes are not the canonical body bytes.
        (root / "replay.json").write_text(json.dumps(replay_record, indent=2) + "\n",
                                           encoding="utf-8", newline="\n")
        paths.append("replay.json")
        replay_records = {"replay.json": replay_record["record_sha256"]}
    score = retained_report(matrix.registration, matrix.rows,
        partitions=matrix.partitions, campaign_receipt=matrix.receipt)
    report = build_report(root, paths, score, origin="fixture",
        campaign_id=matrix.registration.edition, scoring_bundle="bundle.json",
        replay_records=replay_records)
    return report, paths, score


def software_replay_record() -> dict:
    """One retained counterexample; hashes identify software marker bytes only."""
    from bbr.contracts import Counterexample, ExecutionLimits, Observation, ReplayBundle
    from bbr.differential import COMPARATOR_VERSION, compare_observations
    from bbr.report.archive import canonical

    marker = lambda label: sha256(("SOFTWARE_ONLY_" + label).encode()).hexdigest()
    raw = b"1\n"
    pair = compare_observations(Observation(stdout_bytes=b"0\n", exit_code=0, status="ok"),
        Observation(stdout_bytes=b"1\n", exit_code=0, status="ok"), stdin_bytes=raw)
    case = Counterexample(stdin_bytes=raw, outcome=pair,
                          input_sha256=sha256(raw).hexdigest())
    bundle = ReplayBundle(artifact_sha256=marker("NOT_ELF_ARTIFACT"),
        candidate_sha256=marker("INERT_CANDIDATE_TEXT"),
        execution_contract_sha256=marker("NO_EXECUTION_CONTRACT"),
        toolchain_sha256=marker("NO_ACTUAL_TOOLCHAIN"), original=case, reduced=case,
        attempts=1, minimality="not_shrunk", limits=ExecutionLimits(),
        image_sha256=marker("NO_ACTUAL_IMAGE"), argv=(), environment=(),
        comparator_version=COMPARATOR_VERSION,
        move_policy="contiguous-deletion-numeric-boundary-v1", trace=(case,))
    body = {"bundle": bundle.model_dump(mode="json"), "image_sha256": bundle.image_sha256,
        "argv": [], "environment": [], "comparator_version": COMPARATOR_VERSION,
        "move_policy": bundle.move_policy, "minimality_status": "shrink_exhausted",
        "trace": [case.model_dump(mode="json")]}
    return {**body, "record_sha256": sha256(canonical(body)).hexdigest()}


@pytest.mark.parametrize("version,report_schema", [(2, "bbr.report.v3"),
    (3, "bbr.report.v4"), (4, "bbr.report.v5")])
def test_report_versions_roundtrip(tmp_path, software_matrix, version, report_schema):
    from bbr.report.archive import verify_report, write_report

    report, _, _ = make_archive(tmp_path / "evidence", software_matrix, version=version)
    write_report(tmp_path / "view", report)
    checked = verify_report(tmp_path / "view/report.json", tmp_path / "evidence")
    assert report["schema"] == report_schema
    assert checked["summary_recomputed"] is True
    assert checked["resources_recomputed"] is (version >= 3)
    assert checked["strata_recomputed"] is (version == 4)
    assert checked["origin"] == "fixture" and checked["fresh_execution"] is False
    assert checked["runtime_validation"] == "unverified"
    if version == 4:
        table = report["strata"]["tables"]["by_model_arm"]
        assert len(table) == 14 and all(row["scheduled"] == 96 for row in table)
        assert report["domains"]["status"] == "not_supplied"


def test_partial_domain_inventory_keeps_unqualified_disclosures(tmp_path, software_matrix):
    report, _, _ = make_archive(tmp_path / "evidence", software_matrix,
                                version=4, partial_domain=True)
    domains = report["domains"]
    assert domains["source_recomputed"] is True
    assert domains["population_rate"] is None
    partial = domains["summaries"][0]
    assert partial["status"] == "not_qualified"
    assert partial["certificate"] is None and partial["calibration"] is None
    assert partial["unavailable_checks"]


def test_report_render_escapes_hostile_strings(tmp_path, software_matrix):
    from bbr.report.archive import render_html, render_markdown

    report, _, _ = make_archive(tmp_path / "evidence", software_matrix, version=4)
    untrusted = '<script>alert("SOFTWARE_ONLY")</script>|[link](javascript:x)\nnext'
    view = deepcopy(report)
    view["label"] = untrusted
    view["strata"]["tables"]["by_model_arm"][0]["model"] = untrusted
    html = render_html(view)
    markdown = render_markdown(view)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert untrusted not in markdown and "&#124;" in markdown and "&#10;" in markdown
    assert "<table>" in html and "| scheduled |" in markdown
    assert "by_model_arm" in markdown and "&#91;link&#93;" in markdown


@pytest.mark.parametrize("target", ["raw", "body", "html", "markdown"])
def test_report_tampering_refuses(tmp_path, software_matrix, target):
    from bbr.report.archive import ReportError, canonical, verify_report, write_report

    root = tmp_path / "evidence"
    report, _, _ = make_archive(root, software_matrix)
    out = tmp_path / "view"
    write_report(out, report)
    if target == "raw":
        (root / "rows.json").write_bytes((root / "rows.json").read_bytes() + b" ")
    elif target == "body":
        altered = deepcopy(report)
        altered["summary"]["complete"] = not altered["summary"]["complete"]
        (out / "report.json").write_bytes(canonical(altered))
    else:
        file = out / ("report.html" if target == "html" else "report.md")
        file.write_bytes(file.read_bytes() + b"SOFTWARE_ONLY_TAMPER")
    with pytest.raises(ReportError):
        verify_report(out / "report.json", root)


@pytest.mark.parametrize("relative", ["../escape", "./rows.json", "a//b", "C:/escape",
    "a\\b", "rows.json.", "NUL", "a:b", "x\0y"])
def test_archive_path_aliases_refuse(tmp_path, relative):
    from bbr.report.archive import ReportError, safe_file

    with pytest.raises(ReportError):
        safe_file(tmp_path, relative)


def test_archive_symlink_refuses_when_host_permits_links(tmp_path):
    from bbr.report.archive import ReportError, safe_file

    target = tmp_path / "software.json"
    target.write_bytes(b"{}")
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"host cannot create this software-test symlink: {type(error).__name__}")
    with pytest.raises(ReportError, match="links"):
        safe_file(tmp_path, link.name)


def test_archive_declared_data_and_replay_size_ceilings(tmp_path):
    """Sparse/stat boundary only; does NOT prove a full 256-pair replay works."""
    from bbr.report.archive import MAX_FILE, MAX_REPLAY_FILE, ReportError, safe_file

    source = tmp_path / "software-boundary.bin"
    with source.open("wb") as stream:
        stream.truncate(MAX_FILE + 1)
    with pytest.raises(ReportError, match="size cap"):
        safe_file(tmp_path, source.name)
    assert safe_file(tmp_path, source.name, max_bytes=MAX_REPLAY_FILE) == source.resolve()
    with source.open("r+b") as stream:
        stream.truncate(MAX_REPLAY_FILE + 1)
    with pytest.raises(ReportError, match="size cap"):
        safe_file(tmp_path, source.name, max_bytes=MAX_REPLAY_FILE)


def test_archive_replay_raw_hash_is_not_body_commitment(tmp_path, software_matrix):
    from bbr.replay import load_record
    from bbr.report.archive import verify_report, write_report

    record = software_replay_record()
    root = tmp_path / "evidence"
    report, _, _ = make_archive(root, software_matrix, replay_record=record)
    entry = next(row for row in report["evidence"] if row["path"] == "replay.json")
    assert entry["kind"] == "replay"
    assert entry["sha256"] == sha256((root / "replay.json").read_bytes()).hexdigest()
    assert entry["replay_record_sha256"] == record["record_sha256"]
    assert entry["sha256"] != entry["replay_record_sha256"]
    with pytest.raises(ValueError, match="digest mismatch"):
        load_record(root, "replay.json", expected_record_sha256=entry["sha256"])
    write_report(tmp_path / "view", report)
    assert verify_report(tmp_path / "view/report.json", root)["fresh_execution"] is False


def test_replay_type_cannot_expand_scoring_source_cap(tmp_path, software_matrix):
    from bbr.report.archive import ReportError, build_report, canonical

    root = tmp_path / "evidence"
    record = software_replay_record()
    _, paths, score = make_archive(root, software_matrix, replay_record=record)
    bundle = json.loads((root / "bundle.json").read_text(encoding="utf-8"))
    bundle["partitions"] = "replay.json"
    (root / "bundle.json").write_bytes(canonical(bundle))
    with pytest.raises(ReportError, match="bounded data entries"):
        build_report(root, paths, score, origin="fixture", campaign_id=software_matrix.registration.edition,
            scoring_bundle="bundle.json", replay_records={"replay.json": record["record_sha256"]})


def test_bound_resource_counts_require_full_population(tmp_path, bound_matrix):
    report, _, _ = make_archive(tmp_path / "complete", bound_matrix,
                                version=3, resource_task_count=None)
    resources = report["resources"]
    assert resources["pass_count_binding_status"] == "verified"
    assert len(resources["pass_counts"]) == 6
    assert all(row["passed_tasks"] == 0 and row["reason"] is None
               for row in resources["pass_counts"])
    assert all(group["usd_per_pass"] is None and group["usd_per_pass_reason"] == "zero passes"
               for group in resources["summary"]["groups"])
    partial, _, _ = make_archive(tmp_path / "partial", bound_matrix,
                                  version=3, resource_task_count=1)
    assert all(row["passed_tasks"] is None and row["reason"] == "incomplete_retained_resource_task_population"
               for row in partial["resources"]["pass_counts"])


def test_resource_binding_pin_refuses_self_consistent_tamper(tmp_path, bound_matrix):
    from bbr.report.archive import ReportError, build_report, canonical

    root = tmp_path / "evidence"
    _, paths, score = make_archive(root, bound_matrix, version=3, resource_task_count=1)
    mapping = deepcopy(bound_matrix.bindings)
    mapping["bindings"][0]["config_id"] += "-changed"
    (root / "model-bindings.json").write_bytes(canonical(mapping))
    with pytest.raises(ReportError, match="frozen edition/origin/pin"):
        build_report(root, paths, score, origin="fixture", campaign_id=bound_matrix.registration.edition,
                     scoring_bundle="bundle.json")


def test_resource_unknown_liability_does_not_become_zero(tmp_path, bound_matrix):
    report, _, _ = make_archive(tmp_path / "evidence", bound_matrix,
        version=3, resource_task_count=1, unknown_first=True)
    resource = report["resources"]["summary"]
    assert resource["ledger_dispatch_blocked"] is True
    assert resource["campaign_unique"]["unpriced_reserved_liability_usd"] == "1"
    assert resource["campaign_unique"]["committed_usd"] == "1"
    assert resource["campaign_unique"]["cost_complete"] is False
    assert resource["campaign_unique"]["measurements"]["input_tokens"] is None
    assert all(group["usd_per_pass"] is None for group in resource["groups"])


def test_resource_join_requires_each_ledger_attempt_and_single_origin(software_matrix):
    from bbr.report.resource_metrics import summarize_resources

    ledger, receipts = make_resource_inputs(software_matrix, task_count=1)
    with pytest.raises(ValueError, match="every ledger attempt"):
        summarize_resources(ledger, receipts[:-1], campaign_id=software_matrix.registration.edition,
                            origin="fixture")
    wrong_origin = deepcopy(receipts)
    wrong_origin[0]["origin"] = "live"
    with pytest.raises(ValueError, match="campaign/origin/schema mismatch"):
        summarize_resources(ledger, wrong_origin, campaign_id=software_matrix.registration.edition,
                            origin="fixture")


def test_resource_shared_m_views_are_nonadditive(software_matrix):
    from bbr.report.resource_metrics import summarize_resources

    ledger, receipts = make_resource_inputs(software_matrix, task_count=1,
                                             labels=("M:0", "R:1", "P:1"), charge="0.01")
    result = summarize_resources(ledger, receipts,
        campaign_id=software_matrix.registration.edition, origin="fixture")
    assert result["campaign_unique"]["unique_attempts"] == 6
    assert result["campaign_unique"]["settled_spend_usd"] == "0.06"
    refinements = [group for group in result["groups"] if group["arm"] in {"R", "P"}]
    assert all(group["incremental"]["settled_spend_usd"] == "0.01" for group in refinements)
    assert all(group["including_shared_m_nonadditive"]["settled_spend_usd"] == "0.02"
               for group in refinements)
    assert all(len(group["shared_m_reuse"]) == 1 and
               group["shared_m_reuse"][0]["new_charge_usd"] == "0" for group in refinements)
