"""Numeric JSON authority with a content-addressed, bounded evidence archive.

Verification establishes retained-byte consistency only, never fresh execution or
the truth of a producer's observations. Archive input is untrusted data.
"""

from __future__ import annotations

import hashlib
import html
import importlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

MAX_FILE = 16 * 1024 * 1024
MAX_REPLAY_FILE = 32 * 1024 * 1024
MAX_FILES = 8192
MAX_ARCHIVE = 16 * 1024 * 1024 * 1024
BANNER = "SCRIPTED FIXTURE / NO LIVE MODEL RESULT"


class ReportError(ValueError):
    """Malformed or inconsistent retained evidence."""


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise ReportError("canonical JSON value required") from error


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def safe_file(root: Path, relative: str, *, max_bytes: int = MAX_FILE) -> Path:
    """Reject absolute paths, links and ambiguous Windows/POSIX components."""
    if type(max_bytes) is not int or max_bytes not in {MAX_FILE, MAX_REPLAY_FILE}:
        raise ReportError("unsupported archive entry size ceiling")
    if not isinstance(relative, str) or "\\" in relative or ":" in relative or "\0" in relative:
        raise ReportError("archive path must be a relative POSIX path")
    parts = PurePosixPath(relative).parts
    if not parts or relative != "/".join(parts) or relative.startswith("/") or any(p in {".", ".."} or p.endswith((".", " ")) for p in relative.split("/")):
        raise ReportError("unsafe archive path")
    for part in parts:
        if part.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
            raise ReportError("reserved archive component")
    # Check the root chain before resolving it; resolving first hides a symlink
    # or Windows junction used as the evidence/report directory itself.
    absolute = root.absolute()
    for parent in (*reversed(absolute.parents), absolute):
        if parent.is_symlink() or parent.is_junction():
            raise ReportError("archive root links are forbidden")
    base = root.resolve(strict=True)
    candidate = base
    for part in parts:
        candidate = candidate / part
        if candidate.is_symlink() or candidate.is_junction():
            raise ReportError("archive links are forbidden")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(base) or not resolved.is_file():
        raise ReportError("archive entry is not a contained regular file")
    if resolved.stat().st_size > max_bytes:
        raise ReportError("archive entry exceeds size cap")
    return resolved


def _file_hash(path: Path, ceiling: int) -> str:
    value = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while block := stream.read(65536):
            total += len(block)
            if total > ceiling:
                raise ReportError("archive entry grew beyond declared type ceiling")
            value.update(block)
    return value.hexdigest()


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReportError("duplicate JSON key")
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    if path.stat().st_size > MAX_FILE:
        raise ReportError("JSON exceeds size cap")
    def invalid(value: str) -> None:
        raise ReportError(f"non-finite JSON number: {value}")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object,
                          parse_constant=invalid)
    except (UnicodeError, RecursionError) as error:
        raise ReportError("invalid UTF-8 or JSON nesting") from error


def build_report(root: Path, evidence_paths: list[str], summary: dict[str, Any],
                 *, origin: str, campaign_id: str, scoring_bundle: str,
                 replay_records: dict[str, str] | None = None) -> dict[str, Any]:
    if not isinstance(origin, str) or origin not in {"fixture", "live"} or not isinstance(campaign_id, str) or not campaign_id:
        raise ReportError("explicit fixture/live origin and campaign ID required")
    if not isinstance(evidence_paths, list) or not evidence_paths or len(evidence_paths) > MAX_FILES or any(not isinstance(p, str) for p in evidence_paths):
        raise ReportError("bounded evidence path list required")
    if len(evidence_paths) != len({p.casefold() for p in evidence_paths}):
        raise ReportError("nonempty unique evidence inventory required")
    if not isinstance(scoring_bundle, str) or scoring_bundle not in evidence_paths:
        raise ReportError("scoring bundle must be in retained inventory")
    replay_records = {} if replay_records is None else replay_records
    if not isinstance(replay_records, dict) or any(
        not isinstance(p, str) or p not in evidence_paths or not isinstance(h, str)
        or len(h) != 64 or any(c not in "0123456789abcdef" for c in h)
        for p, h in replay_records.items()
    ):
        raise ReportError("replay records require inventory paths and canonical body SHA256 commitments")
    if scoring_bundle in replay_records:
        raise ReportError("scoring bundle must be a data entry")
    ceilings = {p: MAX_REPLAY_FILE if p in replay_records else MAX_FILE for p in evidence_paths}
    files = {p: safe_file(root, p, max_bytes=ceilings[p]) for p in evidence_paths}
    if sum(p.stat().st_size for p in files.values()) > MAX_ARCHIVE:
        raise ReportError("evidence archive exceeds total size cap")
    entries = []
    for path in sorted(files):
        raw_hash = _file_hash(files[path], ceilings[path])
        if path in replay_records:
            # The external replay commitment covers the canonical envelope body,
            # excluding record_sha256. It is never the raw archive file hash.
            try:
                from bbr.replay import load_record
            except ImportError as error:
                raise ReportError("replay verifier producer unavailable") from error
            load_record(root, path, expected_record_sha256=replay_records[path])
        entries.append({"path": path, "kind": "replay" if path in replay_records else "data",
                        "sha256": raw_hash, "replay_record_sha256": replay_records.get(path)})
    bundle = read_json(safe_file(root, scoring_bundle))
    bundle_fields = {"schema", "registration", "partitions", "campaign_receipt", "row_shards"}
    if not isinstance(bundle, dict) or not isinstance(bundle.get("schema"), str):
        raise ReportError("closed frozen scoring bundle required")
    has_analysis = bundle["schema"] == "bbr.scoring-bundle.v4"
    has_resources = bundle["schema"] == "bbr.scoring-bundle.v3" or (
        has_analysis and bundle.get("resource_sources") is not None)
    if has_resources or has_analysis:
        bundle_fields.add("resource_sources")
    if has_analysis:
        bundle_fields.add("domain_sources")
    if bundle["schema"] not in {"bbr.scoring-bundle.v2", "bbr.scoring-bundle.v3", "bbr.scoring-bundle.v4"} or set(bundle) != bundle_fields:
        raise ReportError("unsupported or nonclosed scoring bundle")
    if not isinstance(bundle["row_shards"], list) or not bundle["row_shards"] or any(not isinstance(p, str) for p in bundle["row_shards"]):
        raise ReportError("nonempty retained row-shard list required")
    references = [bundle["partitions"], bundle["campaign_receipt"], *bundle["row_shards"]]
    if has_resources:
        references.append(bundle["resource_sources"])
    if has_analysis and bundle["domain_sources"] is not None:
        references.append(bundle["domain_sources"])
    if any(not isinstance(p, str) for p in references) or len(references) != len(set(references)) or scoring_bundle in references or any(p not in files for p in references):
        raise ReportError("unique bundle inputs must be retained in evidence inventory")
    if any(p in replay_records for p in references):
        raise ReportError("scoring inputs must be bounded data entries, not replay records")
    # evaluation/ deliberately remains outside the installed wheel. A verifier
    # needs that frozen harness on its module path; absence is an explicit refusal.
    try:
        preregister = importlib.import_module("evaluation.preregister")
        scorer = importlib.import_module("evaluation.run")
    except ImportError as error:
        raise ReportError("frozen evaluation harness unavailable") from error
    registration = preregister.registration_from_dict(bundle["registration"])
    if registration.origin != origin or registration.edition != campaign_id:
        raise ReportError("report and preregistration provenance differ")
    rows = []
    for path in bundle["row_shards"]:
        shard = read_json(files[path])
        if not isinstance(shard, list) or len(shard) + len(rows) > len(registration.final_keys):
            raise ReportError("bounded retained row-shard arrays required")
        rows.extend(shard)
    partitions_data = read_json(files[bundle["partitions"]])
    receipt_data = read_json(files[bundle["campaign_receipt"]])
    recomputed = scorer.retained_report(registration, rows,
        partitions=partitions_data, campaign_receipt=receipt_data)
    if canonical(recomputed) != canonical(summary):
        raise ReportError("summary differs from retained-observation recomputation")
    strata_summary = None
    domains_summary = None
    if has_analysis:
        try:
            strata = importlib.import_module("evaluation.strata")
        except ImportError as error:
            raise ReportError("retained strata producer unavailable") from error
        base_keys = {"registration_sha256", "partitions_sha256", "campaign_lock_sha256",
                     "origin", "complete", "rows", "summaries", "verification"}
        base_score = {key: recomputed[key] for key in base_keys}
        strata_summary = strata.summarize_strata(registration, rows,
            partitions=partitions_data, campaign_receipt=receipt_data,
            expected_score_sha256=preregister.digest(base_score))
        if bundle["domain_sources"] is None:
            domains_summary = {"status": "not_supplied", "source_recomputed": False,
                "reason": "No retained domain sources supplied; no certificate/calibration asserted.",
                "summaries": []}
        else:
            from .domain_join import recompute_domains
            domains_summary = recompute_domains(root,
                read_json(files[bundle["domain_sources"]]), files=files,
                inventory={entry["path"]: entry for entry in entries},
                registration=registration, partitions=partitions_data,
                campaign_receipt=receipt_data, primary_rows=rows)
    resource_summary = None
    if has_resources:
        from .resource_join import recompute_resources

        inventory = {entry["path"]: entry for entry in entries}
        scoring_inputs = {"registration_sha256": registration.sha256,
            "partitions": bundle["partitions"],
            "campaign_receipt": bundle["campaign_receipt"],
            "row_shards": bundle["row_shards"]}
        resource_summary = recompute_resources(root,
            read_json(files[bundle["resource_sources"]]), files=files,
            inventory=inventory, scoring_inputs=scoring_inputs, score=recomputed,
            registration=registration)
    if any(_file_hash(safe_file(root, e["path"], max_bytes=ceilings[e["path"]]),
                      ceilings[e["path"]]) != e["sha256"] for e in entries):
        raise ReportError("evidence changed during recomputation")
    body = {"schema": "bbr.report.v5" if has_analysis else "bbr.report.v4" if has_resources else "bbr.report.v3", "campaign_id": campaign_id,
            "origin": origin, "label": BANNER if origin == "fixture" else "LIVE RETAINED EVIDENCE",
            "verification_scope": "retained-evidence consistency only",
            "runtime_validation": "unverified", "evidence": entries,
            "scoring_bundle": scoring_bundle, "summary": summary}
    if has_resources:
        body["resources"] = resource_summary
    if has_analysis:
        body["strata"] = strata_summary
        body["domains"] = domains_summary
    canonical(body)  # Reject non-JSON/non-finite values before writing anything.
    return {**body, "body_sha256": digest(canonical(body))}


def _markdown_data(value: str) -> str:
    return "".join(f"&#{ord(c)};" if not c.isalnum() and c != " " else c for c in value)


def _strata_views(report: dict[str, Any]) -> list[tuple[str, list[str], list[dict]]]:
    if "strata" not in report:
        return []
    strata = report["strata"]
    if not isinstance(strata, dict) or strata.get("schema") != "bbr.strata.v1" or not isinstance(strata.get("tables"), dict):
        raise ReportError("supported strata tables required for rendering")
    output = []
    dimensions = ("origin", "model", "arm", "family_id", "codec", "compiler", "optimization", "tier")
    metrics = ["scheduled", "nominal_valid_pass", "visible_pass", "malformed_pass",
               "primary_identity_group_estimate", "primary_identity_group_reason", "unknown_rows", "status_counts"]
    for name in ("by_model_arm", "by_family", "by_codec", "by_compiler", "by_optimization", "by_tier"):
        rows = strata["tables"].get(name)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ReportError("strata table row list required")
        columns = [key for key in dimensions if any(key in row for row in rows)] + metrics
        output.append((name, columns, rows))
    return output


def _cell(value: Any) -> str:
    return value if isinstance(value, str) else canonical(value).decode("ascii")


def render_markdown(report: dict[str, Any]) -> str:
    tables = ""
    for name, columns, rows in _strata_views(report):
        tables += "\n\n## " + name + "\n\n| " + " | ".join(columns) + " |\n"
        tables += "| " + " | ".join("---" for _ in columns) + " |\n"
        for row in rows:
            tables += "| " + " | ".join(_markdown_data(_cell(row.get(key))) for key in columns) + " |\n"
    return ("# Binary behavior recovery\n\n" + _markdown_data(report["label"]) +
            "\n\nRetained-evidence consistency only; runtime unverified.\n\n" +
            (tables + "\n\n" if tables else "") +
            _markdown_data(canonical(report).decode("ascii")) + "\n")


def render_html(report: dict[str, Any]) -> str:
    tables = ""
    for name, columns, rows in _strata_views(report):
        tables += "<h2>" + html.escape(name) + "</h2><table><thead><tr>"
        tables += "".join("<th>" + html.escape(key) + "</th>" for key in columns) + "</tr></thead><tbody>"
        for row in rows:
            tables += "<tr>" + "".join("<td>" + html.escape(_cell(row.get(key))) + "</td>" for key in columns) + "</tr>"
        tables += "</tbody></table>"
    return ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'none'\">"
            "<title>Binary behavior recovery</title><h1>Binary behavior recovery</h1><p>" +
            html.escape(report["label"]) + "</p><p>Retained-evidence consistency only; "
            "runtime unverified.</p>" + tables + "<pre>" + html.escape(canonical(report).decode("ascii")) +
            "</pre></html>\n")


def write_report(destination: Path, report: dict[str, Any]) -> None:
    """Create a new report directory; never overwrite an existing archive."""
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "report.json").write_bytes(canonical(report) + b"\n")
    (destination / "report.html").write_bytes(render_html(report).encode("utf-8"))
    (destination / "report.md").write_bytes(render_markdown(report).encode("utf-8"))


def verify_report(report_path: Path, evidence_root: Path) -> dict[str, Any]:
    if report_path.name != "report.json":
        raise ReportError("report entrypoint must be report.json")
    report_path = safe_file(report_path.parent, report_path.name)
    report = read_json(report_path)
    fields = {"schema", "campaign_id", "origin", "label", "verification_scope",
              "runtime_validation", "evidence", "scoring_bundle", "summary", "body_sha256"}
    if not isinstance(report, dict) or not isinstance(report.get("schema"), str):
        raise ReportError("unsupported report schema")
    if report["schema"] == "bbr.report.v4" or (report["schema"] == "bbr.report.v5" and "resources" in report):
        fields.add("resources")
    if report["schema"] == "bbr.report.v5":
        fields.update({"strata", "domains"})
    if set(report) != fields or report["schema"] not in {"bbr.report.v3", "bbr.report.v4", "bbr.report.v5"}:
        raise ReportError("unsupported report schema")
    body = {k: v for k, v in report.items() if k != "body_sha256"}
    if digest(canonical(body)) != report["body_sha256"]:
        raise ReportError("report digest mismatch")
    if not isinstance(report["evidence"], list) or any(
        not isinstance(e, dict) or set(e) != {"path", "kind", "sha256", "replay_record_sha256"}
        or not isinstance(e["path"], str) or not isinstance(e["sha256"], str)
        or len(e["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in e["sha256"])
        or not isinstance(e["kind"], str) or e["kind"] not in {"data", "replay"}
        or (e["kind"] == "data" and e["replay_record_sha256"] is not None)
        or (e["kind"] == "replay" and (not isinstance(e["replay_record_sha256"], str)
            or len(e["replay_record_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in e["replay_record_sha256"])))
        for e in report["evidence"]
    ):
        raise ReportError("invalid evidence inventory")
    expected = build_report(evidence_root, [e["path"] for e in report["evidence"]],
                            report["summary"], origin=report["origin"],
                            campaign_id=report["campaign_id"], scoring_bundle=report["scoring_bundle"],
                            replay_records={e["path"]: e["replay_record_sha256"]
                                            for e in report["evidence"] if e["kind"] == "replay"})
    if canonical(expected) != canonical(report):
        raise ReportError("evidence or provenance mismatch")
    for name, rendered in (("report.html", render_html(report)), ("report.md", render_markdown(report))):
        retained = safe_file(report_path.parent, name)
        if retained.read_bytes() != rendered.encode("utf-8"):
            raise ReportError(f"rendered view mismatch: {name}")
    return {"status": "retained_evidence_consistent", "fresh_execution": False,
            "runtime_validation": "unverified", "files_checked": len(report["evidence"]),
            "origin": report["origin"], "summary_recomputed": True,
            "resources_recomputed": "resources" in report,
            "resource_status": "retained_sources_recomputed" if "resources" in report
                               else "not_supplied_score_only",
            "strata_recomputed": report["schema"] == "bbr.report.v5",
            "domains_recomputed": report.get("domains", {}).get("source_recomputed", False),
            "reason": "Metrics recomputed from retained observations; no fresh execution or authenticity claim."}
