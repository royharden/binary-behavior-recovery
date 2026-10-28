"""Join inventory-backed retained resources with an already verified score.

No ledger database, provider, hidden stream or subject is opened here. Accounting
belongs exclusively to resource_metrics.summarize_resources. Inventory hashes and
this join establish retained consistency, not authentic dispatch or custody.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

MAX_RECEIPTS = 1344


def recompute_resources(root: Path, resource_sources: dict, *,
                        files: dict[str, Path], inventory: dict[str, dict],
                        scoring_inputs: dict, score: dict,
                        registration: Any) -> dict:
    """Recompute from bounded data entries; never accept detached costs/passes.

    ``resource_sources`` is schema/ledger_report/receipts, with schema
    bbr.resource-sources.v1 and relative inventory paths; optional model_bindings
    is accepted only with its preregistration pin. ``scoring_inputs`` is
    exactly registration_sha256/partitions/campaign_receipt/row_shards. The parent
    archive must first recompute ``score`` with the frozen evaluation harness.
    """
    # Local imports permit archive.build_report to invoke this module without an
    # archive/resource join import cycle.
    from .archive import MAX_FILE, MAX_FILES, ReportError, _file_hash
    from .archive import canonical, digest, read_json, safe_file

    def closed(value: object, fields: set[str], label: str) -> dict:
        if not isinstance(value, dict) or set(value) != fields:
            raise ReportError(f"closed {label} shape required")
        return value

    def sha256(value: object) -> str:
        if (not isinstance(value, str) or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)):
            raise ReportError("canonical SHA256 commitment required")
        return value

    def data_entry(relative: object) -> tuple[Path, dict]:
        if not isinstance(relative, str) or relative not in files or relative not in inventory:
            raise ReportError("resource/scoring source must be in retained inventory")
        entry = closed(inventory[relative],
            {"path", "kind", "sha256", "replay_record_sha256"}, "data inventory entry")
        if (entry["path"] != relative or entry["kind"] != "data"
                or entry["replay_record_sha256"] is not None):
            raise ReportError("resource/scoring sources must be bounded data entries")
        expected = sha256(entry["sha256"])
        path = safe_file(root, relative)  # Default 16 MiB; replay exception forbidden.
        retained = files[relative]
        if not isinstance(retained, Path) or retained.resolve(strict=True) != path:
            raise ReportError("source path differs from validated inventory file")
        if _file_hash(path, MAX_FILE) != expected:
            raise ReportError("retained source differs from inventory hash")
        return path, {"path": relative, "sha256": expected}

    registration.validate()
    pins = dict(registration.pins)
    binding_pin = pins.get("model_bindings")
    source_fields = {"schema", "ledger_report", "receipts"}
    if isinstance(resource_sources, dict) and "model_bindings" in resource_sources:
        if binding_pin is None:
            raise ReportError("unpinned model-binding source cannot authorize pass counts")
        source_fields.add("model_bindings")
    closed(resource_sources, source_fields, "resource source")
    if resource_sources["schema"] != "bbr.resource-sources.v1":
        raise ReportError("unsupported resource source schema")
    receipt_paths = resource_sources["receipts"]
    if (not isinstance(receipt_paths, list) or len(receipt_paths) > MAX_RECEIPTS
            or any(not isinstance(p, str) for p in receipt_paths)):
        raise ReportError("bounded retained receipt path list required")
    ledger_path = resource_sources["ledger_report"]
    resource_paths = [ledger_path, *receipt_paths]
    if "model_bindings" in resource_sources:
        resource_paths.append(resource_sources["model_bindings"])
    if (any(not isinstance(p, str) for p in resource_paths)
            or len(set(p.casefold() for p in resource_paths)) != len(resource_paths)):
        raise ReportError("unique ledger/receipt data source paths required")

    closed(scoring_inputs, {"registration_sha256", "partitions", "campaign_receipt", "row_shards"},
           "verified scoring input")
    shards = scoring_inputs["row_shards"]
    if (not isinstance(shards, list) or not shards or len(shards) > MAX_FILES
            or any(not isinstance(p, str) for p in shards)):
        raise ReportError("bounded scoring row-shard list required")
    scoring_paths = [scoring_inputs["partitions"], scoring_inputs["campaign_receipt"], *shards]
    if (any(not isinstance(p, str) for p in scoring_paths)
            or len(set(p.casefold() for p in scoring_paths)) != len(scoring_paths)):
        raise ReportError("unique scoring data source paths required")
    if set(p.casefold() for p in resource_paths) & set(p.casefold() for p in scoring_paths):
        raise ReportError("resource sources cannot alias scoring inputs")

    registration_sha256 = registration.sha256
    if (sha256(scoring_inputs["registration_sha256"]) != registration_sha256
            or not isinstance(score, dict)
            or score.get("registration_sha256") != registration_sha256
            or score.get("origin") != registration.origin):
        raise ReportError("resource join requires the verified score registration/origin")
    if score.get("partitions_sha256") != dict(registration.pins)["partitions"]:
        raise ReportError("verified score partition commitment differs from registration")
    score_lock = sha256(score.get("campaign_lock_sha256"))
    scoring_entries = {relative: data_entry(relative)[1] for relative in scoring_paths}
    score_commitment = {
        "schema": "bbr.score-input-commitment.v1",
        "registration_sha256": registration_sha256,
        "partitions_sha256": score["partitions_sha256"],
        "campaign_lock_sha256": score_lock,
        "partitions": scoring_entries[scoring_inputs["partitions"]],
        "campaign_receipt": scoring_entries[scoring_inputs["campaign_receipt"]],
        "row_shards": [scoring_entries[p] for p in shards],
        "score_sha256": digest(canonical(score)),
    }

    ledger_file, ledger_entry = data_entry(ledger_path)
    ledger_report = read_json(ledger_file)
    receipts = []
    resource_entries = [ledger_entry]
    for relative in receipt_paths:
        path, entry = data_entry(relative)
        receipt = read_json(path)
        if not isinstance(receipt, dict):
            raise ReportError("each retained call-resource receipt must be an object")
        receipts.append(receipt)
        resource_entries.append(entry)
    if not isinstance(ledger_report, dict):
        raise ReportError("retained ledger snapshot must be an object")

    bindings = []
    if "model_bindings" in resource_sources:
        path, entry = data_entry(resource_sources["model_bindings"])
        mapping = closed(read_json(path), {"schema", "edition", "origin", "bindings"},
                         "model binding source")
        if (mapping["schema"] != "bbr.model-bindings.v1"
                or mapping["edition"] != registration.edition
                or mapping["origin"] != registration.origin
                or digest(canonical(mapping)) != sha256(binding_pin)):
            raise ReportError("model bindings differ from frozen edition/origin/pin")
        if not isinstance(mapping["bindings"], list) or len(mapping["bindings"]) != 2:
            raise ReportError("exactly two frozen model/config bindings required")
        for binding in mapping["bindings"]:
            closed(binding, {"score_model", "model_id", "config_id", "request_model_config_sha256"},
                   "model binding")
            if any(not isinstance(binding[name], str) or not binding[name].strip()
                   or len(binding[name]) > 256 for name in ("score_model", "model_id", "config_id")):
                raise ReportError("bounded exact model/config identity strings required")
            sha256(binding["request_model_config_sha256"])
            bindings.append(binding)
        if ({b["score_model"] for b in bindings} != set(registration.models)
                or len({(b["model_id"], b["config_id"]) for b in bindings}) != 2):
            raise ReportError("model bindings must cover score identities and unique model/config pairs")
        resource_entries.append(entry)
        score_commitment["model_bindings"] = entry
        score_commitment["model_bindings_sha256"] = binding_pin

    score_source_sha256 = digest(canonical(score_commitment))
    known_tasks = {cell.task_id for cell in registration.cells}
    binding_by_pair = {(b["model_id"], b["config_id"]): b for b in bindings}
    present_pairs = set()
    initial_tasks: dict[tuple[str, str], set[str]] = {}
    for receipt in receipts:
        if (receipt.get("campaign_id") != registration.edition
                or receipt.get("origin") != registration.origin
                or not isinstance(receipt.get("task_id"), str)
                or receipt["task_id"] not in known_tasks):
            raise ReportError("resource receipt differs from frozen campaign/origin/task roster")
        if any(not isinstance(receipt.get(name), str) or not receipt[name]
               for name in ("model_id", "config_id", "call_id")):
            raise ReportError("resource receipt model/config/call identities required")
        pair = (receipt["model_id"], receipt["config_id"])
        present_pairs.add(pair)
        if receipt["call_id"] == "M:0":
            initial_tasks.setdefault(pair, set()).add(receipt["task_id"])
        if bindings:
            binding = binding_by_pair.get(pair)
            request = receipt.get("request")
            if binding is None or not isinstance(request, dict):
                raise ReportError("resource receipt has no frozen model/config binding")
            config = closed(request.get("model_config"),
                {"model_id", "config_id", "endpoint_id", "seed", "origin"}, "request model config")
            if digest(canonical(config)) != binding["request_model_config_sha256"]:
                raise ReportError("retained request full model configuration differs from binding")

    pass_counts = []
    if bindings:
        if type(score.get("complete")) is not bool or not isinstance(score.get("summaries"), list):
            raise ReportError("verified fixed-population score summaries required")
        for binding in bindings:
            pair = (binding["model_id"], binding["config_id"])
            if pair not in present_pairs:
                continue  # No resource group exists; do not invent one or costs.
            for arm in ("M", "R", "P"):
                selected = [s for s in score["summaries"] if isinstance(s, dict)
                            and s.get("model") == binding["score_model"] and s.get("arm") == arm]
                if len(selected) != 1:
                    raise ReportError("one exact verified score summary per model/arm required")
                selected_score = selected[0]
                counts = closed(selected_score.get("nominal_valid_pass"), {"n", "N"},
                                "verified nominal pass count")
                if (selected_score.get("origin") != registration.origin
                        or type(selected_score.get("complete")) is not bool
                        or type(selected_score.get("scheduled")) is not int
                        or selected_score["scheduled"] != 96
                        or type(counts["N"]) is not int or counts["N"] != 96
                        or type(counts["n"]) is not int or not 0 <= counts["n"] <= 96):
                    raise ReportError("verified pass count must retain the exact96-cell population")
                passed = counts["n"]
                reason = None
                if not score["complete"] or not selected_score["complete"]:
                    passed, reason = None, "incomplete_fixed_population"
                elif initial_tasks.get(pair, set()) != known_tasks:
                    passed, reason = None, "incomplete_retained_resource_task_population"
                pass_counts.append({"model_id": pair[0], "config_id": pair[1], "arm": arm,
                    "passed_tasks": passed, "reason": reason, "source_sha256": score_source_sha256})
    try:
        from .resource_metrics import summarize_resources
    except ImportError as error:
        raise ReportError("retained resource summarizer producer unavailable") from error

    summary = summarize_resources(ledger_report, receipts,
        campaign_id=registration.edition, origin=registration.origin, pass_counts=pass_counts)
    if not isinstance(summary, dict):
        raise ReportError("resource summarizer returned a non-object")
    canonical(summary)
    return {"summary": summary, "score_source_sha256": score_source_sha256,
            "source_entries": resource_entries, "pass_counts": pass_counts,
            "pass_count_binding_status": "verified" if bindings else "unavailable",
            "pass_count_binding_reason": None if bindings else "Frozen score model_id/config_id binding unavailable; no USD/pass asserted.",
            "verification_scope": "retained-resource consistency only; no dispatch or custody authentication"}
