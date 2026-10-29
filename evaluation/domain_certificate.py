"""Retained finite-domain consistency and precommitted sample calibration.

No enumeration/generation, subject execution, hidden opening or file/DB access.
All authority/digests are supplied by a trusted caller; hashes cannot authenticate
custody, independence, admission or whether the narrated executions occurred.
"""
from __future__ import annotations

import json
from hashlib import sha256

from bbr.contracts import Domain, PairOutcome
from bbr.corpus.codecs import decode, encode
from bbr.differential import COMPARATOR_VERSION, compare_observations
from .exposure import validate_open_receipt
from .preregister import Registration, closed, digest, require_digest, text
from .validate import canonical_hex, frozen_partitions

_IDENTITY = {"task_id", "model", "arm", "candidate_sha256"}
_COMPARISON = {"artifact_sha256", "execution_contract_sha256", "comparator_version"}
_PINS = {"registration_sha256", "lock_sha256", "partition_sha256", "domain_policy_sha256",
         "canonical_plan_sha256", "observed_probes_sha256", "records_sha256"}
_SCOPE = "retained consistency only; not authentic custody or fresh execution"


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (TypeError, RecursionError) as error:
        raise ValueError("canonical JSON value required") from error


def _name(value: object, label: str) -> str:
    value = text(value, label)
    if len(value) > 256:
        raise ValueError(f"bounded {label} required")
    return value


def _unavailable(reason: str, identity: dict | None = None, *,
                 unavailable_checks: list[str] | None = None) -> dict:
    result = {"schema": "bbr.domain-summary.v1", "status": "not_qualified", "reason": reason,
            "identity": identity, "provenance": None, "certificate": None,
            "calibration": None, "verification_scope": _SCOPE}
    if unavailable_checks is not None:
        result["unavailable_checks"] = unavailable_checks
    return result


def _public_domain(raw: dict) -> Domain:
    closed(raw, {"width", "input_arity", "output_arity", "minimum", "maximum"}, "public Domain")
    if any(type(value) is not int for value in raw.values()):
        raise ValueError("strict integer public Domain fields required")
    return Domain.model_validate_json(_canonical(raw))


def _policy(registration: Registration, policy: dict, rosters: dict | None) -> dict:
    closed(policy, {"schema", "tasks"}, "domain policy")
    if policy["schema"] != "bbr.domain-policy.v1" or type(policy["tasks"]) is not list:
        raise ValueError("domain policy schema/list required")
    if len(policy["tasks"]) != 96 or digest(policy) != dict(registration.pins)["domain_policy"]:
        raise ValueError("domain policy differs from frozen commitment/roster")
    cells = {c.task_id: c for c in registration.cells}
    entries, family_domains, family_plans, family_samples = {}, {}, {}, {}
    for entry in policy["tasks"]:
        closed(entry, {"task_id", "domain", "canonical_plan_sha256", "sampling"}, "domain task")
        task = _name(entry["task_id"], "task")
        if task not in cells or task in entries:
            raise ValueError("duplicate/outside-roster domain task")
        cell = cells[task]
        pin = require_digest(entry["canonical_plan_sha256"])
        if cell.family_id in family_plans and family_plans[cell.family_id] != pin:
            raise ValueError("variants changed frozen canonical input-plan identity")
        family_plans[cell.family_id] = pin
        if entry["domain"] is not None:
            domain = _public_domain(entry["domain"])
            capacity = (domain.maximum-domain.minimum+1) ** domain.input_arity
            if ((cell.tier == "finite" and capacity != 256) or
                    (cell.tier == "ordinary" and capacity < 328)):
                raise ValueError("declared Domain contradicts frozen tier capacity")
            if cell.family_id in family_domains and family_domains[cell.family_id] != entry["domain"]:
                raise ValueError("codec/compiler variants changed declared Domain")
            family_domains[cell.family_id] = entry["domain"]
        sample = entry["sampling"]
        if sample is not None:
            if cell.tier != "finite":
                raise ValueError("finite calibration policy cannot label ordinary tasks")
            closed(sample, {"recipe_id", "size", "canonical_keys"}, "sampling policy")
            _name(sample["recipe_id"], "sample recipe")
            if type(sample["size"]) is not int or not 1 <= sample["size"] <= 256:
                raise ValueError("sample size must be1..256")
            keys = sample["canonical_keys"]
            if type(keys) is not list or len(keys) != min(sample["size"], 184):
                raise ValueError("precommitted sample subset size mismatch")
            for key in keys:
                _name(key, "sample canonical key")
            if len(set(keys)) != len(keys):
                raise ValueError("sample repeats canonical keys")
            if rosters is not None:
                private = {key for _, key in rosters[task]["private_valid"]}
                if not set(keys) <= private:
                    raise ValueError("sample escapes frozen private184")
            if cell.family_id in family_samples and family_samples[cell.family_id] != sample:
                raise ValueError("variants changed precommitted sampling recipe/subset")
            family_samples[cell.family_id] = sample
        entries[task] = entry
    if set(entries) != set(cells):
        raise ValueError("all frozen domain tasks required")
    return entries


def _paired_identity(registration: Registration, source: dict, finals: dict | None,
                     *, comparison: bool) -> tuple:
    """Validate a present source against every available identity authority."""
    for name in ("task_id", "model", "arm"):
        _name(source[name], name)
    require_digest(source["candidate_sha256"])
    key = tuple(source[name] for name in ("task_id", "model", "arm"))
    if key not in registration.final_keys:
        raise ValueError("task/model/arm outside frozen registration")
    cell = next(c for c in registration.cells if c.task_id == key[0])
    if comparison:
        require_digest(source["artifact_sha256"])
        require_digest(source["execution_contract_sha256"])
        if (source["artifact_sha256"] != cell.artifact_sha256 or
                source["execution_contract_sha256"] != cell.execution_contract_sha256 or
                source["comparator_version"] != COMPARATOR_VERSION):
            raise ValueError("retained comparison differs from registered execution/comparator")
    if finals is not None:
        final = finals[key]
        if final["status"] != "candidate":
            raise ValueError("retained candidate claim conflicts with noncandidate final")
        if source["candidate_sha256"] != final["candidate_sha256"]:
            raise ValueError("retained candidate differs from locked final")
    return key, cell


def summarize_domain(registration: Registration, *, domain: Domain | None,
                     partitions: dict | None, campaign_receipt: dict | None,
                     domain_policy: dict | None, binding: dict | None,
                     expected_binding_sha256: str | None, observed_probes: dict | None,
                     records: list[dict] | None) -> dict:
    """Compare only caller-retained records after the existing final-lock gate.

    Missing truth yields null/not_qualified. Present malformed or conflicting
    supplied evidence raises ValueError. No sample is selected from outcomes.
    """
    sources = ((domain, "domain_truth_unavailable"),
               (partitions, "frozen_partitions_unavailable"),
               (campaign_receipt, "post_final_lock_receipt_unavailable"),
               (domain_policy, "domain_sampling_policy_unavailable"),
               (binding, "paired_identity_binding_unavailable"),
               (expected_binding_sha256, "trusted_binding_commitment_unavailable"),
               (observed_probes, "observed_probe_commitment_unavailable"),
               (records, "retained_records_unavailable"))
    # Validate present sources BEFORE any unavailable result. Missing dependencies
    # disable only their joins, never unrelated local or retained-byte checks.
    if type(registration) is not Registration:
        raise ValueError("exact Registration required")
    registration.validate()
    public_domain = None
    if domain is not None:
        if type(domain) is not Domain:
            raise ValueError("exact public Domain required")
        public_domain = _public_domain(domain.model_dump(mode="json"))
    finals = validate_open_receipt(registration, campaign_receipt) if campaign_receipt is not None else None
    rosters = frozen_partitions(registration, partitions) if partitions is not None else None
    policy = _policy(registration, domain_policy, rosters) if domain_policy is not None else None
    if expected_binding_sha256 is not None:
        require_digest(expected_binding_sha256)
    target = None
    key = cell = None
    expected = {"registration_sha256": registration.sha256,
                "partition_sha256": dict(registration.pins)["partitions"],
                "domain_policy_sha256": dict(registration.pins)["domain_policy"]}
    if campaign_receipt is not None:
        expected["lock_sha256"] = campaign_receipt["lock_sha256"]
    if binding is not None:
        closed(binding, {"schema"} | _IDENTITY | _COMPARISON | _PINS, "domain binding")
        if binding["schema"] != "bbr.domain-binding.v1":
            raise ValueError("unknown domain binding schema")
        key, cell = _paired_identity(registration, binding, finals, comparison=True)
        for field in _PINS:
            require_digest(binding[field])
        if expected_binding_sha256 is not None and digest(binding) != expected_binding_sha256:
            raise ValueError("domain binding differs from separate trusted commitment")
        target = binding
    probes = []
    if observed_probes is not None:
        closed(observed_probes, {"schema"} | _IDENTITY | {"lock_sha256", "public_input_hex"}, "observed probes")
        if observed_probes["schema"] != "bbr.observed-probes.v1":
            raise ValueError("unknown observed probe schema")
        probe_key, probe_cell = _paired_identity(registration, observed_probes, finals, comparison=False)
        require_digest(observed_probes["lock_sha256"])
        if campaign_receipt is not None and observed_probes["lock_sha256"] != campaign_receipt["lock_sha256"]:
            raise ValueError("observed probe lock mismatch")
        if target is not None and any(observed_probes[n] != target[n] for n in _IDENTITY | {"lock_sha256"}):
            raise ValueError("observed probe identity/lock mismatch")
        if target is None:
            target, key, cell = observed_probes, probe_key, probe_cell
        probes = observed_probes["public_input_hex"]
        if type(probes) is not list or len(probes) > 48:
            raise ValueError("bounded observed-probe list required")
        for raw in probes:
            canonical_hex(raw, 64)
        if len(set(probes)) != len(probes):
            raise ValueError("observed probes repeat")
        if probe_key[2] != "P" and probes:
            raise ValueError("non-probing arm cannot claim public observations")
        expected["observed_probes_sha256"] = digest(observed_probes)
    retained, raw_seen = [], set()
    if records is not None:
        if type(records) is not list or len(records) != 256:
            raise ValueError("exactly256 retained canonical comparisons required")
        for record in records:
            closed(record, _IDENTITY | _COMPARISON | {"stdin_hex", "outcome"}, "domain comparison")
            record_key, record_cell = _paired_identity(registration, record, finals, comparison=True)
            if target is not None and any(record[n] != target[n] for n in _IDENTITY):
                raise ValueError("retained comparison changes paired candidate identity")
            if target is None:
                target, key, cell = record, record_key, record_cell
            raw_hex = canonical_hex(record["stdin_hex"], 64)
            if raw_hex in raw_seen:
                raise ValueError("repeated retained canonical input")
            raw_seen.add(raw_hex)
            raw = bytes.fromhex(raw_hex)
            if type(record["outcome"]) is not dict:
                raise ValueError("shared PairOutcome JSON object required")
            pair = PairOutcome.model_validate_json(_canonical(record["outcome"]))
            if pair.input_sha256 != sha256(raw).hexdigest():
                raise ValueError("retained pair input digest mismatch")
            recomputed = compare_observations(pair.binary, pair.candidate, stdin_bytes=raw)
            if (pair.status, pair.reason) != (recomputed.status, recomputed.reason):
                raise ValueError("retained comparator status/reason drift")
            retained.append((raw_hex, pair))
        expected["records_sha256"] = digest(records)
    identity = {name: target[name] for name in sorted(_IDENTITY)} if target is not None else None
    entry = policy[key[0]] if policy is not None and key is not None else None
    if cell is not None:
        expected.update(artifact_sha256=cell.artifact_sha256,
                        execution_contract_sha256=cell.execution_contract_sha256,
                        comparator_version=COMPARATOR_VERSION)
    if entry is not None:
        expected["canonical_plan_sha256"] = entry["canonical_plan_sha256"]
        if (entry["domain"] is not None and public_domain is not None and
                entry["domain"] != public_domain.model_dump(mode="json")):
            raise ValueError("caller Domain differs from precommitted public Domain")
    # A present committed policy can validate retained inputs without fabricating
    # the separately required caller Domain or qualifying a partial result.
    validation_domain = public_domain
    if validation_domain is None and entry is not None and entry["domain"] is not None:
        validation_domain = _public_domain(entry["domain"])
    if binding is not None and any(binding[name] != pin for name, pin in expected.items()):
        raise ValueError("certificate comparison/policy/partition/lock/record pins mismatch")
    roster = rosters[key[0]] if rosters is not None and key is not None else None
    valid = None
    if roster is not None:
        valid = {raw: canonical for name in ("visible", "public_valid", "private_valid")
                 for raw, canonical in roster[name]}
        if cell.tier == "finite" and len(valid) != 256:
            raise ValueError("frozen full canonical roster must have256 values")
        if records is not None and raw_seen != set(valid):
            raise ValueError("missing/outside-frozen retained canonical comparison")
        if observed_probes is not None:
            allowed_public = {raw for name in ("public_valid", "public_malformed") for raw, _ in roster[name]}
            if not set(probes) <= allowed_public:
                raise ValueError("observed probes escape frozen public pool")

    def decode_input(raw: bytes) -> tuple[int, ...]:
        values = decode(raw, cell.codec, validation_domain.width)
        if (len(values) != validation_domain.input_arity or
                any(not validation_domain.minimum <= v <= validation_domain.maximum for v in values) or
                encode(values, cell.codec, validation_domain.width) != raw):
            raise ValueError("retained input outside canonical public Domain")
        return values

    if validation_domain is not None and cell is not None:
        for raw_hex, _ in retained:
            decode_input(bytes.fromhex(raw_hex))
        if valid is not None:
            # Count supplied values only; NEVER enumerate the declared domain.
            decoded = {decode_input(bytes.fromhex(raw)) for raw in valid}
            if len(decoded) != len(valid):
                raise ValueError("frozen raw roster repeats decoded canonical values")
    oracle_ok_by_input = {}
    for raw_hex, pair in retained:
        oracle_ok = pair.binary.status == "ok" and pair.binary.exit_code == 0
        if validation_domain is not None and cell is not None:
            try:
                outputs = decode(pair.binary.stdout_bytes, cell.codec, validation_domain.width,
                                 max_elements=validation_domain.output_arity)
                oracle_ok &= len(outputs) == validation_domain.output_arity
            except ValueError:
                oracle_ok = False
        oracle_ok_by_input[raw_hex] = oracle_ok
    missing = [reason for value, reason in sources if value is None]
    if missing:
        unavailable_checks = []
        if domain is None:
            unavailable_checks.append("caller-supplied Domain validation and commitment equality")
        if validation_domain is None:
            unavailable_checks.append("Domain-dependent input decoding, coverage and oracle-output arity")
        if partitions is None:
            unavailable_checks.append("record/probe pool membership, canonical coverage and private sample membership")
        if campaign_receipt is None:
            unavailable_checks.append("post-final-lock candidate and lock-receipt joins")
        if domain_policy is None:
            unavailable_checks.append("target precommitted Domain and canonical-plan/sample-policy joins")
        if binding is None:
            unavailable_checks.append("binding body and its source-commitment joins")
        if binding is None or expected_binding_sha256 is None:
            unavailable_checks.append("binding against separate trusted commitment")
        if observed_probes is None:
            unavailable_checks.append("observed-probe identity, pool membership and binding digest join")
        if records is None:
            unavailable_checks.append("retained comparison identity, input/comparator checks and binding digest join")
        if target is None:
            unavailable_checks.append("target-specific Domain, partition and policy joins; no paired identity available")
        unavailable_checks.append("certificate/calibration qualification and agreement; required source set incomplete")
        return _unavailable(missing[0], identity, unavailable_checks=unavailable_checks)
    if (public_domain.maximum-public_domain.minimum+1) ** public_domain.input_arity != 256:
        return _unavailable("not_exactly256_canonical_domain")
    if cell.tier != "finite":
        return _unavailable("registered_task_is_not_finite", identity)
    if entry["domain"] is None:
        return _unavailable("frozen_domain_truth_unavailable", identity)
    public_keys = {canonical for _, canonical in roster["public_valid"]}
    observed_keys = {valid[raw] for raw in probes if raw in valid}
    private_keys = {canonical for _, canonical in roster["private_valid"]}
    results = {}
    unknown_count, oracle_invalid_count = 0, 0
    for raw_hex, pair in retained:
        oracle_ok = oracle_ok_by_input[raw_hex]
        unknown = pair.status == "infrastructure_error"
        unknown_count += unknown
        oracle_invalid_count += not oracle_ok
        results[valid[raw_hex]] = pair.status == "equal" and oracle_ok and not unknown
    if len(results) != 256:
        raise ValueError("missing/repeated canonical retained comparison")
    qualified = not unknown_count and not oracle_invalid_count
    exhaustive = all(results.values()) if qualified else None
    private_agreement = all(results[k] for k in private_keys) if qualified else None
    certificate = {"status": "qualified" if qualified else "not_qualified",
        "label": "exhaustive_on_declared_domain" if qualified else None,
        "scope": "256 declared canonical values only; not arbitrary stdin strings",
        "canonical_total": 256, "visible_count": 8,
        "probe_observed_count": len(observed_keys),
        "public_but_unobserved_count": len(public_keys-observed_keys),
        "private_count": 184, "observed_malformed_probe_count": len(probes)-len(observed_keys),
        "infrastructure_unknown_count": unknown_count, "invalid_oracle_count": oracle_invalid_count,
        "all256_agreement": exhaustive, "primary184_private_agreement": private_agreement,
        "primary184_denominator": 184}
    sample = entry["sampling"]
    if sample is None:
        calibration = {"status": "not_qualified", "reason": "precommitted_sample_unavailable",
                       "sample_agreement": None, "false_pass_vs256": None, "false_pass_vs184": None}
    else:
        sample_pass = all(results[k] for k in sample["canonical_keys"]) if qualified else None
        calibration = {"status": "qualified" if qualified else "not_qualified",
            "reason": None if qualified else "infrastructure_or_oracle_truth_unavailable",
            "recipe_id": sample["recipe_id"], "requested_size": sample["size"],
            "effective_size": len(sample["canonical_keys"]), "private_population": 184,
            "exhausts_private_pool": len(sample["canonical_keys"]) == 184,
            "unseen_private_count": 184-len(sample["canonical_keys"]),
            "coverage_note": "no additional unseen private coverage" if sample["size"] >= 184 else "sampled private subset",
            "sample_agreement": sample_pass, "exhaustive256_agreement": exhaustive,
            "private184_agreement": private_agreement,
            "false_pass_vs256": sample_pass and not exhaustive if qualified else None,
            "false_pass_vs184": sample_pass and not private_agreement if qualified else None,
            "interpretation": "one exact paired task/model/arm/candidate event, not a population rate"}
    return {"schema": "bbr.domain-summary.v1", "status": "qualified" if qualified else "not_qualified",
            "reason": None if qualified else "infrastructure_or_oracle_truth_unavailable",
            "identity": identity, "provenance": {**expected, "records_sha256": binding["records_sha256"],
                "binding_sha256": expected_binding_sha256}, "certificate": certificate,
            "calibration": calibration, "verification_scope": _SCOPE}
