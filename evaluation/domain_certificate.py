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
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _name(value: object, label: str) -> str:
    value = text(value, label)
    if len(value) > 256:
        raise ValueError(f"bounded {label} required")
    return value


def _unavailable(reason: str, identity: dict | None = None) -> dict:
    return {"schema": "bbr.domain-summary.v1", "status": "not_qualified", "reason": reason,
            "identity": identity, "provenance": None, "certificate": None,
            "calibration": None, "verification_scope": _SCOPE}


def _public_domain(raw: dict) -> Domain:
    closed(raw, {"width", "input_arity", "output_arity", "minimum", "maximum"}, "public Domain")
    return Domain.model_validate_json(_canonical(raw))


def _policy(registration: Registration, policy: dict, rosters: dict) -> dict:
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
            private = {key for _, key in rosters[task]["private_valid"]}
            if len(set(keys)) != len(keys) or not set(keys) <= private:
                raise ValueError("sample repeats or escapes frozen private184")
            if cell.family_id in family_samples and family_samples[cell.family_id] != sample:
                raise ValueError("variants changed precommitted sampling recipe/subset")
            family_samples[cell.family_id] = sample
        entries[task] = entry
    if set(entries) != set(cells):
        raise ValueError("all frozen domain tasks required")
    return entries


def summarize_domain(registration: Registration, *, domain: Domain | None,
                     partitions: dict | None, campaign_receipt: dict | None,
                     domain_policy: dict | None, binding: dict | None,
                     expected_binding_sha256: str | None, observed_probes: dict | None,
                     records: list[dict] | None) -> dict:
    """Compare only caller-retained records after the existing final-lock gate.

    Missing truth yields null/not_qualified. Present malformed or conflicting
    supplied evidence raises ValueError. No sample is selected from outcomes.
    """
    for value, reason in ((domain, "domain_truth_unavailable"),
                          (partitions, "frozen_partitions_unavailable"),
                          (campaign_receipt, "post_final_lock_receipt_unavailable"),
                          (domain_policy, "domain_sampling_policy_unavailable"),
                          (binding, "paired_identity_binding_unavailable"),
                          (expected_binding_sha256, "trusted_binding_commitment_unavailable"),
                          (observed_probes, "observed_probe_commitment_unavailable"),
                          (records, "retained_records_unavailable")):
        if value is None:
            return _unavailable(reason)
    if type(domain) is not Domain:
        raise ValueError("exact public Domain required")
    public_domain = _public_domain(domain.model_dump(mode="json"))
    if (public_domain.maximum-public_domain.minimum+1) ** public_domain.input_arity != 256:
        return _unavailable("not_exactly256_canonical_domain")
    finals = validate_open_receipt(registration, campaign_receipt)
    rosters = frozen_partitions(registration, partitions)
    policy = _policy(registration, domain_policy, rosters)
    closed(binding, {"schema"} | _IDENTITY | _COMPARISON | _PINS, "domain binding")
    if binding["schema"] != "bbr.domain-binding.v1":
        raise ValueError("unknown domain binding schema")
    if digest(binding) != require_digest(expected_binding_sha256):
        raise ValueError("domain binding differs from separate trusted commitment")
    for field in ("task_id", "model", "arm"):
        _name(binding[field], field)
    for field in (_PINS | {"candidate_sha256", "artifact_sha256", "execution_contract_sha256"}):
        require_digest(binding[field])
    identity = {name: binding[name] for name in sorted(_IDENTITY)}
    key = (binding["task_id"], binding["model"], binding["arm"])
    final = finals.get(key)
    if final is None:
        raise ValueError("task/model/arm outside verified final locks")
    if final["status"] != "candidate":
        return _unavailable("locked_final_has_no_candidate", identity)
    if binding["candidate_sha256"] != final["candidate_sha256"]:
        raise ValueError("certificate candidate differs from locked final")
    cell = next(c for c in registration.cells if c.task_id == key[0])
    if cell.tier != "finite":
        return _unavailable("registered_task_is_not_finite", identity)
    entry = policy[key[0]]
    if entry["domain"] is None:
        return _unavailable("frozen_domain_truth_unavailable", identity)
    if entry["domain"] != public_domain.model_dump(mode="json"):
        raise ValueError("caller Domain differs from precommitted public Domain")
    expected = {"artifact_sha256": cell.artifact_sha256,
                "execution_contract_sha256": cell.execution_contract_sha256,
                "comparator_version": COMPARATOR_VERSION,
                "registration_sha256": registration.sha256,
                "lock_sha256": campaign_receipt["lock_sha256"],
                "partition_sha256": dict(registration.pins)["partitions"],
                "domain_policy_sha256": dict(registration.pins)["domain_policy"],
                "canonical_plan_sha256": entry["canonical_plan_sha256"],
                "observed_probes_sha256": digest(observed_probes)}
    if any(binding[name] != pin for name, pin in expected.items()):
        raise ValueError("certificate comparison/policy/partition/lock pins mismatch")
    roster = rosters[key[0]]
    valid = {raw: canonical for name in ("visible", "public_valid", "private_valid")
             for raw, canonical in roster[name]}
    if len(valid) != 256:
        raise ValueError("frozen full canonical roster must have256 values")

    def decode_input(raw: bytes) -> tuple[int, ...]:
        values = decode(raw, cell.codec, public_domain.width)
        if (len(values) != public_domain.input_arity or
                any(not public_domain.minimum <= v <= public_domain.maximum for v in values) or
                encode(values, cell.codec, public_domain.width) != raw):
            raise ValueError("retained input outside canonical public Domain")
        return values

    # Count supplied decoded values; NEVER enumerate the declared domain. Exactly
    #256 distinct in-range values in a256-capacity domain proves declared coverage.
    decoded = {decode_input(bytes.fromhex(raw)) for raw in valid}
    if len(decoded) != 256:
        raise ValueError("frozen raw/canonical roster does not cover declared Domain")
    closed(observed_probes, {"schema"} | _IDENTITY | {"lock_sha256", "public_input_hex"}, "observed probes")
    if (observed_probes["schema"] != "bbr.observed-probes.v1" or
            any(observed_probes[n] != binding[n] for n in _IDENTITY | {"lock_sha256"})):
        raise ValueError("observed probe identity/lock mismatch")
    probes = observed_probes["public_input_hex"]
    if type(probes) is not list or len(probes) > 48:
        raise ValueError("bounded observed-probe list required")
    for raw in probes:
        canonical_hex(raw, 64)
    allowed_public = {raw for name in ("public_valid", "public_malformed") for raw, _ in roster[name]}
    if len(set(probes)) != len(probes) or not set(probes) <= allowed_public:
        raise ValueError("observed probes repeat or escape frozen public pool")
    if key[2] != "P" and probes:
        raise ValueError("non-probing arm cannot claim public observations")
    public_keys = {canonical for _, canonical in roster["public_valid"]}
    observed_keys = {valid[raw] for raw in probes if raw in valid}
    private_keys = {canonical for _, canonical in roster["private_valid"]}
    if type(records) is not list or len(records) != 256:
        raise ValueError("exactly256 retained canonical comparisons required")
    results, raw_seen = {}, set()
    unknown_count, oracle_invalid_count = 0, 0
    for record in records:
        closed(record, _IDENTITY | _COMPARISON | {"stdin_hex", "outcome"}, "domain comparison")
        if any(record[name] != binding[name] for name in _IDENTITY | _COMPARISON):
            raise ValueError("retained comparison changes paired candidate/execution identity")
        raw_hex = canonical_hex(record["stdin_hex"], 64)
        if raw_hex not in valid or raw_hex in raw_seen:
            raise ValueError("repeated/outside-frozen retained canonical input")
        raw_seen.add(raw_hex)
        raw = bytes.fromhex(raw_hex)
        decode_input(raw)
        if type(record["outcome"]) is not dict:
            raise ValueError("shared PairOutcome JSON object required")
        pair = PairOutcome.model_validate_json(_canonical(record["outcome"]))
        if pair.input_sha256 != sha256(raw).hexdigest():
            raise ValueError("retained pair input digest mismatch")
        recomputed = compare_observations(pair.binary, pair.candidate, stdin_bytes=raw)
        if (pair.status, pair.reason) != (recomputed.status, recomputed.reason):
            raise ValueError("retained comparator status/reason drift")
        oracle_ok = pair.binary.status == "ok" and pair.binary.exit_code == 0
        try:
            outputs = decode(pair.binary.stdout_bytes, cell.codec, public_domain.width,
                             max_elements=public_domain.output_arity)
            oracle_ok &= len(outputs) == public_domain.output_arity
        except ValueError:
            oracle_ok = False
        unknown = pair.status == "infrastructure_error"
        unknown_count += unknown
        oracle_invalid_count += not oracle_ok
        results[valid[raw_hex]] = pair.status == "equal" and oracle_ok and not unknown
    if raw_seen != set(valid) or len(results) != 256:
        raise ValueError("missing/repeated canonical retained comparison")
    if digest(records) != binding["records_sha256"]:
        raise ValueError("retained comparisons differ from bound commitment")
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
