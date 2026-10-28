"""Factories for authored SOFTWARE REGRESSION fixtures, not an experiment.

These fixtures test trusted harness bookkeeping against hand-computable outcomes.
No ELF, candidate, independent author, admitted corpus, actual campaign, real Roy
approval, model result, worker execution or original usage is represented here.
The Admission positive-control flag exists solely to exercise a structural parser.
It must never be exported as an actual admission or used with executable workers.

Product imports and fixture construction occur only inside make_matrix. Importing
this support module creates no matrix, source file, input pool or database. Returned
case/pool templates are shared by convention to keep software tests modest in RAM;
copy a row's cases list AND any case/observation being mutated in a negative test.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any


SCOPE = "BUILDER_AUTHORED_SOFTWARE_REGRESSION_ONLY_NO_REAL_AUTHORITY"


@dataclass(frozen=True)
class SoftwareMatrix:
    registration: Any
    partitions: dict
    admission: Any
    receipt: dict
    rows: list[dict]
    domains: dict[str, Any]
    bindings: dict
    domain_policy: dict
    model_configs: dict[str, dict]
    scope: str = SCOPE


def _hash(label: str) -> str:
    """Hash actual inert marker bytes, never pretend they are ELF/source pins."""
    return sha256((SCOPE + ":" + label).encode("ascii")).hexdigest()


def _key(value: int) -> str:
    return json.dumps([value], separators=(",", ":"))


def _json_wire(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _observation(stdout: bytes, *, malformed: bool = False) -> dict:
    return {"stdout_hex": stdout.hex(), "exit_code": 2 if malformed else 0,
            "signal": None, "timed_out": False, "output_limited": False,
            "status": "subject_failure" if malformed else "ok"}


def make_matrix(patterned: bool = True, model_bindings: bool = False) -> SoftwareMatrix:
    """Build a software-only fixed-population bookkeeping positive control.

    Patterned mode has shared target identity group sizes 2,1,1 per family/codec.
    M passes only gcc/O0: nominal 1/4, equal-group primary 1/6. R passes no valid
    tasks, P passes every valid task, and lookup passes visible but fails private.
    S/echo/constant abstain. This is authored arithmetic, not measured recovery.
    With patterned=False every arm abstains; all rows are complete denominator
    failures and the fixture has no case observations, making archives small.
    """
    if type(patterned) is not bool or type(model_bindings) is not bool:
        raise ValueError("software matrix options must be booleans")

    # Trusted product factories are imported only on an explicitly authorized
    # software-test call. No generated/untrusted candidate module is imported.
    from bbr.contracts import Domain
    from bbr.corpus.codecs import encode
    from evaluation.admission import Admission
    from evaluation.preregister import Cell, Registration, digest

    edition = "SOFTWARE_REGRESSION_ONLY_NOT_AN_ADMITTED_CAMPAIGN"
    models = ("software-score-model-a", "software-score-model-b")
    arms = ("S", "M", "R", "P", "echo", "constant", "lookup")
    binding_rows = []
    model_configs = {}
    for suffix, model in zip(("a", "b"), models):
        config = {"model_id": f"software-fixture-model-{suffix}",
                  "config_id": f"software-fixture-config-{suffix}",
                  "endpoint_id": "offline", "seed": 0, "origin": "fixture"}
        model_configs[model] = config
        binding_rows.append({"score_model": model, "model_id": config["model_id"],
                             "config_id": config["config_id"],
                             "request_model_config_sha256": digest(config)})
    bindings = {"schema": "bbr.model-bindings.v1", "edition": edition,
                "origin": "fixture", "bindings": binding_rows}

    cells = []
    domains = {}
    for family_number in range(8):
        family = f"software-regression-family-{family_number}"
        finite = family_number < 2
        width = 8 if finite else 16
        domains[family] = Domain(width=width, input_arity=1, output_arity=1,
                                 minimum=0, maximum=(1 << width) - 1)
        for codec in ("dec", "hex", "bin"):
            for compiler in ("gcc", "clang"):
                for optimization in ("O0", "O2"):
                    task = f"{family}-{codec}-{compiler}-{optimization}"
                    identity = "gcc-shared" if compiler == "gcc" else f"clang-{optimization}"
                    cells.append(Cell(task_id=task, family_id=family, codec=codec,
                        compiler=compiler, optimization=optimization,
                        tier="finite" if finite else "ordinary",
                        artifact_sha256=_hash(f"INERT_NON_ELF_TARGET:{family}:{codec}:{identity}"),
                        execution_contract_sha256=_hash(f"NO_WORKER_CONTRACT:{family}:{codec}")))

    # Same immutable-by-convention pool object is reused across compiler variants
    # and semantically nonexistent software families of the same width/codec.
    pools: dict[tuple[int, str], dict] = {}
    cases: dict[tuple[int, str, str], list[dict]] = {}
    for width in (8, 16):
        private_stop = 256 if width == 8 else 328
        for codec in ("dec", "hex", "bin"):
            def valid(values: range) -> list[dict]:
                return [{"raw_hex": encode((value,), codec, width).hex(),
                         "canonical_key": _key(value)} for value in values]

            pool = {"visible": valid(range(8)), "public_valid": valid(range(8, 72)),
                    "private_valid": valid(range(72, private_stop)),
                    "public_malformed": [{"raw_hex": f"software-public-invalid-{n:02}".encode("ascii").hex(),
                                          "canonical_key": None} for n in range(16)],
                    "private_malformed": [{"raw_hex": f"software-private-invalid-{n:02}".encode("ascii").hex(),
                                           "canonical_key": None} for n in range(32)]}
            pools[width, codec] = pool
            zero = encode((0,), codec, width)
            one = encode((1,), codec, width)
            for mode in ("pass", "fail", "overfit"):
                observations = []
                for partition in ("visible", "private_valid", "private_malformed"):
                    malformed = partition == "private_malformed"
                    for item in pool[partition]:
                        matches = mode == "pass" or (mode == "overfit" and partition == "visible")
                        observations.append({"partition": partition, "input_hex": item["raw_hex"],
                            "canonical_key": item["canonical_key"],
                            "oracle": _observation(b"" if malformed else zero, malformed=malformed),
                            "candidate": _observation(b"" if malformed else zero if matches else one,
                                                      malformed=malformed)})
                cases[width, codec, mode] = observations

    partitions = {"schema": "bbr.partitions.v1", "tasks": []}
    policy_tasks = []
    for cell in cells:
        domain = domains[cell.family_id]
        pool = pools[domain.width, cell.codec]
        partitions["tasks"].append({"task_id": cell.task_id, "partitions": pool})
        sampling = None
        if cell.tier == "finite":
            sampling = {"recipe_id": "AUTHORED_SOFTWARE_REGRESSION_FIRST_EIGHT_KEYS",
                        "size": 8, "canonical_keys": [_key(value) for value in range(72, 80)]}
        policy_tasks.append({"task_id": cell.task_id, "domain": domain.model_dump(mode="json"),
                             "canonical_plan_sha256": _hash(f"NO_GENERATOR_PLAN:{cell.family_id}"),
                             "sampling": sampling})
    domain_policy = {"schema": "bbr.domain-policy.v1", "tasks": policy_tasks}

    required_pins = ("engine", "scorer", "baselines", "prompts", "wrappers", "generators",
                     "domain_policy", "resources", "prices", "schedule", "partitions", "source", "canaries")
    pins = {name: _hash(f"SOFTWARE_ONLY_PIN:{name}") for name in required_pins}
    pins["domain_policy"] = digest(domain_policy)
    pins["partitions"] = digest(partitions)
    if model_bindings:
        pins["model_bindings"] = digest(bindings)
    registration = Registration(edition=edition, cells=tuple(cells), models=models, arms=arms,
                                origin="fixture", pins=tuple(sorted(pins.items())),
                                bootstrap_seed=20261027)
    registration.validate()

    # This flag is a deliberately authored parser positive-control, NOT a receipt
    # of Roy approval or an appointment of these nonexistent stub identities.
    receipt_names = ("roy_appointment_receipt", "rights_receipt", "independence_history_receipt",
        "validity_receipt", "disjointness_receipt", "freeze_receipt",
        "heldout_creation_after_freeze_receipt", "mount_isolation_receipt",
        "sample_admission_receipt", "release_rights_receipt")
    admission = Admission(edition=edition,
        author="SOFTWARE_ONLY_NONPERSON_AUTHOR_STUB_NOT_APPOINTED",
        custodian="SOFTWARE_ONLY_NONPERSON_CUSTODIAN_STUB_NOT_APPOINTED",
        evaluator="SOFTWARE_ONLY_NONPERSON_EVALUATOR_STUB_NOT_APPOINTED",
        builder_identities=("SOFTWARE_ONLY_BUILDER_STUB",),
        source_commitment=pins["source"], partition_commitment=pins["partitions"],
        canary_commitment=pins["canaries"], accepted_by_roy=True,
        **{name: _hash(f"NO_REAL_APPROVAL_OR_RIGHTS:{name}") for name in receipt_names})

    rows = []
    for cell in cells:
        for model in models:
            for arm in arms:
                candidate = patterned and arm in {"M", "R", "P", "lookup"}
                mode = "fail"
                if arm == "P" or (arm == "M" and cell.compiler == "gcc" and cell.optimization == "O0"):
                    mode = "pass"
                elif arm == "lookup":
                    mode = "overfit"
                rows.append({"task_id": cell.task_id, "model": model, "arm": arm,
                    "candidate_sha256": _hash(f"INERT_NOT_EXECUTABLE_CANDIDATE:{cell.task_id}:{model}:{arm}") if candidate else None,
                    "status": "candidate" if candidate else "abstain",
                    "cases": cases[domains[cell.family_id].width, cell.codec, mode] if candidate else []})
    finals = [{name: row[name] for name in ("task_id", "model", "arm", "candidate_sha256", "status")}
              for row in sorted(rows, key=lambda row: (row["task_id"], row["model"], row["arm"]))]
    admission_wire = _json_wire(asdict(admission))
    receipt = {"schema": "bbr.hidden-open.v1", "registration_sha256": registration.sha256,
               "admission": admission_wire, "admission_sha256": digest(admission_wire),
               "evaluator": admission.evaluator, "lease_id": "SOFTWARE_ONLY_NO_REAL_HIDDEN_OPEN",
               "finals": finals}
    receipt["lock_sha256"] = digest(receipt)
    return SoftwareMatrix(registration, partitions, admission, receipt, rows, domains,
                          bindings, domain_policy, model_configs)


def summary_for(score: dict, model: str, arm: str) -> dict:
    """Select one existing software-test score summary without new arithmetic."""
    selected = [row for row in score["summaries"] if row["model"] == model and row["arm"] == arm]
    if len(selected) != 1:
        raise ValueError("exactly one model/arm summary required")
    return selected[0]
