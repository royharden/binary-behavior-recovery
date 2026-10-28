"""AUTHORED SOFTWARE TEST FIXTURE, origin=fixture, builder-lineage/nonindependent.

In-memory public software-domain examples only. These simulated Admission fields
exercise retained-byte validation; they are not appointments, benchmark admission,
heldout data, evidence of execution, or independent author/custodian claims.
Nothing here compiles, imports, or executes candidate source or saves manifests.
"""
from dataclasses import asdict, dataclass, replace

from bbr.contracts import Domain, Observation
from bbr.corpus.codecs import encode
from bbr.differential import COMPARATOR_VERSION, compare_observations
from evaluation.admission import Admission
from evaluation.preregister import Cell, Registration, digest

FIXTURE_LABEL = "AUTHORED SOFTWARE TEST FIXTURE: builder-lineage/nonindependent"
ARMS = ("S", "M", "R", "P", "echo", "constant", "lookup")
PIN_NAMES = ("engine", "scorer", "baselines", "prompts", "wrappers", "generators",
             "domain_policy", "resources", "prices", "schedule", "partitions", "source", "canaries")


def fixture_digest(label):
    return digest({"origin": "fixture", "label": FIXTURE_LABEL, "value": label})


@dataclass
class DomainFixture:
    registration: Registration
    arguments: dict

    def refresh(self, *, policy=False):
        """Recommit intended fixture edits; corruption tests omit this deliberately."""
        a = self.arguments
        if policy:
            pins = dict(self.registration.pins)
            pins["domain_policy"] = digest(a["domain_policy"])
            self.registration = replace(self.registration, pins=tuple(pins.items()))
        receipt = a["campaign_receipt"]
        receipt["registration_sha256"] = self.registration.sha256
        receipt["lock_sha256"] = digest({k: v for k, v in receipt.items() if k != "lock_sha256"})
        a["observed_probes"]["lock_sha256"] = receipt["lock_sha256"]
        binding = a["binding"]
        binding.update(registration_sha256=self.registration.sha256,
                       lock_sha256=receipt["lock_sha256"],
                       domain_policy_sha256=dict(self.registration.pins)["domain_policy"],
                       observed_probes_sha256=digest(a["observed_probes"]),
                       records_sha256=digest(a["records"]))
        a["expected_binding_sha256"] = digest(binding)


def make_domain_fixture(*, sample_size=4, codec="dec", arm="P"):
    """Create structural 96-cell fixture required by the production validators."""
    cells, tasks, policies = [], [], []
    for family in range(8):
        finite = family < 2
        width, maximum, total = (8, 255, 256) if finite else (16, 327, 328)
        domain = dict(width=width, input_arity=1, output_arity=1, minimum=0, maximum=maximum)
        for wire in ("dec", "hex", "bin"):
            for compiler in ("gcc", "clang"):
                for optimization in ("O0", "O2"):
                    task = f"fixture-{family}-{wire}-{compiler}-{optimization}"
                    cells.append(Cell(task, f"fixture-family-{family}", wire, compiler,
                                      optimization, "finite" if finite else "ordinary",
                                      fixture_digest(task), fixture_digest("execution")))
                    def items(start, stop):
                        return [{"raw_hex": encode((v,), wire, width).hex(),
                                 "canonical_key": f"value-{v}"} for v in range(start, stop)]
                    def malformed(start, stop):
                        return [{"raw_hex": f"fixture-invalid-{v}".encode().hex(),
                                 "canonical_key": None} for v in range(start, stop)]
                    tasks.append({"task_id": task, "partitions": {
                        "visible": items(0, 8), "public_valid": items(8, 72),
                        "private_valid": items(72, total),
                        "public_malformed": malformed(0, 16),
                        "private_malformed": malformed(16, 48)}})
                    sampling = None
                    if finite and sample_size is not None:
                        sampling = {"recipe_id": "fixture-prefix-software-regression",
                                    "size": sample_size,
                                    "canonical_keys": [f"value-{v}" for v in range(72, 72 + min(sample_size, 184))]}
                    policies.append({"task_id": task, "domain": domain,
                                     "canonical_plan_sha256": fixture_digest(f"plan-{family}"),
                                     "sampling": sampling})
    partitions = {"schema": "bbr.partitions.v1", "tasks": tasks}
    policy = {"schema": "bbr.domain-policy.v1", "tasks": policies}
    pins = {name: fixture_digest(name) for name in PIN_NAMES}
    pins.update(partitions=digest(partitions), domain_policy=digest(policy))
    reg = Registration("AUTHORED-SOFTWARE-TEST-FIXTURE", tuple(cells),
                       ("fixture-model-a", "fixture-model-b"), ARMS, "fixture",
                       tuple(pins.items()), 0)
    # These are deliberately simulated validator inputs, NOT actual Roy receipts.
    admission_fields = {name: fixture_digest(f"SIMULATED-{name}")
                        for name in Admission.__dataclass_fields__
                        if name.endswith("receipt") or name.endswith("commitment")}
    admission_fields.update(source_commitment=pins["source"],
                            partition_commitment=pins["partitions"], canary_commitment=pins["canaries"])
    admission = Admission(edition=reg.edition, author="SIMULATED-fixture-author",
                          custodian="SIMULATED-fixture-custodian", evaluator="SIMULATED-fixture-evaluator",
                          builder_identities=("ACTUAL-builder-lineage-nonindependent",),
                          accepted_by_roy=True, **admission_fields)
    admission_raw = asdict(admission)
    admission_raw["builder_identities"] = list(admission.builder_identities)
    candidate = fixture_digest("nonexecutable-candidate-identity")
    receipt = {"schema": "bbr.hidden-open.v1", "registration_sha256": reg.sha256,
               "admission": admission_raw, "admission_sha256": digest(asdict(admission)),
               "evaluator": admission.evaluator, "lease_id": "SIMULATED-fixture-lease",
               "finals": [{"task_id": t, "model": m, "arm": ar,
                           "candidate_sha256": candidate, "status": "candidate"}
                          for t, m, ar in sorted(reg.final_keys)]}
    cell = next(c for c in cells if c.family_id == "fixture-family-0" and c.codec == codec)
    identity = dict(task_id=cell.task_id, model=reg.models[0], arm=arm, candidate_sha256=candidate)
    comparison = dict(artifact_sha256=cell.artifact_sha256,
                      execution_contract_sha256=cell.execution_contract_sha256,
                      comparator_version=COMPARATOR_VERSION)
    records = []
    for value in range(256):
        raw = encode((value,), codec, 8)
        observation = Observation(stdout_bytes=raw, status="ok", exit_code=0)
        outcome = compare_observations(observation, observation, stdin_bytes=raw)
        records.append({**identity, **comparison, "stdin_hex": raw.hex(),
                        "outcome": outcome.model_dump(mode="json")})
    probes = {"schema": "bbr.observed-probes.v1", **identity,
              "lock_sha256": fixture_digest("pending-lock"),
              "public_input_hex": [encode((8,), codec, 8).hex(), b"fixture-invalid-0".hex()] if arm == "P" else []}
    binding = {"schema": "bbr.domain-binding.v1", **identity, **comparison,
               "registration_sha256": reg.sha256, "lock_sha256": fixture_digest("pending-lock"),
               "partition_sha256": pins["partitions"], "domain_policy_sha256": pins["domain_policy"],
               "canonical_plan_sha256": fixture_digest("plan-0"),
               "observed_probes_sha256": digest(probes), "records_sha256": digest(records)}
    fixture = DomainFixture(reg, dict(domain=Domain(width=8, input_arity=1, output_arity=1, maximum=255),
                            partitions=partitions, campaign_receipt=receipt, domain_policy=policy,
                            binding=binding, expected_binding_sha256=digest(binding),
                            observed_probes=probes, records=records))
    fixture.refresh()
    return fixture


def change_outcome(fixture, value, *, candidate=None, binary=None):
    """Change observations and recompute genuine comparator semantics, never run code."""
    record = fixture.arguments["records"][value]
    old = record["outcome"]
    import json
    left = binary or Observation.model_validate_json(json.dumps(old["binary"]))
    right = candidate or Observation.model_validate_json(json.dumps(old["candidate"]))
    record["outcome"] = compare_observations(left, right, stdin_bytes=bytes.fromhex(record["stdin_hex"])).model_dump(mode="json")
    fixture.refresh()
