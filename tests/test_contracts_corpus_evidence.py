"""Authored software regressions, origin=fixture; no corpus independence claims.

Only trusted harness/parser code and synthetic public software domains are used.
No candidate/source string or synthetic ELF is compiled/imported/executed.
"""
from dataclasses import replace
from hashlib import sha256
import json
import struct

import pytest
from pydantic import ValidationError

from bbr.build.pipeline import ToolchainPin, ValidityReceipt, build_plan, group_execution_identities, validate_instance
from bbr.contracts import BuildArtifact, CandidateResponse, Domain, ExecutionLimits, Observation, VisibleExample, VisibleTask
from bbr.corpus.codecs import decode, encode
from bbr.corpus.families import DEFINITIONS, family_spec
from bbr.corpus.input_plan import encode_plan, plan_inputs
from bbr.evidence import EvidenceError, EvidenceLimits, PublicEvidenceEnvelope, extract
from support.dl1.elf_fixtures import ORIGIN, canonical, fixture_seed, fixture_sha, import_elf, parser_elf


@pytest.mark.parametrize("codec", ["dec", "hex", "bin"])
@pytest.mark.parametrize("width,values", [(8, (0, 1, 127, 128, 255)), (16, (0, 255, 256, 32768, 65535))])
def test_codec_canonical_byte_roundtrip(codec, width, values):
    raw = encode(values, codec, width)
    assert decode(raw, codec, width) == values
    assert encode(decode(raw, codec, width), codec, width) == raw
    if codec == "bin":
        assert raw[0] == len(values) * (width // 8)
        assert raw[1:] == b"".join(v.to_bytes(width // 8, "little") for v in values)


@pytest.mark.parametrize("codec,empty", [("dec", b"\n"), ("hex", b"\n"), ("bin", b"\0")])
def test_empty_vectors_remain_canonical(codec, empty):
    assert encode((), codec, 8) == empty
    assert decode(empty, codec, 16) == ()


@pytest.mark.parametrize("codec,width,raw", [
    ("dec", 8, b"00\n"), ("dec", 8, b"+1\n"), ("dec", 8, b"1,\n"),
    ("dec", 8, b"256\n"), ("dec", 16, b"65536\n"), ("dec", 8, b"1\n\n"),
    ("hex", 8, b"FF\n"), ("hex", 8, b"f\n"), ("hex", 16, b"ff\n"),
    ("bin", 16, b"\1\0"), ("bin", 8, b"\1\0\0"), ("bin", 8, b"\2\0"),
])
def test_invalid_codec_grammar_is_refused(codec, width, raw):
    with pytest.raises(ValueError):
        decode(raw, codec, width)


@pytest.mark.parametrize("values", [(True,), (-1,), (256,), tuple(range(9))])
def test_invalid_unsigned_vectors_are_refused(values):
    with pytest.raises(ValueError):
        encode(values, "dec", 8)


def test_wire_bytes_are_hex_and_subject_faults_cannot_be_ok():
    observation = Observation(status="ok", exit_code=0, stdout_bytes=b"\0\xff")
    assert observation.model_dump(mode="json")["stdout_bytes"] == "00ff"
    assert Observation.model_validate_json(observation.model_dump_json()) == observation
    for changes in ({"exit_code": 2}, {"signal": 9, "exit_code": None}, {"timed_out": True}):
        with pytest.raises(ValidationError):
            Observation.model_validate({**observation.model_dump(), **changes})
    with pytest.raises(ValidationError):
        Observation(status="infrastructure_error")


@pytest.mark.parametrize("field,value", [("wall_seconds", 2.1), ("cpu_seconds", 2),
    ("memory_bytes", 268435457), ("stdin_bytes", 65), ("stdout_bytes", 4097), ("processes", 2)])
def test_resource_caps_cannot_be_widened(field, value):
    with pytest.raises(ValidationError):
        ExecutionLimits(**{field: value})


def test_response_schema_never_executes_source_and_enforces_choice_and_bytes():
    response = CandidateResponse(code="SOFTWARE_FIXTURE_SOURCE_NEVER_EXECUTED")
    assert response.code
    assert CandidateResponse(abstain=True).abstain
    for changes in ({}, {"code": "x", "abstain": True}, {"code": "é" * 16385},
                    {"code": "x", "probe_inputs": (b"x",) * 9}, {"abstain": True, "family_id": "forbidden"}):
        with pytest.raises(ValidationError):
            CandidateResponse(**changes)


def _software_task(codec="dec"):
    domain = Domain(width=8, input_arity=1, output_arity=1, maximum=255)
    seed = fixture_seed("schema-public-software-domain")
    plan = plan_inputs(domain, seed=seed)
    encoded = encode_plan(plan, codec, seed=seed)
    return VisibleTask(task_id=ORIGIN, evidence_sha256=fixture_sha("evidence"), codec=codec,
        domain=domain, probe_inputs=encoded.public_inputs,
        examples=tuple(VisibleExample(stdin_bytes=encode(v, codec, 8), stdout_bytes=encode((0,), codec, 8))
                       for v in plan.visible))


@pytest.mark.parametrize("codec", ["dec", "hex", "bin"])
def test_visible_pool_partition_and_exact_output_arity(codec):
    task = _software_task(codec)
    assert len(task.probe_inputs) == 80
    assert VisibleTask.model_validate_json(task.model_dump_json()) == task
    empty = encode((), codec, 8)
    bad_examples = (task.examples[0].model_copy(update={"stdout_bytes": empty}),) + task.examples[1:]
    with pytest.raises(ValidationError, match="exact output arity"):
        VisibleTask.model_validate({**task.model_dump(), "examples": bad_examples})
    with pytest.raises(ValidationError):
        VisibleTask.model_validate({**task.model_dump(), "probe_inputs": task.probe_inputs[:-1]})
    with pytest.raises(ValidationError):
        VisibleTask.model_validate({**task.model_dump(), "probe_inputs": task.probe_inputs[:-1] + (task.probe_inputs[0],)})


@pytest.mark.parametrize("width", [8, 16])
def test_finite_input_policy_inherits_values_and_audits_all_codecs(width):
    domain = Domain(width=width, input_arity=1, output_arity=1, maximum=255)
    seed = fixture_seed("finite-public-software-domain")
    plan = plan_inputs(domain, seed=seed, reserved_private=((0,), (255,)))
    assert tuple(map(len, (plan.visible, plan.public, plan.private))) == (8, 64, 184)
    assert {(0,), (255,)} <= set(plan.private)
    assert not (set(plan.visible) & set(plan.public) or set(plan.private) & set(plan.public))
    assert len(set(plan.visible + plan.public + plan.private)) == 256
    assert plan == plan_inputs(domain, seed=seed, reserved_private=((255,), (0,)))
    summary = plan.summary()
    assert not {"visible", "public", "private", "reserved_private", "seed"} & set(summary)
    for codec in ("dec", "hex", "bin"):
        encoded = encode_plan(plan, codec, seed=seed)
        assert len(encoded.public_inputs) == 80
        assert tuple(len(p.malformed) for p in encoded.partitions) == (0, 16, 32)
        assert tuple(tuple(decode(raw, codec, width) for raw in p.valid) for p in encoded.partitions) == (plan.visible, plan.public, plan.private)
        all_raw = [raw for p in encoded.partitions for raw in p.valid + p.malformed]
        assert len(set(all_raw)) == len(all_raw)
        for partition in encoded.partitions:
            for raw in partition.malformed:
                with pytest.raises(ValueError):
                    values = decode(raw, codec, width)
                    if len(values) != domain.input_arity or any(v > domain.maximum for v in values):
                        raise ValueError("outside software Domain")


def test_ordinary_capacity_extra_boundaries_and_tamper_refusal():
    domain = Domain(width=16, input_arity=1, output_arity=1, maximum=329)
    seed = fixture_seed("ordinary-public-software-domain")
    plan = plan_inputs(domain, seed=seed, reserved_private=((0,), (329,)))
    assert tuple(map(len, (plan.visible, plan.public, plan.private))) == (8, 64, 258)
    assert {(0,), (329,)} <= set(plan.private)
    assert len(set(plan.visible + plan.public + plan.private)) == 330
    assert plan.top_up_count >= 0
    with pytest.raises(ValueError, match="plan does not match"):
        encode_plan(replace(plan, private=plan.private[:-1]), "bin", seed=seed)
    for bad_domain in (Domain(width=16, input_arity=1, output_arity=1, maximum=256),
                       Domain(width=16, input_arity=1, output_arity=1, maximum=328)):
        with pytest.raises(ValueError, match="capacity"):
            plan_inputs(bad_domain, seed=seed, reserved_private=((0,), (1,)))
    with pytest.raises(ValueError):
        plan_inputs(domain, seed=b"short-software-test-marker")
    with pytest.raises(ValueError):
        plan_inputs(domain, seed=seed, reserved_private=((0,), (0,)))


def _envelope(data=b"<script>software fixture</script>\0"):
    blob = parser_elf(data)
    bundle = extract(blob)
    return blob, bundle, PublicEvidenceEnvelope.from_bundle(bundle, expected_artifact_sha256=sha256(blob).hexdigest())


def test_elf_evidence_full_content_escaping_provenance_and_wire_identity():
    blob, bundle, envelope = _envelope()
    assert bundle.artifact_sha256 == sha256(blob).hexdigest()
    assert bundle.imports.table_present is False
    assert {s.section for s in bundle.sections} == {".text", ".rodata"}
    for section in bundle.sections:
        assert blob[section.offset:section.offset+section.length].hex() == section.data_hex
        assert section.boundary_uncertain
    assert "&lt;script&gt;" in bundle.strings[0].html
    assert "markup" in bundle.strings[0].flags
    wire = envelope.to_dict()
    assert wire["bundle"]["sections"][0]["data_hex"]
    loaded = PublicEvidenceEnvelope.from_json(envelope.canonical_json(),
        expected_artifact_sha256=bundle.artifact_sha256, expected_evidence_sha256=bundle.digest())
    assert loaded == envelope
    wire["bundle"]["sections"].clear()
    assert envelope.to_dict()["bundle"]["sections"]
    with pytest.raises(EvidenceError, match="live dispatch blocked"):
        envelope.require_live_dispatch()


@pytest.mark.parametrize("mutation", ["unknown", "data", "offset", "missing_text", "omitted_strings", "bad_escape", "false_cut"])
def test_recommitted_structural_tamper_still_refused(mutation):
    _, bundle, envelope = _envelope(b"A" * 120 + b"\0")
    wire = envelope.to_dict()
    if mutation == "unknown":
        wire["bundle"]["source_filename"] = "SOFTWARE_FIXTURE_FORBIDDEN_FIELD"
    elif mutation == "data":
        wire["bundle"]["sections"][0]["data_hex"] = "00" * wire["bundle"]["sections"][0]["length"]
    elif mutation == "offset":
        wire["bundle"]["strings"][0]["offset"] += 1
    elif mutation == "missing_text":
        wire["bundle"]["sections"][0]["section"] = ".data"
    elif mutation == "omitted_strings":
        wire["bundle"]["strings"] = []
        wire["bundle"]["truncated"] = False
    elif mutation == "bad_escape":
        wire["bundle"]["strings"][0]["html"] = "forged"
    else:
        wire["bundle"]["strings"][0]["truncated"] = False
    wire["evidence_sha256"] = sha256(canonical(wire["bundle"])).hexdigest()
    with pytest.raises(EvidenceError):
        PublicEvidenceEnvelope.from_json(canonical(wire),
            expected_artifact_sha256=bundle.artifact_sha256,
            expected_evidence_sha256=wire["evidence_sha256"])


def test_raw_wire_duplicate_keys_noncanonical_bytes_and_identity_refused():
    _, bundle, envelope = _envelope()
    valid = envelope.canonical_json()
    duplicate = b'{"schema_version":1,' + valid[1:]
    for raw in (duplicate, valid+b"\n", b" " * (48*1024+1)):
        with pytest.raises(EvidenceError):
            PublicEvidenceEnvelope.from_json(raw, expected_artifact_sha256=bundle.artifact_sha256,
                                             expected_evidence_sha256=bundle.digest())
    with pytest.raises(EvidenceError):
        envelope.validate_for(artifact_sha256=fixture_sha("wrong-artifact"), evidence_sha256=bundle.digest())


def test_bounded_truncation_and_malformed_elf_refusal():
    blob = parser_elf(b"X" * 200 + b"\0")
    bundle = extract(blob, EvidenceLimits(max_section_bytes=16, max_total_section_bytes=32))
    assert bundle.truncated and sum(s.length for s in bundle.sections) <= 32
    PublicEvidenceEnvelope.from_bundle(bundle, expected_artifact_sha256=sha256(blob).hexdigest())
    bad_offset = bytearray(blob)
    struct.pack_into("<Q", bad_offset, 40, 1 << 30)
    for raw in (b"not-an-elf-software-fixture", bytes(bad_offset), parser_elf(section_name=".symtab")):
        with pytest.raises(EvidenceError):
            extract(raw)


def test_import_metadata_exposes_only_allowlisted_names_and_exact_provenance():
    blob = import_elf((b"puts", b"SOFTWARE_FIXTURE_UNKNOWN_IMPORT"))
    bundle = extract(blob)
    imports = bundle.imports
    assert imports.table_present and imports.known_count == imports.unknown_count == 1
    assert tuple(s.name for s in imports.known) == ("puts",)
    symbol = imports.known[0]
    assert blob[symbol.name_offset:symbol.name_offset+symbol.name_length] == b"puts"
    assert "SOFTWARE_FIXTURE_UNKNOWN_IMPORT" not in bundle.canonical_json().decode("ascii")
    assert "unknown_import_names_omitted" in imports.flags
    PublicEvidenceEnvelope.from_bundle(bundle, expected_artifact_sha256=sha256(blob).hexdigest())
    bad = bytearray(blob)
    shoff = struct.unpack_from("<Q", blob, 40)[0]
    struct.pack_into("<I", bad, shoff + 4*64 + 40, 99)  # Invalid DYNSYM sh_link.
    with pytest.raises(EvidenceError):
        extract(bytes(bad))


def test_import_cap_is_disclosed_in_bundle_and_public_envelope():
    blob = import_elf((b"puts",) * 65)
    bundle = extract(blob)
    assert bundle.imports.known_count == 65 and len(bundle.imports.known) == 64
    assert "known_imports_truncated" in bundle.imports.flags and bundle.truncated
    PublicEvidenceEnvelope.from_bundle(bundle, expected_artifact_sha256=sha256(blob).hexdigest())
    with pytest.raises(EvidenceError, match="truncation"):
        PublicEvidenceEnvelope.from_bundle(replace(bundle, truncated=False),
                                          expected_artifact_sha256=bundle.artifact_sha256)


def _build_claims():
    """Synthetic structural claims; NOT actual builds/rights/independent receipts."""
    spec = family_spec("threshold-byte").model_copy(update={"rights_status": "approved"})
    artifacts, receipts = [], []
    for codec in ("dec", "hex", "bin"):
        for compiler in ("gcc", "clang"):
            for opt in ("O0", "O2"):
                task = f"{spec.family_id}-{codec}-{compiler}-{opt}"
                artifact = BuildArtifact(task_id=task, family_id=spec.family_id, codec=codec,
                    compiler=compiler, optimization=opt, artifact_sha256=fixture_sha("elf-"+task),
                    text_sha256=fixture_sha("same-text"), execution_contract_sha256=fixture_sha("exec"),
                    source_sha256=fixture_sha("source-"+codec), toolchain_sha256=fixture_sha("toolchain"), size_bytes=128)
                artifacts.append(artifact)
                receipts.append(ValidityReceipt(task_id=task, artifact_sha256=artifact.artifact_sha256,
                    source_sha256=artifact.source_sha256, toolchain_sha256=artifact.toolchain_sha256,
                    reference_sha256=fixture_sha("reference"), independent_reviewer=ORIGIN,
                    independent_review_receipt_sha256=fixture_sha("nonindependent-test-claim"),
                    rights_receipt_sha256=fixture_sha("test-rights-claim"), public_domain_sha256=fixture_sha("domain"),
                    rebuild_sha256=artifact.artifact_sha256, valid_cases=256, malformed_cases=1,
                    full_domain_cases=256, stability_repeats=2, reference_agrees=True, manual_traps_agree=True,
                    sanitized_clean=True, unsigned_bounds_reviewed=True, cross_variants_agree=True,
                    deterministic=True, ub_negative_control_rejected=True))
    return spec, tuple(artifacts), tuple(receipts)


def test_receipt_gate_needs_all_twelve_unique_bound_claims():
    spec, artifacts, receipts = _build_claims()
    assert validate_instance(spec, artifacts, receipts).status == "accepted"
    assert validate_instance(spec.model_copy(update={"rights_status": "pending"}), artifacts, receipts).status == "rejected"
    repeated = tuple(a.model_copy(update={"task_id": artifacts[0].task_id}) for a in artifacts)
    assert validate_instance(spec, repeated, receipts[:1]).status == "rejected"
    corrupt = (receipts[0].model_copy(update={"source_sha256": fixture_sha("wrong-source")}),) + receipts[1:]
    assert validate_instance(spec, artifacts, corrupt).status == "rejected"
    short = (receipts[0].model_copy(update={"full_domain_cases": 255}),) + receipts[1:]
    assert validate_instance(spec, artifacts, short).status == "rejected"


def test_complete_elf_grouping_never_merges_text_coincidences():
    _, artifacts, _ = _build_claims()
    assert len(group_execution_identities(artifacts)) == 12
    same = artifacts[1].model_copy(update={"artifact_sha256": artifacts[0].artifact_sha256})
    groups = group_execution_identities((artifacts[0], same) + artifacts[2:])
    assert len(groups) == 11
    assert sum(map(len, groups)) == 12
    with pytest.raises(ValueError):
        group_execution_identities((artifacts[0], artifacts[0]))


def test_build_schedule_is_full_matrix_and_placeholder_pins_fail_closed():
    specs = tuple(family_spec(name) for name in DEFINITIONS)
    pin = ToolchainPin(image_digest="sha256:"+fixture_sha("synthetic-image"),
        gcc_version=ORIGIN, clang_version=ORIGIN, binutils_version=ORIGIN,
        package_snapshot=ORIGIN, source_date_epoch=0, manifest_sha256=fixture_sha("synthetic-toolchain"),
        rights_receipt_sha256=fixture_sha("test-rights-claim"))
    rows = build_plan(specs, pin)
    assert len(rows) == 96 and len({r.task_id for r in rows}) == 96
    assert {(r.codec, r.compiler, r.optimization) for r in rows} == {
        (c, p, o) for c in ("dec", "hex", "bin") for p in ("gcc", "clang") for o in ("O0", "O2")}
    with pytest.raises(ValidationError):
        ToolchainPin.model_validate({**pin.model_dump(), "image_digest": "<PLACEHOLDER_M15_TOOLCHAIN_IMAGE_DIGEST>"})
