"""Closed public transport of the existing full canonical evidence bundle.

Integrity/shape checking is not ELF authentication, leak clearance or token counting.
Only the original extractor owns EvidenceBundle; this envelope never narrows it.
"""
from dataclasses import dataclass, fields
from hashlib import sha256
import json
import re

from . import (EvidenceBundle, EvidenceError, EXTRACTOR_VERSION, ImportMetadata,
               ImportSymbol, SectionSlice, StringEvidence, _LIBC_IMPORTS, _EVIDENCE_LIMITATIONS)
from bbr.screen import screen

_MAX = 48 * 1024
_ARTIFACT_MAX = 8 * 1024 * 1024


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate evidence key")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise EvidenceError("nonfinite evidence number")


def _load(raw: bytes) -> object:
    if type(raw) is not bytes or len(raw) > _MAX:
        raise EvidenceError("evidence requires immutable bytes within 48 KiB")
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
        if _canonical(value) != raw:
            raise EvidenceError("evidence JSON is not canonical")
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise EvidenceError("invalid or noncanonical evidence JSON") from exc


def _object(value: object, keys: set[str]) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise EvidenceError("unexpected public evidence fields")
    return value


def _record(value: object, cls: type) -> dict:
    return _object(value, {f.name for f in fields(cls)})


def _integer(value: object, low: int = 0, high: int = _ARTIFACT_MAX) -> int:
    if type(value) is not int or not low <= value <= high:
        raise EvidenceError("public evidence integer outside bounds")
    return value


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise EvidenceError("public evidence boolean required")
    return value


def _digest(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise EvidenceError("lowercase SHA256 required")
    return value


def _array(value: object, maximum: int) -> list:
    if type(value) is not list or len(value) > maximum:
        raise EvidenceError("public evidence array outside bounds")
    return value


def _bundle(raw: bytes) -> dict:
    value = _record(_load(raw), EvidenceBundle)
    _digest(value["artifact_sha256"])
    if value["extractor_version"] != EXTRACTOR_VERSION:
        raise EvidenceError("unsupported evidence extractor version")
    truncated = _boolean(value["truncated"])
    if value["limitations"] != list(_EVIDENCE_LIMITATIONS):
        raise EvidenceError("unknown evidence limitation/source label")
    sections = {}
    total = 0
    needs_truncation = False
    for row in _array(value["sections"], 3):
        item = _record(row, SectionSlice)
        name = item["section"]
        if type(name) is not str or name not in {".text", ".rodata", ".data"} or name in sections:
            raise EvidenceError("unsupported or duplicate public section")
        offset = _integer(item["offset"], 64)
        length = _integer(item["length"], 1, 4096)
        original = _integer(item["original_length"], length)
        _integer(item["virtual_address"], 0, (1 << 64) - 1)
        if offset + original > _ARTIFACT_MAX or item["boundary_uncertain"] is not True:
            raise EvidenceError("invalid section provenance or boundary claim")
        encoded = item["data_hex"]
        if type(encoded) is not str or re.fullmatch(r"[0-9a-f]*", encoded) is None or len(encoded) != 2 * length:
            raise EvidenceError("invalid retained section hex/length")
        data = bytes.fromhex(encoded)
        if sha256(data).hexdigest() != _digest(item["sha256"]):
            raise EvidenceError("retained section digest mismatch")
        sections[name] = (offset, length, original, data)
        total += length
        needs_truncation |= length < original
    if ".text" not in sections or total > 8192:
        raise EvidenceError("missing text evidence or retained section cap exceeded")
    spans = sorted((o, o + n) for o, _, n, _ in sections.values())
    if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
        raise EvidenceError("overlapping evidence sections")
    # Every retained printable run qualifies at the public minimum. Custom
    # extractor profiles that skip shorter runs must disclose that omission.
    retained_runs = {
        (name, offset + match.start()): len(match.group())
        for name, (offset, _, _, data) in sections.items() if name != ".text"
        for match in re.finditer(rb"[\x20-\x7e]{4,}", data)
    }
    string_spans = []
    for row in _array(value["strings"], 24):
        item = _record(row, StringEvidence)
        name = item["section"]
        if type(name) is not str or name not in sections or name == ".text":
            raise EvidenceError("string outside public data sections")
        offset = _integer(item["offset"])
        length = _integer(item["length"], 4, 96)
        start, retained, _, data = sections[name]
        run_length = retained_runs.pop((name, offset), None)
        text = item["text"]
        if (type(text) is not str or len(text) != length or
                any(not 32 <= ord(c) <= 126 for c in text) or
                run_length is None or length > run_length or
                offset < start or offset + length > start + retained or
                data[offset-start:offset-start+length] != text.encode("ascii")):
            raise EvidenceError("string bytes/provenance mismatch")
        screened = screen(text)
        if item["html"] != screened.html or item["flags"] != list(screened.flags):
            raise EvidenceError("string escaping/screen annotation mismatch")
        cut = _boolean(item["truncated"])
        if cut != (length < run_length):
            raise EvidenceError("string truncation disagrees with retained run")
        needs_truncation |= cut
        string_spans.append((offset, offset + length))
    needs_truncation |= bool(retained_runs)
    string_spans.sort()
    if any(a[1] > b[0] for a, b in zip(string_spans, string_spans[1:])):
        raise EvidenceError("overlapping or duplicate evidence strings")
    imports = _record(value["imports"], ImportMetadata)
    present = _boolean(imports["table_present"])
    known = _array(imports["known"], 64)
    count = _integer(imports["known_count"], len(known), 2047)
    unknown = _integer(imports["unknown_count"], 0, 2047)
    if not present:
        if (imports["table_offset"] is not None or imports["table_length"] != 0 or
                type(imports["table_length"]) is not int or imports["table_sha256"] is not None or
                known or count or unknown or imports["flags"] != ["dynamic_table_absent"]):
            raise EvidenceError("inconsistent absent dynamic table")
    else:
        offset = _integer(imports["table_offset"], 64)
        length = _integer(imports["table_length"], 24, 2048 * 24)
        _digest(imports["table_sha256"])
        if length % 24 or offset + length > _ARTIFACT_MAX or count + unknown > length // 24 - 1:
            raise EvidenceError("dynamic import table bounds mismatch")
        if len(known) != min(count, 64):
            raise EvidenceError("missing retained allowlisted import")
        flags = (["unknown_import_names_omitted"] if unknown else [])
        if count > len(known):
            flags.append("known_imports_truncated")
            needs_truncation = True
        if imports["flags"] != flags:
            raise EvidenceError("dynamic import omission flags mismatch")
        seen = set()
        for row in known:
            item = _record(row, ImportSymbol)
            name = item["name"]
            symbol = _integer(item["symbol_offset"])
            name_offset = _integer(item["name_offset"])
            name_length = _integer(item["name_length"], 1, 128)
            if (type(name) is not str or name not in _LIBC_IMPORTS or name_length != len(name) or
                    name_offset + name_length > _ARTIFACT_MAX or
                    not offset + 24 <= symbol <= offset + length - 24 or
                    (symbol - offset) % 24 or symbol in seen):
                raise EvidenceError("invalid allowlisted import provenance")
            seen.add(symbol)
    if needs_truncation and not truncated:
        raise EvidenceError("missing evidence truncation disclosure")
    return value


@dataclass(frozen=True, slots=True)
class PublicEvidenceEnvelope:
    """Canonical bundle + identity. All wire fields are fixed by to_dict()."""

    artifact_sha256: str
    evidence_sha256: str
    bundle_json: bytes

    def __post_init__(self) -> None:
        bundle = _bundle(self.bundle_json)
        if (_digest(self.artifact_sha256) != bundle["artifact_sha256"] or
                _digest(self.evidence_sha256) != sha256(self.bundle_json).hexdigest()):
            raise EvidenceError("public evidence artifact/digest mismatch")
        if len(_canonical(self._wire(bundle))) > _MAX:
            raise EvidenceError("full public evidence envelope exceeds 48 KiB")

    def _wire(self, bundle: dict) -> dict[str, object]:
        return {"schema_version": 1, "artifact_sha256": self.artifact_sha256,
                "evidence_sha256": self.evidence_sha256, "bundle": bundle}

    @classmethod
    def from_bundle(cls, bundle: EvidenceBundle, *, expected_artifact_sha256: str):
        if type(bundle) is not EvidenceBundle:
            raise EvidenceError("original EvidenceBundle required")
        result = cls(bundle.artifact_sha256, bundle.digest(), bundle.canonical_json())
        result.validate_for(artifact_sha256=expected_artifact_sha256,
                            evidence_sha256=bundle.digest())
        return result

    @classmethod
    def from_json(cls, raw: bytes, *, expected_artifact_sha256: str,
                  expected_evidence_sha256: str):
        wire = _object(_load(raw), {"schema_version", "artifact_sha256", "evidence_sha256", "bundle"})
        if type(wire["schema_version"]) is not int or wire["schema_version"] != 1:
            raise EvidenceError("unsupported public evidence envelope version")
        result = cls(wire["artifact_sha256"], wire["evidence_sha256"], _canonical(wire["bundle"]))
        result.validate_for(artifact_sha256=expected_artifact_sha256,
                            evidence_sha256=expected_evidence_sha256)
        return result

    def validate_for(self, *, artifact_sha256: str, evidence_sha256: str) -> None:
        self.__post_init__()
        if (_digest(artifact_sha256) != self.artifact_sha256 or
                _digest(evidence_sha256) != self.evidence_sha256):
            raise EvidenceError("public evidence differs from trusted task identity")

    def to_dict(self) -> dict[str, object]:
        self.__post_init__()
        return self._wire(_bundle(self.bundle_json))

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())

    def require_live_dispatch(self) -> None:
        raise EvidenceError("live dispatch blocked: verified tokenizer and independent pre-dispatch leak clearance unavailable")
