"""Bounded, tool-free evidence from stripped ELF64 x86-64 artifacts.

No binary is executed. Code bytes are not disassembled: instruction boundaries
and function boundaries remain unknown. Only an explicit section allowlist is
exposed; debug, file paths and build metadata are not evidence inputs. Undefined
dynamic imports expose only fixed libc names; other names are counted, not emitted.
"""

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import struct
from typing import TYPE_CHECKING

from bbr.screen import screen

if TYPE_CHECKING:
    from bbr.contracts import Evidence

EXTRACTOR_VERSION = "bbr-elf-sections-v2"
_EVIDENCE_LIMITATIONS = (
    "raw sections only; instruction and function boundaries unknown",
    "strings are untrusted data; heuristic screening does not establish safety",
    "allowlist omits defined symbols, source/debug metadata and other section contents",
    "only fixed libc undefined import names are exposed; unknown names are counted",
    "binary behavior and source leakage require separate validation",
)
_ALLOWED = frozenset({".text", ".rodata", ".data"})
_ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
_SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
_SYMBOL = struct.Struct("<IBBHQQ")
_LIBC_IMPORTS = frozenset({
    "__libc_start_main", "__stack_chk_fail", "_Exit", "abort", "atoi", "calloc",
    "close", "exit", "fclose", "fflush", "fgetc", "fgets", "fopen", "fprintf",
    "fputc", "fputs", "fread", "free", "fwrite", "getchar", "malloc", "memcmp",
    "memcpy", "memmove", "memset", "perror", "printf", "putchar", "puts", "read",
    "realloc", "scanf", "snprintf", "sscanf", "strcmp", "strcpy", "strlen",
    "strncmp", "strncpy", "strtol", "strtoul", "strtoull", "write",
})
_LIBC_IMPORT_BYTES = frozenset(name.encode("ascii") for name in _LIBC_IMPORTS)


class EvidenceError(ValueError):
    """Unsupported, malformed, unstripped or oversized input; no partial bundle."""


@dataclass(frozen=True)
class EvidenceLimits:
    max_artifact_bytes: int = 8 * 1024 * 1024
    max_sections: int = 256
    max_section_bytes: int = 4 * 1024
    max_total_section_bytes: int = 8 * 1024
    max_strings: int = 24
    max_string_bytes: int = 96
    min_string_bytes: int = 4
    max_bundle_bytes: int = 48 * 1024

    def __post_init__(self) -> None:
        if any(type(v) is not int or v <= 0 for v in asdict(self).values()):
            raise ValueError("evidence limits must be positive integers")
        if self.min_string_bytes > self.max_string_bytes:
            raise ValueError("minimum string length exceeds maximum")
        ceilings = EvidenceLimits.__dataclass_fields__
        if any(getattr(self, k) > field.default for k, field in ceilings.items()):
            raise ValueError("limits may tighten but never exceed built-in ceilings")


@dataclass(frozen=True)
class SectionSlice:
    section: str
    virtual_address: int
    offset: int
    length: int
    sha256: str
    data_hex: str
    original_length: int
    boundary_uncertain: bool = True


@dataclass(frozen=True)
class StringEvidence:
    section: str
    offset: int
    length: int
    text: str
    html: str
    flags: tuple[str, ...]
    truncated: bool = False


@dataclass(frozen=True)
class ImportSymbol:
    """Allowlisted name and absolute file provenance, never a defined symbol."""

    name: str
    symbol_offset: int
    name_offset: int
    name_length: int


@dataclass(frozen=True)
class ImportMetadata:
    """Validated dynamic table facts; absent table differs from empty imports.

    Unknown counts refer to undefined global/weak entries, including duplicates.
    Unknown names/hashes are deliberately omitted to avoid a symbol-label channel.
    Table offset/length/hash authenticate the inspected bytes in the pinned ELF.
    """

    table_present: bool
    table_offset: int | None
    table_length: int
    table_sha256: str | None
    known: tuple[ImportSymbol, ...]
    known_count: int
    unknown_count: int
    flags: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceBundle:
    artifact_sha256: str
    extractor_version: str
    sections: tuple[SectionSlice, ...]
    strings: tuple[StringEvidence, ...]
    imports: ImportMetadata
    truncated: bool
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def canonical_json(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    def digest(self) -> str:
        return sha256(self.canonical_json()).hexdigest()

    def to_contract(self) -> "Evidence":
        """Narrow envelope adapter: raw hex, HTML and imports stay bundle-local.

        Until shared contracts admit ImportMetadata, callers needing import
        evidence must consume this canonical bundle, not this narrow envelope.
        """
        from bbr.contracts import Evidence, EvidencePointer, EvidenceString

        return Evidence(
            artifact_sha256=self.artifact_sha256,
            extractor_version=self.extractor_version,
            sections=tuple(EvidencePointer(section=s.section, offset=s.offset,
                length=s.length, sha256=s.sha256, boundary_uncertain=s.boundary_uncertain)
                for s in self.sections),
            strings=tuple(EvidenceString(section=s.section, offset=s.offset,
                length=s.length, text=s.text, flags=s.flags) for s in self.strings),
            truncated=self.truncated,
            limitations=self.limitations + ("dynamic import metadata remains in canonical evidence bundle",),
        )


@dataclass(frozen=True)
class _Section:
    name: str
    kind: int
    flags: int
    address: int
    offset: int
    size: int


def _span(blob: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset > len(blob) or size > len(blob) - offset:
        raise EvidenceError("ELF span outside artifact")
    return blob[offset:offset + size]


def _sections(blob: bytes, limits: EvidenceLimits) -> tuple[_Section, ...]:
    if len(blob) < _ELF_HEADER.size:
        raise EvidenceError("truncated ELF header")
    h = _ELF_HEADER.unpack_from(blob)
    ident, kind, machine, version = h[:4]
    if ident[:7] != b"\x7fELF\x02\x01\x01" or machine != 62 or version != 1 or kind not in (2, 3):
        raise EvidenceError("requires executable/shared ELF64 little-endian x86-64 v1")
    shoff, ehsize, shentsize, shnum, shstrndx = h[6], h[8], h[11], h[12], h[13]
    if ehsize != 64 or shentsize != 64 or not 1 <= shnum <= limits.max_sections:
        raise EvidenceError("unsupported section table or section-count cap")
    if shstrndx == 0 or shstrndx >= shnum:
        raise EvidenceError("missing or extended section-name table")
    _span(blob, shoff, shnum * shentsize)
    headers = tuple(_SECTION_HEADER.unpack_from(blob, shoff + i * shentsize) for i in range(shnum))
    name_header = headers[shstrndx]
    if name_header[1] != 3 or name_header[5] > 64 * 1024:
        raise EvidenceError("invalid or oversized section-name table")
    names = _span(blob, name_header[4], name_header[5])
    found: list[_Section] = []
    exposed_names: set[str] = set()
    for header in headers:
        name_start, section_kind, flags, address, offset, size = header[:6]
        if name_start >= len(names):
            raise EvidenceError("section name offset outside table")
        end = names.find(b"\0", name_start)
        if end < 0 or end - name_start > 256:
            raise EvidenceError("unterminated or oversized section name")
        try:
            name = names[name_start:end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise EvidenceError("non-ASCII section name") from exc
        if name == ".symtab" or name.startswith((".debug", ".zdebug")) or name in (".gnu_debuglink", ".gnu_debugdata"):
            raise EvidenceError("symbol/debug-bearing artifact is not stripped evidence")
        if section_kind != 8:  # NOBITS has no file bytes.
            _span(blob, offset, size)
        if name in _ALLOWED:
            if name in exposed_names or section_kind != 1 or not flags & 2:
                raise EvidenceError("duplicate or invalid allowed evidence section")
            if offset < 64 or offset < shoff + shnum * shentsize and offset + size > shoff:
                raise EvidenceError("evidence section overlaps ELF metadata")
            exposed_names.add(name)
            found.append(_Section(name, section_kind, flags, address, offset, size))
    if ".text" not in exposed_names:
        raise EvidenceError("missing .text evidence section")
    ordered = sorted(found, key=lambda s: (s.offset, s.name))
    if any(a.offset + a.size > b.offset for a, b in zip(ordered, ordered[1:])):
        raise EvidenceError("overlapping evidence sections")
    return tuple(ordered)


def _strings(data: bytes, section: str, file_offset: int, limits: EvidenceLimits,
             remaining: int) -> tuple[list[StringEvidence], bool]:
    result: list[StringEvidence] = []
    start = 0
    omitted = False
    while start < len(data):
        if not 32 <= data[start] <= 126:
            start += 1
            continue
        end = start + 1
        while end < len(data) and 32 <= data[end] <= 126:
            end += 1
        if end - start >= limits.min_string_bytes:
            if len(result) >= remaining:
                omitted = True
                break
            count = min(end - start, limits.max_string_bytes)
            screened = screen(data[start:start + count].decode("ascii"))
            cut = count < end - start
            result.append(StringEvidence(section, file_offset + start, count,
                screened.text, screened.html, screened.flags, cut))
            omitted |= cut
        start = end
    return result, omitted


def _imports(blob: bytes) -> ImportMetadata:
    """Read at most one 2,048-entry DYNSYM and a 64-KiB linked STRTAB.

    Called only after full ELF/section-span validation. No dynamic loader runs.
    Only undefined global/weak symbols of ordinary object/function/notype/IFUNC
    types participate. Extended indices, malformed names and links fail closed.
    """
    header = _ELF_HEADER.unpack_from(blob)
    shoff, shentsize, shnum = header[6], header[11], header[12]
    tables = tuple(_SECTION_HEADER.unpack_from(blob, shoff + i * shentsize)
                   for i in range(shnum))
    dynamic = tuple(s for s in tables if s[1] == 11)
    if not dynamic:
        return ImportMetadata(False, None, 0, None, (), 0, 0, ("dynamic_table_absent",))
    if len(dynamic) != 1:
        raise EvidenceError("multiple dynamic symbol tables unsupported")
    table = dynamic[0]
    offset, size, link, first_global, entry_size = table[4], table[5], table[6], table[7], table[9]
    if entry_size != _SYMBOL.size or size < entry_size or size % entry_size or size // entry_size > 2048:
        raise EvidenceError("invalid dynamic symbol table shape or symbol cap")
    if not 0 < link < shnum or not 1 <= first_global <= size // entry_size:
        raise EvidenceError("invalid dynamic symbol table link/local boundary")
    strings = tables[link]
    if strings[1] != 3 or not 1 <= strings[5] <= 64 * 1024:
        raise EvidenceError("dynamic symbols require bounded linked string table")
    raw = _span(blob, offset, size)
    names = _span(blob, strings[4], strings[5])
    if names[0] != 0 or names[-1] != 0 or any(raw[:entry_size]):
        raise EvidenceError("missing dynamic table/string null entry")
    known: list[ImportSymbol] = []
    known_count = 0
    unknown = 0
    for index in range(1, size // entry_size):
        name_start, info, other, section_index, _, _ = _SYMBOL.unpack_from(raw, index * entry_size)
        binding, symbol_type = info >> 4, info & 15
        if section_index == 0xFFFF or other & ~3:
            raise EvidenceError("unsupported extended symbol index or visibility")
        if shnum <= section_index < 0xFF00:
            raise EvidenceError("dynamic symbol section index outside section table")
        if (index < first_global) != (binding == 0):
            raise EvidenceError("dynamic local/global boundary disagrees with binding")
        if name_start >= len(names):
            raise EvidenceError("dynamic name offset outside linked string table")
        end = names.find(b"\0", name_start, min(len(names), name_start + 129))
        if end < 0:
            raise EvidenceError("unterminated or oversized dynamic symbol name")
        if section_index != 0 or name_start == 0:
            continue
        if binding not in (1, 2) or symbol_type not in (0, 1, 2, 10):
            raise EvidenceError("unsupported undefined dynamic symbol type/binding")
        name = names[name_start:end]
        if name in _LIBC_IMPORT_BYTES:
            known_count += 1
            if len(known) < 64:
                known.append(ImportSymbol(name.decode("ascii"), offset + index * entry_size,
                    strings[4] + name_start, end - name_start))
        else:
            unknown += 1
    flags = (("unknown_import_names_omitted",) if unknown else ())
    if known_count > len(known):
        flags += ("known_imports_truncated",)
    return ImportMetadata(True, offset, size, sha256(raw).hexdigest(), tuple(known),
        known_count, unknown, flags)


def extract(artifact: bytes, limits: EvidenceLimits | None = None) -> EvidenceBundle:
    """Extract a deterministic, bounded allowlisted bundle or fail closed.

    File offsets are absolute, lengths describe only retained bytes, and the
    digest of each section slice authenticates precisely those retained bytes.
    Nothing scans source paths, references, defined symbols or caller directories.
    """
    limits = limits or EvidenceLimits()
    if type(artifact) is not bytes or len(artifact) > limits.max_artifact_bytes:
        raise EvidenceError("artifact must be bounded immutable bytes")
    sections = _sections(artifact, limits)
    imports = _imports(artifact)
    slices: list[SectionSlice] = []
    strings: list[StringEvidence] = []
    used = 0
    truncated = "known_imports_truncated" in imports.flags
    for section in sections:
        count = min(section.size, limits.max_section_bytes, limits.max_total_section_bytes - used)
        truncated |= count < section.size
        if not count:
            continue
        data = _span(artifact, section.offset, count)
        slices.append(SectionSlice(section.name, section.address, section.offset, count, sha256(data).hexdigest(),
            data.hex(), section.size))
        # Executable bytes are retained but never presented as guessed strings.
        if section.name != ".text":
            additions, omitted = _strings(data, section.name, section.offset, limits,
                limits.max_strings - len(strings))
            strings.extend(additions)
            truncated |= omitted
        used += count
    bundle = EvidenceBundle(sha256(artifact).hexdigest(), EXTRACTOR_VERSION,
        tuple(slices), tuple(strings), imports, truncated, _EVIDENCE_LIMITATIONS)
    if len(bundle.canonical_json()) > limits.max_bundle_bytes:
        raise EvidenceError("serialized bundle exceeds byte cap")
    return bundle


__all__ = ["EvidenceBundle", "EvidenceError", "EvidenceLimits", "EXTRACTOR_VERSION",
    "ImportMetadata", "ImportSymbol", "SectionSlice", "StringEvidence", "extract",
    "PublicEvidenceEnvelope"]

# Import after extractor dataclasses are defined; the envelope validates that exact schema.
from .public import PublicEvidenceEnvelope
