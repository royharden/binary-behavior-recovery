"""Authored SOFTWARE TEST FIXTURES, origin=fixture, builder lineage.

These byte arrays are deliberately synthetic parser inputs, not compiled subject
artifacts, benchmark evidence, expected reference answers or independent data.
Nothing here executes their bytes or creates a subprocess.
"""
from hashlib import sha256
import json
import struct

ORIGIN = "authored_software_test_fixture_not_independent"


def fixture_sha(label: str) -> str:
    return sha256((ORIGIN + ":" + label).encode("ascii")).hexdigest()


def fixture_seed(label: str = "input-policy") -> bytes:
    """Public software-test reproducibility marker, never a corpus/custodian seed."""
    return bytes.fromhex(fixture_sha(label))


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def parser_elf(rodata: bytes = b"SOFTWARE FIXTURE\0", *, section_name: str = ".rodata") -> bytes:
    """Minimal synthetic ELF64 section-table parser fixture; NEVER execute."""
    names = b"\0.text\0" + section_name.encode("ascii") + b"\0.shstrtab\0"
    text = b"\x90\xc3"
    text_offset = 64
    data_offset = text_offset + len(text)
    names_offset = data_offset + len(rodata)
    shoff = (names_offset + len(names) + 7) & ~7
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0x401000,
                         0, shoff, 0, 64, 0, 0, 64, 4, 3)
    sections = [bytes(64),
        struct.pack("<IIQQQQIIQQ", names.index(b".text"), 1, 6, 0x401000,
                    text_offset, len(text), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", names.index(section_name.encode("ascii")), 1, 2,
                    0x402000, data_offset, len(rodata), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", names.index(b".shstrtab"), 3, 0, 0,
                    names_offset, len(names), 0, 0, 1, 0)]
    return (header + text + rodata + names).ljust(shoff, b"\0") + b"".join(sections)


def import_elf(import_names: tuple[bytes, ...]) -> bytes:
    """Synthetic undefined-symbol metadata parser fixture; not executable code."""
    names = b"\0.text\0.rodata\0.dynstr\0.dynsym\0.shstrtab\0"
    strings = bytearray(b"\0")
    symbols = bytearray(24)  # Required null symbol.
    for name in import_names:
        offset = len(strings)
        strings.extend(name + b"\0")
        symbols.extend(struct.pack("<IBBHQQ", offset, 0x12, 0, 0, 0, 0))
    data = bytearray(64)
    definitions = [("", 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name, payload, kind, flags, link, info, alignment, entry_size in (
        (".text", b"\x90\xc3", 1, 6, 0, 0, 1, 0),
        (".rodata", b"SOFTWARE FIXTURE\0", 1, 2, 0, 0, 1, 0),
        (".dynstr", bytes(strings), 3, 2, 0, 0, 1, 0),
        (".dynsym", bytes(symbols), 11, 2, 3, 1, 8, 24),
        (".shstrtab", names, 3, 0, 0, 0, 1, 0),
    ):
        offset = (len(data) + alignment - 1) // alignment * alignment
        data.extend(bytes(offset-len(data)))
        data.extend(payload)
        definitions.append((names.index(name.encode()), kind, flags, 0,
                            offset, len(payload), link, info, alignment, entry_size))
    shoff = (len(data)+7) & ~7
    data.extend(bytes(shoff-len(data)))
    for definition in definitions:
        name, *rest = definition
        data.extend(struct.pack("<IIQQQQIIQQ", name if type(name) is int else 0, *rest))
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    data[:64] = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0, 0,
                           shoff, 0, 64, 0, 0, 64, len(definitions), 5)
    return bytes(data)
