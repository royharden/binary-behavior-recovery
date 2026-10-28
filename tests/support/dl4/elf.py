"""Authored software-parser fixture; no executable image or benchmark evidence.

The bytes have section metadata only (no program headers/loadable segments).
Tests pass them to trusted metadata parsers, never an OS loader or worker.
"""
from __future__ import annotations

import struct


def metadata_only_elf() -> bytes:
    names = b"\0.text\0.rodata\0.shstrtab\0"
    text = b"\xc3"
    data = b"BUILDER_AUTHORED_SOFTWARE_TEST_ONLY <script>inert</script>\0"
    name_offset = 64 + len(text) + len(data)
    shoff = (name_offset + len(names) + 7) // 8 * 8
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0, 0, shoff,
                         0, 64, 0, 0, 64, 4, 3)
    section = struct.Struct("<IIQQQQIIQQ")
    table = section.pack(*([0] * 10))
    table += section.pack(1, 1, 6, 0x400000, 64, len(text), 0, 0, 1, 0)
    table += section.pack(7, 1, 2, 0x401000, 65, len(data), 0, 0, 1, 0)
    table += section.pack(15, 3, 0, 0, name_offset, len(names), 0, 0, 1, 0)
    prefix = header + text + data + names
    return prefix + b"\0" * (shoff - len(prefix)) + table
