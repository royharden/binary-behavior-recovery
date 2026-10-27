"""Canonical public wire formats. Invalid input raises ValueError."""

from collections.abc import Iterable
import re


def _settings(codec: str, width: int) -> int:
    if codec not in {"dec", "hex", "bin"} or type(width) is not int or width not in {8, 16}:
        raise ValueError("unsupported codec or element width")
    return (1 << width) - 1


def encode(values: Iterable[int], codec: str, width: int) -> bytes:
    maximum = _settings(codec, width)
    items = tuple(values)
    if len(items) > 8 or any(type(v) is not int or not 0 <= v <= maximum for v in items):
        raise ValueError("invalid unsigned vector")
    if codec == "dec":
        return (",".join(str(v) for v in items) + "\n").encode("ascii")
    if codec == "hex":
        return ("".join(f"{v:0{width // 4}x}" for v in items) + "\n").encode("ascii")
    payload = b"".join(v.to_bytes(width // 8, "little") for v in items)
    return bytes([len(payload)]) + payload


def decode(raw: bytes, codec: str, width: int, max_elements: int = 8) -> tuple[int, ...]:
    maximum = _settings(codec, width)
    if type(raw) is not bytes or len(raw) > 64:
        raise ValueError("stdin must be bytes, at most 64 bytes")
    if type(max_elements) is not int or not 0 <= max_elements <= 8:
        raise ValueError("invalid element limit")
    if codec == "bin":
        step = width // 8
        if not raw or raw[0] != len(raw) - 1 or raw[0] % step:
            raise ValueError("invalid payload byte length")
        items = tuple(int.from_bytes(raw[i:i + step], "little") for i in range(1, len(raw), step))
    elif codec == "dec":
        if not re.fullmatch(rb"(?:0|[1-9][0-9]*)(?:,(?:0|[1-9][0-9]*))*\n|\n", raw):
            raise ValueError("noncanonical decimal")
        items = tuple(int(v) for v in raw[:-1].split(b",") if v)
    else:
        step = width // 4
        if not re.fullmatch(rb"[0-9a-f]*\n", raw) or (len(raw) - 1) % step:
            raise ValueError("noncanonical hexadecimal")
        items = tuple(int(raw[i:i + step], 16) for i in range(0, len(raw) - 1, step))
    if len(items) > max_elements or any(v > maximum for v in items):
        raise ValueError("vector outside public domain")
    return items
