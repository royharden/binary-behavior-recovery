"""Audit supplied inputs, never generate independent or held-out expected answers."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Callable, Iterable


@dataclass(frozen=True)
class InputPartition:
    name: str
    valid: tuple[bytes, ...]
    malformed: tuple[bytes, ...] = ()


def audit_partitions(partitions: tuple[InputPartition, ...], *,
                     decode: Callable[[bytes], tuple[int, ...]],
                     finite_domain: frozenset[tuple[int, ...]] | None = None,
                     minimum_valid: tuple[int, ...] | None = None) -> str:
    """Refuse overlap in bytes AND decoded values, including malformed streams.

    The caller supplies a strict codec/domain decoder. A canonical decoder that
    accepts malformed bytes cannot establish the public grammar admission gate.
    Returns a deterministic commitment only after every supplied audit passes.
    """
    if len({p.name for p in partitions}) != len(partitions):
        raise ValueError("partition names must be unique")
    if minimum_valid is not None and len(minimum_valid) != len(partitions):
        raise ValueError("minimum count arity mismatch")
    all_raw: set[bytes] = set()
    all_values: set[tuple[int, ...]] = set()
    record = []
    for index, partition in enumerate(partitions):
        if minimum_valid is not None and len(partition.valid) < minimum_valid[index]:
            raise ValueError("partition capacity not satisfied")
        canonical = []
        for raw in partition.valid:
            if type(raw) is not bytes or len(raw) > 64 or raw in all_raw:
                raise ValueError("duplicate/oversized raw input")
            values = decode(raw)
            if values in all_values:
                raise ValueError("canonical overlap or duplicate")
            if finite_domain is not None and values not in finite_domain:
                raise ValueError("input outside declared finite domain")
            all_raw.add(raw)
            all_values.add(values)
            canonical.append(list(values))
        for raw in partition.malformed:
            if type(raw) is not bytes or len(raw) > 64 or raw in all_raw:
                raise ValueError("malformed/raw overlap or oversized input")
            try:
                decode(raw)
            except ValueError:
                pass
            else:
                raise ValueError("malformed pool contains valid input")
            all_raw.add(raw)
        record.append({"name": partition.name,
                       "valid": [r.hex() for r in partition.valid],
                       "values": canonical,
                       "malformed": [r.hex() for r in partition.malformed]})
    if finite_domain is not None and all_values != finite_domain:
        raise ValueError("finite domain is not exhaustively partitioned")
    return sha256(json.dumps(record, sort_keys=True, separators=(",", ":"))
                  .encode("ascii")).hexdigest()


def deterministic_partition(values: Iterable[tuple[int, ...]], *, seed: bytes,
                            visible: int = 8, public: int = 64,
                            private: int = 256) -> tuple[tuple[tuple[int, ...], ...], ...]:
    """Hash-order a caller-owned canonical population; no RNG-version dependency.

    Finite 256-value callers explicitly request private=184. All selected values
    inherit the same partition when encoded into any codec/compiler variant.
    """
    if type(seed) is not bytes or not seed:
        raise ValueError("nonempty committed seed required")
    if any(type(n) is not int or n < 0 for n in (visible, public, private)):
        raise ValueError("invalid partition sizes")
    population = list(values)
    if len(set(population)) != len(population):
        raise ValueError("duplicate canonical population")
    if len(population) < visible + public + private:
        raise ValueError("insufficient canonical capacity")
    def key(value: tuple[int, ...]) -> tuple[bytes, tuple[int, ...]]:
        encoded = json.dumps(value, separators=(",", ":")).encode("ascii")
        return sha256(seed + b"\x00" + encoded).digest(), value
    ordered = sorted(population, key=key)
    return (tuple(ordered[:visible]), tuple(ordered[visible:visible + public]),
            tuple(ordered[visible + public:visible + public + private]))
