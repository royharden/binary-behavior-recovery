"""Partition checks called by trusted custodian before seal."""
from __future__ import annotations

from .preregister import Registration, closed, digest

PARTITIONS = {"visible", "public_valid", "public_malformed", "private_valid", "private_malformed"}


def canonical_hex(value: object, max_bytes: int) -> str:
    if not isinstance(value, str) or len(value) > 2 * max_bytes:
        raise ValueError("bounded hex string required")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("invalid hex") from error
    if decoded.hex() != value:
        raise ValueError("noncanonical hex")
    return value


def audit_partitions(partitions: dict[str, list[dict]], tier: str) -> None:
    closed(partitions, PARTITIONS, "partitions")
    if not isinstance(tier, str) or tier not in {"finite", "ordinary"}:
        raise ValueError("closed partition roster/tier required")
    raw_seen, canonical_seen = set(), set()
    for name, records in partitions.items():
        if not isinstance(records, list):
            raise ValueError("partition record list required")
        for item in records:
            closed(item, {"raw_hex", "canonical_key"}, "input commitment")
            raw = canonical_hex(item["raw_hex"], 64)
            if raw in raw_seen:
                raise ValueError("raw partition intersection")
            raw_seen.add(raw)
            value = item["canonical_key"]
            if name.endswith("malformed"):
                if value is not None:
                    raise ValueError("malformed has no decoded canonical value")
            else:
                if not isinstance(value, str) or not value or value in canonical_seen:
                    raise ValueError("decoded canonical partition intersection/absence")
                canonical_seen.add(value)
    expected = {"visible": 8, "public_valid": 64, "public_malformed": 16, "private_malformed": 32}
    if any(len(partitions[k]) != n for k, n in expected.items()):
        raise ValueError("fixed partition sizes violated")
    hidden = len(partitions["private_valid"])
    if (tier == "finite" and hidden != 184) or (tier == "ordinary" and hidden < 256):
        raise ValueError("private canonical capacity violated")


def frozen_partitions(registration: Registration, manifest: dict) -> dict[str, dict]:
    """Validate supplied inputs only; never derive a corpus or expected answers."""
    registration.validate()
    closed(manifest, {"schema", "tasks"}, "partition manifest")
    if manifest["schema"] != "bbr.partitions.v1" or not isinstance(manifest["tasks"], list):
        raise ValueError("partition manifest schema/task list required")
    if digest(manifest) != dict(registration.pins)["partitions"]:
        raise ValueError("partition manifest differs from frozen commitment")
    cells = {c.task_id: c for c in registration.cells}
    tasks = {}
    variant_rosters, canonical_rosters = {}, {}
    for task in manifest["tasks"]:
        closed(task, {"task_id", "partitions"}, "partition task")
        task_id = task["task_id"]
        if not isinstance(task_id, str) or task_id not in cells or task_id in tasks:
            raise ValueError("duplicate/outside-roster partition task")
        cell = cells[task_id]
        audit_partitions(task["partitions"], cell.tier)
        # Sets are compared independent of supplied record order. Variants of a
        # family/codec inherit the identical raw/canonical roster.
        roster = {p: frozenset((r["raw_hex"], r["canonical_key"]) for r in rs)
                  for p, rs in task["partitions"].items()}
        variant_key = (cell.family_id, cell.codec)
        if variant_key in variant_rosters and variant_rosters[variant_key] != roster:
            raise ValueError("compiler/optimization variants changed input partitions")
        variant_rosters[variant_key] = roster
        canonical = {p: frozenset(r["canonical_key"] for r in rs)
                     for p, rs in task["partitions"].items() if not p.endswith("malformed")}
        if cell.family_id in canonical_rosters and canonical_rosters[cell.family_id] != canonical:
            raise ValueError("codecs changed canonical valid-input partitions")
        canonical_rosters[cell.family_id] = canonical
        tasks[task_id] = roster
    if set(tasks) != set(cells):
        raise ValueError("all 96 partition tasks required")
    return tasks
