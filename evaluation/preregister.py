"""Frozen experiment population. No corpus or expected answers are defined here."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re


def digest(value: object) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, RecursionError) as error:
        raise ValueError("canonical JSON value required") from error
    return sha256(encoded).hexdigest()


def require_digest(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("expected lowercase SHA256")
    return value


def closed(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"closed {label} shape required")
    return value


def text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"nonempty {label} required")
    return value


@dataclass(frozen=True)
class Cell:
    task_id: str
    family_id: str
    codec: str
    compiler: str
    optimization: str
    tier: str
    artifact_sha256: str
    execution_contract_sha256: str

    @property
    def identity(self) -> tuple[str, ...]:
        # Complete ELF and execution contract, never .text identity alone.
        return (self.family_id, self.codec, self.artifact_sha256, self.execution_contract_sha256)


@dataclass(frozen=True)
class Registration:
    edition: str
    cells: tuple[Cell, ...]
    models: tuple[str, ...]
    arms: tuple[str, ...]
    origin: str
    pins: tuple[tuple[str, str], ...]
    bootstrap_seed: int
    bootstrap_draws: int = 2000

    def validate(self) -> None:
        text(self.edition, "edition")
        if not isinstance(self.origin, str) or self.origin not in {"fixture", "live"}:
            raise ValueError("edition/origin required")
        if not isinstance(self.models, tuple) or any(not isinstance(x, str) or not x for x in self.models) or len(self.models) != 2 or len(set(self.models)) != 2:
            raise ValueError("freeze exactly two distinct model/config identities")
        if self.arms != ("S", "M", "R", "P", "echo", "constant", "lookup"):
            raise ValueError("fixed arm roster required")
        if self.bootstrap_draws != 2000 or type(self.bootstrap_seed) is not int:
            raise ValueError("freeze 2000 draws and an integer seed")
        if not isinstance(self.cells, tuple) or any(not isinstance(c, Cell) for c in self.cells):
            raise ValueError("cell tuple required")
        for c in self.cells:
            for name in ("task_id", "family_id", "codec", "compiler", "optimization", "tier"):
                text(getattr(c, name), name)
        if len(self.cells) != 96 or len({c.task_id for c in self.cells}) != 96:
            raise ValueError("all 96 distinct nominal cells required")
        families = {c.family_id for c in self.cells}
        if len(families) != 8 or any(not f for f in families):
            raise ValueError("exactly eight opaque semantic family identities required")
        expected = {(a, b, c) for a in ("dec", "hex", "bin") for b in ("gcc", "clang") for c in ("O0", "O2")}
        finite = 0
        for family in families:
            cells = [c for c in self.cells if c.family_id == family]
            if len(cells) != 12 or {(c.codec, c.compiler, c.optimization) for c in cells} != expected:
                raise ValueError("missing/duplicate crossed matrix cell")
            tiers = {c.tier for c in cells}
            if tiers not in ({"finite"}, {"ordinary"}):
                raise ValueError("family tier inconsistent")
            finite += tiers == {"finite"}
        if finite != 2:
            raise ValueError("exactly two finite-domain families required")
        for c in self.cells:
            require_digest(c.artifact_sha256)
            require_digest(c.execution_contract_sha256)
        required = {"engine", "scorer", "baselines", "prompts", "wrappers", "generators", "domain_policy", "resources", "prices", "schedule", "partitions", "source", "canaries"}
        if not isinstance(self.pins, tuple) or any(not isinstance(p, tuple) or len(p) != 2 or not isinstance(p[0], str) for p in self.pins):
            raise ValueError("pin name/digest pairs required")
        names = set(dict(self.pins))
        if len(dict(self.pins)) != len(self.pins) or names not in (required, required | {"model_bindings"}):
            raise ValueError("closed preregistration pin set required")
        for _, value in self.pins:
            require_digest(value)

    @property
    def sha256(self) -> str:
        self.validate()
        return digest(asdict(self))

    @property
    def final_keys(self) -> set[tuple[str, str, str]]:
        return {(c.task_id, model, arm) for c in self.cells for model in self.models for arm in self.arms}


def registration_from_dict(raw: dict) -> Registration:
    closed(raw, set(Registration.__dataclass_fields__), "registration")
    for field in ("cells", "models", "arms", "pins"):
        if not isinstance(raw[field], list):
            raise ValueError(f"registration {field} list required")
    cells = []
    for cell in raw["cells"]:
        closed(cell, set(Cell.__dataclass_fields__), "cell")
        cells.append(Cell(**cell))
    if any(not isinstance(p, list) or len(p) != 2 for p in raw["pins"]):
        raise ValueError("pin pairs required")
    result = Registration(**{**raw, "cells": tuple(cells), "models": tuple(raw["models"]), "arms": tuple(raw["arms"]), "pins": tuple(tuple(x) for x in raw["pins"])})
    result.validate()
    return result
