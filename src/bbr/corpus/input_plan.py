"""Generic, bounded input-policy software; no admission or independent data.

Builders must not invoke this module to materialize independent/held-out pools.
A separately appointed custodian selects and commits actual seeds and boundaries
after engine freeze. No family semantics, reference functions or outcomes enter.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from bbr.contracts import Domain
from bbr.differential.partitions import InputPartition, audit_partitions, deterministic_partition
from .codecs import decode, encode

Values = tuple[int, ...]
RECIPE_VERSION = "bbr-input-plan-v1"
_MAX_BOUNDARIES = 1024
_LIMITATIONS = (
    "software-generated policy, not independently authored/sealed/admitted data",
    "SHA256 counter recipe; modulo mapping and bounded top-up are not IID sampling",
    "malformed byte pools are codec-specific; canonical valid partitions are shared",
    "no expected answers, family semantics or candidate scores are consulted",
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _domain(domain: Domain) -> dict[str, int]:
    if type(domain) is not Domain:
        raise ValueError("exact public Domain required, without family/source fields")
    result = {key: getattr(domain, key) for key in
              ("width", "input_arity", "output_arity", "minimum", "maximum")}
    if (any(type(v) is not int for v in result.values()) or domain.width not in (8, 16) or
            not 1 <= domain.input_arity <= 8 or not 0 <= domain.output_arity <= 8 or
            not 0 <= domain.minimum <= domain.maximum < (1 << domain.width)):
        raise ValueError("unsupported public domain")
    return result


def _capacity(domain: Domain) -> int:
    return (domain.maximum - domain.minimum + 1) ** domain.input_arity


def _prefix(domain: Domain, seed: bytes) -> bytes:
    if type(seed) is not bytes or len(seed) != 32:
        raise ValueError("caller must supply exactly 32 committed seed bytes")
    return sha256(RECIPE_VERSION.encode("ascii") + b"\0" +
                  _canonical(_domain(domain)) + b"\0" + seed).digest()


def _stream(prefix: bytes, label: bytes, counter: int) -> bytes:
    return sha256(prefix + b"\0" + label + b"\0" + counter.to_bytes(8, "big")).digest()


def _value(domain: Domain, rank: int) -> Values:
    radix = domain.maximum - domain.minimum + 1
    values = [domain.minimum] * domain.input_arity
    for index in range(domain.input_arity - 1, -1, -1):
        rank, digit = divmod(rank, radix)
        values[index] += digit
    if rank:
        raise ValueError("rank outside public capacity")
    return tuple(values)


def _check_value(domain: Domain, values: Values) -> None:
    if (type(values) is not tuple or len(values) != domain.input_arity or
            any(type(v) is not int or not domain.minimum <= v <= domain.maximum for v in values)):
        raise ValueError("canonical value outside public Domain")


def _top_up(domain: Domain, prefix: bytes, label: bytes, initial: tuple[Values, ...],
            excluded: set[Values], target: int) -> tuple[tuple[Values, ...], int]:
    """One seeded rotation, at most target+excluded ranks; never retry forever."""
    capacity = _capacity(domain)
    if capacity < target + len(excluded):
        raise ValueError("insufficient distinct capacity for required population")
    selected = list(dict.fromkeys(v for v in initial if v not in excluded))
    if len(selected) > target:
        raise ValueError("recipe exceeds declared target")
    seen = set(selected)
    before = len(selected)
    start = int.from_bytes(_stream(prefix, label, 0), "big") % capacity
    # This many distinct cyclic ranks contains enough nonexcluded/nonselected
    # values to fill target. The domain may be huge; it is never enumerated here.
    for counter in range(target + len(excluded)):
        if len(selected) == target:
            break
        value = _value(domain, (start + counter) % capacity)
        if value not in excluded and value not in seen:
            selected.append(value)
            seen.add(value)
    if len(selected) != target:
        raise ValueError("bounded top-up exhausted; population must not shrink")
    return tuple(selected), len(selected) - before


def _values_sha(values: tuple[Values, ...]) -> str:
    return sha256(_canonical(values)).hexdigest()


@dataclass(frozen=True)
class InputPlan:
    """Custodian-only canonical pools. summary() reveals no values or raw seed."""

    domain: Domain
    seed_sha256: str
    visible: tuple[Values, ...]
    public: tuple[Values, ...]
    private: tuple[Values, ...]
    reserved_private: tuple[Values, ...]
    grammar_sha256: str | None
    encoding_sha256: str | None
    private_top_up_count: int
    public_top_up_count: int

    @property
    def top_up_count(self) -> int:
        return self.private_top_up_count + self.public_top_up_count

    def _record(self) -> dict[str, object]:
        return {"recipe_version": RECIPE_VERSION, "domain": _domain(self.domain),
                "seed_sha256": self.seed_sha256, "visible": self.visible,
                "public": self.public, "private": self.private,
                "reserved_private": self.reserved_private,
                "grammar_sha256": self.grammar_sha256, "encoding_sha256": self.encoding_sha256,
                "private_top_up_count": self.private_top_up_count,
                "public_top_up_count": self.public_top_up_count}

    def commitment(self) -> str:
        return sha256(_canonical(self._record())).hexdigest()

    def summary(self) -> dict[str, object]:
        return {"recipe_version": RECIPE_VERSION,
                "domain_sha256": sha256(_canonical(_domain(self.domain))).hexdigest(),
                "seed_sha256": self.seed_sha256, "canonical_sha256": self.commitment(),
                "tier": "finite256" if _capacity(self.domain) == 256 else "ordinary",
                "capacity": _capacity(self.domain), "visible_count": len(self.visible),
                "public_count": len(self.public), "private_count": len(self.private),
                "reserved_private_count": len(self.reserved_private),
                "grammar_sha256": self.grammar_sha256, "encoding_sha256": self.encoding_sha256,
                "private_top_up_count": self.private_top_up_count,
                "public_top_up_count": self.public_top_up_count,
                "top_up_count": self.top_up_count, "limitations": _LIMITATIONS}


def plan_inputs(domain: Domain, *, seed: bytes,
                reserved_private: tuple[Values, ...] = ()) -> InputPlan:
    """Pure future-custodian recipe. No files, reference answers or model calls.

    Finite: exactly256 canonical values,8/64/184. Ordinary:8/64/(256+B),
    requiring at least328+B capacity; caller boundaries B never become visible.
    """
    prefix = _prefix(domain, seed)
    if type(reserved_private) is not tuple or len(reserved_private) > _MAX_BOUNDARIES:
        raise ValueError("reserved private boundaries must be a bounded tuple")
    for value in reserved_private:
        _check_value(domain, value)
    if len(set(reserved_private)) != len(reserved_private):
        raise ValueError("duplicate reserved private boundary")
    reserved = tuple(sorted(reserved_private))
    blocked = set(reserved)
    capacity = _capacity(domain)
    partition_seed = _stream(prefix, b"canonical-partition", 0)
    if capacity == 256:
        if len(reserved) > 184:
            raise ValueError("reserved boundaries exceed finite private capacity")
        population = tuple(_value(domain, rank) for rank in range(256))
        visible, public, private = deterministic_partition(
            (v for v in population if v not in blocked), seed=partition_seed,
            visible=8, public=64, private=184-len(reserved))
        private = deterministic_partition(private + reserved,
            seed=_stream(prefix, b"private-order", 0), visible=0, public=0, private=184)[2]
        return InputPlan(domain, sha256(seed).hexdigest(), visible, public, private,
                         reserved, None, None, 0, 0)
    if capacity < 328 + len(reserved):
        raise ValueError("ordinary capacity requires328 plus all extra private boundaries")
    # One rank per stratum; no family-specific boundaries or behavior are used.
    grammar = tuple(_value(domain, (i * capacity // 128) +
        int.from_bytes(_stream(prefix, b"grammar-valid", i), "big") %
        (((i+1) * capacity // 128) - (i * capacity // 128))) for i in range(128))
    step = domain.width // 8
    radix = domain.maximum - domain.minimum + 1
    # Draw little-endian width-shaped bytes, map into the public domain, then
    # inherit the SAME canonical values when each codec is encoded later.
    encoding = tuple(tuple(domain.minimum + int.from_bytes(
        _stream(prefix, b"encoding-random", i)[j*step:(j+1)*step], "little") % radix
        for j in range(domain.input_arity)) for i in range(128))
    generated, private_top_up = _top_up(domain, prefix, b"private-top-up",
                                      grammar + encoding, blocked, 256)
    private = deterministic_partition(generated + reserved,
        seed=_stream(prefix, b"private-order", 0), visible=0, public=0,
        private=256+len(reserved))[2]
    initial_public = tuple(_value(domain, int.from_bytes(
        _stream(prefix, b"visible-public", i), "big") % capacity) for i in range(72))
    public_population, public_top_up = _top_up(domain, prefix, b"public-top-up",
                                               initial_public, set(private), 72)
    visible, public, _ = deterministic_partition(public_population, seed=partition_seed,
                                                  visible=8, public=64, private=0)
    return InputPlan(domain, sha256(seed).hexdigest(), visible, public, private, reserved,
                     _values_sha(grammar), _values_sha(encoding), private_top_up, public_top_up)


def _decode_domain(raw: bytes, domain: Domain, codec: str) -> Values:
    values = decode(raw, codec, domain.width)
    _check_value(domain, values)
    if encode(values, codec, domain.width) != raw:
        raise ValueError("noncanonical domain input")
    return values


def _malformed(domain: Domain, prefix: bytes, codec: str) -> tuple[bytes, ...]:
    """At most288 attempts; unique tagged fallback every sixth attempt is invalid.

    Counter bytes make all48 fallback candidates distinct even if digests collide.
    Every candidate is still checked through the actual codec+Domain predicate.
    """
    result = []
    seen = set()
    for counter in range(288):
        draw = _stream(prefix, b"malformed-" + codec.encode("ascii"), counter)
        valid = encode(_value(domain, int.from_bytes(draw, "big") % _capacity(domain)),
                       codec, domain.width)
        payload = counter.to_bytes(2, "big") + draw[:16]
        if codec == "bin":
            candidates = (bytes([valid[0]+1]) + valid[1:], valid + draw[:1],
                          valid[:-1], b"\0" + valid,
                          bytes([len(payload)+1]) + payload,
                          bytes([len(payload)+1]) + payload)
        else:
            candidates = (valid+b"\n", b" "+valid, valid[:-1],
                          (b"+" if codec == "dec" else b"G")+valid,
                          b"\xff"+payload, b"\xff"+payload)
        raw = candidates[counter % 6]
        if len(raw) > 64 or raw in seen:
            continue
        try:
            _decode_domain(raw, domain, codec)
        except ValueError:
            seen.add(raw)
            result.append(raw)
        if len(result) == 48:
            return tuple(result)
    raise ValueError("malformed capacity exhausted; required population must not shrink")


@dataclass(frozen=True)
class EncodedInputPlan:
    codec: str
    canonical_sha256: str
    partitions: tuple[InputPartition, ...]
    audit_sha256: str

    @property
    def public_inputs(self) -> tuple[bytes, ...]:
        return self.partitions[1].valid + self.partitions[1].malformed

    def summary(self) -> dict[str, object]:
        return {"recipe_version": RECIPE_VERSION, "codec": self.codec,
                "canonical_sha256": self.canonical_sha256, "audit_sha256": self.audit_sha256,
                "counts": tuple({"name": p.name, "valid": len(p.valid),
                                 "malformed": len(p.malformed)} for p in self.partitions),
                "limitations": _LIMITATIONS}


def encode_plan(plan: InputPlan, codec: str, *, seed: bytes) -> EncodedInputPlan:
    """Encode one canonical plan and invoke the sole existing byte/value audit.

    Actual execution is custodian work after freeze. Never send this private-bearing
    return value to providers; public_inputs is the only probe-eligible byte list.
    """
    if type(plan) is not InputPlan or codec not in ("dec", "hex", "bin"):
        raise ValueError("supported InputPlan and codec required")
    rebuilt = plan_inputs(plan.domain, seed=seed, reserved_private=plan.reserved_private)
    if plan != rebuilt:
        raise ValueError("plan does not match the committed seed/domain/recipe")
    malformed = _malformed(plan.domain, _prefix(plan.domain, seed), codec)
    groups = (plan.visible, plan.public, plan.private)
    partitions = tuple(InputPartition(name,
        tuple(encode(value, codec, plan.domain.width) for value in values), invalid)
        for name, values, invalid in zip(("visible", "public", "private"), groups,
                                        ((), malformed[:16], malformed[16:])))
    finite = frozenset(plan.visible+plan.public+plan.private) if _capacity(plan.domain) == 256 else None
    audit = audit_partitions(partitions,
        decode=lambda raw: _decode_domain(raw, plan.domain, codec), finite_domain=finite,
        minimum_valid=(8, 64, len(plan.private)))
    return EncodedInputPlan(codec, plan.commitment(), partitions, audit)
