"""Frozen generic, visible-only DSL and deliberately weak controls.

Generated candidate programs are text. This module never compiles, imports or
executes candidate code. All future execution belongs to the isolated runner.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from time import monotonic
from typing import Iterable, Sequence


@dataclass(frozen=True)
class VisiblePair:
    stdin: bytes
    stdout: bytes
    exit_code: int = 0


@dataclass(frozen=True)
class BaselineResult:
    code: str | None
    status: str
    enumerated: int
    elapsed: float
    expression: tuple[tuple[str, int], ...] | None = None


def _validate_pairs(pairs: Sequence[VisiblePair]) -> None:
    if len(pairs) != 8:
        raise ValueError("requires exactly eight visible pairs")
    for pair in pairs:
        if not isinstance(pair.stdin, bytes) or not isinstance(pair.stdout, bytes):
            raise ValueError("visible inputs and outputs must be bytes")
        if len(pair.stdin) > 64 or len(pair.stdout) > 4096:
            raise ValueError("visible example exceeds public I/O bounds")
        if type(pair.exit_code) is not int:
            raise ValueError("visible exit status must be an integer")


# This source is original, standalone codec glue for sandbox candidates. Host
# matching uses the producer codec port; future parity checks must check both.
_CODEC_SOURCE = r'''
import sys
def decode(raw, codec, width):
    if len(raw) > 64:
        raise ValueError("input cap")
    size = width // 8
    limit = (1 << width) - 1
    if codec == "bin":
        if not raw or raw[0] != len(raw)-1 or raw[0] % size:
            raise ValueError("length")
        values = tuple(int.from_bytes(raw[i:i+size], "little") for i in range(1,len(raw),size))
    else:
        if not raw.endswith(b"\n"):
            raise ValueError("terminator")
        body = raw[:-1]
        if codec == "dec":
            fields = body.split(b",") if body else []
            if any(not f or any(c < 48 or c > 57 for c in f) or (len(f)>1 and f[0]==48) for f in fields):
                raise ValueError("decimal")
            values = tuple(int(f) for f in fields)
        elif codec == "hex":
            digits = size*2
            if len(body)%digits or any(c not in b"0123456789abcdef" for c in body):
                raise ValueError("hex")
            values = tuple(int(body[i:i+digits],16) for i in range(0,len(body),digits))
        else:
            raise ValueError("codec")
    if len(values)>8 or any(v>limit for v in values):
        raise ValueError("domain")
    return values
def encode(values, codec, width):
    if codec == "dec":
        return b",".join(str(v).encode("ascii") for v in values)+b"\n"
    if codec == "hex":
        return "".join(format(v,"0"+str(width//4)+"x") for v in values).encode("ascii")+b"\n"
    body = b"".join(v.to_bytes(width//8,"little") for v in values)
    return bytes([len(body)])+body
'''


def _apply(values: tuple[int, ...], step: tuple[str, int], mask: int) -> tuple[int, ...]:
    name, constant = step
    if name == "add":
        return tuple((v + constant) & mask for v in values)
    if name == "mul":
        return tuple((v * constant) & mask for v in values)
    if name == "xor":
        return tuple(v ^ constant for v in values)
    if name == "and":
        return tuple(v & constant for v in values)
    if name == "or":
        return tuple(v | constant for v in values)
    if name == "shl":
        return tuple((v << constant) & mask for v in values)
    if name == "shr":
        return tuple(v >> constant for v in values)
    if name == "reverse":
        return values[::-1]
    if name == "sort":
        return tuple(sorted(values))
    if name == "sum":
        return (sum(values) & mask,)
    if name == "length":
        return (len(values),)
    if name == "first":
        return values[:1]
    if name == "last":
        return values[-1:]
    if name == "delta":
        return tuple((v - (values[i-1] if i else 0)) & mask for i, v in enumerate(values))
    raise ValueError("unknown frozen DSL primitive")


def _expression(step: tuple[str, int], value: str, mask: int) -> str:
    name, k = step
    mapped = {
        "add": f"(v+{k})&{mask}", "mul": f"(v*{k})&{mask}",
        "xor": f"v^{k}", "and": f"v&{k}", "or": f"v|{k}",
        "shl": f"(v<<{k})&{mask}", "shr": f"v>>{k}",
    }
    if name in mapped:
        return f"tuple({mapped[name]} for v in {value})"
    return {
        "reverse": f"{value}[::-1]", "sort": f"tuple(sorted({value}))",
        "sum": f"(sum({value})&{mask},)", "length": f"(len({value}),)",
        "first": f"{value}[:1]", "last": f"{value}[-1:]",
        "delta": f"tuple((v-({value}[i-1] if i else 0))&{mask} for i,v in enumerate({value}))",
    }[name]


def _program(
    steps: tuple[tuple[str, int], ...], codec: str, width: int,
    input_arity: int | None, input_min: int, input_max: int,
    output_arity: int | None,
) -> str:
    lines = [_CODEC_SOURCE, "try:", f"    values = decode(sys.stdin.buffer.read(65), {codec!r}, {width})"]
    if input_arity is not None:
        lines.extend([f"    if len(values) != {input_arity}:", "        raise ValueError('arity')"])
    lines.extend([f"    if any(v < {input_min} or v > {input_max} for v in values):", "        raise ValueError('range')"])
    for step in steps:
        lines.append("    values = " + _expression(step, "values", (1 << width) - 1))
    if output_arity is not None:
        lines.extend([f"    if len(values) != {output_arity}:", "        raise ValueError('output arity')"])
    lines.extend([f"    sys.stdout.buffer.write(encode(values, {codec!r}, {width}))", "except (ValueError, OverflowError):", "    raise SystemExit(2)", ""])
    return "\n".join(lines)


def _grammar(constants: tuple[int, ...], width: int) -> Iterable[tuple[tuple[str, int], ...]]:
    # Length/lexical ranking is frozen here; caller order cannot tune the ranking.
    structural = tuple((name, 0) for name in ("reverse", "sort", "sum", "length", "first", "last", "delta"))
    arithmetic = tuple((name, k) for name in ("add", "mul", "xor", "and", "or") for k in constants)
    shifts = tuple((name, k) for name in ("shl", "shr") for k in (1, 2, width-1))
    primitives = structural + arithmetic + shifts
    yield ()
    for primitive in primitives:
        yield (primitive,)
    for left, right in product(primitives, repeat=2):
        yield (left, right)


def enumerate_baseline(
    pairs: Sequence[VisiblePair], *, codec: str, width: int,
    evidence_constants: Sequence[int] = (), max_candidates: int = 10_000,
    seconds: float = 2.0, input_arity: int | None = None,
    input_min: int = 0, input_max: int | None = None,
    output_arity: int | None = None,
) -> BaselineResult:
    """Find the first fitting generic transducer; no target execution is used.

    Supply exactly the public eight visible examples. Constants may come only
    from the allowlisted static evidence bundle. No family/template selector or
    target callback is accepted. Timer/candidate exhaustion always abstains.
    """
    if codec not in {"dec", "hex", "bin"} or width not in {8, 16}:
        raise ValueError("unsupported public codec contract")
    _validate_pairs(pairs)
    if type(max_candidates) is not int or not 1 <= max_candidates <= 10_000 or not 0 < seconds <= 2:
        raise ValueError("requires eight pairs and bounded search")
    if len(evidence_constants) > 64 or any(type(k) is not int for k in evidence_constants):
        raise ValueError("at most 64 integer evidence constants")
    from bbr.corpus.codecs import decode, encode

    start = monotonic()
    mask = (1 << width) - 1
    upper = mask if input_max is None else input_max
    if input_arity is not None and (type(input_arity) is not int or not 0 <= input_arity <= 8):
        raise ValueError("invalid public input arity")
    if output_arity is not None and (type(output_arity) is not int or not 0 <= output_arity <= 8):
        raise ValueError("invalid public output arity")
    if type(input_min) is not int or type(upper) is not int or not 0 <= input_min <= upper <= mask:
        raise ValueError("invalid public input range")
    constants = tuple(sorted({0, 1, 2, mask, *(k & mask for k in evidence_constants)}))
    examples: list[tuple[VisiblePair, tuple[int, ...] | None]] = []
    for pair in pairs:
        try:
            values = decode(pair.stdin, codec, width)
            if input_arity is not None and len(values) != input_arity:
                raise ValueError("arity")
            if any(v < input_min or v > upper for v in values):
                raise ValueError("range")
        except ValueError:
            values = None
        examples.append((pair, values))
    count = 0
    for steps in _grammar(constants, width):
        if count >= max_candidates or monotonic() - start >= seconds:
            return BaselineResult(None, "baseline_abstain_budget", count, monotonic()-start)
        count += 1
        fits = True
        for pair, values in examples:
            if monotonic() - start >= seconds:
                return BaselineResult(None, "baseline_abstain_budget", count, monotonic()-start)
            if values is None:
                predicted, exit_code = b"", 2
            else:
                for step in steps:
                    values = _apply(values, step, mask)
                if output_arity is not None and len(values) != output_arity:
                    predicted, exit_code = b"", 2
                else:
                    predicted, exit_code = encode(values, codec, width), 0
            if predicted != pair.stdout or exit_code != pair.exit_code:
                fits = False
                break
        if fits:
            code = _program(steps, codec, width, input_arity, input_min, upper, output_arity)
            if monotonic() - start >= seconds:
                return BaselineResult(None, "baseline_abstain_budget", count, monotonic()-start)
            return BaselineResult(code, "fit_visible_only", count, monotonic()-start, steps)
    return BaselineResult(None, "baseline_abstain_no_fit", count, monotonic()-start)


def controls(pairs: Sequence[VisiblePair]) -> dict[str, str]:
    """Frozen echo, first-visible constant and exact visible-pair lookup.

    Lookup preserves visible exit codes; unseen bytes always return empty/2.
    Contradictory visible duplicates are refused rather than silently overwritten.
    """
    _validate_pairs(pairs)
    lookup: dict[bytes, tuple[bytes, int]] = {}
    for pair in pairs:
        outcome = (pair.stdout, pair.exit_code)
        if pair.stdin in lookup and lookup[pair.stdin] != outcome:
            raise ValueError("contradictory visible examples")
        lookup[pair.stdin] = outcome
    prefix = "import sys\nraw = sys.stdin.buffer.read(65)\n"
    first = pairs[0]
    result = {
        "echo": prefix + "sys.stdout.buffer.write(raw)\n",
        "constant": prefix + f"sys.stdout.buffer.write({first.stdout!r})\nraise SystemExit({first.exit_code})\n",
        "visible_lookup": prefix + f"table = {lookup!r}\nout, status = table.get(raw, (b'', 2))\nsys.stdout.buffer.write(out)\nraise SystemExit(status)\n",
    }
    if any(len(code.encode("utf-8")) > 32_768 for code in result.values()):
        raise ValueError("control source exceeds 32 KiB candidate cap; do not truncate visible examples")
    return result


def baseline_for_task(visible_task, *, evidence_constants: Sequence[int] = ()) -> BaselineResult:
    """Production entrypoint always applies producer-owned public domain pins."""
    from bbr.contracts import VisibleTask

    task = VisibleTask.model_validate(visible_task)
    pairs = tuple(VisiblePair(row.stdin_bytes, row.stdout_bytes, row.exit_code)
                  for row in task.examples)
    return enumerate_baseline(pairs, codec=task.codec, width=task.domain.width,
                              evidence_constants=evidence_constants,
                              input_arity=task.domain.input_arity,
                              output_arity=task.domain.output_arity,
                              input_min=task.domain.minimum,
                              input_max=task.domain.maximum)
