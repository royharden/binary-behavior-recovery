"""Bounded deterministic greedy reduction; no claim of global minimality."""

from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from bbr.contracts import PairOutcome


@dataclass(frozen=True)
class ShrinkResult:
    original: bytes
    reduced: bytes
    original_outcome: PairOutcome
    reduced_outcome: PairOutcome
    trace: tuple[tuple[bytes, PairOutcome], ...]
    status: str
    paired_executions: int
    elapsed_seconds: float
    move_policy: str = "contiguous-deletion-numeric-boundary-v1"


def grammar_moves(raw: bytes, *, decode: Callable[[bytes], tuple[int, ...]],
                  encode: Callable[[tuple[int, ...]], bytes], width: int,
                  in_domain: Callable[[tuple[int, ...]], bool]) -> tuple[bytes, ...]:
    if width not in (8, 16):
        raise ValueError("width must be 8 or 16 bits")
    values = decode(raw)
    if len(values) > 8 or not in_domain(values):
        raise ValueError("input outside declared domain")
    proposals: set[tuple[int, ...]] = set()
    for start in range(len(values)):
        for stop in range(start + 1, len(values) + 1):
            proposals.add(values[:start] + values[stop:])
    maximum = (1 << width) - 1
    for index, value in enumerate(values):
        boundaries = {0, 1, maximum, maximum - 1, value // 2,
                      max(0, value - 1)}
        for boundary in boundaries:
            proposals.add(values[:index] + (boundary,) + values[index + 1:])
    encoded = set()
    for proposal in proposals:
        if not in_domain(proposal):
            continue
        item = encode(proposal)
        if type(item) is not bytes or len(item) > 64 or decode(item) != proposal:
            raise ValueError("codec move failed round trip")
        if (len(item), item) < (len(raw), raw):
            encoded.add(item)
    return tuple(sorted(encoded, key=lambda item: (len(item), item)))


def shrink(case: bytes, move_policy: Callable[[bytes], tuple[bytes, ...]], *,
           evaluate: Callable[[bytes], PairOutcome], final_locked: bool,
           max_pairs: int = 256, max_seconds: float = 30.0) -> ShrinkResult:
    """Only call after final locks; evaluate must honor the remaining deadline.

    Synchronous callbacks cannot be forcibly interrupted here. The isolated worker
    must bound each pair by the supplied campaign deadline. No new evaluation is
    launched after this budget; an overrun returns a budget-limited certificate.
    """
    if not final_locked:
        raise ValueError("feedback-stage shrinking is forbidden")
    if type(case) is not bytes or len(case) > 64:
        raise ValueError("invalid case bytes")
    if type(max_pairs) is not int or not 1 <= max_pairs <= 256:
        raise ValueError("pair budget outside 1..256")
    if not 0 < max_seconds <= 30:
        raise ValueError("time budget outside (0,30]")
    start = monotonic()
    original = evaluate(case)
    trace = [(case, original)]
    current, outcome = case, original
    status = "shrink_exhausted"
    if original.status in {"equal", "infrastructure_error"}:
        return ShrinkResult(case, case, original, original, tuple(trace), status,
                            1, monotonic() - start)
    while True:
        moves = move_policy(current)
        if len(moves) > 256 or len(set(moves)) != len(moves):
            raise ValueError("move policy must return <=256 distinct moves")
        moves = tuple(sorted(moves, key=lambda item: (len(item), item)))
        improved = False
        unknown = False
        for proposed in moves:
            if type(proposed) is not bytes or len(proposed) > 64:
                raise ValueError("invalid move bytes")
            if (len(proposed), proposed) >= (len(current), current):
                raise ValueError("move did not strictly decrease declared order")
            if len(trace) >= max_pairs or monotonic() - start >= max_seconds:
                status = "reduced_budget_limited"
                break
            result = evaluate(proposed)
            trace.append((proposed, result))
            if monotonic() - start >= max_seconds:
                status = "reduced_budget_limited"
                break
            if result.status == "infrastructure_error":
                unknown = True
                break
            if result.status != "equal":
                current, outcome = proposed, result
                improved = True
                break
        if status == "reduced_budget_limited":
            break
        if unknown:
            status = "shrink_exhausted"
            break
        if improved:
            continue
        # A complete final pass, including the zero-move case, is required.
        status = ("one_minimal_under_moves" if monotonic() - start < max_seconds
                  else "reduced_budget_limited")
        break
    return ShrinkResult(case, current, original, outcome, tuple(trace), status,
                        len(trace), monotonic() - start)
