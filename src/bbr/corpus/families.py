"""Original builder-authored development definitions; never independent truth."""

from collections.abc import Sequence

from bbr.contracts import FamilySpec

AUTHOR = "0934_Codex_gpt-61-sol_Sub_M15Corpus"
CREATED = "2026-10-27"

# The operation descriptions are fingerprints, not claims of independent review.
DEFINITIONS = {
    "threshold-byte": (8, 1, 1, "piecewise(x<73:0;x<201:1;else:2)", "threshold boundaries 72/73 and 200/201"),
    "nibble-exchange": (8, 1, 1, "or(shl(and(x,15),4),shr(x,4))", "high-bit unsigned and nibble boundaries"),
    "pair-fold": (8, 2, 1, "mod256(add(x0,mul(3,x1)))", "sum overflow wraps explicitly"),
    "rolling-four": (16, 4, 1, "fold(state=7;state=mod65536(state*33+x))", "uint16 wrap after every step"),
    "escape-four": (8, 4, 8, "flatmap(x:[x==0-or-x==255,xor(x,32)-if-escaped-else-x])", "zero and 255 are escaped; output arity eight"),
    "sort-three": (16, 3, 3, "sort3(compare-swap(0,1);(1,2);(0,1))", "ties and values above signed16 range"),
    "runs-four": (8, 4, 8, "rle-pairs(count,value);pad-pairs(0,0)-to-eight", "runs are adjacent; zero is a real value"),
    "delta-state": (8, 4, 4, "scan(prev=19;emit=mod256(x-prev);prev=x)", "within-record state resets for every invocation"),
}


def family_spec(family_id: str) -> FamilySpec:
    """Create the shared, closed public family contract."""
    width, arity, outputs, fingerprint, _ = DEFINITIONS[family_id]
    return FamilySpec(
        family_id=family_id, split="dev", width=width,
        input_arity=arity, output_arity=outputs, minimum=0,
        maximum=(1 << width) - 1, semantic_fingerprint=fingerprint,
        finite_domain_size=256 if arity == 1 and width == 8 else None,
        author=AUTHOR, created=CREATED, rights_status="pending",
    )


def dossier(family_id: str) -> dict[str, object]:
    width, arity, outputs, fingerprint, trap = DEFINITIONS[family_id]
    return {
        "family_id": family_id, "split": "dev", "width": width,
        "input_arity": arity, "output_arity": outputs, "minimum": 0,
        "maximum": (1 << width) - 1, "semantic_fingerprint": fingerprint,
        "finite_domain_size": 256 if arity == 1 and width == 8 else None,
        "author": AUTHOR, "created": CREATED, "rights_status": "pending",
        "trap_description": trap, "parser_lineage": "original-m15-canonical-v1",
        "independent_reference_status": "pending", "validation_status": "not_run",
    }


def reference(family_id: str, values: Sequence[int]) -> tuple[int, ...]:
    """Dev builder reference, explicitly not independent admission evidence."""
    width, arity, _, _, _ = DEFINITIONS[family_id]
    if len(values) != arity or any(type(v) is not int or not 0 <= v < (1 << width) for v in values):
        raise ValueError("input outside family domain")
    if family_id == "threshold-byte":
        return (0 if values[0] < 73 else 1 if values[0] < 201 else 2,)
    if family_id == "nibble-exchange":
        return (((values[0] & 15) << 4) | (values[0] >> 4),)
    if family_id == "pair-fold":
        return ((values[0] + 3 * values[1]) & 255,)
    if family_id == "rolling-four":
        state = 7
        for value in values:
            state = (state * 33 + value) & 65535
        return (state,)
    if family_id == "escape-four":
        return tuple(part for value in values for part in ((1, value ^ 32) if value in (0, 255) else (0, value)))
    if family_id == "sort-three":
        return tuple(sorted(values))
    if family_id == "runs-four":
        pairs: list[int] = []
        previous, count = values[0], 0
        for value in values:
            if value != previous:
                pairs.extend((count, previous))
                previous, count = value, 0
            count += 1
        pairs.extend((count, previous))
        return tuple(pairs + [0] * (8 - len(pairs)))
    previous = 19
    result = []
    for value in values:
        result.append((value - previous) & 255)
        previous = value
    return tuple(result)
