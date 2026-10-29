"""Paired whole-family percentile bootstrap with auditable draw digest."""
from __future__ import annotations

import random
import sys
from .preregister import Registration, digest


def paired_bootstrap(registration: Registration, score: dict) -> list[dict]:
    registration.validate()
    if score["registration_sha256"] != registration.sha256:
        raise ValueError("statistics registration mismatch")
    results = []
    for model in registration.models:
        arms = {s["arm"]: s for s in score["summaries"] if s["model"] == model}
        for left, right in (("P", "R"), ("P", "M"), ("M", "S")):
            families = sorted(arms[left]["family_estimates"])
            qualified = score["complete"] and len(families) == 8 and all(arms[a]["family_estimates"][f] is not None for a in (left, right) for f in families)
            result = {"origin": registration.origin, "model": model, "difference": f"{left}-{right}", "estimate": None, "interval95": None, "reason": "incomplete_fixed_population", "draw_digest": None, "draws": 2000, "seed": registration.bootstrap_seed, "rng": "stdlib.random.Random/MT19937/randrange", "python_version": sys.version.split()[0], "family_order": families, "exploratory": True, "generation_variability_estimated": False, "multiplicity_adjusted": False}
            if qualified:
                differences = [arms[left]["family_estimates"][f] - arms[right]["family_estimates"][f] for f in families]
                rng = random.Random(registration.bootstrap_seed)
                draws = [[rng.randrange(8) for _ in range(8)] for _ in range(2000)]
                samples = sorted(sum(differences[i] for i in draw)/8 for draw in draws)
                def percentile(q: float) -> float:
                    position = (len(samples)-1)*q
                    lo = int(position)
                    hi = min(lo+1, len(samples)-1)
                    return samples[lo] + (samples[hi]-samples[lo])*(position-lo)
                result.update(estimate=sum(differences)/8, interval95=[percentile(.025), percentile(.975)], reason=None, draw_digest=digest(draws), raw_family_differences=dict(zip(families, differences)))
            results.append(result)
    return results
