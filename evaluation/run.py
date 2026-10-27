"""Post-lock scorer orchestration. No binary/candidate execution on host."""
from __future__ import annotations

from .preregister import Registration
from .score import score_rows
from .statistics import paired_bootstrap


def retained_report(registration: Registration, rows: list[dict], *, partitions: dict,
                    campaign_receipt: dict) -> dict:
    result = score_rows(registration, rows, partitions=partitions,
                        campaign_receipt=campaign_receipt)
    result["paired_differences"] = paired_bootstrap(registration, result)
    result["claim_limits"] = ["retained evidence only", "no formal equivalence", "eight clusters and one generation seed", "no broad population superiority", "fixture origin never populates live rows"]
    return result
