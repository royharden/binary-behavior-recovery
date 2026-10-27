"""Keyless command surface. Unsafe/unconfigured actions fail closed."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from bbr.report import ReportError, verify_report
from bbr.report.archive import BANNER


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="bbr", description="Binary behavior recovery; runtime unverified")
    commands = root.add_subparsers(dest="command", required=True)
    corpus = commands.add_parser("corpus").add_subparsers(dest="action", required=True)
    for name in ("build", "gate"):
        corpus.add_parser(name)
    commands.add_parser("evidence").add_argument("--artifact", required=True)
    run = commands.add_parser("run")
    run.add_argument("--arm", choices=("S", "M", "R", "P"), required=True)
    run.add_argument("--config", type=Path, required=True)
    commands.add_parser("replay").add_argument("--bundle", type=Path, required=True)
    demo = commands.add_parser("demo")
    demo.add_argument("--mock", action="store_true", default=True)
    verify = commands.add_parser("verify-report")
    verify.add_argument("report", type=Path)
    verify.add_argument("--evidence-root", type=Path, required=True)
    ledger = commands.add_parser("ledger").add_subparsers(dest="action", required=True)
    ledger.add_parser("report").add_argument("--database", type=Path, required=True)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "verify-report":
        try:
            output = verify_report(args.report, args.evidence_root)
        except (ReportError, OSError, ValueError, TypeError, KeyError) as error:
            print(json.dumps({"status": "refused", "reason": str(error)}))
            return 2
        print(json.dumps(output, sort_keys=True))
        return 0
    if args.command == "demo":
        print(BANNER)
        print(json.dumps({"origin": "fixture", "live_status": "not_run",
                          "status": "pending_fixture_integration", "runtime_validation": "unverified",
                          "reason": "No sandbox or authored fixture execution is configured; no results fabricated."}))
        return 2
    print(json.dumps({"status": "unavailable", "command": args.command,
                      "reason": "Producer adapter and admitted isolated execution configuration required.",
                      "runtime_validation": "unverified"}))
    return 2
