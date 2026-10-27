"""Keyless command surface using accepted producers without host execution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from bbr.report import ReportError, verify_report
from bbr.report.archive import BANNER
from .journey import (corpus_build, corpus_gate, evidence, fixture_preflight,
                      ledger_report, replay_retained)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="bbr", description="Binary behavior recovery; runtime unverified")
    commands = root.add_subparsers(dest="command", required=True)
    corpus = commands.add_parser("corpus").add_subparsers(dest="action", required=True)
    build = corpus.add_parser("build", help="construct the pinned schedule; does not compile")
    build.add_argument("--spec-dir", type=Path, default=Path("corpus/dev"))
    build.add_argument("--toolchain-pin", type=Path, required=True)
    corpus.add_parser("gate", help="check retained whole-instance receipts").add_argument(
        "--receipts", type=Path, required=True)
    extract = commands.add_parser("evidence")
    extract.add_argument("--artifact", type=Path, required=True)
    extract.add_argument("--artifact-sha256", required=True)
    run = commands.add_parser("run")
    run.add_argument("--arm", choices=("S", "M", "R", "P"), required=True)
    run.add_argument("--config", type=Path, required=True)
    replay = commands.add_parser("replay", help="verify retained replay; fresh execution stays unavailable")
    replay.add_argument("--bundle", type=Path, required=True)
    replay.add_argument("--record-sha256", required=True,
                        help="digest from a separately trusted manifest")
    demo = commands.add_parser("demo")
    demo.add_argument("--mock", action="store_true", default=True)
    demo.add_argument("--config", type=Path)
    verify = commands.add_parser("verify-report")
    verify.add_argument("report", type=Path)
    verify.add_argument("--evidence-root", type=Path, required=True)
    ledger = commands.add_parser("ledger").add_subparsers(dest="action", required=True)
    ledger.add_parser("report").add_argument("--database", type=Path, required=True)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "verify-report":
            output = verify_report(args.report, args.evidence_root)
            code = 0
        elif args.command == "corpus" and args.action == "build":
            output, code = corpus_build(args.spec_dir, args.toolchain_pin)
        elif args.command == "corpus" and args.action == "gate":
            output, code = corpus_gate(args.receipts)
        elif args.command == "evidence":
            output, code = evidence(args.artifact, args.artifact_sha256)
        elif args.command == "replay":
            output, code = replay_retained(args.bundle, args.record_sha256)
        elif args.command in {"run", "demo"}:
            print(BANNER)
            if args.command == "demo" and args.config is None:
                output, code = ({"origin": "fixture", "status": "configuration_required",
                    "reason": "Supply --config with pinned public artifact, VisibleTask and worker policy.",
                    "live_status": "not_run", "runtime_validation": "unverified"}, 2)
            else:
                output, code = fixture_preflight(args.config, getattr(args, "arm", "P"))
        else:
            output, code = ledger_report(args.database)
    except ImportError as error:
        output, code = ({"status": "unavailable", "reason": "Required producer module is not integrated.",
                         "module": error.name, "runtime_validation": "unverified"}, 2)
    except (ReportError, OSError, ValueError, TypeError, KeyError, AttributeError,
            RecursionError, OverflowError) as error:
        output, code = ({"status": "refused", "reason": str(error),
                         "runtime_validation": "unverified"}, 2)
    print(json.dumps(output, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return code
