"""Standalone authored SOFTWARE ledger regressions; stdlib + bbr.ledger only.

No candidate/provider/contract imports, benchmark corpus or real spending.
Temporary SQLite software fixtures are retained in the caller's fresh run dir.
"""
from decimal import Decimal
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import bbr.ledger as ledger_module
from bbr.ledger import BudgetStop, Ledger, read_report

__test__ = False  # Separate unittest entrypoint, not an extra pytest collection.
SOFTWARE_FIXTURE_ID = "dl3-stdlib-authored-software-ledger-v1-not-benchmark"


def request_digest(label):
    return sha256((SOFTWARE_FIXTURE_ID + label).encode()).hexdigest()


class LedgerSoftwareChecks(unittest.TestCase):
    def setUp(self):
        root = Path(os.environ["M15_DL3_STDLIB_RUN_DIR"]).resolve(strict=True)
        self.case_dir = root / self._testMethodName
        self.case_dir.mkdir(exist_ok=False)
        self.path = self.case_dir / "software.sqlite"

    def test_reserve_settle_reopen_decimal_identity(self):
        ledger = Ledger(self.path, cap_usd="1")
        first = ledger.reserve("software-first", request_digest("first"), "0.30")
        self.assertEqual(first, ledger.reserve("software-first", request_digest("first"), "0.30"))
        reopened = Ledger(self.path, cap_usd="1")
        reopened.mark_sent(first)
        reopened.settle(first, "0.20", reason="authored software simulation")
        reopened.settle(first, "0.20", reason="idempotent software replay")
        report = Ledger(self.path, cap_usd="1").report()
        self.assertEqual(Decimal(report["committed_usd"]), Decimal("0.20"))
        self.assertEqual(Decimal(report["available_usd"]), Decimal("0.80"))
        self.assertEqual(len(report["attempts"]), 1)
        self.assertEqual(report["attempts"][0]["status"], "settled")

    def test_unknown_liability_survives_reopen_and_blocks(self):
        ledger = Ledger(self.path, cap_usd="1")
        reservation = ledger.reserve("software-unknown", request_digest("unknown"), "0.70")
        ledger.mark_sent(reservation)
        ledger.settle(reservation, None, reason="authored software unknown")
        reopened = Ledger(self.path, cap_usd="1")
        report = reopened.report()
        self.assertEqual(Decimal(report["committed_usd"]), Decimal("0.70"))
        self.assertTrue(report["dispatch_blocked"])
        with self.assertRaises(BudgetStop):
            reopened.reserve("software-next", request_digest("next"), "0.01")
        reopened.reconcile(reservation, billed_usd="0.20", evidence="authored software bill")
        self.assertFalse(read_report(self.path)["dispatch_blocked"])
        self.assertEqual(Decimal(read_report(self.path)["available_usd"]), Decimal("0.80"))

    def test_cap_and_persisted_configuration_are_enforced(self):
        ledger = Ledger(self.path, cap_usd="0.30")
        for label, amount in (("one", "0.10"), ("two", "0.20")):
            reservation = ledger.reserve(label, request_digest(label), amount)
            ledger.mark_sent(reservation)
            ledger.settle(reservation, amount, reason="authored software simulated charge")
        report = read_report(self.path)
        self.assertEqual(Decimal(report["committed_usd"]), Decimal("0.30"))
        self.assertTrue(report["dispatch_blocked"])
        with self.assertRaises(BudgetStop):
            ledger.reserve("over", request_digest("over"), "0.01")
        with self.assertRaises(BudgetStop):
            Ledger(self.path, cap_usd="0.40")

    def test_read_only_report_does_not_initialize_or_change_bytes(self):
        Ledger(self.path)
        before = self.path.read_bytes()
        with patch.object(Ledger, "__init__", side_effect=AssertionError("initializer forbidden")):
            report = read_report(self.path)
        self.assertEqual(report["attempts"], [])
        self.assertEqual(Decimal(report["committed_usd"]), Decimal("0"))
        self.assertEqual(self.path.read_bytes(), before)

    def test_read_only_missing_database_is_not_created(self):
        with self.assertRaises(FileNotFoundError):
            read_report(self.path)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    forbidden = [name for name in ("pytest", "pydantic", "bbr.providers", "bbr.contracts", "bbr.arms")
                 if name in sys.modules]
    expected_source = Path(__file__).resolve().parents[3] / "src" / "bbr" / "ledger" / "__init__.py"
    environment = {"kind": "stdlib_environment", "executable": sys.executable,
        "python": sys.version, "ledger_module": ledger_module.__file__,
        "pythonpath": os.environ.get("PYTHONPATH"), "forbidden_imports_present": forbidden,
        "fixture_id": SOFTWARE_FIXTURE_ID, "origin": "authored_software_test_fixture"}
    print(json.dumps(environment), flush=True)
    if sys.version_info[:3] != (3, 12, 13) or forbidden or Path(ledger_module.__file__).resolve() != expected_source:
        raise SystemExit("Wrong interpreter/import origin or forbidden imports; checks not run")
    program = unittest.main(verbosity=2, exit=False)
    outcome = program.result
    print(json.dumps({"kind": "unittest_result", "tests_run": outcome.testsRun,
        "failures": len(outcome.failures), "errors": len(outcome.errors),
        "skipped": len(outcome.skipped), "was_successful": outcome.wasSuccessful(),
        "scope": "stdlib_ledger_software_only", "spend_usd": "0"}), flush=True)
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
