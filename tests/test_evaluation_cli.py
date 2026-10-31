"""CLI evaluation tests use synthetic JSON only and do not call any API."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops_sentinel.__main__ import main

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "evaluation_cases.json"


class EvaluationCliTests(unittest.TestCase):
    def test_evaluation_cli_produces_report(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "evaluation.json"
            arguments = ["ops_sentinel", "evaluate", str(SAMPLE), "--output",
                         str(destination), "--repeats", "1", "--recovery-trials", "1"]
            with patch("sys.argv", arguments), contextlib.redirect_stdout(io.StringIO()):
                main()
            report = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(report["scenario_count"], 13)
            self.assertEqual(report["detection"]["overall"]["fp"], 1)
            self.assertEqual(report["recovery"]["successful_recoveries"], 1)

    def test_evaluation_cli_refuses_external_transfer(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "evaluation.json"
            arguments = ["ops_sentinel", "evaluate", str(SAMPLE), "--output",
                         str(destination), "--allow-external-data-transfer"]
            with patch("sys.argv", arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as result:
                    main()
            self.assertEqual(result.exception.code, 2)
            self.assertFalse(destination.exists())

    def test_evaluation_cli_rejects_narrator(self):
        arguments = ["ops_sentinel", "evaluate", str(SAMPLE), "--narrator", "openai"]
        with patch("sys.argv", arguments), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                main()
        self.assertEqual(result.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
