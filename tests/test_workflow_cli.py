"""End-to-end CLI checks on synthetic data (no external services)."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ops_sentinel.__main__ import main


SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "synthetic_events.csv"


class WorkflowCliTests(unittest.TestCase):
    def test_offline_workflow_creates_and_resumes_three_cases(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "summary.json"
            args = ["ops_sentinel", "workflow", str(SAMPLE),
                    "--state-dir", folder, "--output", str(output)]
            with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()):
                main()
            result = json.loads(output.read_text())
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["summary"]["investigations_count"], 3)
            self.assertEqual(result["summary"]["approval_requests_pending"], 3)
            audit_path = Path(result["audit_path"])
            before = audit_path.read_text()
            with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()):
                main()
            self.assertEqual(audit_path.read_text(), before)
            self.assertEqual(json.loads(output.read_text())["run_id"], result["run_id"])

    def test_workflow_refuses_external_data_transfer(self):
        with tempfile.TemporaryDirectory() as folder:
            args = ["ops_sentinel", "workflow", str(SAMPLE),
                    "--state-dir", folder, "--allow-external-data-transfer"]
            with patch("sys.argv", args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    main()
            self.assertEqual(error.exception.code, 2)
            self.assertFalse(list(Path(folder).glob("*.state.json")))


if __name__ == "__main__":
    unittest.main()
