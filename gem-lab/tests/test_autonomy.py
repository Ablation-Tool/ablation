from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from gem.cli import main


WORKSPACE = Path(__file__).resolve().parents[3]


class AutonomyCase(unittest.TestCase):
    def test_shared_full_autonomy_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "profile.json"
            environment = {"ZOE_ROOT": str(WORKSPACE / "zoe"), "ZOE_AUTONOMY_ROOT": str(WORKSPACE / "Zoe-Autonomy")}
            with mock.patch.dict(os.environ, environment), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["autonomy", "run", "--output", str(output)]), 0)
                self.assertEqual(main(["autonomy", "verify", str(output)]), 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["autonomy_profile"]["classification"], "full_autonomy")
            values = report["autonomy_profile"]["dimensions"]
            self.assertEqual(values["internal_goal_authorship_ratio"], 1)
            self.assertEqual(values["internally_authorized_execution_ratio"], 1)
            self.assertEqual(values["guard_compliance"], 1)
            self.assertEqual(report["external_actions"], 0)


if __name__ == "__main__":
    unittest.main()
