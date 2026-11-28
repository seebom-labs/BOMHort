"""Helm template tests for the API gateway's scan evaluation settings (#513).

Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).
"""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class ScanTemplatesTest(unittest.TestCase):
    def helm(self, values):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            return subprocess.run(
                ["helm", "template", "test", str(CHART), "-f", str(values_file)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )

    def render(self, values=None):
        result = self.helm(values)
        self.assertEqual(result.returncode, 0, result.stderr)
        return {doc.split("# Source: ", 1)[1].split("\n", 1)[0]: doc
                for doc in result.stdout.split("\n---\n") if "# Source: " in doc}

    def gateway(self, docs):
        return docs["bomhort/templates/deployment-api-gateway.yaml"]

    def test_scan_env_rendered_when_configured(self):
        gw = self.gateway(self.render({"apiGateway": {"scanTimeout": 2, "scanMaxPurls": 1}}))
        self.assertIn('- name: SCAN_TIMEOUT\n              value: "2"', gw)
        self.assertIn('- name: SCAN_MAX_PURLS\n              value: "1"', gw)

    def test_invalid_scan_timeout_fails_template(self):
        result = self.helm({"apiGateway": {"scanTimeout": 0}})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("apiGateway.scanTimeout must be positive", result.stderr)

    def test_invalid_scan_max_purls_fails_template(self):
        result = self.helm({"apiGateway": {"scanMaxPurls": -1}})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("apiGateway.scanMaxPurls must be positive", result.stderr)


if __name__ == "__main__":
    unittest.main()

