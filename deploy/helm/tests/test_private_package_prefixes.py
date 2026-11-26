"""Helm template tests for private license resolver boundaries."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class PrivatePackagePrefixesTest(unittest.TestCase):
    def render(self, values=None):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            result = subprocess.run(
                ["helm", "template", "test", str(CHART), "-f", str(values_file)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_prefixes_are_forwarded_to_the_config_map(self):
        prefixes = "pkg:npm/%40acme-private/,pkg:maven/com.acme.private/"
        rendered = self.render({"parsingWorker": {"privatePackagePrefixes": prefixes}})
        self.assertIn(f'PRIVATE_PACKAGE_PREFIXES: "{prefixes}"', rendered)

    def test_prefixes_default_to_empty(self):
        self.assertIn('PRIVATE_PACKAGE_PREFIXES: ""', self.render())


if __name__ == "__main__":
    unittest.main()
