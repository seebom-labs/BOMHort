"""Helm template tests for the API Gateway upload concurrency budget."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class UploadConcurrencyTemplatesTest(unittest.TestCase):
    def helm(self, values):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            return subprocess.run(
                ["helm", "template", "test", str(CHART), "-f", str(values_file)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )

    def test_default_limit_is_injected_in_gateway_only(self):
        result = self.helm({})
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = result.stdout.split("\n---\n")
        gateway = next(doc for doc in docs if "deployment-api-gateway.yaml" in doc)
        self.assertIn('- name: MAX_CONCURRENT_UPLOADS\n              value: "10"', gateway)
        for doc in docs:
            if "deployment-api-gateway.yaml" not in doc:
                self.assertNotIn("MAX_CONCURRENT_UPLOADS", doc)

    def test_explicit_zero_disables_the_limit(self):
        result = self.helm({"apiGateway": {"maxConcurrentUploads": 0}})
        self.assertEqual(result.returncode, 0, result.stderr)
        gateway = next(doc for doc in result.stdout.split("\n---\n")
                       if "deployment-api-gateway.yaml" in doc)
        self.assertIn('- name: MAX_CONCURRENT_UPLOADS\n              value: "0"', gateway)

    def test_invalid_values_fail_render(self):
        for value, message in ((-1, "must not be negative"),
                               ("unlimited", "must be a number")):
            result = self.helm({"apiGateway": {"maxConcurrentUploads": value}})
            self.assertNotEqual(result.returncode, 0, f"value {value!r} unexpectedly rendered")
            self.assertIn(message, result.stderr)


if __name__ == "__main__":
    unittest.main()
