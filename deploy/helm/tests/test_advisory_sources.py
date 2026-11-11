"""Helm template tests for OSV-format advisory feeds (ADVISORY_SOURCES).

Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).
Standard library only, like the other chart tests.
"""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class AdvisorySourcesTemplatesTest(unittest.TestCase):
    def render(self, values=None, expect_ok=True):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            cmd = ["helm", "template", "test", str(CHART), "-f", str(values_file),
                   "--show-only", "templates/configmap.yaml"]
            result = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=False)
        if expect_ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_default_is_osv_only(self):
        self.assertIn('ADVISORY_SOURCES: ""', self.render().stdout)

    def test_sources_render_in_backend_syntax(self):
        out = self.render({"advisorySources": [
            {"name": "wolfi", "index": "https://feed.example/osv/all.json",
             "prefixes": ["pkg:apk/wolfi", "pkg:apk/chainguard"]},
            {"name": "private", "index": "s3://advisories/all.json"},
        ]}).stdout
        self.assertIn(
            'ADVISORY_SOURCES: "wolfi|https://feed.example/osv/all.json|pkg:apk/wolfi|pkg:apk/chainguard,'
            'private|s3://advisories/all.json"',
            out,
        )

    def test_entry_without_index_fails(self):
        result = self.render({"advisorySources": [{"name": "wolfi"}]}, expect_ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("needs a name and an index", result.stderr)

    def test_null_values_from_an_older_release(self):
        self.assertIn('ADVISORY_SOURCES: ""', self.render({"advisorySources": None}).stdout)


if __name__ == "__main__":
    unittest.main()
