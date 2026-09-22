"""Helm template tests for image tag resolution.

Chart 0.6.0 shipped with `image.tag: "0.1.3"` pinned in values.yaml. Release CI
rewrites Chart.yaml on tag but never touches values.yaml, so the two drifted
apart across five releases and the published chart deployed 0.1.3 images. These
tests pin the contract: no literal default, appVersion as the fallback, and an
explicit tag still wins.

Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).
"""

import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"

# The five first-party images the chart deploys.
COMPONENTS = ("api-gateway", "ui", "parsing-worker", "ingestion-watcher", "cve-refresher")


def chart_app_version():
    for line in (CHART / "Chart.yaml").read_text().splitlines():
        if line.startswith("appVersion:"):
            return line.split(":", 1)[1].strip().strip('"')
    raise AssertionError("appVersion not found in Chart.yaml")


class ImageTagTest(unittest.TestCase):
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

    def tags_for(self, rendered, component):
        """Every tag the rendered manifests use for a first-party component."""
        pattern = re.compile(r"/%s:([^\"\s]+)" % re.escape(component))
        tags = pattern.findall(rendered)
        self.assertTrue(tags, "no image reference rendered for %s" % component)
        return set(tags)

    def test_values_does_not_pin_a_literal_tag(self):
        """A literal here silently outranks the chart version - that was the bug."""
        values = (CHART / "values.yaml").read_text()
        image_block = values.split("image:", 1)[1].split("\n\n", 1)[0]
        match = re.search(r"^\s+tag:\s*(.+)$", image_block, re.MULTILINE)
        self.assertIsNotNone(match, "image.tag key missing from values.yaml")
        self.assertIn(match.group(1).strip(), ('""', "''"),
                      "image.tag must default to empty so the chart falls back to appVersion")

    def test_default_tag_is_the_chart_app_version(self):
        out = self.render()
        expected = chart_app_version()
        for component in COMPONENTS:
            self.assertEqual(self.tags_for(out, component), {expected},
                             "%s must default to appVersion %s" % (component, expected))

    def test_explicit_tag_still_wins(self):
        out = self.render({"image": {"tag": "9.9.9-rc1"}})
        for component in COMPONENTS:
            self.assertEqual(self.tags_for(out, component), {"9.9.9-rc1"},
                             "%s must honour an explicit image.tag" % component)

    def test_all_components_share_one_tag(self):
        """A partial override would mix versions across the deployment."""
        out = self.render()
        tags = set()
        for component in COMPONENTS:
            tags |= self.tags_for(out, component)
        self.assertEqual(len(tags), 1, "components disagree on the image tag: %s" % sorted(tags))


if __name__ == "__main__":
    unittest.main()

