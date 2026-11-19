"""ui.customTheme mounts a ConfigMap the operator manages.

The chart used to render a theme ConfigMap holding only comments, with no value
to put CSS into it. The stylesheet now comes from ui.customTheme.existingConfigMap.

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
UI = "templates/deployment-ui.yaml"


def documents(rendered):
    """Map 'templates/<file>' -> rendered document text."""
    docs = {}
    for doc in rendered.split("\n---\n"):
        match = re.search(r"# Source: bomhort/(templates/\S+)", doc)
        if match:
            docs[match.group(1)] = doc
    return docs


def theme_volume(deployment):
    """The custom-theme volumes: entry, up to the next volume."""
    volumes = deployment.split("\n      volumes:\n", 1)[1]
    match = re.search(r"        - name: custom-theme\n(.*?)(?=\n        - name: |\Z)",
                      volumes, re.DOTALL)
    assert match, "custom-theme volume not found"
    return match.group(1)


class CustomThemeTest(unittest.TestCase):
    def render(self, theme=None, success=True):
        values = {"ui": {"customTheme": theme}} if theme is not None else {}
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values))
            result = subprocess.run(
                ["helm", "template", "rel", str(CHART), "-f", str(values_file)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return documents(result.stdout)
        self.assertNotEqual(result.returncode, 0, "render should have failed")
        return result.stderr

    def test_default_mounts_no_theme(self):
        self.assertNotIn("custom-theme", self.render()[UI])

    def test_existing_configmap_is_mounted_and_none_rendered(self):
        docs = self.render({"enabled": True, "existingConfigMap": "my-theme"})
        self.assertNotIn("templates/configmap-custom-theme.yaml", docs)
        entry = theme_volume(docs[UI])
        self.assertIn("name: my-theme\n", entry)
        self.assertIn("- key: custom-theme.css\n", entry)
        self.assertIn("path: custom-theme.css", entry)
        self.assertIn("mountPath: /usr/share/nginx/html/custom-theme.css", docs[UI])
        self.assertIn("subPath: custom-theme.css", docs[UI])

    def test_existing_configmap_key_is_mapped_to_the_served_file(self):
        docs = self.render({"enabled": True, "existingConfigMap": "branding",
                            "existingConfigMapKey": "corporate.css"})
        entry = theme_volume(docs[UI])
        self.assertIn("name: branding\n", entry)
        self.assertIn("- key: corporate.css\n", entry)
        # nginx serves /custom-theme.css, whatever the key is called.
        self.assertIn("path: custom-theme.css", entry)
        self.assertIn("subPath: custom-theme.css", docs[UI])

    def test_enabled_without_a_configmap_fails(self):
        error = self.render({"enabled": True}, success=False)
        self.assertIn("ui.customTheme.existingConfigMap", error)

    def test_disabled_ignores_existing_configmap(self):
        docs = self.render({"enabled": False, "existingConfigMap": "my-theme"})
        self.assertNotIn("custom-theme", docs[UI])

    def test_headless_ignores_the_theme(self):
        result = subprocess.run(
            ["helm", "template", "rel", str(CHART),
             "--set", "ui.enabled=false", "--set", "ui.customTheme.enabled=true"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(UI, documents(result.stdout))


if __name__ == "__main__":
    unittest.main()
