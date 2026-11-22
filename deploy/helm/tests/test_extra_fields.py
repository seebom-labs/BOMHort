"""Helm template tests for the parsing worker's extra-fields config."""

import json
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class ExtraFieldsTemplatesTest(unittest.TestCase):
    def render(self, values=None, show_only=None):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            command = ["helm", "template", "test", str(CHART), "-f", str(values_file)]
            if show_only:
                command += ["--show-only", show_only]
            result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def config(self, values=None):
        output = self.render(values, "templates/configmap-extra-fields.yaml")
        block = output.split("extra-fields.json: |-\n", 1)[1]
        return json.loads(textwrap.dedent(block))

    def test_default_config_is_mounted_for_the_worker(self):
        config = self.config()
        self.assertEqual(config["fields"][0]["name"], "owner_contact")

        output = self.render()
        self.assertIn('EXTRA_FIELDS_FILE: "/data/config/extra-fields/extra-fields.json"', output)
        worker = output.split("# Source: bomhort/templates/deployment-parsing-worker.yaml\n", 1)[1]
        mount = worker.split("- name: extra-fields\n", 1)[1].split("- name:", 1)[0]
        self.assertIn("mountPath: /data/config/extra-fields", mount)
        self.assertIn("name: test-extra-fields", worker.rsplit("- name: extra-fields\n", 1)[1])

    def test_values_override_the_recognised_fields(self):
        config = {
            "fields": [{
                "name": "issue_tracker",
                "from": [{"cyclonedx": "metadata.component.externalReferences", "type": "issue-tracker"}],
            }]
        }
        rendered = self.config({"extraFields": {"config": config}})
        self.assertEqual(rendered["fields"], config["fields"])
        self.assertEqual(rendered["version"], "1.0.0")


if __name__ == "__main__":
    unittest.main()
