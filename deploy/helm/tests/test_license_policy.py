"""Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm)."""

import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class LicensePolicyExpressionModeTest(unittest.TestCase):
    def render(self, values=None, args=(), success=True):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            result = subprocess.run(
                ["helm", "template", "test", str(CHART), "-f", str(values_file), *args],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result.stdout if success else result.stderr

    def config_map(self, rendered):
        match = re.search(
            r"# Source: bomhort/templates/configmap\.yaml\n(.*?)(?=\n---|\Z)", rendered, re.DOTALL
        )
        self.assertIsNotNone(match, rendered)
        return match.group(1)

    def rollout_hash(self, template, annotation, values=None):
        rendered = self.render(values, args=("--show-only", template))
        match = re.search(rf"{re.escape(annotation)}: ([0-9a-f]{{64}})", rendered)
        self.assertIsNotNone(match, rendered)
        return match.group(1)

    def test_unset_by_default(self):
        # Empty value: defer to the policy file / binary default, do not
        # inject an empty env var that config.Load would have to special-case.
        self.assertNotIn("LICENSE_EXPRESSION_MODE", self.config_map(self.render()))

    def test_valid_modes_are_injected(self):
        for mode in ("strict", "permissive-wins", "off"):
            with self.subTest(mode=mode):
                output = self.render({"licensePolicy": {"expressionMode": mode}})
                self.assertIn(f'LICENSE_EXPRESSION_MODE: "{mode}"', self.config_map(output))

    def test_invalid_mode_fails_render(self):
        error = self.render({"licensePolicy": {"expressionMode": "lenient"}}, success=False)
        self.assertIn("licensePolicy.expressionMode", error)

    def test_cncf_example_uses_permissive_wins(self):
        output = self.render(args=("-f", str(ROOT / "examples/kubernetes/values-cncf.yaml")))
        self.assertIn('LICENSE_EXPRESSION_MODE: "permissive-wins"', self.config_map(output))

    def test_policy_and_mode_changes_roll_the_api_and_worker(self):
        for template in (
            "templates/deployment-api-gateway.yaml",
            "templates/deployment-parsing-worker.yaml",
        ):
            with self.subTest(template=template):
                config = self.rollout_hash(template, "checksum/config")
                changed_mode = self.rollout_hash(
                    template, "checksum/config", {"licensePolicy": {"expressionMode": "permissive-wins"}}
                )
                self.assertNotEqual(config, changed_mode)

                policy = self.rollout_hash(template, "checksum/license-policy")
                changed_policy = self.rollout_hash(
                    template,
                    "checksum/license-policy",
                    {"licensePolicy": {"custom": '{"permissive":["MIT"],"copyleft":["GPL-3.0-only"]}'}},
                )
                self.assertNotEqual(policy, changed_policy)

                external_a = self.rollout_hash(
                    template,
                    "checksum/license-policy",
                    {"licensePolicy": {"existingConfigMap": "external-policy", "rolloutChecksum": "rev-a"}},
                )
                external_b = self.rollout_hash(
                    template,
                    "checksum/license-policy",
                    {"licensePolicy": {"existingConfigMap": "external-policy", "rolloutChecksum": "rev-b"}},
                )
                self.assertNotEqual(external_a, external_b)


if __name__ == "__main__":
    unittest.main()

