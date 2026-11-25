"""Run with python3 -m unittest discover -s deploy/helm/tests -p "test_private_vulnerabilities.py" -v (requires helm)."""

import json
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class PrivateVulnerabilitiesTemplatesTest(unittest.TestCase):
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

    def advisories(self, rendered):
        match = re.search(
            r"^  private-vulnerabilities\.json: \|-\n((?:    .*\n|\n)+)",
            rendered, re.MULTILINE,
        )
        self.assertIsNotNone(match, rendered)
        return json.loads(textwrap.dedent(match.group(1)))

    def workloads(self, rendered):
        result = {}
        patterns = {
            "api-gateway": r"# Source: bomhort/templates/deployment-api-gateway\.yaml\n(.*?)(?=\n---|\Z)",
            "parsing-worker": r"# Source: bomhort/templates/deployment-parsing-worker\.yaml\n(.*?)(?=\n---|\Z)",
            "cve-refresher": r"# Source: bomhort/templates/cronjob-cve-refresher\.yaml\n(.*?)(?=\n---|\Z)",
        }
        for name, pattern in patterns.items():
            match = re.search(pattern, rendered, re.DOTALL)
            self.assertIsNotNone(match, f"missing manifest for {name}")
            result[name] = match.group(1)
        return result

    def assert_live_reload(self, rendered):
        """Pods reload private advisories automatically via a directory mount
        without subPath and without pod-restarting checksum annotations."""
        self.assertNotIn("checksum/private-vulnerabilities", rendered)
        for name, manifest in self.workloads(rendered).items():
            mount = manifest.split("- name: private-vulnerabilities\n", 1)[1].split("- name:", 1)[0]
            self.assertIn("mountPath: /data/config/private-vulnerabilities\n", mount, name)
            self.assertNotIn("subPath", mount, name)

    def config(self, rendered):
        return dict(re.findall(r'^  (PRIVATE_VULNERABILITIES_[A-Z_]+): "(.*)"$', rendered, re.MULTILINE))

    def test_defaults_and_example_values_are_empty(self):
        for filename in (
            None,
            "examples/kind/values-kind.yaml",
            "examples/kubernetes/values-production.yaml",
            "examples/kubernetes/values-minimal.yaml",
        ):
            with self.subTest(filename=filename):
                output = self.render(args=("-f", str(ROOT / filename)) if filename else ())
                self.assertEqual(self.advisories(output), [])
                self.assert_live_reload(output)
                self.assertEqual(self.config(output), {
                    "PRIVATE_VULNERABILITIES_FILE": "/data/config/private-vulnerabilities/private-vulnerabilities.json",
                    "PRIVATE_VULNERABILITIES_SOURCE": "",
                    "PRIVATE_VULNERABILITIES_REFRESH_INTERVAL": "60s",
                })

    def test_custom_list_json_string_and_set_file(self):
        entries = [
            {
                "id": "BOMHORT-2024-001",
                "summary": "Internal flaw",
                "affected": [
                    {
                        "package": {"name": "internal-lib", "ecosystem": "npm", "purl": "pkg:npm/internal-lib"},
                        "versions": ["1.0.0"],
                    }
                ],
            }
        ]
        for custom in (entries, json.dumps(entries)):
            output = self.render({"privateVulnerabilities": {"custom": custom}})
            self.assertEqual(self.advisories(output), entries)
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "private-vulnerabilities.json"
            filename.write_text(json.dumps(entries))
            output = self.render(args=("--set-file", f"privateVulnerabilities.custom={filename.as_posix()}"))
            self.assertEqual(self.advisories(output), entries)

    def test_updating_advisories_changes_only_configmap(self):
        v1 = [{"id": "ORG-2024-1", "summary": "v1", "affected": []}]
        v2 = [{"id": "ORG-2024-1", "summary": "v2", "withdrawn": "2024-06-01T00:00:00Z", "affected": []}]
        first = self.render({"privateVulnerabilities": {"custom": v1}})
        second = self.render({"privateVulnerabilities": {"custom": v2}})
        self.assertNotEqual(self.advisories(first), self.advisories(second))
        self.assertEqual(self.workloads(first), self.workloads(second))

    def test_disabled_removes_configmap_mounts_and_secret_env(self):
        output = self.render({"privateVulnerabilities": {
            "enabled": False,
            "source": "https://example.org/advisories.json",
            "sourceTokenSecret": {"name": "adv-token"},
        }})
        self.assertNotIn("configmap-private-vulnerabilities.yaml", output)
        self.assertNotIn("name: private-vulnerabilities", output)
        self.assertNotIn("adv-token", output)
        self.assertEqual(self.config(output)["PRIVATE_VULNERABILITIES_SOURCE"], "")

    def test_existing_configmap_works_without_custom_conflict(self):
        for extra in ({}, {"custom": []}, {"custom": ""}):
            with self.subTest(extra=extra):
                output = self.render({"privateVulnerabilities": {
                    "existingConfigMap": "org-advisories",
                    "existingConfigMapKey": "vulns.json",
                    **extra,
                }})
                self.assertNotIn("configmap-private-vulnerabilities.yaml", output)
                for name, manifest in self.workloads(output).items():
                    self.assertIn("name: org-advisories", manifest, name)
                    self.assertRegex(
                        manifest,
                        r"- key: vulns\.json\s+path: private-vulnerabilities\.json",
                        name,
                    )

    def test_remote_source_and_token_secret_in_all_workloads(self):
        for source in (
            "https://example.org/security/private-vulnerabilities.json",
            "s3://security-bucket/private-vulnerabilities.json",
        ):
            with self.subTest(source=source):
                output = self.render({"privateVulnerabilities": {
                    "source": source,
                    "refreshInterval": "5m",
                    "sourceTokenSecret": {"name": "sec-token", "key": "bearer"},
                }})
                self.assertNotIn("configmap-private-vulnerabilities.yaml", output)
                self.assertNotIn("name: private-vulnerabilities", output)
                self.assertEqual(self.config(output)["PRIVATE_VULNERABILITIES_SOURCE"], source)
                self.assertEqual(self.config(output)["PRIVATE_VULNERABILITIES_REFRESH_INTERVAL"], "5m")
                for name, manifest in self.workloads(output).items():
                    env = manifest.split("- name: PRIVATE_VULNERABILITIES_SOURCE_TOKEN\n", 1)[1].split("- name:", 1)[0]
                    self.assertIn("name: sec-token", env, name)
                    self.assertIn("key: bearer", env, name)

    def test_custom_mount_path_legacy_path_and_collisions(self):
        output = self.render({"privateVulnerabilities": {"mountPath": "/custom/pvt.json"}})
        self.assertEqual(self.config(output)["PRIVATE_VULNERABILITIES_FILE"], "/custom/pvt.json")
        self.assertEqual(output.count("mountPath: /custom\n"), 3)
        self.assertNotIn("subPath: private-vulnerabilities.json", output)
        self.assertGreaterEqual(
            len(re.findall(r"- key: private-vulnerabilities\.json\s+path: pvt\.json", output)),
            3,
        )

        legacy = self.render({"privateVulnerabilities": {"mountPath": "/data/config/private-vulnerabilities.json"}})
        self.assertEqual(
            self.config(legacy)["PRIVATE_VULNERABILITIES_FILE"],
            "/data/config/private-vulnerabilities/private-vulnerabilities.json",
        )
        self.assert_live_reload(legacy)

        for bad_path in (
            "/data/config/pvt.json",
            "/data/sboms/pvt.json",
            "/data/config/license-exceptions/pvt.json",
            "/pvt.json",
        ):
            with self.subTest(bad_path=bad_path):
                err = self.render({"privateVulnerabilities": {"mountPath": bad_path}}, success=False)
                self.assertIn("privateVulnerabilities.mountPath", err)

    def test_refresh_interval(self):
        for value, expected in ((0, "0"), ("0", "0"), ("90s", "90s"), ("1h30m", "1h30m")):
            with self.subTest(value=value):
                output = self.render({"privateVulnerabilities": {"refreshInterval": value}})
                self.assertEqual(self.config(output)["PRIVATE_VULNERABILITIES_REFRESH_INTERVAL"], expected)
        for bad in ("soon", "60", "-1s", "1d"):
            with self.subTest(bad=bad):
                err = self.render({"privateVulnerabilities": {"refreshInterval": bad}}, success=False)
                self.assertIn("privateVulnerabilities.refreshInterval", err)

    def test_invalid_settings_are_rejected(self):
        for values in (
            {"source": "http://example.org/x.json"},
            {"source": "file:///etc/passwd"},
            {"source": "https://example.org/x.json", "existingConfigMap": "x"},
            {"source": "https://example.org/x.json", "custom": [{"id": "ORG-1"}]},
            {"existingConfigMap": "x", "custom": [{"id": "ORG-1"}]},
            {"sourceTokenSecret": {"name": "token-without-source"}},
        ):
            with self.subTest(values=values):
                err = self.render({"privateVulnerabilities": values}, success=False)
                self.assertIn("privateVulnerabilities.", err)

        for bad_custom in ("{", "null", "{}", "42", {}, 42, False):
            with self.subTest(bad_custom=bad_custom):
                err = self.render({"privateVulnerabilities": {"custom": bad_custom}}, success=False)
                self.assertRegex(err, r"privateVulnerabilities\.custom|mustFromJson")


if __name__ == "__main__":
    unittest.main()
