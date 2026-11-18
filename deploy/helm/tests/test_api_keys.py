"""Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).

Named, scoped API keys (#456) in Helm templates:
- String apiKeys renders into secret.data.API_KEYS (backward-compatible)
- Slice/list apiKeys renders into secret.data.API_KEYS_JSON (named scoped keys)
- deployment-api-gateway.yaml exposes both API_KEYS and API_KEYS_JSON
"""

import base64
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class APIKeysTemplatesTest(unittest.TestCase):
    def render(self, values=None):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            result = subprocess.run(
                ["helm", "template", "test-release", str(CHART), "-f", str(values_file)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def source(self, rendered, template):
        match = re.search(
            rf"# Source: bomhort/templates/{re.escape(template)}\n(.*?)(?=\n---|\Z)",
            rendered,
            re.DOTALL,
        )
        return match.group(1) if match else None

    def api_auth_secret(self, rendered):
        match = re.search(
            r"metadata:\s+name: test-release-api-auth.*?data:\s*\n(.*?)(?=\n---|\Z)",
            rendered,
            re.DOTALL,
        )
        return match.group(1) if match else None

    def test_legacy_string_api_keys_renders_api_keys_only(self):
        values = {
            "apiGateway": {
                "auth": {
                    "enabled": True,
                    "serviceToken": "test-token",
                    "apiKeys": "key-a,key-b",
                }
            }
        }
        rendered = self.render(values)
        secret_data = self.api_auth_secret(rendered)
        self.assertIsNotNone(secret_data, "test-release-api-auth should be rendered")
        self.assertIn("API_KEYS:", secret_data)
        self.assertTrue(re.search(r'API_KEYS_JSON:\s*""', secret_data) is not None)

        m = re.search(r'API_KEYS:\s*"([A-Za-z0-9+/=]+)"', secret_data)
        self.assertIsNotNone(m)
        decoded = base64.b64decode(m.group(1)).decode()
        self.assertEqual(decoded, "key-a,key-b")

    def test_slice_api_keys_renders_api_keys_json(self):
        values = {
            "apiGateway": {
                "auth": {
                    "enabled": True,
                    "serviceToken": "test-token",
                    "apiKeys": [
                        {
                            "name": "ci-pipeline",
                            "secret": "super-secret",
                            "scope": {
                                "origins": ["ci"],
                                "clusters": ["prod-cluster"],
                            },
                        }
                    ],
                }
            }
        }
        rendered = self.render(values)
        secret_data = self.api_auth_secret(rendered)
        self.assertIsNotNone(secret_data, "test-release-api-auth should be rendered")
        self.assertIn("API_KEYS_JSON:", secret_data)
        self.assertTrue(re.search(r'API_KEYS:\s*""', secret_data) is not None)

        m = re.search(r'API_KEYS_JSON:\s*"([A-Za-z0-9+/=]+)"', secret_data)
        self.assertIsNotNone(m)
        parsed = json.loads(base64.b64decode(m.group(1)).decode())
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["name"], "ci-pipeline")
        self.assertEqual(parsed[0]["secret"], "super-secret")
        self.assertEqual(parsed[0]["scope"]["origins"], ["ci"])
        self.assertEqual(parsed[0]["scope"]["clusters"], ["prod-cluster"])

    def test_deployment_mounts_both_env_vars(self):
        values = {
            "apiGateway": {
                "auth": {
                    "enabled": True,
                    "serviceToken": "test-token",
                }
            }
        }
        rendered = self.render(values)
        deploy = self.source(rendered, "deployment-api-gateway.yaml")
        self.assertIsNotNone(deploy, "deployment-api-gateway.yaml should be rendered")
        self.assertIn("name: API_KEYS", deploy)
        self.assertIn("key: API_KEYS", deploy)
        self.assertIn("name: API_KEYS_JSON", deploy)
        self.assertIn("key: API_KEYS_JSON", deploy)


if __name__ == "__main__":
    unittest.main()
