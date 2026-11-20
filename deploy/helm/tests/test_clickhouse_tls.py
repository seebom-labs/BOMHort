"""Chart tests for ClickHouse TLS wiring (requires helm)."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class ClickHouseTLSTest(unittest.TestCase):
    def render(self, values=None, success=True):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            result = subprocess.run(
                ["helm", "template", "test", str(CHART), "-f", str(values_file)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout
        self.assertNotEqual(result.returncode, 0, result.stdout)
        return result.stderr

    def test_default_keeps_plain_local_connections(self):
        output = self.render()
        self.assertIn('CLICKHOUSE_SECURE: "false"', output)
        self.assertIn('CLICKHOUSE_SKIP_VERIFY: "false"', output)
        self.assertIn('CLICKHOUSE_CA_FILE: ""', output)
        self.assertIn('CLICKHOUSE_CERT_FILE: ""', output)
        self.assertIn('CLICKHOUSE_KEY_FILE: ""', output)

    def test_secret_and_mtls_settings_reach_every_connection_path(self):
        output = self.render({"clickhouse": {"tls": {
            "enabled": True,
            "existingSecret": "clickhouse-client-tls",
            "caKey": "root.pem",
            "clientCertKey": "client.pem",
            "clientKeyKey": "client-key.pem",
        }}})
        for component in ("api-gateway", "parsing-worker", "ingestion-watcher", "cve-refresher"):
            self.assertIn(f"app.kubernetes.io/component: {component}", output)
        self.assertIn("CLICKHOUSE_CA_FILE: \"/etc/bomhort/clickhouse-tls/root.pem\"", output)
        self.assertIn("CLICKHOUSE_CERT_FILE: \"/etc/bomhort/clickhouse-tls/client.pem\"", output)
        self.assertIn("CLICKHOUSE_KEY_FILE: \"/etc/bomhort/clickhouse-tls/client-key.pem\"", output)
        self.assertGreaterEqual(output.count("secretName: \"clickhouse-client-tls\""), 6)
        self.assertIn("--secure --config-file=/scripts/clickhouse-client.xml", output)
        self.assertIn("<certificateFile>/etc/bomhort/clickhouse-tls/client.pem</certificateFile>", output)
        self.assertIn("<privateKeyFile>/etc/bomhort/clickhouse-tls/client-key.pem</privateKeyFile>", output)

    def test_rejects_tls_options_without_tls_or_secret(self):
        cases = (
            {"skipVerify": True},
            {"caKey": "ca.crt"},
            {"existingSecret": "tls-secret"},
            {"enabled": True, "caKey": "ca.crt"},
            {"enabled": True, "existingSecret": "tls-secret", "clientCertKey": "client.crt"},
            {"enabled": True, "existingSecret": "tls-secret", "clientKeyKey": "client.key"},
        )
        for tls in cases:
            with self.subTest(tls=tls):
                error = self.render({"clickhouse": {"tls": tls}}, success=False)
                self.assertIn("clickhouse.tls", error)


if __name__ == "__main__":
    unittest.main()
