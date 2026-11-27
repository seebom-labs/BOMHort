"""Ingress authentication warnings and strict checks must match exposed routes."""

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"
UI_HOSTS = (
    '[{"host":"bomhort.example.test","paths":'
    '[{"path":"/api","pathType":"Prefix"},'
    '{"path":"/","pathType":"Prefix","serviceSuffix":"ui"}]}]'
)
API_HOSTS = (
    '[{"host":"bomhort.example.test","paths":'
    '[{"path":"/api","pathType":"Prefix"}]}]'
)


def helm_template(*args):
    return subprocess.run(
        ["helm", "template", "test", str(CHART), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


class IngressAuthTest(unittest.TestCase):
    def test_rendered_ingress_warns_when_api_auth_is_disabled(self):
        result = helm_template(
            "--show-only", "templates/ingress.yaml",
            "--set", "ingress.enabled=true",
            "--set-json", f"ingress.hosts={API_HOSTS}",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bomhort.dev/security-warning:", result.stdout)
        self.assertIn("API gateway authentication is disabled", result.stdout)

    def test_rendered_ingress_warns_when_public_ui_uses_gateway_token(self):
        result = helm_template(
            "--show-only", "templates/ingress.yaml",
            "--set", "ingress.enabled=true",
            "--set", "apiGateway.auth.enabled=true",
            "--set-json", f"ingress.hosts={UI_HOSTS}",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bomhort.dev/security-warning:", result.stdout)
        self.assertIn("public UI proxies anonymous reads", result.stdout)

    def test_require_auth_rejects_unauthenticated_api(self):
        result = helm_template(
            "--set", "ingress.enabled=true",
            "--set", "ingress.requireAuth=true",
            "--set-json", f"ingress.hosts={API_HOSTS}",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires apiGateway.auth.enabled=true", result.stderr)

    def test_require_auth_rejects_ui_without_external_auth(self):
        result = helm_template(
            "--set", "ingress.enabled=true",
            "--set", "ingress.requireAuth=true",
            "--set", "apiGateway.auth.enabled=true",
            "--set-json", f"ingress.hosts={UI_HOSTS}",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot expose the bundled UI without external authentication", result.stderr)

    def test_require_auth_accepts_ui_with_external_auth_declared(self):
        result = helm_template(
            "--set", "ingress.enabled=true",
            "--set", "ingress.requireAuth=true",
            "--set", "ingress.externalAuth.enabled=true",
            "--set", "apiGateway.auth.enabled=true",
            "--set-json", f"ingress.hosts={UI_HOSTS}",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_require_auth_accepts_api_only_ingress_with_gateway_auth(self):
        result = helm_template(
            "--set", "ingress.enabled=true",
            "--set", "ingress.requireAuth=true",
            "--set", "apiGateway.auth.enabled=true",
            "--set-json", f"ingress.hosts={API_HOSTS}",
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
