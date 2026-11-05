"""Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).

The UI's nginx injects the gateway SERVICE_TOKEN into /api/ requests that
carry no Authorization header of their own. The UI is public, so that proxy
authenticates every anonymous visitor: injecting on a write method would open
POST /api/v1/sboms/upload and PATCH /api/v1/sboms/{id} to anyone. These tests
pin the injection to GET and HEAD in both copies of the nginx config — the
chart's ConfigMap and the template baked into the UI image.
"""

from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"
IMAGE_TEMPLATE = ROOT / "ui/nginx.conf.template"
TOKEN = "${BOMHORT_AUTH_HEADER_VALUE}"
READ_METHODS = {"GET", "HEAD"}


def map_block(conf, variable):
    """Return {key: value} of the nginx `map <source> <variable> { ... }` block."""
    match = re.search(r"map\s+\S+\s+" + re.escape(variable) + r"\s*\{(.*?)^\s*\}", conf, re.S | re.M)
    if match is None:
        raise AssertionError(f"no map defining {variable}")
    entries = {}
    for line in match.group(1).splitlines():
        line = line.split("#", 1)[0].strip().rstrip(";").strip()
        if line:
            key, value = line.split(None, 1)
            entries[key.strip('"')] = value.strip().strip('"')
    return entries


def chart_config():
    result = subprocess.run(
        ["helm", "template", "test", str(CHART), "--show-only", "templates/configmap-nginx.yaml"],
        cwd=ROOT, text=True, capture_output=True, check=True,
    )
    return result.stdout


class UIProxyAuthTest(unittest.TestCase):
    def assert_read_only_injection(self, conf):
        read_auth = map_block(conf, "$bomhort_read_auth")
        self.assertEqual(read_auth.get("default"), "", "non-read methods must get no token")
        injected = {k for k, v in read_auth.items() if v == TOKEN}
        self.assertEqual(injected, READ_METHODS)
        self.assertTrue(all(v in ("", TOKEN) for v in read_auth.values()), read_auth)

        effective = map_block(conf, "$bomhort_effective_auth")
        self.assertEqual(effective.get("default"), "$http_authorization",
                         "a client-supplied Authorization header must pass through")
        self.assertEqual(effective.get(""), "$bomhort_read_auth")

        self.assertEqual(conf.count(TOKEN), len(READ_METHODS),
                         "the token must only appear in the read-method map")
        self.assertRegex(conf, r"proxy_set_header\s+Authorization\s+\$bomhort_effective_auth;")

    def test_chart_configmap_injects_token_on_reads_only(self):
        self.assert_read_only_injection(chart_config())

    def test_image_template_injects_token_on_reads_only(self):
        self.assert_read_only_injection(IMAGE_TEMPLATE.read_text())

    def test_badges_public_defaults_to_false(self):
        result = subprocess.run(
            ["helm", "template", "test", str(CHART), "--show-only", "templates/configmap.yaml"],
            cwd=ROOT, text=True, capture_output=True, check=True,
        )
        self.assertIn('BADGES_PUBLIC: "false"', result.stdout)

    def test_badges_public_can_be_enabled(self):
        result = subprocess.run(
            ["helm", "template", "test", str(CHART), "--show-only", "templates/configmap.yaml",
             "--set", "apiGateway.auth.badgesPublic=true"],
            cwd=ROOT, text=True, capture_output=True, check=True,
        )
        self.assertIn('BADGES_PUBLIC: "true"', result.stdout)


if __name__ == "__main__":
    unittest.main()
