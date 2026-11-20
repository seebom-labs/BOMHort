"""Regression tests for the ClickHouse NetworkPolicy and its pod selectors.

The tests render the chart (no Kubernetes cluster required). A live CNI test is
still needed to verify enforcement and Altinity reconciliation in the target
cluster.
"""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"
CLIENT_TEMPLATES = {
    "api-gateway": "templates/deployment-api-gateway.yaml",
    "parsing-worker": "templates/deployment-parsing-worker.yaml",
    "cve-refresher": "templates/cronjob-cve-refresher.yaml",
    "ingestion-watcher": "templates/cronjob-ingestion-watcher.yaml",
    "migrate": "templates/job-migrate.yaml",
    "data-migration": "templates/job-data-migration.yaml",
}


def render(*args):
    result = subprocess.run(
        ["helm", "template", "test", str(CHART), *args],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout


def pod_template_labels(output):
    match = re.search(
        r"(?ms)^[ \t]*template:[ \t]*\n[ \t]*metadata:[ \t]*\n"
        r"[ \t]*labels:[ \t]*\n(?P<labels>.*?)(?=^[ \t]*spec:[ \t]*$)",
        output,
    )
    if not match:
        raise AssertionError("rendered workload has no pod-template labels")
    return match.group("labels")


class ClickHouseNetworkPolicyTest(unittest.TestCase):
    def test_policy_is_opt_in(self):
        self.assertNotIn("name: test-clickhouse-access", render())

    def test_policy_allows_clients_operator_and_replicas(self):
        output = render(
            "--set", "clickhouse.networkPolicy.enabled=true",
            "--set", "clickhouse.cluster.replicasCount=2",
        )
        policy = next(
            document for document in output.split("---")
            if "name: test-clickhouse-access" in document
        )

        self.assertIn("app.kubernetes.io/instance: test", policy)
        self.assertIn("app.kubernetes.io/name: bomhort", policy)
        self.assertIn("operator: In", policy)
        for component in CLIENT_TEMPLATES:
            with self.subTest(component=component):
                self.assertIn(f"- {component}", policy)
        self.assertRegex(policy, r"(?s)port: 9000")
        self.assertRegex(policy, r"(?s)port: 8123")
        self.assertRegex(policy, r"(?s)port: 9009")
        self.assertIn("clickhouse.altinity.com/chi: test-clickhouse", policy)
        self.assertIn("kubernetes.io/metadata.name: kube-system", policy)
        self.assertIn("app.kubernetes.io/name: clickhouse-operator", policy)
        self.assertIn("replicasCount: 2", output)

    def test_operator_namespace_selector_is_configurable(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = Path(tmp) / "operator-values.yaml"
            values.write_text(
                "clickhouse:\n"
                "  networkPolicy:\n"
                "    enabled: true\n"
                "    operatorNamespaceSelector:\n"
                "      kubernetes.io/metadata.name: operators\n"
                "    operatorPodSelector:\n"
                "      app.kubernetes.io/name: custom-clickhouse-operator\n",
                encoding="utf-8",
            )
            output = render("--values", str(values))
        policy = next(
            document for document in output.split("---")
            if "name: test-clickhouse-access" in document
        )
        self.assertIn("kubernetes.io/metadata.name: operators", policy)
        self.assertIn("app.kubernetes.io/name: custom-clickhouse-operator", policy)

    def test_every_allowed_client_pod_matches_policy_selector(self):
        args = [
            "--set", "clickhouse.networkPolicy.enabled=true",
            "--set", "cveRefresher.enabled=true",
            "--set", "dataMigration.enabled=true",
        ]
        for component, template in CLIENT_TEMPLATES.items():
            with self.subTest(component=component):
                labels = pod_template_labels(render(*args, "--show-only", template))
                self.assertIn("app.kubernetes.io/name: bomhort", labels)
                self.assertIn(f"app.kubernetes.io/component: {component}", labels)
                self.assertIn("app.kubernetes.io/instance: test", labels)

    def test_ui_pod_is_not_allowed_as_a_direct_client(self):
        policy = next(
            document for document in render(
                "--set", "clickhouse.networkPolicy.enabled=true"
            ).split("---") if "name: test-clickhouse-access" in document
        )
        self.assertNotIn("- ui", policy)
        self.assertNotIn("- mcp-server", policy)


if __name__ == "__main__":
    unittest.main()
