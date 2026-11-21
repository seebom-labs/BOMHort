"""Checks the backup runbook against the rendered Helm maintenance controls."""

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"
DOC = ROOT / "docs/content/docs/deployment/backup-restore.md"


def render(template, maintenance=False):
    args = ["helm", "template", "test", str(CHART), "--show-only", template]
    if maintenance:
        args.extend(["--set", "maintenance.writersSuspended=true"])
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout


class BackupRestoreRunbookTest(unittest.TestCase):
    def test_maintenance_stops_deployments_and_cronjobs(self):
        api = render("templates/deployment-api-gateway.yaml", maintenance=True)
        worker = render("templates/deployment-parsing-worker.yaml", maintenance=True)
        watcher = render("templates/cronjob-ingestion-watcher.yaml", maintenance=True)
        refresher = render("templates/cronjob-cve-refresher.yaml", maintenance=True)
        self.assertIn("replicas: 0", api)
        self.assertIn("replicas: 0", worker)
        self.assertIn("suspend: true", watcher)
        self.assertIn("suspend: true", refresher)

    def test_cronjob_jobs_have_release_labels_for_cleanup(self):
        for template, component in [
            ("templates/cronjob-ingestion-watcher.yaml", "ingestion-watcher"),
            ("templates/cronjob-cve-refresher.yaml", "cve-refresher"),
        ]:
            with self.subTest(component=component):
                output = render(template)
                job_template = output.split("jobTemplate:", 1)[1].split("    spec:", 1)[0]
                self.assertIn("app.kubernetes.io/instance: test", job_template)
                self.assertIn(f"app.kubernetes.io/component: {component}", job_template)

    def test_runbook_uses_real_restore_route_and_versioned_snapshot_flow(self):
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("/api/v1/sboms/${SBOM_ID}/download", doc)
        self.assertIn("X-BOMHort-Original: true", doc)
        self.assertIn("X-BOMHort-SHA256", doc)
        self.assertIn("--versioning-configuration Status=Enabled", doc)
        self.assertIn("--set maintenance.writersSuspended=true --no-hooks --wait", doc)
        self.assertIn("--set dataMigration.enabled=false --wait", doc)
        self.assertIn("jsonpath='{.status.active[0].name}'", doc)
        self.assertNotRegex(doc, r"(?m)^\s*aws s3 sync --delete(?:\s|$)")
        self.assertNotIn("ALTER TABLE bomhort.schema_migrations", doc)
        self.assertNotIn("scale cronjob", doc)
        self.assertNotIn("/download/original", doc)
        self.assertIn("restore --schema --data --rm \"$DB_BACKUP_NAME\"", doc)


if __name__ == "__main__":
    unittest.main()
