"""Helm template tests for the optional sbom-data volume (#590).

With git-sync disabled the chart used to create the sbomSource PVC and pin the
watcher, the workers and the gateway to one node for it, even when every SBOM
came from S3. sbomSource.enabled=false removes the volume and the pinning.

Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).
"""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"

S3_ONLY = {
    "gitSync": {"enabled": False},
    "sbomSource": {"enabled": False},
    "s3": {"buckets": '[{"name":"sboms","region":"us-east-1"}]'},
}


class SbomSourceVolumeTest(unittest.TestCase):
    def render(self, values, success=True):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values))
            result = subprocess.run(
                ["helm", "template", "test", str(CHART), "-f", str(values_file)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout
        self.assertNotEqual(result.returncode, 0, "render should have failed")
        return result.stderr

    def workload(self, output, kind, component):
        return next(d for d in output.split("\n---")
                    if f"kind: {kind}" in d and f"name: test-{component}" in d)

    def test_s3_only_has_no_volume_and_no_node_pinning(self):
        out = self.render(S3_ONLY)
        self.assertNotIn("kind: PersistentVolumeClaim", out)
        self.assertNotIn("sbom-data", out)
        self.assertNotIn("bomhort.io/sbom-volume", out)
        self.assertNotIn("podAffinity", out)
        # The watcher has no other volume, so the keys go as well.
        watcher = self.workload(out, "CronJob", "ingestion-watcher")
        self.assertNotIn("volumes:", watcher)
        self.assertNotIn("volumeMounts:", watcher)
        # Still told where local files would be; the binaries skip a
        # directory that does not exist.
        self.assertIn('SBOM_DIR: "/data/sboms"', out)

    def test_missing_enabled_key_keeps_the_pvc(self):
        """`helm upgrade --reuse-values` from a chart without the key must not
        drop a PVC that is in use."""
        out = self.render({"gitSync": {"enabled": False},
                           "sbomSource": {"enabled": None}})
        self.assertIn("name: bomhort-sbom-data", out)
        self.assertEqual(out.count("claimName: bomhort-sbom-data"), 3)
        self.assertEqual(out.count("podAffinity:"), 3)

    def test_originals_pvc_keeps_workers_and_gateway_together(self):
        """originalStore.fs is a ReadWriteOnce PVC shared by both; it relied on
        the sbom-data affinity and must not lose it."""
        out = self.render({**S3_ONLY, "originalStore": {"fs": {"enabled": True}}})
        self.assertNotIn("sbom-data", out)
        for component in ("parsing-worker", "api-gateway"):
            with self.subTest(component=component):
                doc = self.workload(out, "Deployment", component)
                self.assertIn('bomhort.io/sbom-volume: "true"', doc)
                self.assertIn("podAffinity:", doc)
                self.assertIn("claimName: bomhort-originals", doc)
        self.assertNotIn("podAffinity", self.workload(out, "CronJob", "ingestion-watcher"))

    def test_git_sync_keeps_its_emptydir(self):
        out = self.render({"gitSync": {"enabled": True}, "sbomSource": {"enabled": False}})
        self.assertEqual(out.count("emptyDir: {}"), 3)
        self.assertNotIn("kind: PersistentVolumeClaim", out)

    def test_no_volume_and_no_buckets_is_refused(self):
        error = self.render({"gitSync": {"enabled": False},
                             "sbomSource": {"enabled": False}}, success=False)
        self.assertIn("without an SBOM source", error)
        self.assertIn("s3.buckets", error)

    def test_writable_without_a_volume_is_refused(self):
        error = self.render({**S3_ONLY, "sbomSource": {"enabled": False, "writable": True}},
                            success=False)
        self.assertIn("sbomSource.writable=true needs the sbom-data volume", error)
        self.assertIn("skipScan", error)


if __name__ == "__main__":
    unittest.main()
