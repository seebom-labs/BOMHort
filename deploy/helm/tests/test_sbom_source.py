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

    def test_no_volume_tells_the_binaries_sbom_dir_is_not_shared(self):
        """The gateway probes SBOM_DIR for writability; a custom mountPath such
        as /tmp/sboms is writable in its own container without any volume, and
        an upload stored there is one no worker can read."""
        out = self.render({**S3_ONLY, "sbomSource": {"enabled": False,
                                                    "mountPath": "/tmp/sboms"}})
        self.assertIn('SBOM_DIR: "/tmp/sboms"', out)
        self.assertIn('SBOM_DIR_DISABLED: "true"', out)
        for name, values in {
            "pvc": {"gitSync": {"enabled": False}},
            "git-sync": {"gitSync": {"enabled": True}, "sbomSource": {"enabled": False}},
        }.items():
            with self.subTest(mode=name):
                self.assertNotIn("SBOM_DIR_DISABLED", self.render(values))

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
        """'[]' is a non-empty string, so the buckets are checked as data."""
        for name, buckets in {"unset": None, "empty string": "", "string list": "[]",
                              "native list": []}.items():
            with self.subTest(buckets=name):
                values = {"gitSync": {"enabled": False}, "sbomSource": {"enabled": False}}
                if buckets is not None:
                    values["s3"] = {"buckets": buckets}
                error = self.render(values, success=False)
                self.assertIn("without an SBOM source", error)
                self.assertIn("s3.buckets", error)

    def test_no_volume_and_unusable_buckets_is_refused(self):
        for name, buckets in {
            "malformed JSON": '[{"name":"sboms"',
            "JSON object": '{"name":"sboms"}',
            "string entries": '["sboms"]',
            "native string entries": ["sboms"],
            "entry without a name": [{"region": "us-east-1"}],
            "native map": {"name": "sboms"},
        }.items():
            with self.subTest(buckets=name):
                error = self.render({**S3_ONLY, "s3": {"buckets": buckets}}, success=False)
                self.assertIn("s3.buckets must be a JSON array of bucket objects", error)

    def test_no_volume_accepts_a_native_bucket_list(self):
        out = self.render({**S3_ONLY, "s3": {"buckets": [
            {"name": "sboms", "region": "us-east-1"},
            {"name": "pushed", "skipScan": True}]}})
        self.assertNotIn("kind: PersistentVolumeClaim", out)
        self.assertIn(r'S3_BUCKETS: "[{\"name\":\"sboms\",\"region\":\"us-east-1\"},'
                      r'{\"name\":\"pushed\",\"skipScan\":true}]"', out)

    def test_bucket_checks_only_apply_without_a_volume(self):
        self.render({"gitSync": {"enabled": False}, "s3": {"buckets": "[]"}})

    def test_writable_without_a_volume_is_refused(self):
        error = self.render({**S3_ONLY, "sbomSource": {"enabled": False, "writable": True}},
                            success=False)
        self.assertIn("sbomSource.writable=true needs the sbom-data volume", error)
        self.assertIn("skipScan", error)


if __name__ == "__main__":
    unittest.main()
