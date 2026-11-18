"""Helm template tests for the original-document store (#256).

Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).
"""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class OriginalStoreTemplatesTest(unittest.TestCase):
    def render(self, values=None):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            result = subprocess.run(
                ["helm", "template", "test", str(CHART), "-f", str(values_file)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_defaults_are_auto_with_reserved_prefix_and_no_pvc(self):
        out = self.render()
        self.assertIn('ORIGINAL_STORE_BACKEND: "auto"', out)
        self.assertIn('ORIGINAL_STORE_S3_PREFIX: "_bomhort/originals/"', out)
        self.assertNotIn("ORIGINAL_STORE_S3_BUCKET", out)
        self.assertNotIn("ORIGINAL_STORE_FS_PATH", out)
        self.assertNotIn("name: bomhort-originals", out)
        self.assertNotIn("name: originals", out)

    def test_s3_bucket_and_prefix_are_forwarded(self):
        out = self.render({"originalStore": {"backend": "s3",
                                             "s3": {"bucket": "archive", "prefix": "keep/"}}})
        self.assertIn('ORIGINAL_STORE_BACKEND: "s3"', out)
        self.assertIn('ORIGINAL_STORE_S3_BUCKET: "archive"', out)
        self.assertIn('ORIGINAL_STORE_S3_PREFIX: "keep/"', out)

    def test_fs_backend_creates_pvc_and_mounts_worker_rw_gateway_ro(self):
        out = self.render({"originalStore": {"backend": "fs", "fs": {
            "enabled": True, "pvcName": "orig", "mountPath": "/mnt/orig",
            "storageSize": "20Gi", "accessMode": "ReadWriteMany",
            "storageClassName": "nfs"}}})
        self.assertIn('ORIGINAL_STORE_BACKEND: "fs"', out)
        self.assertIn('ORIGINAL_STORE_FS_PATH: "/mnt/orig"', out)

        # PVC rendered with the requested spec.
        pvc = [d for d in out.split("---") if "kind: PersistentVolumeClaim" in d and "name: orig" in d]
        self.assertEqual(len(pvc), 1, "exactly one originals PVC expected")
        self.assertIn("ReadWriteMany", pvc[0])
        self.assertIn("storage: 20Gi", pvc[0])
        self.assertIn('storageClassName: "nfs"', pvc[0])

        # Both deployments mount it; gateway read-only, worker read-write.
        docs = out.split("---")
        worker = next(d for d in docs if "kind: Deployment" in d and "parsing-worker" in d)
        gateway = next(d for d in docs if "kind: Deployment" in d and "api-gateway" in d)
        for doc in (worker, gateway):
            self.assertIn("claimName: orig", doc)
            self.assertIn("mountPath: /mnt/orig", doc)
        w_mount = worker[worker.index("name: originals"):]
        w_mount = w_mount[:w_mount.index("{{") if "{{" in w_mount else 200]
        self.assertNotIn("readOnly: true", w_mount.split("- name:")[0])
        g_mount = gateway[gateway.index("name: originals"):][:200]
        self.assertNotIn("readOnly: true", g_mount.split("- name:")[0])

    def test_pod_security_context_defaults_to_nobody_fsgroup(self):
        """Images run as nobody (65534); without fsGroup a fresh PVC is
        root-owned and neither originals nor push uploads can be written."""
        out = self.render({"originalStore": {"backend": "fs", "fs": {"enabled": True}}})
        self.assertEqual(out.count("fsGroup: 65534"), 2, "worker + gateway")
        self.assertIn("fsGroupChangePolicy: OnRootMismatch", out)
        out = self.render({"podSecurityContext": None})
        self.assertNotIn("fsGroup", out)
        out = self.render({"podSecurityContext": {"fsGroup": 1000, "runAsNonRoot": True}})
        self.assertEqual(out.count("fsGroup: 1000"), 2)
        self.assertEqual(out.count("runAsNonRoot: true"), 2)
    def test_none_disables_but_keeps_prefix_key(self):
        out = self.render({"originalStore": {"backend": "none"}})
        self.assertIn('ORIGINAL_STORE_BACKEND: "none"', out)
        self.assertNotIn("name: originals", out)

    def test_data_migration_job_copies_document_store(self):
        out = self.render({"dataMigration": {"enabled": True}})
        self.assertIn("document_store", out)


if __name__ == "__main__":
    unittest.main()
