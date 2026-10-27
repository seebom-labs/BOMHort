#!/usr/bin/env python3
import http.server
import json
import os
import subprocess
import tempfile
import threading
import unittest

MOCK_PORT = 18080

class MockBOMHortHandler(http.server.BaseHTTPRequestHandler):
    last_request = {}

    def log_message(self, format, *args):
        # Silence HTTP logs in test output
        pass

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        MockBOMHortHandler.last_request = {
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        }

        # Check path
        if not self.path.startswith("/api/v1/sboms/upload"):
            self.send_response(404)
            self.end_headers()
            return

        # Check required header
        if not self.headers.get("X-Filename"):
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "X-Filename header is required"}')
            return

        # Check auth
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Forbidden"}')
            return

        # Success response
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {
            "status": "pending",
            "job_id": "test-job-uuid-1234",
            "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "job_type": "sbom",
            "cluster": "test-cluster",
            "namespace": "test-ns",
            "project": "test-proj",
        }
        self.wfile.write(json.dumps(resp).encode("utf-8"))


class TestUploadSBOMAction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", MOCK_PORT), MockBOMHortHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def run_script(self, env_vars):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        script_path = os.path.join(repo_root, ".github", "actions", "upload-sbom", "upload.sh")
        # Run via bash if available or sh
        full_env = os.environ.copy()
        full_env.update(env_vars)
        return subprocess.run(
            ["bash", script_path],
            env=full_env,
            capture_output=True,
            text=True,
            cwd=repo_root,
        )

    def test_missing_required_inputs(self):
        # Missing URL
        res = self.run_script({})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Input 'url' is required", res.stderr)

        # Missing token
        res = self.run_script({"INPUT_URL": "http://localhost"})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Input 'token' is required", res.stderr)

        # Missing SBOM
        res = self.run_script({"INPUT_URL": "http://localhost", "INPUT_TOKEN": "secret"})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Input 'sbom' is required", res.stderr)

    def test_nonexistent_sbom_file(self):
        res = self.run_script({
            "INPUT_URL": f"http://127.0.0.1:{MOCK_PORT}",
            "INPUT_TOKEN": "secret-token",
            "INPUT_SBOM": "nonexistent-file.spdx.json",
        })
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("No file found matching sbom path", res.stderr)

    def test_successful_upload(self):
        with tempfile.NamedTemporaryFile(suffix="my-app.spdx.json", delete=False) as f:
            f.write(b'{"spdxVersion": "SPDX-2.3"}')
            temp_path = f.name

        output_file = temp_path + ".output"
        try:
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{MOCK_PORT}",
                "INPUT_TOKEN": "my-secret-token",
                "INPUT_SBOM": temp_path,
                "INPUT_PROJECT": "payment-api",
                "INPUT_CLUSTER": "prod-eu",
                "INPUT_NAMESPACE": "payments",
                "INPUT_TAGS": "finance,pci",
                "INPUT_SOURCE_REPO": "https://github.com/my-org/my-repo",
                "INPUT_SOURCE_REF": "refs/heads/main",
                "GITHUB_OUTPUT": output_file,
            })
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")
            self.assertIn("Upload completed successfully", res.stdout)

            # Check that token was not echoed in stdout/stderr
            self.assertNotIn("my-secret-token", res.stdout)
            self.assertNotIn("my-secret-token", res.stderr)

            # Verify received HTTP request
            req = MockBOMHortHandler.last_request
            self.assertIn("project=payment-api", req["path"])
            self.assertIn("cluster=prod-eu", req["path"])
            self.assertIn("namespace=payments", req["path"])
            self.assertIn("tags=finance%2Cpci", req["path"])
            self.assertEqual(req["headers"].get("Authorization"), "Bearer my-secret-token")
            self.assertEqual(req["headers"].get("X-Filename"), os.path.basename(temp_path))
            self.assertEqual(req["headers"].get("X-Source-Repo"), "https://github.com/my-org/my-repo")
            self.assertEqual(req["headers"].get("X-Source-Ref"), "refs/heads/main")
            self.assertEqual(req["body"], b'{"spdxVersion": "SPDX-2.3"}')

            # Verify GITHUB_OUTPUT
            with open(output_file, "r") as out_f:
                out_content = out_f.read()
            self.assertIn("status=pending", out_content)
            self.assertIn("job-id=test-job-uuid-1234", out_content)
            self.assertIn("sha256-hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", out_content)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            if os.path.exists(output_file):
                os.remove(output_file)


if __name__ == "__main__":
    unittest.main()
