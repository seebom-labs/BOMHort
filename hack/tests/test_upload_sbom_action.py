#!/usr/bin/env python3
import http.server
import json
import os
import subprocess
import tempfile
import threading
import unittest


class MockBOMHortHandler(http.server.BaseHTTPRequestHandler):
    last_request = {}
    request_count = 0
    responses_before_success = 0
    return_duplicate = False
    return_newline_status = False
    return_workflow_command_error = False

    def log_message(self, format, *args):
        # Silence HTTP logs in test output
        pass

    def do_POST(self):
        MockBOMHortHandler.request_count += 1
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
        api_key = self.headers.get("X-API-Key", "")
        if not auth.startswith("Bearer ") and not api_key:
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Forbidden"}')
            return

        if MockBOMHortHandler.return_workflow_command_error:
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"bad request\n::warning::forged")
            return

        if MockBOMHortHandler.responses_before_success > 0:
            MockBOMHortHandler.responses_before_success -= 1
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Temporarily unavailable"}')
            return

        # Success response
        status_code = 200 if MockBOMHortHandler.return_duplicate else 202
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if MockBOMHortHandler.return_newline_status:
            resp = {
                "status": "pending\ninjected=yes",
                "job_id": "test-job-uuid-1234",
                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            }
        elif MockBOMHortHandler.return_duplicate:
            resp = {
                "status": "duplicate",
                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            }
        else:
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
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockBOMHortHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        MockBOMHortHandler.last_request = {}
        MockBOMHortHandler.request_count = 0
        MockBOMHortHandler.responses_before_success = 0
        MockBOMHortHandler.return_duplicate = False
        MockBOMHortHandler.return_newline_status = False
        MockBOMHortHandler.return_workflow_command_error = False

    def run_script(self, env_vars):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        script_path = os.path.join(repo_root, ".github", "actions", "upload-sbom", "upload.sh")
        # BASH can point to Git Bash on Windows; Linux CI uses the default bash.
        bash = os.environ.get("BASH", "bash")
        full_env = os.environ.copy()
        full_env.update(env_vars)
        return subprocess.run(
            [bash, script_path],
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
            "INPUT_URL": f"http://127.0.0.1:{self.port}",
            "INPUT_TOKEN": "secret-token",
            "INPUT_SBOM": "nonexistent-file.spdx.json",
        })
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("No file found matching sbom path", res.stderr)

    def test_successful_upload(self):
        with tempfile.TemporaryDirectory(prefix="sbom action ") as directory:
            temp_path = os.path.join(directory, "my app.spdx.json")
            output_file = os.path.join(directory, "github output.txt")
            with open(temp_path, "wb") as f:
                f.write(b'{"spdxVersion": "SPDX-2.3"}')
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "my-secret-token",
                "INPUT_SBOM": temp_path,
                "INPUT_PROJECT": "payment café&team=platform",
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
            self.assertIn("project=payment%20caf%C3%A9%26team%3Dplatform", req["path"])
            self.assertIn("cluster=prod-eu", req["path"])
            self.assertIn("namespace=payments", req["path"])
            self.assertIn("tags=finance%2Cpci", req["path"])
            self.assertEqual(req["headers"].get("Authorization"), "Bearer my-secret-token")
            self.assertEqual(req["headers"].get("X-Filename"), "my app.spdx.json")
            self.assertEqual(req["headers"].get("X-Source-Repo"), "https://github.com/my-org/my-repo")
            self.assertEqual(req["headers"].get("X-Source-Ref"), "refs/heads/main")
            self.assertEqual(req["body"], b'{"spdxVersion": "SPDX-2.3"}')

            # Verify GITHUB_OUTPUT
            with open(output_file, "r") as out_f:
                out_content = out_f.read()
            self.assertIn("status=pending", out_content)
            self.assertIn("job-id=test-job-uuid-1234", out_content)
            self.assertIn("sha256-hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", out_content)

    def test_glob_with_spaces_in_path(self):
        with tempfile.TemporaryDirectory(prefix="sbom directory ") as directory:
            sbom_path = os.path.join(directory, "generated-bom.spdx.json")
            with open(sbom_path, "wb") as f:
                f.write(b'{"spdxVersion": "SPDX-2.3"}')
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": os.path.join(directory, "*.spdx.json"),
            })
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")
            self.assertEqual(MockBOMHortHandler.last_request["headers"].get("X-Filename"), "generated-bom.spdx.json")

    @unittest.skipIf(os.name == "nt", "Windows filesystems prohibit quotes in file names")
    def test_filename_with_quote_is_sent_safely(self):
        with tempfile.TemporaryDirectory(prefix="sbom action ") as directory:
            sbom_path = os.path.join(directory, 'bom"quoted.spdx.json')
            with open(sbom_path, "wb") as f:
                f.write(b'{"spdxVersion": "SPDX-2.3"}')
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": sbom_path,
            })
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")
            self.assertEqual(MockBOMHortHandler.last_request["headers"].get("X-Filename"), 'bom"quoted.spdx.json')

    def test_api_key_authentication(self):
        with tempfile.NamedTemporaryFile(suffix=".spdx.json", delete=False) as f:
            f.write(b'{"spdxVersion": "SPDX-2.3"}')
            temp_path = f.name
        try:
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "my-api-key",
                "INPUT_AUTH_TYPE": "api-key",
                "INPUT_SBOM": temp_path,
            })
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")
            headers = MockBOMHortHandler.last_request["headers"]
            self.assertEqual(headers.get("X-API-Key"), "my-api-key")
            self.assertIsNone(headers.get("Authorization"))
        finally:
            os.remove(temp_path)

    def test_retries_temporary_server_failure(self):
        with tempfile.NamedTemporaryFile(suffix=".spdx.json", delete=False) as f:
            f.write(b'{"spdxVersion": "SPDX-2.3"}')
            temp_path = f.name
        try:
            MockBOMHortHandler.responses_before_success = 1
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": temp_path,
            })
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")
            self.assertEqual(MockBOMHortHandler.request_count, 2)
        finally:
            os.remove(temp_path)

    def test_duplicate_response_without_job_id_succeeds(self):
        with tempfile.NamedTemporaryFile(suffix=".spdx.json", delete=False) as f:
            f.write(b'{"spdxVersion": "SPDX-2.3"}')
            temp_path = f.name
        try:
            MockBOMHortHandler.return_duplicate = True
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": temp_path,
                "GITHUB_OUTPUT": temp_path + ".output",
            })
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")
            with open(temp_path + ".output", encoding="utf-8") as out_f:
                self.assertIn("status=duplicate", out_f.read())
        finally:
            os.remove(temp_path)
            if os.path.exists(temp_path + ".output"):
                os.remove(temp_path + ".output")

    def test_newline_in_response_output_is_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".spdx.json", delete=False) as f:
            f.write(b'{"spdxVersion": "SPDX-2.3"}')
            temp_path = f.name
        output_path = temp_path + ".output"
        try:
            MockBOMHortHandler.return_newline_status = True
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": temp_path,
                "GITHUB_OUTPUT": output_path,
            })
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("must not contain newline characters", res.stderr)
            if os.path.exists(output_path):
                with open(output_path, encoding="utf-8") as out_f:
                    self.assertNotIn("injected=yes", out_f.read())
        finally:
            os.remove(temp_path)
            if os.path.exists(output_path):
                os.remove(output_path)

    def test_error_response_cannot_inject_workflow_command(self):
        with tempfile.NamedTemporaryFile(suffix=".spdx.json", delete=False) as f:
            f.write(b'{"spdxVersion": "SPDX-2.3"}')
            temp_path = f.name
        try:
            MockBOMHortHandler.return_workflow_command_error = True
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": temp_path,
            })
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("bad request%0A::warning::forged", res.stderr)
            self.assertNotIn("\n::warning::forged", res.stderr)
        finally:
            os.remove(temp_path)

    def test_newline_in_token_is_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".spdx.json", delete=False) as f:
            f.write(b'{"spdxVersion": "SPDX-2.3"}')
            temp_path = f.name
        try:
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": 'secret-token\r\nurl = "https://attacker.example"',
                "INPUT_SBOM": temp_path,
            })
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("must not contain newline characters", res.stderr)
            self.assertNotIn("secret-token", res.stderr)
        finally:
            os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
