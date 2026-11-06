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
    detail_responses_before_success = 0
    mock_critical_vulns = 0
    mock_high_vulns = 0
    mock_medium_vulns = 0
    mock_low_vulns = 0
    sarif_download_requested = False
    return_duplicate = False
    return_newline_status = False
    return_workflow_command_error = False

    def log_message(self, format, *args):
        # Silence HTTP logs in test output
        pass

    def do_GET(self):
        MockBOMHortHandler.request_count += 1
        MockBOMHortHandler.last_request = {
            "path": self.path,
            "headers": dict(self.headers),
        }

        # Check auth
        auth = self.headers.get("Authorization", "")
        api_key = self.headers.get("X-API-Key", "")
        if not auth.startswith("Bearer ") and not api_key:
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Forbidden"}')
            return

        if "/vulnerabilities?format=sarif" in self.path:
            MockBOMHortHandler.sarif_download_requested = True
            self.send_response(200)
            self.send_header("Content-Type", "application/sarif+json")
            self.end_headers()
            sarif = {
                "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "BOMHort", "version": "1.0.0"}},
                        "results": [],
                    }
                ],
            }
            self.wfile.write(json.dumps(sarif).encode("utf-8"))
            return

        if "/detail" in self.path:
            if MockBOMHortHandler.detail_responses_before_success > 0:
                MockBOMHortHandler.detail_responses_before_success -= 1
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "SBOM not found"}')
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            total_vulns = (
                MockBOMHortHandler.mock_critical_vulns
                + MockBOMHortHandler.mock_high_vulns
                + MockBOMHortHandler.mock_medium_vulns
                + MockBOMHortHandler.mock_low_vulns
            )
            detail = {
                "sbom_id": "ee586207-a68c-505a-8dfb-1dc50feb38b8",
                "source_file": "pushed/test.spdx.json",
                "spdx_version": "SPDX-2.3",
                "document_name": "test-doc",
                "package_count": 42,
                "vuln_count": total_vulns,
                "critical_vulns": MockBOMHortHandler.mock_critical_vulns,
                "high_vulns": MockBOMHortHandler.mock_high_vulns,
                "medium_vulns": MockBOMHortHandler.mock_medium_vulns,
                "low_vulns": MockBOMHortHandler.mock_low_vulns,
            }
            self.wfile.write(json.dumps(detail).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

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
        MockBOMHortHandler.detail_responses_before_success = 0
        MockBOMHortHandler.mock_critical_vulns = 0
        MockBOMHortHandler.mock_high_vulns = 0
        MockBOMHortHandler.mock_medium_vulns = 0
        MockBOMHortHandler.mock_low_vulns = 0
        MockBOMHortHandler.sarif_download_requested = False
        MockBOMHortHandler.return_duplicate = False
        MockBOMHortHandler.return_newline_status = False
        MockBOMHortHandler.return_workflow_command_error = False

    def run_script(self, env_vars):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        script_path = os.path.join(repo_root, ".github", "actions", "upload-sbom", "upload.sh")
        if os.name == "nt":
            script_path = os.path.relpath(script_path, repo_root).replace("\\", "/")
        bash = os.environ.get("BASH")
        if not bash and os.name == "nt":
            git_bash = r"C:\Program Files\Git\bin\bash.exe"
            if os.path.exists(git_bash):
                bash = git_bash
        if not bash:
            bash = "bash"
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

    def test_wait_and_outputs_success(self):
        with tempfile.TemporaryDirectory(prefix="sbom action ") as directory:
            temp_path = os.path.join(directory, "app.spdx.json")
            output_file = os.path.join(directory, "github_output.txt")
            with open(temp_path, "wb") as f:
                f.write(b'{"spdxVersion": "SPDX-2.3"}')

            MockBOMHortHandler.detail_responses_before_success = 1
            MockBOMHortHandler.mock_critical_vulns = 0
            MockBOMHortHandler.mock_high_vulns = 1
            MockBOMHortHandler.mock_medium_vulns = 2
            MockBOMHortHandler.mock_low_vulns = 0

            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": temp_path,
                "INPUT_WAIT": "true",
                "INPUT_WAIT_TIMEOUT": "5",
                "POLL_INTERVAL": "0.1",
                "GITHUB_OUTPUT": output_file,
            })
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")
            self.assertIn("Waiting for SBOM", res.stdout)
            self.assertIn("SBOM ee586207-a68c-505a-8dfb-1dc50feb38b8 processed", res.stdout)

            with open(output_file, "r") as out_f:
                out_content = out_f.read()
            self.assertIn("sbom-id=ee586207-a68c-505a-8dfb-1dc50feb38b8", out_content)
            self.assertIn(f"url=http://127.0.0.1:{self.port}/sboms/ee586207-a68c-505a-8dfb-1dc50feb38b8", out_content)
            self.assertIn('vulnerabilities={"critical":0,"high":1,"medium":2,"low":0}', out_content)

    def test_wait_timeout_fails(self):
        with tempfile.NamedTemporaryFile(suffix=".spdx.json", delete=False) as f:
            f.write(b'{"spdxVersion": "SPDX-2.3"}')
            temp_path = f.name
        try:
            MockBOMHortHandler.detail_responses_before_success = 999
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": temp_path,
                "INPUT_WAIT": "true",
                "INPUT_WAIT_TIMEOUT": "1",
                "POLL_INTERVAL": "0.1",
            })
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Timed out after 1s waiting for SBOM", res.stderr)
        finally:
            os.remove(temp_path)

    def test_sarif_download_success(self):
        with tempfile.TemporaryDirectory(prefix="sbom action ") as directory:
            temp_path = os.path.join(directory, "app.spdx.json")
            sarif_file = os.path.join(directory, "reports", "output.sarif")
            with open(temp_path, "wb") as f:
                f.write(b'{"spdxVersion": "SPDX-2.3"}')

            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": temp_path,
                "INPUT_SARIF": sarif_file,
                "POLL_INTERVAL": "0.1",
            })
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")
            self.assertTrue(os.path.exists(sarif_file))
            with open(sarif_file, "r") as f:
                content = f.read()
            self.assertIn('"version": "2.1.0"', content)
            self.assertTrue(MockBOMHortHandler.sarif_download_requested)

    def test_fail_on_threshold_exceeded(self):
        with tempfile.NamedTemporaryFile(suffix=".spdx.json", delete=False) as f:
            f.write(b'{"spdxVersion": "SPDX-2.3"}')
            temp_path = f.name
        try:
            MockBOMHortHandler.mock_high_vulns = 1
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": temp_path,
                "INPUT_FAIL_ON": "high",
                "POLL_INTERVAL": "0.1",
            })
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Vulnerability threshold exceeded (fail-on=high)", res.stderr)
        finally:
            os.remove(temp_path)

    def test_fail_on_threshold_passed(self):
        with tempfile.NamedTemporaryFile(suffix=".spdx.json", delete=False) as f:
            f.write(b'{"spdxVersion": "SPDX-2.3"}')
            temp_path = f.name
        try:
            MockBOMHortHandler.mock_critical_vulns = 0
            MockBOMHortHandler.mock_high_vulns = 0
            MockBOMHortHandler.mock_medium_vulns = 2
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": temp_path,
                "INPUT_FAIL_ON": "high",
                "POLL_INTERVAL": "0.1",
            })
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")
            self.assertIn("Vulnerability policy passed: threshold 'high' not exceeded", res.stdout)
        finally:
            os.remove(temp_path)

    def test_invalid_fail_on_value(self):
        with tempfile.NamedTemporaryFile(suffix=".spdx.json", delete=False) as f:
            f.write(b'{"spdxVersion": "SPDX-2.3"}')
            temp_path = f.name
        try:
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": temp_path,
                "INPUT_FAIL_ON": "supercritical",
            })
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Input 'fail-on' must be one of: none, low, medium, high, critical", res.stderr)
        finally:
            os.remove(temp_path)

    def test_invalid_wait_timeout(self):
        with tempfile.NamedTemporaryFile(suffix=".spdx.json", delete=False) as f:
            f.write(b'{"spdxVersion": "SPDX-2.3"}')
            temp_path = f.name
        try:
            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": temp_path,
                "INPUT_WAIT_TIMEOUT": "invalid",
            })
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Input 'wait-timeout' must be a positive integer", res.stderr)
        finally:
            os.remove(temp_path)

    def test_duplicate_upload_with_wait(self):
        with tempfile.TemporaryDirectory(prefix="sbom action ") as directory:
            temp_path = os.path.join(directory, "app.spdx.json")
            output_file = os.path.join(directory, "github_output.txt")
            with open(temp_path, "wb") as f:
                f.write(b'{"spdxVersion": "SPDX-2.3"}')

            MockBOMHortHandler.return_duplicate = True
            MockBOMHortHandler.mock_critical_vulns = 0
            MockBOMHortHandler.mock_high_vulns = 0

            res = self.run_script({
                "INPUT_URL": f"http://127.0.0.1:{self.port}",
                "INPUT_TOKEN": "secret-token",
                "INPUT_SBOM": temp_path,
                "INPUT_WAIT": "true",
                "POLL_INTERVAL": "0.1",
                "GITHUB_OUTPUT": output_file,
            })
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}\n{res.stdout}")
            with open(output_file, "r") as out_f:
                out_content = out_f.read()
            self.assertIn("status=duplicate", out_content)
            self.assertIn("sbom-id=ee586207-a68c-505a-8dfb-1dc50feb38b8", out_content)
            self.assertIn('vulnerabilities={"critical":0,"high":0,"medium":0,"low":0}', out_content)


if __name__ == "__main__":
    unittest.main()
