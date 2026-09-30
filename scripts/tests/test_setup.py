import base64
import importlib.util
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import call, patch


SCRIPT = Path(__file__).resolve().parents[1] / "setup.py"
spec = importlib.util.spec_from_file_location("scanr_setup", SCRIPT)
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class SetupTests(unittest.TestCase):
    def test_creates_unique_private_env_with_fernet_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            template = root / ".env.example"
            target = root / ".env"
            template.write_text("SECRET_KEY=\nVAULT_KEY=\nPOSTGRES_PASSWORD=\nADMIN_EMAIL=admin@example.com\nADMIN_PASSWORD=\nALLOWED_ORIGINS=http://localhost\nSANDBOX_TOKEN=\nBROWSER_SERVICE_TOKEN=\n", encoding="utf-8")
            setup.create_env(template, target, "https://scanr.example", "ops@example.com")
            values = dict(line.split("=", 1) for line in target.read_text().splitlines() if "=" in line)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(values["ALLOWED_ORIGINS"], "https://scanr.example")
            self.assertEqual(values["ADMIN_EMAIL"], "ops@example.com")
            self.assertEqual(len(base64.urlsafe_b64decode(values["VAULT_KEY"])), 32)
            self.assertTrue(all(values[name] for name in setup.REQUIRED_SECRETS))

    def test_refuses_to_overwrite_existing_env(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            template, target = root / "example", root / ".env"
            template.write_text("SECRET_KEY=\n")
            target.write_text("keep me\n")
            with self.assertRaises(setup.SetupError):
                setup.create_env(template, target, "http://localhost", "admin@example.com")
            self.assertEqual(target.read_text(), "keep me\n")

    def test_origin_validation_keeps_local_http_and_requires_https_remote(self):
        self.assertEqual(setup.validate_origin("http://localhost/"), "http://localhost")
        self.assertEqual(setup.validate_origin("https://scanr.example"), "https://scanr.example")
        for invalid in ("http://scanr.example", "https://scanr.example/path", "https://user@scanr.example", "file:///tmp"):
            with self.subTest(invalid=invalid), self.assertRaises(Exception):
                setup.validate_origin(invalid)

    def test_rejects_invalid_ports_and_dotenv_metacharacters(self):
        for invalid in (
            "https://scanr.example:bad", "https://scanr.example:99999",
            "https://scanr.example/$VAR", "https://scanr.example#comment",
            "https://scanr.example'",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(Exception):
                setup.validate_origin(invalid)
        for invalid in ("ops+$VAR@example.com", "ops#comment@example.com", "'ops'@example.com", "ops@example.com;touch"):
            with self.subTest(invalid=invalid), self.assertRaises(Exception):
                setup.validate_email(invalid)

    @patch.object(setup.shutil, "which", return_value="/usr/bin/docker")
    @patch.object(setup.subprocess, "run")
    def test_start_validates_pulls_profile_and_sandbox_then_waits(self, run, _which):
        run.side_effect = [
            setup.subprocess.CompletedProcess([], 0, stdout="Docker Compose version v2.30.0", stderr=""),
            setup.subprocess.CompletedProcess([], 0, stdout='{"services":{"sandbox-runner":{"environment":{"SANDBOX_IMAGE":"example/sandbox:1"}},"api":{"environment":{"ALLOWED_ORIGINS":"https://scanr.example"}}}}', stderr=""),
            setup.subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            setup.subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            setup.subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        ]
        with tempfile.TemporaryDirectory() as temp:
            setup.ROOT = Path(temp)
        self.assertEqual(setup.run_compose(Path(temp) / ".env"), "https://scanr.example")
        invoked = [item.args[0] for item in run.call_args_list]
        self.assertIn("config", invoked[1])
        self.assertIn("--profile", invoked[2])
        self.assertIn("pull", invoked[2])
        self.assertEqual(invoked[3], ["/usr/bin/docker", "pull", "example/sandbox:1"])
        self.assertIn("--wait", invoked[4])

    @patch.object(setup, "run_compose", return_value="https://custom.example")
    def test_start_reuses_existing_env_unchanged_and_reports_its_origin(self, run_compose):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            env_path = root / ".env"
            env_path.write_text("ALLOWED_ORIGINS=https://custom.example\nsecret=leave-this-alone\n")
            before = env_path.read_bytes()
            output = StringIO()
            with patch.object(setup, "ROOT", root), redirect_stdout(output):
                result = setup.main(["--start"])
            self.assertEqual(result, 0)
            self.assertEqual(env_path.read_bytes(), before)
            run_compose.assert_called_once_with(env_path)
            self.assertIn("https://custom.example", output.getvalue())
            self.assertNotIn("leave-this-alone", output.getvalue())


if __name__ == "__main__":
    unittest.main()
