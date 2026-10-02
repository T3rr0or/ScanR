"""install.sh, run for real with a stub docker and a local git remote."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

INSTALLER = Path(__file__).resolve().parents[2] / "install.sh"
# Stands in for scripts/setup.py inside the fake checkout: records its arguments.
SETUP_STUB = (
    "import json, pathlib, sys\n"
    "pathlib.Path(__file__).parent.parent.joinpath('setup-args.json').write_text(json.dumps(sys.argv[1:]))\n"
)


def git(*args, cwd=None):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


class InstallScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        docker = bin_dir / "docker"
        docker.write_text('#!/bin/sh\nexit "${DOCKER_TEST_EXIT:-0}"\n')
        docker.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}

        # A "GitHub" remote and an existing install cloned from it.
        self.remote = root / "remote.git"
        work = root / "work"
        git("init", "-q", "-b", "master", str(work))
        (work / "scripts").mkdir()
        (work / "scripts" / "setup.py").write_text(SETUP_STUB)
        (work / "docker-compose.yml").write_text("services: {}\n")
        (work / "VERSION").write_text("1\n")
        git("add", ".", cwd=work)
        git("commit", "-qm", "v1", cwd=work)
        git("clone", "-q", "--bare", str(work), str(self.remote))
        self.work = work
        self.install = root / "scanr install"
        git("clone", "-q", "--depth", "1", f"file://{self.remote}", str(self.install))
        (self.install / ".env").write_text("SECRET_KEY=keep\n")

    def tearDown(self):
        self.temp.cleanup()

    def run_installer(self, *args, **env):
        return subprocess.run(["sh", str(INSTALLER), *args], capture_output=True, text=True,
                              env={**self.env, "SCANR_INSTALL_DIR": str(self.install), **env})

    def publish_v2(self):
        (self.work / "VERSION").write_text("2\n")
        git("commit", "-qam", "v2", cwd=self.work)
        git("push", "-q", str(self.remote), "master", cwd=self.work)

    def test_update_pulls_and_restarts_keeping_env(self):
        self.publish_v2()
        result = self.run_installer("--update")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.install / "VERSION").read_text(), "2\n")
        self.assertEqual((self.install / ".env").read_text(), "SECRET_KEY=keep\n")
        self.assertEqual(json.loads((self.install / "setup-args.json").read_text()), ["--start"])

    def test_update_refuses_local_edits_instead_of_discarding_them(self):
        self.publish_v2()
        (self.install / "VERSION").write_text("my edit\n")
        result = self.run_installer("--update")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("If you edited them", result.stderr)
        self.assertEqual((self.install / "VERSION").read_text(), "my edit\n")
        self.assertFalse((self.install / "setup-args.json").exists())

    def test_update_requires_an_existing_install(self):
        result = self.run_installer("--update", SCANR_INSTALL_DIR=str(Path(self.temp.name) / "nothing"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not a ScanR install", result.stderr)

        (self.install / ".env").unlink()
        result = self.run_installer("--update")
        self.assertIn("missing .env", result.stderr)

    def test_update_rejects_other_options(self):
        result = self.run_installer("--update", "--origin", "https://x.example")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("takes no other options", result.stderr)

    def test_fresh_install_into_existing_directory_points_to_update(self):
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--update", result.stderr)

    def test_docker_must_be_usable(self):
        result = self.run_installer("--update", DOCKER_TEST_EXIT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.install / "setup-args.json").exists())

    def test_help(self):
        result = self.run_installer("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--update", result.stdout)


if __name__ == "__main__":
    unittest.main()
