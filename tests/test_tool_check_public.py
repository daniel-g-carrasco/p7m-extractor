# SPDX-License-Identifier: GPL-3.0-or-later
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "check_public.py"
spec = importlib.util.spec_from_file_location("check_public", TOOL)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class PublicSnapshot(unittest.TestCase):
    def test_rules(self):
        for text in ("C:" + r"\Users\demo", "C:" + r"\\Users\\demo", "/home/" + "demo",
                     "/var/" + "home/", "I:" + "\\", "person@" + "somewhere.dev",
                     "API_TOKEN=" + "abc123xyz", "postgres://" + "person:abc123xyz@localhost/db",
                     "ghp_" + "a" * 36, "AKIA" + "A" * 16,
                     "-----BEGIN " + "OPENSSH PRIVATE KEY-----", 'password = "' + "Q9abc789" + '"'):
            with self.subTest(text=text):
                self.assertIsNotNone(checker.category(text, set()))
        self.assertIsNone(checker.category("test@example.org", set()))

    @unittest.skipUnless(shutil.which("git"), "git is not installed here (MSYS2 without git)")
    def test_index_and_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            def git(*args):
                subprocess.run(["git", *args], cwd=tmp, check=True, capture_output=True)

            def scan():
                return subprocess.run([sys.executable, TOOL], cwd=tmp, capture_output=True, text=True, check=False)

            git("init")
            secret = "ghp_" + "a" * 36
            file = Path(tmp, "note")
            file.write_bytes(secret.encode("utf-16"))
            git("add", "note")
            file.write_text("clean", encoding="utf-8")
            result = scan()
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("possible credential", result.stdout)
            self.assertNotIn(secret, result.stdout)
            git("add", "note")
            self.assertEqual(scan().returncode, 0)
