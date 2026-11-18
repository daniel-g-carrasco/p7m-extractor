#!/usr/bin/env python3
"""P7M Extractor's own instances of the shared services (app/services.py)
and its identity: the project the updates come from, the key the releases
are signed with and the CI checks, the folders (the ones of the releases
before the shared modules), the language. The shared modules themselves
are tested by the common tests (test_updates, test_minisign, test_paths,
test_i18n), with made-up names: what is this app's is tested here."""

import os
import io
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import _setup
from test_minisign import PAYLOAD, SIGNED_V9, digest_of

from p7m_extractor import EXE_NAME, GITHUB_REPO, PUBLIC_KEY, SLUG, __version__, cli
from p7m_extractor.app import (
    diagnostics,
    errorlog,
    minisign,
    services,
    settings,
    updates,
)
from p7m_extractor.data import atomic


def absolute(name: str) -> str:
    """An absolute folder: the XDG variables are taken only when absolute."""
    return rf"C:\{name}" if _setup.WINDOWS else f"/{name}"


class ProjectTest(unittest.TestCase):
    def test_the_updates_come_from_this_apps_releases(self):
        project = services.project()
        self.assertEqual((project.repo, project.slug, project.exe_name, project.version, project.public_key),
                         (GITHUB_REPO, SLUG, EXE_NAME, __version__, PUBLIC_KEY))
        self.assertEqual(project.latest_release_api,
                         "https://api.github.com/repos/daniel-g-carrasco/p7m-extractor/releases/latest")
        self.assertEqual(project.downloads, "https://github.com/daniel-g-carrasco/p7m-extractor/releases/download/")

    def test_the_installer_is_known_by_the_name_the_release_gives_it(self):
        # the name installer/p7m-extractor.iss gives it (OutputBaseFilename)
        project = services.project()
        name = project.installer_name("v1.5.0")
        self.assertEqual(name, "p7m-extractor-setup-v1.5.0-windows-x64.exe")
        self.assertTrue(project.is_installer(name))
        self.assertFalse(project.is_installer("p7m-extractor-setup-vdev-windows-x64.exe"))     # a CI build
        iss = (_setup.ROOT / "installer" / "p7m-extractor.iss").read_text(encoding="utf-8")
        self.assertIn("OutputBaseFilename=p7m-extractor-setup-v{#AppVersion}-windows-x64", iss)

    def test_the_requests_say_who_asks_as_before(self):
        self.assertEqual(f"{services.project().exe_name}/{__version__}", f"p7m-extractor/{__version__}")


class KeyTest(unittest.TestCase):
    def test_the_ci_checks_its_signatures_with_the_key_the_app_trusts(self):
        workflow = (_setup.ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
        self.assertIn(f"PUBLIC_KEY: {PUBLIC_KEY}\n", workflow)

    def test_the_apps_key_is_not_the_one_the_tests_sign_with(self):
        with self.assertRaisesRegex(minisign.SignatureError, "another key"):
            minisign.verify(digest_of(PAYLOAD), SIGNED_V9, PUBLIC_KEY)


class FoldersTest(unittest.TestCase):
    def test_the_xdg_folders_are_named_by_the_slug(self):
        paths = services.app_paths({"XDG_CONFIG_HOME": absolute("c"), "XDG_STATE_HOME": absolute("s"),
                                    "XDG_DATA_HOME": absolute("d"), "HOME": absolute("h")})
        self.assertEqual((paths.config, paths.state, paths.data),
                         (Path(absolute("c")) / SLUG, Path(absolute("s")) / SLUG, Path(absolute("d")) / SLUG))
        self.assertEqual(paths.config_file, Path(absolute("c")) / SLUG / "settings.ini")
        self.assertEqual(paths.trusted_lists, Path(absolute("c")) / SLUG / "trusted-lists")

    @unittest.skipUnless(_setup.WINDOWS, "Windows only")
    def test_on_windows_the_settings_and_the_lists_stay_where_they_were(self):
        # %LOCALAPPDATA%\p7m-extractor, as the releases up to 1.4.0 kept them
        local = r"C:\U\me\AppData\Local"
        paths = services.app_paths({"APPDATA": r"C:\U\me\AppData\Roaming", "LOCALAPPDATA": local})
        self.assertEqual(paths.config_file, Path(local) / "p7m-extractor" / "settings.ini")
        self.assertEqual(paths.trusted_lists, Path(local) / "p7m-extractor" / "trusted-lists")
        self.assertEqual(paths.state, Path(local) / "p7m-extractor" / "state")

    def test_the_tests_folders_are_not_the_users(self):
        # tests/_setup.py points the XDG variables into a temporary folder:
        # the settings the tests write are never the installed app's
        paths = services.app_paths()
        self.assertTrue(paths.config.is_relative_to(Path(os.environ["XDG_CONFIG_HOME"])))
        self.assertTrue(paths.state.is_relative_to(Path(os.environ["XDG_STATE_HOME"])))
        if _setup.WINDOWS:
            self.assertNotEqual(paths.config, Path(os.environ["LOCALAPPDATA"]) / SLUG)


class ReportTest(unittest.TestCase):
    def test_the_report_names_settings_ini_and_the_errors_file(self):
        # what the About window's Troubleshooting shows (gui: _debug_info)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = services.Folders(root / "config", root / "state", root / "data")
            prefs = diagnostics.Preferences(theme="auto", language="it", check_updates=True)
            lines = diagnostics.summary("P7M Extractor", __version__, prefs, paths, "GTK").splitlines()
            self.assertIn(f"settings: {root / 'config' / 'settings.ini'}", lines)
            self.assertIn(f"errors: {errorlog.log_file(root / 'state')} (none)", lines)
            self.assertFalse(os.listdir(root))          # a report only reads


class SettingsTest(unittest.TestCase):
    @unittest.skipUnless(_setup.WINDOWS, "Windows only")
    def test_existing_local_ini_and_lists_are_authoritative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local, roaming = root / "Local", root / "Roaming"
            paths = services.app_paths({"LOCALAPPDATA": str(local), "APPDATA": str(roaming)})
            paths.trusted_lists.mkdir(parents=True)
            kept = paths.trusted_lists / "synthetic.xml"
            kept.write_bytes(b"synthetic trust list")
            paths.config_file.write_text(
                "[general]\nlanguage = it\nverify_signatures = false\nfuture_key = kept\n"
                "[future_section]\nfield = kept\n", encoding="utf-8")
            other = roaming / SLUG / "settings.ini"
            other.parent.mkdir(parents=True)
            other.write_text("[general]\nlanguage = en\n", encoding="utf-8")
            existing = settings.Settings(paths.config_file)
            self.assertEqual(existing.get("language"), "it")
            self.assertFalse(existing.get_bool("verify_signatures"))
            existing.set("color_scheme", "dark")
            saved = paths.config_file.read_text(encoding="utf-8")
            self.assertIn("future_key = kept", saved)
            self.assertIn("[future_section]\nfield = kept", saved)
            self.assertEqual(kept.read_bytes(), b"synthetic trust list")
            self.assertEqual(other.read_text(encoding="utf-8"), "[general]\nlanguage = en\n")

    def test_saved_whole_and_read_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = Path(tmp) / "config" / "settings.ini"
            settings.Settings(ini).set("language", "it")
            self.assertEqual(settings.Settings(ini).get("language"), "it")
            self.assertEqual(os.listdir(ini.parent), ["settings.ini"])      # no temporary file left

    def test_a_refused_rename_is_tried_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            ini = Path(tmp) / "settings.ini"
            real, calls = os.replace, []

            def busy_once(src, dst):
                calls.append(dst)
                if len(calls) == 1:
                    raise PermissionError(13, "held by the indexer")
                real(src, dst)
            with mock.patch.object(atomic.os, "replace", busy_once), mock.patch.object(atomic.time, "sleep"):
                settings.Settings(ini).set("ask_default_app", False)
            self.assertFalse(settings.Settings(ini).get_bool("ask_default_app"))
            self.assertEqual(len(calls), 2)


class LanguageTest(unittest.TestCase):
    def test_the_desktop_language_is_one_of_ours(self):
        self.assertIn(services.desktop_language(), services.LANGUAGES)

    def test_every_language_of_po_is_offered(self):
        catalogues = sorted(p.stem for p in (_setup.ROOT / "po").glob("*.po"))
        self.assertEqual(sorted(set(services.LANGUAGES) - {"en"}), catalogues)


class CheckUpdateTest(unittest.TestCase):
    """--check-update: 0 when GitHub answered, 3 when the network failed."""

    def outcome(self, *, response=None, error=None):
        with mock.patch.object(updates.urllib.request, "urlopen",
                               return_value=response, side_effect=error), \
                mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            return cli.run_check_update()

    def test_an_answer_of_github_is_not_a_failure_of_the_network(self):
        for status in (403, 404, 429):
            with self.subTest(status=status):
                http = urllib.error.HTTPError("https://api.github.com", status, "error", None, None)
                self.assertEqual(self.outcome(error=http), 0)
        for payload in (b"{", b"{}", b'{"tag_name": "v9.1.2"}'):
            self.assertEqual(self.outcome(response=io.BytesIO(payload)), 0)

    def test_the_network_failing_is(self):
        self.assertEqual(self.outcome(error=urllib.error.URLError("no route")), 3)
        self.assertEqual(self.outcome(error=TimeoutError("timed out")), 3)


if __name__ == "__main__":
    unittest.main()
