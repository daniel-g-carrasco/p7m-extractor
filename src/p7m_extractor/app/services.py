"""P7M Extractor's own instances of the services that know no app.

paths, log, errorlog, updates, minisign, win32, diagnostics (and i18n at
the root, atomic in data) are the shared modules: copies, byte for byte,
of the model's comune/ (app-template), listed with their fingerprints in
impronte/comune.json and held to them by tests/test_impronte.py. They are
never edited here: a change goes to the model and comes back with its
tools/impronte.py --apply. They take a name, an id, a version as
arguments, so that the same files serve every app of mine, GTK or Qt.
This is where they meet the names in the package's __init__
(tests/test_services.py)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from p7m_extractor import (
    EXE_NAME,
    GITHUB_REPO,
    PACKAGE_DIR,
    PUBLIC_KEY,
    SLUG,
    TEXTDOMAIN,
    WINDOWS,
    __version__,
    i18n,
)

from .paths import Paths

# the languages of po/, and the preference's value that follows the desktop
LANGUAGES = ("en", "it")
AUTOMATIC = "auto"


class Folders(Paths):
    """The shared folders, with P7M Extractor's files in them."""

    @property
    def config_file(self) -> Path:
        return self.config / "settings.ini"

    @property
    def trusted_lists(self) -> Path:
        # the European trusted lists, kept for the checks without the network
        return self.config / "trusted-lists"


def app_paths(environ=None) -> Folders:
    """Where P7M Extractor keeps its files: the folders of the releases
    before the shared ones, kept so that nobody's settings and lists are
    left behind. On Windows %LOCALAPPDATA%\\p7m-extractor (settings.ini
    and the trusted lists; state, data and cache in folders under it),
    elsewhere the XDG folders named by the slug (~/.config/p7m-extractor).
    The XDG variables still win on Windows, for the tests."""
    environ = os.environ if environ is None else environ
    if WINDOWS and not environ.get("XDG_CONFIG_HOME"):
        local = Path(environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / SLUG
        return Folders(config=local, state=local / "state", data=local / "data", cache=local / "cache")
    shared = Paths.from_env(SLUG, EXE_NAME, environ)
    return Folders(shared.config, shared.state, shared.data, shared.cache)


def project():
    """Whose releases an update comes from (updates.py is loaded only when
    asked: on Linux the Flatpak brings the updates)."""
    from .updates import Project
    return Project(repo=GITHUB_REPO, slug=SLUG, exe_name=EXE_NAME, version=__version__, public_key=PUBLIC_KEY)


def desktop_language() -> str:
    """The desktop's language among ours: the Windows display language, or
    the usual environment variables elsewhere. English when in doubt."""
    if sys.platform == "win32":
        try:
            import ctypes
            langid = ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF
            return "it" if langid == 0x10 else "en"
        except (AttributeError, OSError):
            return "en"
    for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(var)
        if value:
            return "it" if value.split(":")[0].lower().startswith("it") else "en"
    return "en"


def setup_language(choice: str = AUTOMATIC) -> str:
    """The catalogue for `choice` ("auto", "it" or "en"), and the language
    in use. Must run before any text the user sees is made."""
    language = choice if choice in LANGUAGES else desktop_language()
    if WINDOWS or choice in LANGUAGES:
        # GTK's own strings (the buttons of a dialog, the file chooser) come
        # from libintl, which reads LANGUAGE: kept in step with ours
        os.environ["LANGUAGE"] = language
    i18n.setup(TEXTDOMAIN, PACKAGE_DIR.parent.parent, language)
    return language
