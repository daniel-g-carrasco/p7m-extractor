"""Shared test helpers: put src/ on sys.path, tell the platform. The test
modules start with `import _setup`.

This file is the app's own (it has no fingerprint). The common tests, the
copies of the model's comune/tests listed in impronte/comune.json, ask it
for ROOT, WINDOWS, PACKAGE and shared(name): they never name the package."""

import importlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

PACKAGE = "p7m_extractor"
WINDOWS = sys.platform == "win32"


def shared(name: str):
    """The shared module of that name ("i18n", "app.updates"), as the
    common tests ask for it: p7m_extractor.<name>."""
    return importlib.import_module(f"{PACKAGE}.{name}")


# No test writes in the user's own folders (tests/_userfolders.py, a copy of
# the model's). They are watched as the environment names them now, before
# anything changes it: a run that writes next to the installed P7M
# Extractor's own files (its settings.ini, its trusted lists) fails at its
# exit. Then the tests get folders of their own: the four XDG variables
# (config, state, data, cache) point into one temporary folder, removed at
# the exit (app/services.py lets them win on Windows too). The guard looks
# at folders, not at Windows' registry: no test of this app writes there
# (app/windows_shell.py, which does, is never called by a test).
import _userfolders

from p7m_extractor import EXE_NAME, SLUG

_userfolders.watch(SLUG, EXE_NAME)
_userfolders.isolate()

os.environ.setdefault("LANGUAGE", "en")        # the tests read the source strings
def gtk_or_skip():
    """GTK 4 and libadwaita with a display, or unittest.SkipTest: the
    dialog tests run where they can (the CI's xvfb job, Windows), and say
    why not elsewhere. GTK sets the user's locale on init: it is put back,
    so that the other tests read numbers as in C."""
    import locale
    import unittest
    before = locale.setlocale(locale.LC_ALL)
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw, Gdk, Gtk
    except (ImportError, ValueError):
        raise unittest.SkipTest("GTK 4 and libadwaita") from None
    initialised = Gtk.init_check()
    locale.setlocale(locale.LC_ALL, before)
    if not initialised or Gdk.Display.get_default() is None:
        raise unittest.SkipTest("no display")
    Adw.init()
    return Gtk, Adw
