"""P7M Extractor: extract the original document from CAdES (.p7m) signed files.

A .p7m file is a PKCS#7/CMS SignedData envelope wrapping the original
document (PDF, XML, ...). This tool parses the BER/DER structure directly
with no external dependencies and writes the embedded content out,
byte-for-byte identical to what was signed.

Run with file/folder arguments for CLI mode, or without arguments for the
GTK 4 GUI. Signature *validation* (certificate chains, revocation, legal
value) is out of scope: use a qualified verification service for that.

The package is in four layers, and the imports go one way only (tests/
test_strati.py holds them to it): core/ works things out and data/ reads
formats, both plain Python that know nobody; app/ is the services without
a window (extraction of a file, settings, updates, Windows' registry) and
joins the two; gui/ is the window, the one place GTK comes in.

The constants below are the one place the app's identity lives, with the
names every app of mine has (the model's): the modules shared with the
other apps get them as arguments, from app/services.py.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

__version__ = "1.5.0"

WINDOWS = sys.platform == "win32"

APP_ID = "io.github.daniel_g_carrasco.p7m-extractor"
APP_NAME = "P7M Extractor"
SLUG = "p7m-extractor"              # the repository, the binary on Linux, the folders, a release's files
EXE_NAME = "p7m-extractor"          # the Windows executable (p7m-extractor.exe)
TEXTDOMAIN = SLUG
ENV_PREFIX = "P7M"                  # the developer aids: P7M_STARTUP_LOG and the like
GITHUB_REPO = "daniel-g-carrasco/p7m-extractor"
WEBSITE = f"https://github.com/{GITHUB_REPO}"
RELEASES_URL = f"https://github.com/{GITHUB_REPO}/releases"
DOWNLOADS_URL = f"https://github.com/{GITHUB_REPO}/releases/download/"
LATEST_RELEASE_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
# The releases' signing key (minisign, key id CEFFF9269F08F845, the one
# shared by the author's apps); its secret half is the CI's
# MINISIGN_SECRET_KEY (a test checks that the CI verifies its signatures
# with this very key)
PUBLIC_KEY = "RWRF+AifJvn/zhz0o7MBObIYHgw9+sWoc4GaBK+qYnJY0AqeJm540y0a"

# Windows shell integration identifiers (see the "Windows" section below and
# installer/p7m-extractor.iss, which must stay in sync with these).
PROGID = "P7MExtractor.p7m"
WIN_VERB = "P7MExtractor.extract"

# the one anchor for files found from the code's own place (a checkout's
# data/, locale/, bin/): never a chain of .parent in a module, which a move breaks
PACKAGE_DIR = Path(__file__).resolve().parent


def _mark(label: str) -> None:
    """Start-up profiling aid: append a timestamp to $P7M_STARTUP_LOG."""
    path = os.environ.get("P7M_STARTUP_LOG")
    if path:
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"{time.time():.3f} {label}\n")
        except OSError:
            pass
