"""The command line: files and folders extracted without a window, the
options, the update check printed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from p7m_extractor import __version__
from p7m_extractor.app.extract import extract_file, iter_p7m
from p7m_extractor.app.updates import UpdateError, fetch_latest_release, is_newer
from p7m_extractor.data.cms import BerError

from .i18n import _


def run_check_update() -> int:
    """`--check-update`: print the latest release. Exit 0 when GitHub answered
    (up to date or not), 3 when the network/TLS layer failed."""
    print(_("Installed version: {version}").format(version=__version__))
    try:
        rel = fetch_latest_release()
    except UpdateError as e:
        print(_("Update check failed: {error}").format(error=e), file=sys.stderr)
        return 0 if e.reached else 3
    if is_newer(rel["version"]):
        print(_("Available: {version}  ({url})").format(version=rel["version"], url=rel["url"]))
    else:
        print(_("Latest version: {version} (up to date)").format(version=rel["version"]))
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run_cli(paths, overwrite: bool) -> int:
    files = iter_p7m(paths)
    if not files:
        print(_("No .p7m files found."), file=sys.stderr)
        return 1
    n_ok = n_skip = n_err = 0
    for f in files:
        try:
            dest, layers = extract_file(f, overwrite)
            extra = ("  " + _("({n} nested signatures)").format(n=layers)) if layers > 1 else ""
            print(f"OK    {dest}{extra}")
            n_ok += 1
        except FileExistsError as e:
            print(_("SKIP  {file}  (already exists: {name}; use --overwrite)").format(
                file=f, name=Path(str(e)).name))
            n_skip += 1
        except (BerError, OSError) as e:
            print(f"ERR   {f}  ({e})", file=sys.stderr)
            n_err += 1
    print("\n" + _("Extracted: {ok}  Skipped: {skipped}  Errors: {errors}").format(
        ok=n_ok, skipped=n_skip, errors=n_err))
    return 0 if n_err == 0 else 1


def run_verify(paths, online: bool) -> int:
    """`--verify`: who signed each file and whether the signature holds,
    without extracting anything. Exit 0 when every signature of every file
    passed, 3 when something could not be established (or only the integrity
    was checked, without the network), 1 when a signature is wrong or a file
    could not be read."""
    from p7m_extractor.app import verify
    from p7m_extractor.app.settings import config_dir
    from p7m_extractor.core import verdict

    files = iter_p7m(paths)
    if not files:
        print(_("No .p7m files found."), file=sys.stderr)
        return 1
    if not verify.available():
        print(_("This build cannot verify signatures: the pyHanko library is missing."), file=sys.stderr)
        return 1
    lists = config_dir() / "trusted-lists"
    states = set()
    for f in files:
        print(f)
        try:
            layers = verify.verify_file(f, online=online, lists_folder=lists)
        except (BerError, OSError) as e:
            print(f"  ERR   {e}", file=sys.stderr)
            states.add(verdict.FAILED)
            continue
        title, outcome = verdict.headline(layers)
        print(f"  {title}: {outcome}")
        for depth, signers in enumerate(layers):            # each envelope a step further in
            pad = "  " * (depth + 1)
            print(f"{pad}{verdict.layer_caption(depth, len(layers))}")
            for signer in signers:
                for number, line in enumerate(verdict.lines(signer)):
                    print(f"{pad}  {'- ' if number == 0 else '  '}{line}")
        everyone = [signer for signers in layers for signer in signers]
        states.add(verdict.worst(everyone) if everyone else verdict.FAILED)
    print()
    print(_("Checked by this program, which is not a qualified validation service."))
    if not online:
        age = verify.lists_age(lists)
        print(_("Without the network: revocations were not checked.") + " " + (
            _("Trusted lists kept {days} days ago.").format(days=age.days) if age is not None
            else _("No trusted lists kept: certifiers were not looked up.")))
    if verdict.FAILED in states:
        return 1
    return 0 if states == {verdict.PASSED} else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="p7m-extractor",
        description=_("Extract the original document from .p7m (CAdES) signed files."),
        epilog=_("Without arguments the graphical interface (GTK 4) starts. "
                 "Examples: p7m-extractor invoice.xml.p7m | "
                 "p7m-extractor --overwrite folder/"),
    )
    parser.add_argument("paths", nargs="*", metavar=_("FILE_OR_FOLDER"),
                        help=_(".p7m files or folders to scan (recursive)"))
    parser.add_argument("--overwrite", action="store_true",
                        help=_("overwrite existing extracted files"))
    parser.add_argument("--verify", action="store_true",
                        help=_("check the signatures of the files and say who signed, instead of extracting"))
    parser.add_argument("--offline", action="store_true",
                        help=_("with --verify: do not use the network (integrity only, and the trusted lists kept)"))
    parser.add_argument("--gui", action="store_true",
                        help=_("force the graphical interface"))
    parser.add_argument("--check-update", action="store_true",
                        help=_("check whether a newer version exists and exit"))
    parser.add_argument("--register", action="store_true",
                        help=_("(Windows) register the app in File Explorer for "
                               "the current user and exit"))
    parser.add_argument("--unregister", action="store_true",
                        help=_("(Windows) remove the registration and exit"))
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser
