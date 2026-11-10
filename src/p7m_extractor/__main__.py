"""Entry point: the command line when files are given, the window otherwise."""

from __future__ import annotations

import os
import sys

from p7m_extractor.app.settings import Settings
from p7m_extractor.app.windows_shell import win_register, win_unregister

from . import _mark
from .cli import build_parser, run_check_update, run_cli
from .i18n import _, setup_i18n


def main() -> int:
    _mark("main")
    # PyInstaller --windowed builds have no console streams.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")

    settings = Settings()
    setup_i18n(settings.get("language"))
    args = build_parser().parse_args()

    if args.check_update:
        return run_check_update()
    if args.register or args.unregister:
        if sys.platform != "win32":
            print(_("Option available on Windows only."), file=sys.stderr)
            return 2
        if args.register:
            win_register()
            print(_("File Explorer integration registered for the current user."))
        else:
            win_unregister()
            print(_("File Explorer integration removed for the current user."))
        return 0
    if args.paths and not args.gui:
        return run_cli(args.paths, args.overwrite)
    from p7m_extractor.gui.application import run_gui       # the toolkit, only when a window is wanted
    return run_gui(sys.argv, settings)


if __name__ == "__main__":
    sys.exit(main())
