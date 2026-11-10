"""Windows: the .p7m association, the context menu and "set as default",
in the per-user registry.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from p7m_extractor import APP_NAME, PACKAGE_DIR, PROGID, WIN_VERB
from p7m_extractor.i18n import _

from .updates import is_frozen

# The installer writes the same keys (HKLM when installed for all users);
# these functions cover the portable build and the in-app "set as default".
_USERCHOICE = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.p7m\UserChoice"


def _launch_command() -> str:
    """Command line that opens files with this program (registry format)."""
    if is_frozen():
        return f'"{sys.executable}" --gui "%1"'
    launcher = PACKAGE_DIR.parent.parent / "bin" / "p7m-extractor"       # a run from the sources
    return f'"{sys.executable}" "{launcher}" --gui "%1"'


def _shell_notify() -> None:
    try:
        import ctypes
        # SHCNE_ASSOCCHANGED, SHCNF_IDLIST
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
    except (AttributeError, OSError):
        pass


def _reg_delete_tree(root, path: str) -> None:
    import winreg
    try:
        with winreg.OpenKey(root, path) as k:
            subs = []
            while True:
                try:
                    subs.append(winreg.EnumKey(k, len(subs)))
                except OSError:
                    break
    except FileNotFoundError:
        return
    for sub in subs:
        _reg_delete_tree(root, f"{path}\\{sub}")
    try:
        winreg.DeleteKey(root, path)
    except FileNotFoundError:
        pass


def win_register() -> None:
    """Register the ProgID, the "Open with" entry, the context-menu verb and
    the Default Programs capabilities under HKEY_CURRENT_USER."""
    import winreg
    hkcu = winreg.HKEY_CURRENT_USER
    cmd = _launch_command()
    icon = f"{sys.executable},0" if is_frozen() else ""

    def put(path, value="", name=""):
        with winreg.CreateKey(hkcu, path) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)

    classes = r"Software\Classes"
    # ProgID: what a .p7m is and how to open it
    put(rf"{classes}\{PROGID}", _("Digitally signed document (P7M)"))
    if icon:
        put(rf"{classes}\{PROGID}\DefaultIcon", icon)
    put(rf"{classes}\{PROGID}\shell\open", _("Extract with P7M Extractor"))
    put(rf"{classes}\{PROGID}\shell\open\command", cmd)
    # offer the ProgID in the "Open with" list for .p7m
    put(rf"{classes}\.p7m\OpenWithProgids", "", PROGID)
    # context-menu verb: shown on every .p7m whatever the default app is
    verb = rf"{classes}\SystemFileAssociations\.p7m\shell\{WIN_VERB}"
    put(verb, _("Extract content with P7M Extractor"))
    if icon:
        put(verb, icon, "Icon")
    put(verb, "Player", "MultiSelectModel")  # no 15-files prompt on multi-select
    put(rf"{verb}\command", cmd)
    # Default Programs registration (Settings > Apps > Default apps)
    caps = rf"Software\{APP_NAME}\Capabilities"
    put(caps, APP_NAME, "ApplicationName")
    put(caps, _("Extracts the original document from signed .p7m files"),
        "ApplicationDescription")
    put(rf"{caps}\FileAssociations", PROGID, ".p7m")
    put(r"Software\RegisteredApplications", caps, APP_NAME)
    if is_frozen():  # friendly name in "Open with" when picked by exe
        app = rf"{classes}\Applications\{Path(sys.executable).name}"
        put(app, APP_NAME, "FriendlyAppName")
        put(rf"{app}\SupportedTypes", "", ".p7m")
        put(rf"{app}\shell\open\command", cmd)
    _shell_notify()


def win_unregister() -> None:
    """Remove everything win_register() wrote (current user only)."""
    import winreg
    hkcu = winreg.HKEY_CURRENT_USER
    classes = r"Software\Classes"
    _reg_delete_tree(hkcu, rf"{classes}\{PROGID}")
    _reg_delete_tree(hkcu, rf"{classes}\SystemFileAssociations\.p7m\shell\{WIN_VERB}")
    _reg_delete_tree(hkcu, rf"Software\{APP_NAME}")
    if is_frozen():
        _reg_delete_tree(hkcu, rf"{classes}\Applications\{Path(sys.executable).name}")
    for path, name in ((rf"{classes}\.p7m\OpenWithProgids", PROGID),
                       (r"Software\RegisteredApplications", APP_NAME)):
        try:
            with winreg.OpenKey(hkcu, path, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, name)
        except OSError:
            pass
    try:  # release the per-user extension default if it points at us
        with winreg.OpenKey(hkcu, rf"{classes}\.p7m", 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
            if winreg.QueryValueEx(k, "")[0] == PROGID:
                winreg.DeleteValue(k, "")
    except OSError:
        pass
    _shell_notify()


def win_current_handler() -> str | None:
    """ProgID currently opening .p7m files (the user's explicit choice wins)."""
    import winreg
    for root, path, name in ((winreg.HKEY_CURRENT_USER, _USERCHOICE, "ProgId"),
                             (winreg.HKEY_CLASSES_ROOT, ".p7m", "")):
        try:
            with winreg.OpenKey(root, path) as k:
                value = winreg.QueryValueEx(k, name)[0]
            if value:
                return str(value)
        except OSError:
            continue
    return None


def win_is_default() -> bool:
    try:
        handler = (win_current_handler() or "").lower()
    except OSError:
        return False
    if handler == PROGID.lower():
        return True
    return is_frozen() and handler == f"applications\\{Path(sys.executable).name.lower()}"


def win_make_default() -> str:
    """Try to become the .p7m handler. Return "done" when settled, or
    "settings" when Windows Settings was opened for the user to confirm."""
    import winreg
    from urllib.parse import quote
    win_register()
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_CURRENT_USER, _USERCHOICE))
        user_choice = True
    except OSError:
        user_choice = False
    if not user_choice:
        # No explicit (hash-protected) user choice yet: the per-user class
        # default is enough to win the association.
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.p7m") as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, PROGID)
        _shell_notify()
        if win_is_default():
            return "done"
    # Since Windows 10 only the user can change a protected default, through
    # Settings. This deep link lands on our app's page (Windows 11) or on the
    # Default apps page (Windows 10).
    os.startfile(f"ms-settings:defaultapps?registeredAppUser={quote(APP_NAME)}")
    return "settings"
