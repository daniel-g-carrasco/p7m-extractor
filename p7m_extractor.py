#!/usr/bin/env python3
"""P7M Extractor — extract the original document from CAdES (.p7m) signed files.

A .p7m file is a PKCS#7/CMS SignedData envelope wrapping the original
document (PDF, XML, ...). This tool parses the BER/DER structure directly
with no external dependencies and writes the embedded content out,
byte-for-byte identical to what was signed.

Run with file/folder arguments for CLI mode, or without arguments for the
GTK 4 GUI. Signature *validation* (certificate chains, revocation, legal
value) is out of scope: use a qualified verification service for that.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import configparser
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

__version__ = "1.2.0"

APP_ID = "com.danielgrasso.P7mExtractor"
APP_NAME = "P7M Extractor"
GITHUB_REPO = "daniel-g-carrasco/p7m-extractor"
RELEASES_URL = f"https://github.com/{GITHUB_REPO}/releases"
LATEST_RELEASE_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

# Windows shell integration identifiers (see the "Windows" section below and
# installer/p7m-extractor.iss, which must stay in sync with these).
PROGID = "P7MExtractor.p7m"
WIN_VERB = "P7MExtractor.extract"

# ---------------------------------------------------------------------------
# BER/DER parsing (pure stdlib)
# ---------------------------------------------------------------------------

OID_SIGNED_DATA = bytes.fromhex("2A864886F70D010702")  # 1.2.840.113549.1.7.2
OID_DATA = bytes.fromhex("2A864886F70D010701")         # 1.2.840.113549.1.7.1


class BerError(ValueError):
    """Raised when the input is not a (supported) PKCS#7 SignedData blob."""


def _read_header(data: bytes, i: int):
    """Parse a BER TLV header. Return (tag, constructed, length, content_start).

    length is None for indefinite-length encodings (BER streaming).
    """
    tag = data[i]
    constructed = bool(tag & 0x20)
    i += 1
    if tag & 0x1F == 0x1F:  # high tag number form
        while data[i] & 0x80:
            i += 1
        i += 1
    length = data[i]
    i += 1
    if length == 0x80:
        if not constructed:
            raise BerError("indefinite length on a primitive element")
        return tag, constructed, None, i
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 8:
            raise BerError("unsupported length-of-length")
        length = int.from_bytes(data[i:i + n], "big")
        i += n
    return tag, constructed, length, i


def _end_of(data: bytes, i: int) -> int:
    """Index just past the TLV starting at i (EOC included if indefinite)."""
    _tag, _cons, length, cs = _read_header(data, i)
    if length is not None:
        return cs + length
    j = cs
    while data[j:j + 2] != b"\x00\x00":
        j = _end_of(data, j)
    return j + 2


def _node(data: bytes, i: int):
    """Return (tag, constructed, content_start, content_end, next_index)."""
    tag, cons, length, cs = _read_header(data, i)
    nxt = _end_of(data, i)
    ce = cs + length if length is not None else nxt - 2
    return tag, cons, cs, ce, nxt


def _children(data: bytes, start: int, end: int):
    i = start
    while i < end:
        node = _node(data, i)
        yield node
        i = node[4]


def _collect_octets(data: bytes, start: int, end: int, out: list) -> None:
    """Concatenate every OCTET STRING found under [start, end)."""
    for tag, cons, cs, ce, _nxt in _children(data, start, end):
        if tag & 0xDF == 0x04:  # OCTET STRING, primitive (0x04) or constructed (0x24)
            if cons:
                _collect_octets(data, cs, ce, out)
            else:
                out.append(data[cs:ce])
        else:
            raise BerError(f"unexpected element {tag:#04x} inside eContent")


def extract_econtent(der: bytes) -> bytes:
    """Return the encapsulated content of a BER/DER PKCS#7 SignedData blob."""
    try:
        tag, cons, cs, ce, _ = _node(der, 0)
        if tag != 0x30 or not cons:
            raise BerError("not a PKCS#7/CMS structure")
        kids = list(_children(der, cs, ce))
        if not kids or kids[0][0] != 0x06:
            raise BerError("missing content-type OID")
        ctype = der[kids[0][2]:kids[0][3]]
        if ctype != OID_SIGNED_DATA:
            raise BerError("not a signedData envelope")
        wrapper = next((k for k in kids if k[0] == 0xA0), None)
        if wrapper is None:
            raise BerError("missing signedData body")
        sd = _node(der, wrapper[2])
        if sd[0] != 0x30:
            raise BerError("malformed SignedData")
        # SignedData children: INTEGER version, SET digestAlgorithms,
        # SEQUENCE encapContentInfo, [certificates], [crls], SET signerInfos.
        enc = next((k for k in _children(der, sd[2], sd[3]) if k[0] == 0x30), None)
        if enc is None:
            raise BerError("missing encapContentInfo")
        e0 = next((k for k in _children(der, enc[2], enc[3]) if k[0] == 0xA0), None)
        if e0 is None:
            raise BerError("detached signature: the signed content is not embedded")
        out: list = []
        _collect_octets(der, e0[2], e0[3], out)
        content = b"".join(out)
        if not content:
            raise BerError("empty signed content")
        return content
    except IndexError:
        raise BerError("truncated structure") from None
    except RecursionError:
        raise BerError("structure nested too deeply") from None


_B64_RE = re.compile(rb"[A-Za-z0-9+/=]+\Z")


def decode_container(raw: bytes) -> bytes:
    """Return DER/BER bytes from raw file content (handles PEM and bare base64)."""
    s = raw.lstrip()
    if s.startswith(b"-----BEGIN"):
        body = b"".join(
            line.strip() for line in s.splitlines()
            if line.strip() and not line.strip().startswith(b"-----")
        )
        try:
            return base64.b64decode(body, validate=True)
        except binascii.Error as e:
            raise BerError(f"invalid PEM base64: {e}") from None
    if raw[:1] == b"\x30":
        return raw
    compact = b"".join(raw.split())
    if compact[:2] == b"MI" and _B64_RE.fullmatch(compact):
        # DER starts with 0x30 0x8x, which is "MI..." once base64-encoded.
        try:
            return base64.b64decode(compact, validate=True)
        except binascii.Error:
            pass
    return raw


# ---------------------------------------------------------------------------
# File-level operations
# ---------------------------------------------------------------------------


def _strip_p7m(name: str) -> str:
    return name[:-4] if name.lower().endswith(".p7m") and len(name) > 4 else name + ".out"


def extract_file(src: Path, overwrite: bool = False) -> tuple[Path, int]:
    """Extract src next to itself. Return (dest, signature_layers).

    Nested envelopes (file.pdf.p7m.p7m) are unwrapped in a single pass.
    Raises FileExistsError when dest exists and overwrite is False,
    BerError for unsupported/corrupt input, OSError on I/O problems.
    """
    src = Path(src)
    content = extract_econtent(decode_container(src.read_bytes()))
    name = _strip_p7m(src.name)
    layers = 1
    while True:
        try:
            content = extract_econtent(decode_container(content))
        except BerError:
            break
        layers += 1
        name = _strip_p7m(name)
    dest = src.with_name(name)
    if dest.exists() and not overwrite:
        raise FileExistsError(str(dest))
    dest.write_bytes(content)
    return dest, layers


def iter_p7m(paths) -> list[Path]:
    """Expand files/folders into a flat list of .p7m files (folders: recursive)."""
    found: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            found.extend(sorted(
                x for x in p.rglob("*")
                if x.is_file() and x.suffix.lower() == ".p7m"
            ))
        elif p.is_file():
            found.append(p)
    return found


# ---------------------------------------------------------------------------
# Preferences (INI file in the per-user configuration directory)
# ---------------------------------------------------------------------------


def config_dir() -> Path:
    """Per-user configuration directory, following platform conventions:
    $XDG_CONFIG_HOME on Linux (Flatpak points it inside the sandbox),
    %LOCALAPPDATA% on Windows."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "p7m-extractor"


class Settings:
    """Tiny persistent key/value store (settings.ini). No file means defaults."""

    DEFAULTS = {
        "ask_default_app": "true",   # Windows: offer to become the .p7m handler
        "check_updates": "true",     # Windows: look for a new release daily
        "last_update_check": "",     # ISO date of the last automatic check
    }

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else config_dir() / "settings.ini"
        self._cp = configparser.ConfigParser()
        self._cp["general"] = dict(self.DEFAULTS)
        try:
            self._cp.read(self.path, encoding="utf-8")
        except (OSError, configparser.Error):
            pass

    def get(self, key: str) -> str:
        return self._cp["general"].get(key, self.DEFAULTS.get(key, ""))

    def get_bool(self, key: str) -> bool:
        return self.get(key).strip().lower() in ("1", "true", "yes", "on")

    def set(self, key: str, value) -> None:
        if isinstance(value, bool):
            value = "true" if value else "false"
        self._cp["general"][key] = str(value)
        self.save()

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                self._cp.write(f)
        except OSError:
            pass  # preferences are a convenience, never fatal


# ---------------------------------------------------------------------------
# Update check (GitHub Releases API, stdlib only)
#
# Used by the Windows builds only: on Linux updates come from the package
# manager / Flatpak (GNOME Software), as the platform conventions require.
# ---------------------------------------------------------------------------


class UpdateError(Exception):
    """Problem while talking to GitHub. `reached` tells whether the server
    answered at all (HTTP error) or the network/TLS layer failed."""

    def __init__(self, message: str, reached: bool = False):
        super().__init__(message)
        self.reached = reached


def parse_version(text: str) -> tuple[int, ...]:
    """'v1.2.0' -> (1, 2, 0). Non-numeric components count as 0."""
    parts = []
    for piece in text.strip().lstrip("vV").split("."):
        m = re.match(r"\d+", piece)
        parts.append(int(m.group()) if m else 0)
    return tuple(parts)


def is_newer(candidate: str, current: str = __version__) -> bool:
    a, b = parse_version(candidate), parse_version(current)
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) > b + (0,) * (n - len(b))


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def is_installed_build() -> bool:
    """True for the Inno Setup installation (uninstaller next to the exe),
    False for the portable zip and for source checkouts."""
    return (sys.platform == "win32" and is_frozen()
            and (Path(sys.executable).parent / "unins000.exe").is_file())


def pick_asset(assets, installed: bool):
    """Choose the release asset matching this build: installer or portable zip."""
    pattern = (r"^p7m-extractor-setup-.*-windows-x64\.exe$" if installed
               else r"^p7m-extractor-.*-windows-x64-portable\.zip$")
    for a in assets:
        if re.match(pattern, a.get("name", ""), re.IGNORECASE):
            return a
    return None


def _ssl_context():
    import ssl
    ctx = ssl.create_default_context()
    # The frozen Windows build ships a CA bundle: MSYS2's OpenSSL cannot
    # always see the Windows certificate store.
    bundled = Path(getattr(sys, "_MEIPASS", "")) / "certs" / "ca-bundle.crt"
    if bundled.is_file():
        try:
            ctx.load_verify_locations(cafile=str(bundled))
        except (ssl.SSLError, OSError):
            pass
    return ctx


def _http_get(url: str, timeout: float = 15.0):
    req = urllib.request.Request(url, headers={
        "User-Agent": f"p7m-extractor/{__version__}",
        "Accept": "application/vnd.github+json",
    })
    return urllib.request.urlopen(req, timeout=timeout, context=_ssl_context())


def fetch_latest_release(timeout: float = 15.0) -> dict:
    """Return {"version", "tag", "url", "notes", "assets": [{"name", "url", "size"}]}."""
    try:
        with _http_get(LATEST_RELEASE_API, timeout) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        raise UpdateError(f"GitHub ha risposto {e.code}", reached=True) from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise UpdateError(str(getattr(e, "reason", e))) from None
    tag = str(data.get("tag_name") or "")
    if not tag:
        raise UpdateError("risposta inattesa dal server", reached=True)
    return {
        "version": tag.lstrip("vV"),
        "tag": tag,
        "url": data.get("html_url") or RELEASES_URL,
        "notes": data.get("body") or "",
        "assets": [
            {"name": a.get("name", ""), "url": a.get("browser_download_url", ""),
             "size": int(a.get("size") or 0)}
            for a in data.get("assets", [])
        ],
    }


def download_file(url: str, dest: Path, progress=None, cancelled=None) -> Path:
    """Download url to dest. progress(done, total) is called along the way;
    cancelled is an optional threading.Event."""
    dest = Path(dest)
    tmp = dest.with_name(dest.name + ".part")
    try:
        with _http_get(url, timeout=30) as resp, open(tmp, "wb") as out:
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            while True:
                if cancelled is not None and cancelled.is_set():
                    raise UpdateError("annullato", reached=True)
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
        tmp.replace(dest)
        return dest
    except urllib.error.HTTPError as e:
        raise UpdateError(f"download fallito ({e.code})", reached=True) from None
    except (urllib.error.URLError, OSError) as e:
        raise UpdateError(str(getattr(e, "reason", e))) from None
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def run_check_update() -> int:
    """`--check-update`: print the latest release. Exit 0 when GitHub answered
    (up to date or not), 3 when the network/TLS layer failed."""
    print(f"Versione installata: {__version__}")
    try:
        rel = fetch_latest_release()
    except UpdateError as e:
        print(f"Controllo aggiornamenti non riuscito: {e}", file=sys.stderr)
        return 0 if e.reached else 3
    if is_newer(rel["version"]):
        print(f"Disponibile: {rel['version']}  ({rel['url']})")
    else:
        print(f"Ultima versione: {rel['version']} (aggiornato)")
    return 0


# ---------------------------------------------------------------------------
# Windows shell integration (per-user registry, no admin rights)
#
# The installer writes the same keys (HKLM when installed for all users);
# these functions cover the portable build and the in-app "set as default".
# ---------------------------------------------------------------------------

_USERCHOICE = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.p7m\UserChoice"


def _launch_command() -> str:
    """Command line that opens files with this program (registry format)."""
    if is_frozen():
        return f'"{sys.executable}" --gui "%1"'
    return f'"{sys.executable}" "{Path(__file__).resolve()}" --gui "%1"'


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
    put(rf"{classes}\{PROGID}", "Documento firmato digitalmente (P7M)")
    if icon:
        put(rf"{classes}\{PROGID}\DefaultIcon", icon)
    put(rf"{classes}\{PROGID}\shell\open", "Estrai con P7M Extractor")
    put(rf"{classes}\{PROGID}\shell\open\command", cmd)
    # offer the ProgID in the "Open with" list for .p7m
    put(rf"{classes}\.p7m\OpenWithProgids", "", PROGID)
    # context-menu verb: shown on every .p7m whatever the default app is
    verb = rf"{classes}\SystemFileAssociations\.p7m\shell\{WIN_VERB}"
    put(verb, "Estrai il contenuto con P7M Extractor")
    if icon:
        put(verb, icon, "Icon")
    put(verb, "Player", "MultiSelectModel")  # no 15-files prompt on multi-select
    put(rf"{verb}\command", cmd)
    # Default Programs registration (Settings > Apps > Default apps)
    caps = rf"Software\{APP_NAME}\Capabilities"
    put(caps, APP_NAME, "ApplicationName")
    put(caps, "Estrae il documento originale dai file firmati .p7m",
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


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run_cli(paths, overwrite: bool) -> int:
    files = iter_p7m(paths)
    if not files:
        print("Nessun file .p7m trovato.", file=sys.stderr)
        return 1
    n_ok = n_skip = n_err = 0
    for f in files:
        try:
            dest, layers = extract_file(f, overwrite)
            extra = f"  ({layers} firme annidate)" if layers > 1 else ""
            print(f"OK    {dest}{extra}")
            n_ok += 1
        except FileExistsError as e:
            print(f"SALTO {f}  (esiste gia': {Path(str(e)).name}; usa --overwrite)")
            n_skip += 1
        except (BerError, OSError) as e:
            print(f"ERR   {f}  ({e})", file=sys.stderr)
            n_err += 1
    print(f"\nEstratti: {n_ok}  Saltati: {n_skip}  Errori: {n_err}")
    return 0 if n_err == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="p7m-extractor",
        description="Estrae il documento originale dai file firmati .p7m (CAdES).",
        epilog="Senza argomenti si avvia l'interfaccia grafica (GTK 4). "
               "Esempi: p7m-extractor fattura.xml.p7m | "
               "p7m-extractor --overwrite cartella/",
    )
    parser.add_argument("paths", nargs="*", metavar="FILE_O_CARTELLA",
                        help="file .p7m o cartelle da scansionare (ricorsivo)")
    parser.add_argument("--overwrite", action="store_true",
                        help="sovrascrivi i file estratti già esistenti")
    parser.add_argument("--gui", action="store_true",
                        help="forza l'avvio dell'interfaccia grafica")
    parser.add_argument("--check-update", action="store_true",
                        help="controlla se esiste una versione più recente ed esci")
    parser.add_argument("--register", action="store_true",
                        help="(Windows) registra l'app in Esplora file per "
                             "l'utente corrente ed esci")
    parser.add_argument("--unregister", action="store_true",
                        help="(Windows) rimuovi la registrazione ed esci")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser


def _close_splash() -> None:
    """Close the start-up splash of the Windows build (PyInstaller), if any."""
    try:
        import pyi_splash  # exists only inside a frozen build with a splash
        pyi_splash.close()
    except Exception:  # noqa: BLE001 - any failure here is irrelevant
        pass


# ---------------------------------------------------------------------------
# GTK 4 GUI
# ---------------------------------------------------------------------------

_CSS = b"""
.dropzone {
    border: 2px dashed alpha(currentColor, 0.25);
    border-radius: 12px;
}
.dropzone.hover {
    border-color: @theme_selected_bg_color;
    background: alpha(@theme_selected_bg_color, 0.08);
}
.banner {
    background: alpha(@theme_selected_bg_color, 0.14);
    border-radius: 8px;
    padding: 6px 6px 6px 12px;
}
"""


def run_gui(argv) -> int:
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Gdk", "4.0")
        from gi.repository import Gdk, Gio, GLib, Gtk, Pango
    except (ImportError, ValueError):
        _close_splash()
        print(
            "GTK 4 / PyGObject non disponibili. Installa:\n"
            "  Debian/Ubuntu:  sudo apt install python3-gi gir1.2-gtk-4.0\n"
            "  Fedora:         sudo dnf install python3-gobject gtk4\n"
            "  Arch:           sudo pacman -S python-gobject gtk4\n"
            "  Windows(MSYS2): pacman -S mingw-w64-x86_64-gtk4 "
            "mingw-w64-x86_64-python-gobject\n"
            "oppure scarica la build portable dalle Release su GitHub.\n"
            "Uso senza GUI:  p7m-extractor FILE_O_CARTELLA...",
            file=sys.stderr,
        )
        return 2

    import queue
    import threading

    has_filedialog = Gtk.check_version(4, 10, 0) is None
    is_win = sys.platform == "win32"
    in_flatpak = not is_win and Path("/.flatpak-info").is_file()

    # --- small helpers ----------------------------------------------------

    def set_margins(widget, value=None, **sides):
        for side in ("top", "bottom", "start", "end"):
            v = sides.get(side, value)
            if v is not None:
                getattr(widget, f"set_margin_{side}")(v)

    def close_on_escape(window):
        ctl = Gtk.EventControllerKey()

        def on_key(_c, keyval, _code, _state):
            if keyval == Gdk.KEY_Escape:
                window.close()
                return True
            return False
        ctl.connect("key-pressed", on_key)
        window.add_controller(ctl)

    def dialog_window(parent, title, width=440):
        """Modal secondary window with the usual header bar (GNOME HIG)."""
        win = Gtk.Window(transient_for=parent, modal=True, title=title,
                         resizable=False, default_width=width)
        win.set_titlebar(Gtk.HeaderBar())
        close_on_escape(win)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        set_margins(box, 24)
        win.set_child(box)
        return win, box

    def button_row(*buttons):
        row = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        row.set_margin_top(8)
        for b in buttons:
            row.append(b)
        return row

    def open_uri(uri, parent=None):
        if has_filedialog:  # GTK >= 4.10
            Gtk.UriLauncher.new(uri).launch(parent, None, None)
        elif is_win:
            os.startfile(uri)
        else:
            Gio.AppInfo.launch_default_for_uri(uri, None)

    def host_paths(paths):
        """Inside a Flatpak, files dropped or picked through the portals may
        arrive as /run/user/UID/doc/ID/... paths. The output is written next
        to the source, so map them back to the real location whenever the
        sandbox can write there (org.freedesktop.portal.Documents.GetHostPaths)."""
        if not in_flatpak:
            return paths
        doc_root = Path(GLib.get_user_runtime_dir()) / "doc"
        rels = {}
        for p in paths:
            try:
                rels[p] = Path(p).relative_to(doc_root)
            except ValueError:
                pass
        ids = sorted({r.parts[0] for r in rels.values() if len(r.parts) >= 2})
        if not ids:
            return paths
        try:
            bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            reply = bus.call_sync(
                "org.freedesktop.portal.Documents",
                "/org/freedesktop/portal/documents",
                "org.freedesktop.portal.Documents", "GetHostPaths",
                GLib.Variant("(as)", (ids,)), GLib.VariantType("(a{say})"),
                Gio.DBusCallFlags.NONE, 3000, None)
            mapping = reply.unpack()[0]
        except GLib.Error:
            return paths
        out = []
        for p in paths:
            rel = rels.get(p)
            host = mapping.get(rel.parts[0]) if rel is not None and len(rel.parts) >= 2 else None
            if host is None:
                out.append(p)
                continue
            if isinstance(host, list):
                host = bytes(host)
            real = Path(os.fsdecode(bytes(host).rstrip(b"\0"))).joinpath(*rel.parts[2:])
            target_dir = real if real.is_dir() else real.parent
            out.append(str(real) if real.exists() and os.access(target_dir, os.W_OK) else p)
        return out

    # --- main window ------------------------------------------------------

    class Window(Gtk.ApplicationWindow):
        def __init__(self, app):
            super().__init__(
                application=app, title=APP_NAME,
                default_width=680, default_height=560,
            )
            self.settings = app.settings
            self._overwrite = False
            self._jobs: queue.Queue = queue.Queue()
            self._counts = [0, 0, 0]  # ok, skipped, errors
            self._pending = 0         # batches queued or running
            self._native = None       # keep FileChooserNative alive
            self._banner_cb = None
            self._about = None

            header = Gtk.HeaderBar()
            self.set_titlebar(header)

            menu = Gio.Menu()
            if is_win:
                section = Gio.Menu()
                section.append("Controlla aggiornamenti…", "app.check-updates")
                menu.append_section(None, section)
                section = Gio.Menu()
                section.append("Preferenze", "app.preferences")
                menu.append_section(None, section)
            section = Gio.Menu()
            section.append(f"Informazioni su {APP_NAME}", "app.about")
            menu.append_section(None, section)
            menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu,
                                      primary=True, tooltip_text="Menu principale")
            header.pack_end(menu_btn)
            self.spinner = Gtk.Spinner(tooltip_text="Estrazione in corso…")
            header.pack_end(self.spinner)

            content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            set_margins(content, 16)
            self.set_child(content)

            # --- in-app notification banner ---------------------------------
            self.banner = Gtk.Revealer(
                transition_type=Gtk.RevealerTransitionType.SLIDE_DOWN)
            bbox = Gtk.Box(spacing=12)
            bbox.add_css_class("banner")
            self.banner_label = Gtk.Label(hexpand=True, xalign=0.0, wrap=True)
            self.banner_button = Gtk.Button(valign=Gtk.Align.CENTER)
            self.banner_button.connect("clicked", self._on_banner_button)
            close_btn = Gtk.Button(icon_name="window-close-symbolic",
                                   valign=Gtk.Align.CENTER, tooltip_text="Chiudi")
            close_btn.add_css_class("flat")
            close_btn.connect("clicked", lambda _b: self.banner.set_reveal_child(False))
            for w in (self.banner_label, self.banner_button, close_btn):
                bbox.append(w)
            self.banner.set_child(bbox)
            content.append(self.banner)

            # --- drop zone -------------------------------------------------
            self.dropzone = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            self.dropzone.add_css_class("dropzone")
            set_margins(self.dropzone, top=4, bottom=4)
            icon = Gtk.Image.new_from_icon_name("document-open-symbolic")
            icon.set_pixel_size(48)
            icon.set_margin_top(20)
            title = Gtk.Label(label="Trascina qui file o cartelle .p7m")
            title.add_css_class("title-4")
            hint = Gtk.Label(label="Il documento originale viene estratto accanto al file firmato")
            hint.add_css_class("dim-label")
            btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8,
                           halign=Gtk.Align.CENTER)
            btns.set_margin_bottom(20)
            b_files = Gtk.Button(label="Scegli file…", action_name="app.open-files")
            b_folder = Gtk.Button(label="Scegli cartella…", action_name="app.open-folder")
            btns.append(b_files)
            btns.append(b_folder)
            for w in (icon, title, hint, btns):
                self.dropzone.append(w)
            content.append(self.dropzone)

            # --- results list ---------------------------------------------
            self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
            placeholder = Gtk.Label(label="I file estratti appariranno qui")
            placeholder.add_css_class("dim-label")
            set_margins(placeholder, top=24, bottom=24)
            self.listbox.set_placeholder(placeholder)
            scrolled = Gtk.ScrolledWindow(vexpand=True, child=self.listbox)
            scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            frame = Gtk.Frame(child=scrolled)
            content.append(frame)

            # --- bottom bar ------------------------------------------------
            bottom = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            check = Gtk.CheckButton(label="Sovrascrivi i file già esistenti")
            check.connect("toggled", self.on_overwrite_toggled)
            self.summary = Gtk.Label(label="", hexpand=True, xalign=1.0)
            self.summary.add_css_class("dim-label")
            bottom.append(check)
            bottom.append(self.summary)
            content.append(bottom)

            # --- drag & drop ----------------------------------------------
            drop = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
            drop.connect("drop", self.on_drop)
            drop.connect("enter", self.on_drop_enter)
            # "motion" must keep returning COPY on every pointer move:
            # without it Windows gets DROPEFFECT_NONE mid-drag and hides
            # the drag cursor/icon while hovering the window.
            drop.connect("motion", self.on_drop_motion)
            drop.connect("leave", self.on_drop_leave)
            self.add_controller(drop)

            threading.Thread(target=self._worker, daemon=True).start()

        # --- public API used by the application ------------------------------
        def enqueue(self, paths):
            paths = [p for p in paths if p]
            if not paths:
                return
            self._pending += 1
            self.spinner.start()
            self.summary.set_label("Estrazione in corso…")
            self._jobs.put(paths)

        def first_shown(self):
            """One-shot tasks after the window is on screen (Windows only:
            default-app prompt and the daily update check)."""
            if is_win:
                if self.settings.get_bool("ask_default_app") and not win_is_default():
                    DefaultAppDialog(self).present()
                today = date.today().isoformat()
                if (self.settings.get_bool("check_updates")
                        and self.settings.get("last_update_check") != today):
                    self.settings.set("last_update_check", today)
                    self.check_updates(manual=False)
            return False  # one-shot GLib.idle_add

        def show_banner(self, text, button_label=None, callback=None):
            self.banner_label.set_label(text)
            self._banner_cb = callback
            self.banner_button.set_label(button_label or "")
            self.banner_button.set_visible(bool(button_label))
            self.banner.set_reveal_child(True)

        def _on_banner_button(self, _btn):
            self.banner.set_reveal_child(False)
            if self._banner_cb:
                self._banner_cb()

        def show_about(self):
            if self._about is None:  # built once, hidden on close
                self._about = Gtk.AboutDialog(
                    transient_for=self, modal=True, hide_on_close=True,
                    program_name=APP_NAME, version=__version__,
                    comments="Estrae il documento originale dai file firmati "
                             "digitalmente (.p7m, CAdES).",
                    website=f"https://github.com/{GITHUB_REPO}",
                    website_label="Progetto su GitHub",
                    license_type=Gtk.License.MIT_X11,
                    copyright="© 2026 Daniel Grasso",
                    authors=["Daniel Grasso"],
                    logo_icon_name=APP_ID,
                )
            self._about.present()

        # --- update check (Windows) -----------------------------------------
        def check_updates(self, manual):
            if manual:
                self.show_banner("Controllo aggiornamenti in corso…")

            def work():
                try:
                    rel = fetch_latest_release()
                except UpdateError as e:
                    GLib.idle_add(self._update_result, None, str(e), manual)
                    return
                GLib.idle_add(self._update_result, rel, None, manual)
            threading.Thread(target=work, daemon=True).start()

        def _update_result(self, rel, err, manual):
            if err:
                if manual:
                    self.show_banner(f"Controllo aggiornamenti non riuscito: {err}")
                return False
            if is_newer(rel["version"]):
                if manual:
                    self.banner.set_reveal_child(False)
                    UpdateDialog(self, rel).present()
                else:
                    self.show_banner(
                        f"È disponibile la versione {rel['version']} di {APP_NAME}.",
                        "Aggiorna…", lambda: UpdateDialog(self, rel).present())
            elif manual:
                self.show_banner(f"{APP_NAME} {__version__} è aggiornato: "
                                 "nessuna nuova versione.")
            return False

        # --- signal handlers ----------------------------------------------
        def on_overwrite_toggled(self, check):
            self._overwrite = check.get_active()

        def on_drop_enter(self, _t, _x, _y):
            self.dropzone.add_css_class("hover")
            return Gdk.DragAction.COPY

        def on_drop_motion(self, _t, _x, _y):
            return Gdk.DragAction.COPY

        def on_drop_leave(self, _t):
            self.dropzone.remove_css_class("hover")

        def on_drop(self, _t, value, _x, _y):
            self.dropzone.remove_css_class("hover")
            self.enqueue([f.get_path() for f in value.get_files()])
            return True

        def on_pick_files(self):
            if has_filedialog:
                dlg = Gtk.FileDialog(title="Scegli file .p7m")
                f_p7m = Gtk.FileFilter()
                f_p7m.set_name("File firmati (*.p7m)")
                f_p7m.add_pattern("*.p7m")
                f_p7m.add_pattern("*.P7M")
                f_all = Gtk.FileFilter()
                f_all.set_name("Tutti i file")
                f_all.add_pattern("*")
                store = Gio.ListStore.new(Gtk.FileFilter)
                store.append(f_p7m)
                store.append(f_all)
                dlg.set_filters(store)
                dlg.set_default_filter(f_p7m)
                dlg.open_multiple(self, None, self._files_chosen)
            else:
                self._native = Gtk.FileChooserNative.new(
                    "Scegli file .p7m", self, Gtk.FileChooserAction.OPEN,
                    "Apri", "Annulla")
                self._native.set_select_multiple(True)
                self._native.connect("response", self._native_response)
                self._native.show()

        def on_pick_folder(self):
            if has_filedialog:
                dlg = Gtk.FileDialog(title="Scegli una cartella")
                dlg.select_folder(self, None, self._folder_chosen)
            else:
                self._native = Gtk.FileChooserNative.new(
                    "Scegli una cartella", self,
                    Gtk.FileChooserAction.SELECT_FOLDER, "Apri", "Annulla")
                self._native.connect("response", self._native_response)
                self._native.show()

        def _files_chosen(self, dlg, res):
            try:
                files = dlg.open_multiple_finish(res)
            except GLib.Error:
                return
            self.enqueue([files.get_item(i).get_path()
                          for i in range(files.get_n_items())])

        def _folder_chosen(self, dlg, res):
            try:
                folder = dlg.select_folder_finish(res)
            except GLib.Error:
                return
            if folder:
                self.enqueue([folder.get_path()])

        def _native_response(self, native, response):
            if response == Gtk.ResponseType.ACCEPT:
                files = native.get_files()
                self.enqueue([files.get_item(i).get_path()
                              for i in range(files.get_n_items())])
            self._native = None

        # --- worker thread ------------------------------------------------
        def _worker(self):
            while True:
                batch = self._jobs.get()
                files = iter_p7m(host_paths(batch))
                if not files:
                    GLib.idle_add(self._set_summary, "Nessun file .p7m trovato")
                for f in files:
                    try:
                        dest, layers = extract_file(f, self._overwrite)
                        GLib.idle_add(self._add_row, f, dest, layers, None)
                    except FileExistsError:
                        GLib.idle_add(self._add_row, f, None, 0, "exists")
                    except (BerError, OSError) as e:
                        GLib.idle_add(self._add_row, f, None, 0, str(e))
                GLib.idle_add(self._batch_done)

        # --- UI updates (main thread) -------------------------------------
        def _batch_done(self):
            self._pending = max(0, self._pending - 1)
            if self._pending == 0:
                self.spinner.stop()
                if any(self._counts):
                    self._set_counts()
            return False

        def _add_row(self, src, dest, layers, err):
            if err is None:
                icon_name, cls = "object-select-symbolic", None
                extra = f" ({layers} firme annidate)" if layers > 1 else ""
                status = f"Estratto{extra} → {dest.name}"
                self._counts[0] += 1
            elif err == "exists":
                icon_name, cls = "action-unavailable-symbolic", "dim-label"
                status = "Saltato: il file estratto esiste già (attiva Sovrascrivi)"
                self._counts[1] += 1
            else:
                icon_name, cls = "dialog-error-symbolic", "error"
                status = f"Errore: {err}"
                self._counts[2] += 1

            row = Gtk.ListBoxRow(activatable=False)
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            set_margins(box, top=6, bottom=6, start=10, end=10)
            icon = Gtk.Image.new_from_icon_name(icon_name)
            if cls:
                icon.add_css_class(cls)
            texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, hexpand=True)
            name = Gtk.Label(label=src.name, xalign=0.0)
            name.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
            sub = Gtk.Label(label=status, xalign=0.0)
            sub.set_ellipsize(Pango.EllipsizeMode.END)
            sub.add_css_class("dim-label")
            texts.append(name)
            texts.append(sub)
            box.append(icon)
            box.append(texts)
            if err is None:
                open_btn = Gtk.Button(icon_name="folder-open-symbolic",
                                      valign=Gtk.Align.CENTER,
                                      tooltip_text="Apri la cartella")
                open_btn.add_css_class("flat")
                open_btn.connect(
                    "clicked",
                    lambda _b, p=dest.resolve(): self._reveal(p))
                box.append(open_btn)
            row.set_child(box)
            self.listbox.append(row)
            self._set_counts()
            return False  # one-shot GLib.idle_add

        def _set_counts(self):
            ok, skip, errn = self._counts
            self._set_summary(f"{ok} estratti · {skip} saltati · {errn} errori")

        def _set_summary(self, text):
            self.summary.set_label(text)
            return False

        def _reveal(self, dest):
            """Show the extracted file in the platform file manager.

            Gio.AppInfo.launch_default_for_uri silently fails for file://
            URIs on Windows, hence the per-platform paths.
            """
            if is_win:
                try:
                    subprocess.Popen(["explorer", f"/select,{dest}"])
                except OSError:
                    os.startfile(dest.parent)
            elif has_filedialog:  # GTK >= 4.10
                launcher = Gtk.FileLauncher.new(
                    Gio.File.new_for_path(str(dest)))
                launcher.open_containing_folder(self, None, None)
            else:
                Gio.AppInfo.launch_default_for_uri(
                    dest.parent.as_uri(), None)

    # --- "open .p7m with this app?" prompt (Windows) ------------------------

    class DefaultAppDialog(Gtk.Window):
        def __init__(self, parent):
            super().__init__(transient_for=parent, modal=True, resizable=False,
                             title="App predefinita", default_width=440)
            self.set_titlebar(Gtk.HeaderBar())
            close_on_escape(self)
            self._parent = parent
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            set_margins(box, 24)
            icon = Gtk.Image.new_from_icon_name(APP_ID)
            icon.set_pixel_size(64)
            heading = Gtk.Label(label=f"Vuoi aprire i file .p7m con {APP_NAME}?",
                                wrap=True, justify=Gtk.Justification.CENTER)
            heading.add_css_class("title-2")
            body = Gtk.Label(
                label="Con un doppio clic su un file firmato il documento "
                      "originale viene estratto subito, accanto all'originale. "
                      "Puoi cambiare idea in qualsiasi momento dalle "
                      "Impostazioni di Windows.",
                wrap=True, justify=Gtk.Justification.CENTER, max_width_chars=48)
            body.add_css_class("dim-label")
            self.dont_ask = Gtk.CheckButton(label="Non chiedere più",
                                            halign=Gtk.Align.CENTER)
            later = Gtk.Button(label="Non ora")
            later.connect("clicked", lambda _b: self._finish(False))
            yes = Gtk.Button(label="Imposta come predefinita")
            yes.add_css_class("suggested-action")
            yes.connect("clicked", lambda _b: self._finish(True))
            for w in (icon, heading, body, self.dont_ask, button_row(later, yes)):
                box.append(w)
            self.set_child(box)
            self.set_default_widget(yes)

        def _finish(self, make_default):
            if self.dont_ask.get_active():
                self._parent.settings.set("ask_default_app", False)
            self.close()
            if not make_default:
                return
            try:
                outcome = win_make_default()
            except OSError as e:
                self._parent.show_banner(f"Impostazione non riuscita: {e}")
                return
            if outcome == "done":
                self._parent.show_banner(
                    f"{APP_NAME} è ora l'app predefinita per i file .p7m.")
            else:
                self._parent.show_banner(
                    "Nella pagina Impostazioni appena aperta scegli "
                    f"{APP_NAME} alla voce .p7m.")

    # --- update dialog (Windows) --------------------------------------------

    class UpdateDialog(Gtk.Window):
        def __init__(self, parent, rel):
            super().__init__(transient_for=parent, modal=True, resizable=False,
                             title="Aggiornamento disponibile", default_width=480)
            self.set_titlebar(Gtk.HeaderBar())
            close_on_escape(self)
            self._app = parent.get_application()
            self._rel = rel
            self._cancel = threading.Event()
            self.connect("close-request", self._on_close)

            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            set_margins(box, 24)
            heading = Gtk.Label(label=f"{APP_NAME} {rel['version']} è disponibile",
                                xalign=0.0, wrap=True)
            heading.add_css_class("title-2")
            sub = Gtk.Label(label=f"Stai usando la versione {__version__}.", xalign=0.0)
            sub.add_css_class("dim-label")
            box.append(heading)
            box.append(sub)
            notes = rel["notes"].strip()
            if notes:
                lbl = Gtk.Label(label=notes[:4000], xalign=0.0, yalign=0.0,
                                wrap=True, selectable=True, max_width_chars=56)
                set_margins(lbl, 8)
                sc = Gtk.ScrolledWindow(child=lbl, min_content_height=120,
                                        max_content_height=240,
                                        propagate_natural_height=True)
                sc.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
                box.append(Gtk.Frame(child=sc))
            self.progress = Gtk.ProgressBar(show_text=True, visible=False)
            self.status = Gtk.Label(xalign=0.0, wrap=True)
            self.status.add_css_class("dim-label")
            box.append(self.progress)
            box.append(self.status)

            later = Gtk.Button(label="Più tardi")
            later.connect("clicked", lambda _b: self.close())
            self.asset = pick_asset(rel["assets"], is_installed_build()) if is_win else None
            if self.asset and is_installed_build():
                self.action = Gtk.Button(label="Scarica e installa")
                self.action.connect("clicked", self._download)
                self.status.set_label("L'installazione sostituisce la versione "
                                      "attuale; il programma verrà chiuso.")
            else:
                self.action = Gtk.Button(label="Apri la pagina di download")
                self.action.connect("clicked", self._open_page)
            self.action.add_css_class("suggested-action")
            box.append(button_row(later, self.action))
            self.set_child(box)
            self.set_default_widget(self.action)

        def _on_close(self, _win):
            self._cancel.set()
            return False

        def _open_page(self, _btn):
            open_uri(self._rel["url"], self)
            self.close()

        def _download(self, _btn):
            self.action.set_sensitive(False)
            self.progress.set_visible(True)
            self.progress.set_fraction(0)
            self.status.set_label("Scaricamento in corso…")
            dest = Path(tempfile.gettempdir()) / self.asset["name"]

            def progress(done, total):
                GLib.idle_add(self._on_progress, done, total)

            def work():
                try:
                    download_file(self.asset["url"], dest, progress, self._cancel)
                except UpdateError as e:
                    GLib.idle_add(self._on_error, str(e))
                    return
                GLib.idle_add(self._on_downloaded, dest)
            threading.Thread(target=work, daemon=True).start()

        def _on_progress(self, done, total):
            if total:
                self.progress.set_fraction(min(done / total, 1.0))
                self.progress.set_text(f"{done / 1e6:.1f} / {total / 1e6:.1f} MB")
            else:
                self.progress.pulse()
            return False

        def _on_error(self, msg):
            self.progress.set_visible(False)
            self.status.set_label(f"Download non riuscito: {msg}")
            self.action.set_sensitive(True)
            return False

        def _on_downloaded(self, dest):
            self.status.set_label("Avvio dell'installazione…")
            try:
                os.startfile(str(dest))
            except OSError as e:
                self.status.set_label(f"Impossibile avviare l'installer: {e}")
                self.action.set_sensitive(True)
                return False
            self._app.quit()  # let the installer replace the files in peace
            return False

    # --- preferences (Windows) ----------------------------------------------

    class PreferencesWindow(Gtk.Window):
        def __init__(self, parent):
            super().__init__(transient_for=parent, modal=True, resizable=False,
                             title="Preferenze", default_width=540)
            self.set_titlebar(Gtk.HeaderBar())
            close_on_escape(self)
            self._parent = parent
            s = parent.settings
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            set_margins(box, 24)

            box.append(self._section("Generale"))
            general = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
            general.append(self._row(
                "Chiedi di impostare come app predefinita all'avvio",
                f"Solo finché {APP_NAME} non è già l'app che apre i file .p7m",
                self._switch(s, "ask_default_app")))
            general.append(self._row(
                "Controlla aggiornamenti all'avvio",
                "Una volta al giorno, dalle Release del progetto su GitHub",
                self._switch(s, "check_updates")))
            box.append(Gtk.Frame(child=general))

            box.append(self._section("Esplora file"))
            shell = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
            self.handler_label = None
            set_btn = Gtk.Button(label="Imposta…", valign=Gtk.Align.CENTER)
            set_btn.connect("clicked", self._on_set_default)
            row, self.handler_label = self._row(
                "App predefinita per i file .p7m", self._handler_text(), set_btn,
                return_subtitle=True)
            shell.append(row)
            reg = Gtk.Box(spacing=6, valign=Gtk.Align.CENTER)
            b_reg = Gtk.Button(label="Registra")
            b_reg.connect("clicked", self._on_register)
            b_unreg = Gtk.Button(label="Rimuovi")
            b_unreg.connect("clicked", self._on_unregister)
            reg.append(b_reg)
            reg.append(b_unreg)
            shell.append(self._row(
                "Menu contestuale e «Apri con»",
                "Voce «Estrai il contenuto» sui file .p7m e presenza "
                "nell'elenco delle app (utente corrente)", reg))
            box.append(Gtk.Frame(child=shell))
            self.set_child(box)

        @staticmethod
        def _section(text):
            lbl = Gtk.Label(label=text, xalign=0.0)
            lbl.add_css_class("heading")
            lbl.set_margin_top(8)
            return lbl

        @staticmethod
        def _switch(settings, key):
            sw = Gtk.Switch(active=settings.get_bool(key), valign=Gtk.Align.CENTER)
            sw.connect("state-set", lambda _s, state: (settings.set(key, bool(state)), False)[1])
            return sw

        @staticmethod
        def _row(title, subtitle, widget, return_subtitle=False):
            row = Gtk.ListBoxRow(activatable=False)
            hbox = Gtk.Box(spacing=12)
            set_margins(hbox, top=8, bottom=8, start=12, end=12)
            texts = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, hexpand=True,
                            valign=Gtk.Align.CENTER)
            t = Gtk.Label(label=title, xalign=0.0, wrap=True)
            st = Gtk.Label(label=subtitle, xalign=0.0, wrap=True)
            st.add_css_class("dim-label")
            st.add_css_class("caption")
            texts.append(t)
            texts.append(st)
            hbox.append(texts)
            hbox.append(widget)
            row.set_child(hbox)
            return (row, st) if return_subtitle else row

        @staticmethod
        def _handler_text():
            try:
                if win_is_default():
                    return f"Attualmente: {APP_NAME}"
                handler = win_current_handler()
            except OSError:
                handler = None
            return f"Attualmente: {handler}" if handler else "Attualmente: nessuna app"

        def _refresh(self, message=None):
            self.handler_label.set_label(self._handler_text())
            if message:
                self._parent.show_banner(message)

        def _on_set_default(self, _btn):
            try:
                outcome = win_make_default()
            except OSError as e:
                self._refresh(f"Impostazione non riuscita: {e}")
                return
            self._refresh(f"{APP_NAME} è ora l'app predefinita per i file .p7m."
                          if outcome == "done" else
                          f"Nella pagina Impostazioni appena aperta scegli {APP_NAME} "
                          "alla voce .p7m.")

        def _on_register(self, _btn):
            try:
                win_register()
                self._refresh("Integrazione con Esplora file registrata.")
            except OSError as e:
                self._refresh(f"Registrazione non riuscita: {e}")

        def _on_unregister(self, _btn):
            try:
                win_unregister()
                self._refresh("Voci di Esplora file rimosse per l'utente corrente.")
            except OSError as e:
                self._refresh(f"Rimozione non riuscita: {e}")

    # --- application --------------------------------------------------------

    class App(Gtk.Application):
        """Single-instance application: a second launch (double-click on a
        .p7m, context-menu entry, several files selected at once) forwards its
        command line to the running window instead of opening another one."""

        def __init__(self):
            super().__init__(application_id=APP_ID,
                             flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE)
            self.settings = Settings()
            self.window = None

        def do_startup(self):
            Gtk.Application.do_startup(self)
            display = Gdk.Display.get_default()
            bundle = getattr(sys, "_MEIPASS", None)
            if bundle:  # icons shipped inside the PyInstaller bundle
                Gtk.IconTheme.get_for_display(display).add_search_path(
                    os.path.join(bundle, "share", "icons"))
            Gtk.Window.set_default_icon_name(APP_ID)

            css = Gtk.CssProvider()
            try:  # GTK >= 4.12
                css.load_from_string(_CSS.decode())
            except AttributeError:  # older GTK 4, PyGObject signature varies
                try:
                    css.load_from_data(_CSS)
                except TypeError:
                    css.load_from_data(_CSS, len(_CSS))
            Gtk.StyleContext.add_provider_for_display(
                display, css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

            self._action("quit", lambda *_: self.quit(), ["<Control>q"])
            self._action("about", lambda *_: self._win().show_about())
            self._action("open-files", lambda *_: self._win().on_pick_files(),
                         ["<Control>o"])
            self._action("open-folder", lambda *_: self._win().on_pick_folder(),
                         ["<Control><Shift>o"])
            if is_win:
                self._action("check-updates",
                             lambda *_: self._win().check_updates(manual=True))
                self._action("preferences",
                             lambda *_: PreferencesWindow(self._win()).present(),
                             ["<Control>comma"])

        def _action(self, name, callback, accels=()):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)
            if accels:
                self.set_accels_for_action(f"app.{name}", list(accels))

        def _win(self):
            if self.window is None:
                self.window = Window(self)
            return self.window

        def do_activate(self):
            self._show(())

        def do_open(self, files, _n_files, _hint):  # D-Bus activation
            self._show([f.get_path() for f in files])

        def do_command_line(self, cmdline):
            # Runs in the primary instance, also for command lines forwarded
            # by later launches (their cwd may differ from ours).
            args = list(cmdline.get_arguments())[1:]
            try:
                ns, _unknown = build_parser().parse_known_args(args)
            except SystemExit:
                return 1
            cwd = cmdline.get_cwd() or os.getcwd()
            self._show([os.path.normpath(os.path.join(cwd, p)) for p in ns.paths])
            return 0

        def _show(self, paths):
            first = self.window is None
            win = self._win()
            win.present()
            if paths:
                win.enqueue(list(paths))
            _close_splash()
            if first:
                GLib.idle_add(win.first_shown)

    status = App().run(argv)
    _close_splash()  # remote instance: the command line went to the primary
    return status


# ---------------------------------------------------------------------------


def main() -> int:
    # PyInstaller --windowed builds have no console streams.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")

    args = build_parser().parse_args()

    if args.check_update:
        _close_splash()
        return run_check_update()
    if args.register or args.unregister:
        _close_splash()
        if sys.platform != "win32":
            print("Opzione disponibile solo su Windows.", file=sys.stderr)
            return 2
        if args.register:
            win_register()
            print("Integrazione con Esplora file registrata per l'utente corrente.")
        else:
            win_unregister()
            print("Integrazione con Esplora file rimossa per l'utente corrente.")
        return 0
    if args.paths and not args.gui:
        _close_splash()
        return run_cli(args.paths, args.overwrite)
    return run_gui(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
