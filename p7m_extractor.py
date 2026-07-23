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
import os
import re
import subprocess
import sys
from pathlib import Path

__version__ = "1.1.1"

APP_ID = "com.danielgrasso.P7mExtractor"

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
"""


def run_gui(initial_paths=()) -> int:
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Gdk", "4.0")
        from gi.repository import Gdk, Gio, GLib, Gtk, Pango
    except (ImportError, ValueError):
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

    class Window(Gtk.ApplicationWindow):
        def __init__(self, app, initial=()):
            super().__init__(
                application=app, title="P7M Extractor",
                default_width=680, default_height=560,
            )
            self._overwrite = False
            self._jobs: queue.Queue = queue.Queue()
            self._counts = [0, 0, 0]  # ok, skipped, errors
            self._native = None  # keep FileChooserNative alive

            header = Gtk.HeaderBar()
            self.set_titlebar(header)

            content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            for side in ("top", "bottom", "start", "end"):
                getattr(content, f"set_margin_{side}")(16)
            self.set_child(content)

            # --- drop zone -------------------------------------------------
            self.dropzone = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            self.dropzone.add_css_class("dropzone")
            for side in ("top", "bottom"):
                getattr(self.dropzone, f"set_margin_{side}")(4)
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
            b_files = Gtk.Button(label="Scegli file…")
            b_files.connect("clicked", self.on_pick_files)
            b_folder = Gtk.Button(label="Scegli cartella…")
            b_folder.connect("clicked", self.on_pick_folder)
            btns.append(b_files)
            btns.append(b_folder)
            for w in (icon, title, hint, btns):
                self.dropzone.append(w)
            content.append(self.dropzone)

            # --- results list ---------------------------------------------
            self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
            placeholder = Gtk.Label(label="I file estratti appariranno qui")
            placeholder.add_css_class("dim-label")
            for side in ("top", "bottom"):
                getattr(placeholder, f"set_margin_{side}")(24)
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

            css = Gtk.CssProvider()
            try:  # GTK >= 4.12
                css.load_from_string(_CSS.decode())
            except AttributeError:  # older GTK 4, PyGObject signature varies
                try:
                    css.load_from_data(_CSS)
                except TypeError:
                    css.load_from_data(_CSS, len(_CSS))
            Gtk.StyleContext.add_provider_for_display(
                Gdk.Display.get_default(), css,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
            )

            threading.Thread(target=self._worker, daemon=True).start()
            if initial:  # files passed on the command line (e.g. double-click)
                self._jobs.put([str(p) for p in initial])

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
            paths = [f.get_path() for f in value.get_files() if f.get_path()]
            if paths:
                self._jobs.put(paths)
            return True

        def on_pick_files(self, _btn):
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

        def on_pick_folder(self, _btn):
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
            paths = [files.get_item(i).get_path()
                     for i in range(files.get_n_items())]
            self._jobs.put([p for p in paths if p])

        def _folder_chosen(self, dlg, res):
            try:
                folder = dlg.select_folder_finish(res)
            except GLib.Error:
                return
            if folder and folder.get_path():
                self._jobs.put([folder.get_path()])

        def _native_response(self, native, response):
            if response == Gtk.ResponseType.ACCEPT:
                files = native.get_files()
                paths = [files.get_item(i).get_path()
                         for i in range(files.get_n_items())]
                self._jobs.put([p for p in paths if p])
            self._native = None

        # --- worker thread ------------------------------------------------
        def _worker(self):
            while True:
                batch = self._jobs.get()
                files = iter_p7m(batch)
                if not files:
                    GLib.idle_add(self._set_summary, "Nessun file .p7m trovato")
                    continue
                for f in files:
                    try:
                        dest, layers = extract_file(f, self._overwrite)
                        GLib.idle_add(self._add_row, f, dest, layers, None)
                    except FileExistsError:
                        GLib.idle_add(self._add_row, f, None, 0, "exists")
                    except (BerError, OSError) as e:
                        GLib.idle_add(self._add_row, f, None, 0, str(e))

        # --- UI updates (main thread) -------------------------------------
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
            for side in ("top", "bottom"):
                getattr(box, f"set_margin_{side}")(6)
            for side in ("start", "end"):
                getattr(box, f"set_margin_{side}")(10)
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
            ok, skip, errn = self._counts
            self._set_summary(f"{ok} estratti · {skip} saltati · {errn} errori")
            return False  # one-shot GLib.idle_add

        def _set_summary(self, text):
            self.summary.set_label(text)
            return False

        def _reveal(self, dest):
            """Show the extracted file in the platform file manager.

            Gio.AppInfo.launch_default_for_uri silently fails for file://
            URIs on Windows, hence the per-platform paths.
            """
            if sys.platform == "win32":
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

    class App(Gtk.Application):
        # NON_UNIQUE: every launch (e.g. double-clicking a .p7m when the
        # file association is installed) gets its own window and processes
        # its own arguments, with no primary-instance forwarding involved.
        def __init__(self):
            super().__init__(application_id=APP_ID,
                             flags=Gio.ApplicationFlags.NON_UNIQUE)

        def do_activate(self):
            win = self.get_active_window() or Window(self, initial_paths)
            win.present()

    return App().run(None)


# ---------------------------------------------------------------------------


def main() -> int:
    # PyInstaller --windowed builds have no console streams.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")

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
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    if args.paths and not args.gui:
        return run_cli(args.paths, args.overwrite)
    return run_gui(args.paths)


if __name__ == "__main__":
    sys.exit(main())
