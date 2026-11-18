"""GTK 4.24's window quirks on Windows, worked around per window."""

from __future__ import annotations

import ctypes
from ctypes import wintypes


def win_watch_quirks(win) -> None:
    """Two quirks of GTK 4.24 on Windows, worked around per window, and the
    window otherwise left to Windows (measured on GTK 4.24.1, 2026-11-10,
    with probe 13; nothing here is needed once GTK fixes them).

    A window maximized by Windows (the title bar's button, Win+Up, a drag to
    the top edge) goes back to its normal size when a popover opens, while
    GTK and Windows still call it maximized: GTK falls back to its default
    size. So while the window is maximized its default size is the size it
    has, and the fall is to where it stands; the normal size comes back
    with the restore.

    A popover open when the window is minimized comes back without its grab
    (no click outside closes it): closed on the resume, it is gone.

    What is no longer done, and why (Daniel, 2026-11-10: "the build without
    workarounds is the best" at resizing, maximizing and dragging): the
    maximize made by Windows is not made GTK's own any more. That kept the
    menu from shrinking the window, and made every restore by Windows the
    broken kind, which then needed a second workaround that acted after a
    drag. A maximize that stays Windows' own restores and drags right by
    itself. (This app never maximizes by itself; one that does must ask
    Windows, not GTK: the template's winquirks.maximize_at_start.)"""
    from gi.repository import GLib, Gtk

    def hold(w):
        """While maximized, the default size is the size the window has."""
        if w.is_maximized() and w.get_width() > 0 and w.get_height() > 0:
            if w.get_default_size() != (w.get_width(), w.get_height()):
                w.set_default_size(w.get_width(), w.get_height())
        return False

    def on_maximized(w, _pspec):
        if w.is_maximized():
            if getattr(w, "normal_size", None) is None:
                w.normal_size = w.get_default_size()
            # once GTK has the maximized size (the next turn of the loop),
            # and again a moment later for a slow first layout
            GLib.idle_add(hold, w)
            GLib.timeout_add(250, hold, w)
        elif getattr(w, "normal_size", None) is not None:
            width, height = w.normal_size
            w.normal_size = None
            w.set_default_size(width, height)

    def popovers_below(widget):
        child = widget.get_first_child()
        while child is not None:
            if isinstance(child, Gtk.Popover):
                yield child
            yield from popovers_below(child)
            child = child.get_next_sibling()

    def on_suspended(w, _pspec):
        if not w.get_property("suspended"):
            def close():
                for popover in popovers_below(w):
                    if popover.get_visible():
                        popover.popdown()
                return False
            GLib.timeout_add(150, close)
            GLib.timeout_add(600, close)        # a slow restore: looked at once more

    win.normal_size = None
    win.connect("notify::maximized", on_maximized)
    win.connect("notify::suspended", on_suspended)
    if win.is_maximized():
        on_maximized(win, None)


def hwnd_of(window) -> int:
    """The HWND of this exact surface, also when GdkWin32 has no typelib."""
    surface = window.get_surface()
    if surface is None:
        return 0
    try:
        import gi
        gi.require_version("GdkWin32", "4.0")
        from gi.repository import GdkWin32
        return int(GdkWin32.Win32Surface.get_handle(surface) or 0)
    except (ImportError, ValueError, AttributeError):
        # Frozen GTK may omit GdkWin32's typelib. Read this surface's pointer,
        # never another window with a matching title (Preferences can repeat).
        get_pointer = ctypes.pythonapi.PyCapsule_GetPointer
        get_pointer.argtypes = [ctypes.py_object, ctypes.c_char_p]
        get_pointer.restype = ctypes.c_void_p
        gtk = ctypes.CDLL("libgtk-4-1.dll")
        gtk.gdk_win32_surface_get_handle.argtypes = [ctypes.c_void_p]
        gtk.gdk_win32_surface_get_handle.restype = wintypes.HWND
        return int(gtk.gdk_win32_surface_get_handle(get_pointer(surface.__gpointer__, None)) or 0)
