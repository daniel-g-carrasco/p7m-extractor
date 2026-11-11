"""What the window says of a file's signatures: who signed, each envelope
drawn inside the one that signed over it, the document at the bottom.

Laid out as GNOME's guidelines ask: boxed lists, rows that open to show
more, one line at the top with the outcome of it all. Values come from
core/verdict.py; nothing is worked out here.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Pango  # noqa: E402

from p7m_extractor.core import verdict  # noqa: E402
from p7m_extractor.i18n import _  # noqa: E402

# Envelopes drawn one inside the other; past this depth the ones further in
# follow at the same width, each with its caption ("3 of 7 from the outside"),
# so that a file signed over many times stays readable and the window narrow.
MAX_INSET = 3
PAD = 12

ICONS = {verdict.PASSED: "security-high-symbolic", verdict.FAILED: "security-low-symbolic"}
CLASSES = {verdict.PASSED: "success", verdict.FAILED: "error"}


def state_of(signer) -> str:
    """The state that decides the icon: a signature that is not intact is a failed one."""
    return signer.status if signer.intact or signer.status != verdict.INTEGRITY_ONLY else verdict.FAILED


def icon_of(state: str) -> str:
    return ICONS.get(state, "security-medium-symbolic")


def class_of(state: str) -> str:
    return CLASSES.get(state, "warning")


def everyone(layers) -> list:
    return [signer for layer in layers for signer in layer]


def one_line(layers) -> str:
    """For the row of the file in the main list."""
    title, outcome = verdict.headline(layers)
    return f"{title}: {outcome}"


def _label(text: str, *classes: str, wrap: bool = True) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0.0, wrap=wrap, css_classes=list(classes))
    label.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
    return label


def _signer_row(Adw, signer):
    """One signature: who, by which certifier and when, the outcome on the
    right; opened, everything that is known of it."""
    state = state_of(signer)
    when = signer.proven_time or signer.claimed_time
    under = " · ".join(part for part in (signer.issuer, when.strftime("%d/%m/%Y %H:%M") if when else "") if part)
    row = Adw.ExpanderRow(title=signer.name or _("(no name in the certificate)"), subtitle=under, use_markup=False,
                          title_lines=1, subtitle_lines=1)
    row.add_prefix(Gtk.Image(icon_name=icon_of(state), css_classes=[class_of(state)]))
    row.add_suffix(Gtk.Label(label=verdict.state_word(signer), valign=Gtk.Align.CENTER,
                             css_classes=[class_of(state), "caption-heading"]))
    for what, value in [(_("Outcome"), verdict.summary(signer)), *verdict.details(signer)[1:]]:
        detail = Adw.ActionRow(title=what, subtitle=value, use_markup=False, subtitle_selectable=True,
                               css_classes=["property"])
        detail.set_subtitle_lines(0)
        row.add_row(detail)
    return row


def _boxed(rows) -> Gtk.ListBox:
    box = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
    for row in rows:
        box.append(row)
    return box


def _document(Adw, name: str) -> Gtk.ListBox:
    row = Adw.ActionRow(title=name, subtitle=_("The document that was signed"), use_markup=False, title_lines=1)
    row.add_prefix(Gtk.Image(icon_name="text-x-generic-symbolic"))
    return _boxed([row])


def _envelope(Adw, layers, depth: int, document: str) -> Gtk.Widget:
    """The envelope number `depth` (0 the outermost) with everything inside it."""
    total = len(layers)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=PAD, css_classes=["card"])
    inside = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=PAD, margin_top=PAD, margin_bottom=PAD,
                     margin_start=PAD, margin_end=PAD)
    box.append(inside)

    def put(level: int) -> None:
        inside.append(_label(verdict.layer_caption(level, total), "caption-heading", "dim-label"))
        inside.append(_boxed([_signer_row(Adw, signer) for signer in layers[level]]))

    put(depth)
    if depth + 1 == total:
        inside.append(_document(Adw, document))
    elif depth + 1 < MAX_INSET:
        inside.append(_envelope(Adw, layers, depth + 1, document))
    else:                       # further in: at the same width, one after the other
        for level in range(depth + 1, total):
            put(level)
        inside.append(_document(Adw, document))
    return box


def content(layers, document: str, lists_days: int | None) -> Gtk.Widget:
    """The body of the signatures' window (libadwaita)."""
    gi.require_version("Adw", "1")
    from gi.repository import Adw

    title, outcome = verdict.headline(layers)
    state = verdict.worst(everyone(layers))
    top = Gtk.Box(spacing=PAD)
    top.append(Gtk.Image(icon_name=icon_of(state), pixel_size=32, valign=Gtk.Align.START, css_classes=[class_of(state)]))
    words = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
    words.append(_label(title, "title-3"))
    words.append(_label(outcome, "dim-label"))
    top.append(words)

    page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18, margin_top=18, margin_bottom=18,
                   margin_start=PAD, margin_end=PAD)
    page.append(top)
    if layers:
        page.append(_envelope(Adw, layers, 0, document))
    page.append(_label(footer(lists_days), "caption", "dim-label"))
    clamp = Adw.Clamp(child=page, maximum_size=600, tightening_threshold=400)
    return Gtk.ScrolledWindow(child=clamp, hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)


def footer(lists_days: int | None) -> str:
    text = _("Checked by this program, which is not a qualified validation service.")
    if lists_days is not None:
        text += " " + (_("Trusted lists of today.") if lists_days == 0
                       else _("Trusted lists kept {days} days ago.").format(days=lists_days))
    return text


def plain(layers, document: str, lists_days: int | None) -> Gtk.Widget:
    """The same without libadwaita: the lines, each envelope a step further in."""
    title, outcome = verdict.headline(layers)
    out = [f"{title}: {outcome}", ""]
    for depth, signers in enumerate(layers):
        pad = "    " * depth
        out.append(pad + verdict.layer_caption(depth, len(layers)))
        for signer in signers:
            out += [f"{pad}    {line}" for line in verdict.lines(signer)]
        out.append("")
    out += ["    " * len(layers) + document, "", footer(lists_days)]
    label = Gtk.Label(label="\n".join(out), xalign=0.0, yalign=0.0, wrap=True, selectable=True,
                      margin_top=PAD, margin_bottom=PAD, margin_start=PAD, margin_end=PAD)
    return Gtk.ScrolledWindow(child=label, hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
