#!/usr/bin/env python3
"""Standalone tests for the P7M extraction core (no external deps).

Run:  python tests/test_extract.py
Also used by CI to generate a smoke-test sample:
      python tests/test_extract.py --make-sample out.p7m
"""

import base64
import sys
import tempfile
from pathlib import Path

import _setup  # noqa: F401 - sets up imports and isolated folders

import p7m_extractor
from p7m_extractor import cli
from p7m_extractor.app import extract, services, settings
from p7m_extractor.data import cms

# --- tiny BER builders ------------------------------------------------------

OID_SIGNED = bytes.fromhex("06092A864886F70D010702")
OID_DATA = bytes.fromhex("06092A864886F70D010701")


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def indef(tag: int, *parts: bytes) -> bytes:
    return bytes([tag, 0x80]) + b"".join(parts) + b"\x00\x00"


def p7m_definite(payload: bytes) -> bytes:
    """Plain DER SignedData with a single primitive OCTET STRING eContent."""
    encap = tlv(0x30, OID_DATA + tlv(0xA0, tlv(0x04, payload)))
    signed = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x31, b"") + encap)
    return tlv(0x30, OID_SIGNED + tlv(0xA0, signed))


def p7m_streaming(payload: bytes, chunk: int = 1000) -> bytes:
    """BER indefinite-length SignedData with chunked constructed OCTET STRING,
    as produced by common Italian signing software."""
    chunks = [tlv(0x04, payload[i:i + chunk])
              for i in range(0, len(payload), chunk)] or [tlv(0x04, b"")]
    encap = indef(0x30, OID_DATA, indef(0xA0, indef(0x24, *chunks)))
    signed = indef(0x30, tlv(0x02, b"\x01"), tlv(0x31, b""), encap)
    return indef(0x30, OID_SIGNED, indef(0xA0, signed))


def p7m_detached() -> bytes:
    encap = tlv(0x30, OID_DATA)  # no [0] eContent
    signed = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x31, b"") + encap)
    return tlv(0x30, OID_SIGNED + tlv(0xA0, signed))


# binary payload exercising every byte value, including \n and \x00
PAYLOAD = (b"%PDF-1.7 fake\n" + bytes(range(256)) * 40 + b"\n%%EOF\n")


def expect_raises(exc, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except exc:
        return
    raise AssertionError(f"{fn.__name__} did not raise {exc.__name__}")


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--make-sample":
        Path(sys.argv[2]).write_bytes(p7m_streaming(PAYLOAD))
        print(f"sample written: {sys.argv[2]}")
        return 0

    # core: definite DER
    assert cms.extract_econtent(p7m_definite(PAYLOAD)) == PAYLOAD
    # core: BER streaming with 1000-byte chunks
    assert cms.extract_econtent(p7m_streaming(PAYLOAD)) == PAYLOAD
    # container: bare base64 and PEM
    assert cms.decode_container(
        base64.encodebytes(p7m_definite(PAYLOAD))) == p7m_definite(PAYLOAD)
    pem = (b"-----BEGIN PKCS7-----\n"
           + base64.encodebytes(p7m_streaming(PAYLOAD))
           + b"-----END PKCS7-----\n")
    assert cms.extract_econtent(cms.decode_container(pem)) == PAYLOAD
    # errors: detached and garbage
    expect_raises(cms.BerError, cms.extract_econtent, p7m_detached())
    expect_raises(cms.BerError, cms.extract_econtent, b"%PDF-1.4 not signed")
    expect_raises(cms.BerError, cms.extract_econtent, p7m_definite(PAYLOAD)[:50])

    # file-level: naming, nested envelopes, skip/overwrite
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        f = td / "doc.pdf.p7m"
        f.write_bytes(p7m_streaming(PAYLOAD))
        dest, layers = extract.extract_file(f)
        assert dest == td / "doc.pdf" and layers == 1
        assert dest.read_bytes() == PAYLOAD

        nested = td / "doppia.pdf.p7m.p7m"
        nested.write_bytes(p7m_definite(p7m_streaming(PAYLOAD)))
        dest, layers = extract.extract_file(nested)
        assert dest == td / "doppia.pdf" and layers == 2
        assert dest.read_bytes() == PAYLOAD

        expect_raises(FileExistsError, extract.extract_file, f)
        seen = []
        dest, _ = extract.extract_file(f, overwrite=True, progress=seen.append)
        assert dest.read_bytes() == PAYLOAD
        # progress climbs monotonically from the read phase to 1.0
        assert seen == sorted(seen) and seen[-1] == 1.0 and 0.0 < seen[0] <= 0.5

        # folder scan finds .p7m case-insensitively, recursively
        (td / "sub").mkdir()
        upper = td / "sub" / "UPPER.XML.P7M"
        upper.write_bytes(p7m_definite(b"<xml/>"))
        found = extract.iter_p7m([td])
        assert upper in found and f in found and nested in found

    # --- preferences round-trip ----------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        ini = Path(td) / "cfg" / "settings.ini"
        s = settings.Settings(ini)
        assert s.get_bool("ask_default_app") and s.get("last_update_check") == ""
        s.set("ask_default_app", False)
        s.set("last_update_check", "2026-09-08")
        again = settings.Settings(ini)
        assert not again.get_bool("ask_default_app")
        assert again.get("last_update_check") == "2026-09-08"
        assert again.get_bool("check_updates")  # untouched default survives

    # --- command line as re-parsed by the primary GUI instance ---------------
    ns, unknown = cli.build_parser().parse_known_args(["--gui", "a.p7m", "--future-flag"])
    assert ns.gui and ns.paths == ["a.p7m"] and unknown == ["--future-flag"]

    # --- translations: po -> mo compiler and gettext plumbing ----------------
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    import compile_po
    root = Path(compile_po.ROOT)
    with tempfile.TemporaryDirectory() as td:
        written = compile_po.compile_all(Path(td), python=True, root=root)
        assert written == [Path(td) / "it" / "LC_MESSAGES" / f"{p7m_extractor.TEXTDOMAIN}.mo"]
        import gettext
        it = gettext.translation(p7m_extractor.TEXTDOMAIN, td, languages=["it"])
        assert it.gettext("Queued") == "In coda"
        assert it.gettext("Extracting… {percent}%") == "Estrazione in corso… {percent}%"
        assert it.gettext("not a translated string") == "not a translated string"
    # every msgid in the catalogue must exist in the source (adjacent string
    # literals split over lines are joined first)
    import re
    source = re.sub(r'"\s*\n\s*"', "", "\n".join(p.read_text(encoding="utf-8")
                                                    for p in sorted((root / "src" / "p7m_extractor").rglob("*.py"))))
    entries = compile_po.parse((root / "po" / "it.po").read_text(encoding="utf-8"))
    missing = [e["msgid"] for e in entries if e["msgid"] and e["msgid"] not in source]
    assert not missing, f"msgids not found in the source: {missing[:5]}"
    assert services.desktop_language() in services.LANGUAGES

    # --- icons: gdk-pixbuf must be able to sniff them ------------------------
    # It only looks for the <svg> element in the first 256 bytes; past that the
    # file is "not a valid icon" and `flatpak build-export` fails. A long
    # leading comment is enough to trigger it, so guard the offset here (pure
    # stdlib: the CI test job has no GdkPixbuf).
    icons = sorted((root / "data" / "icons").rglob("*.svg"))
    assert icons, "no icon SVGs found"
    for icon in icons:
        head = icon.read_bytes()
        offset = head.find(b"<svg")
        assert 0 <= offset <= 256, (
            f"{icon.name}: <svg> starts at byte {offset}; gdk-pixbuf only sniffs "
            "the first 256 bytes, so flatpak-builder would reject this icon")

    print("all tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
