#!/usr/bin/env python3
"""The wheels of pyHanko and of what it needs, as the `sources:` of the
Flatpak manifest's module: each with its URL and SHA-256 from PyPI, pure
ones once and binary ones for x86_64 and aarch64, so that the build needs
no network of its own and nothing is taken that was not pinned here.

    python3 tools/flatpak_wheels.py            prints the YAML block
    python3 tools/flatpak_wheels.py --write    puts it in the manifest, between the two marks
    python3 tools/flatpak_wheels.py --check    1 if the manifest's block is not this one
    python3 tools/flatpak_wheels.py --version  pyHanko's version alone, without the network

PINS is the one place where pyHanko's version is written: the Windows and
the portable Linux builds ask this file for it (.github/workflows/build.yml)
and take what goes with it from pip. To move to a newer pyHanko: change PINS
(pip install "pyhanko[etsi]==X" in a throw-away environment says which
versions go together), run --write, build the Flatpak (its build runs
tests/test_verify.py with these wheels). PYTHON is the runtime's Python
(GNOME 50: 3.13).
"""

import json
import sys
import urllib.request
from pathlib import Path

PYTHON = "cp313"
ARCHES = ("x86_64", "aarch64")
PINS = {
    "aiohappyeyeballs": "2.7.1", "aiohttp": "3.14.5", "aiosignal": "1.4.0", "asn1crypto": "1.5.1",
    "attrs": "26.1.0", "certifi": "2026.10.23", "cffi": "2.1.1", "cryptography": "50.0.2",
    "frozenlist": "1.8.0", "idna": "3.20", "lxml": "6.1.3", "multidict": "7.2.1", "oscrypto": "1.3.0",
    "propcache": "0.5.4", "pycparser": "3.12", "pyhanko": "0.38.1", "pyhanko-certvalidator": "0.33.0",
    "signxml": "5.2.0", "typing-extensions": "4.16.0", "tzlocal": "5.4.5", "uritools": "7.0.0",
    "xsdata": "26.10", "yarl": "1.25.1",
}
MANIFEST = Path(__file__).resolve().parent.parent / "build-aux" / "flatpak" / \
    "io.github.daniel_g_carrasco.p7m-extractor.yaml"
BEGIN, END = "      # wheels: begin (tools/flatpak_wheels.py)\n", "      # wheels: end\n"


def files_of(name: str, version: str) -> list[dict]:
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as answer:
        return [f for f in json.load(answer)["urls"] if f["packagetype"] == "bdist_wheel"]


def chosen(name: str, version: str) -> list[tuple[dict, str | None]]:
    """(the file, the architecture it is for or None for every one)."""
    files = files_of(name, version)
    pure = [f for f in files if f["filename"].endswith("-none-any.whl")]
    if pure:
        return [(pure[0], None)]
    out = []
    for arch in ARCHES:
        fitting = [f for f in files if "manylinux" in f["filename"] and f["filename"].endswith(f"_{arch}.whl")
                   and (f"-{PYTHON}-{PYTHON}-" in f["filename"] or "-abi3-" in f["filename"])]
        if not fitting:
            sys.exit(f"{name} {version}: no wheel for {PYTHON} on {arch}")
        # the one built for this Python before an abi3 one, the oldest glibc first
        fitting.sort(key=lambda f: ("-abi3-" in f["filename"], f["filename"]))
        out.append((fitting[0], arch))
    return out


def block() -> str:
    lines = [BEGIN]
    for name, version in sorted(PINS.items()):
        for wheel, arch in chosen(name, version):
            lines += ["      - type: file\n", f"        url: {wheel['url']}\n",
                      f"        sha256: {wheel['digests']['sha256']}\n"]
            if arch:
                lines.append(f"        only-arches: [{arch}]\n")
    return "".join([*lines, END])


def main() -> int:
    if "--version" in sys.argv:
        print(PINS["pyhanko"])
        return 0
    made = block()
    if "--check" not in sys.argv and "--write" not in sys.argv:
        print(made, end="")
        return 0
    text = MANIFEST.read_text(encoding="utf-8")
    there = text[text.index(BEGIN):text.index(END) + len(END)] if BEGIN in text and END in text else ""
    if "--write" in sys.argv:
        if not there:
            sys.exit("the manifest has no marks to write between")
        MANIFEST.write_text(text.replace(there, made), encoding="utf-8", newline="\n")
        print(f"{made.count('type: file')} wheels written in {MANIFEST.name}")
        return 0
    if there != made:
        print("the manifest's wheels are not what tools/flatpak_wheels.py gives today")
        return 1
    print("the manifest's wheels are the pinned ones")
    return 0


if __name__ == "__main__":
    sys.exit(main())
