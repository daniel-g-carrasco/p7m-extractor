#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fetch what ties a Windows bundle's inventory to its corresponding sources.

For collect_sources.py, which verifies all of it: for every MSYS2 component,
the binary package and the source package with their signatures, from the
official MSYS2 repositories; for every wheel, its source distribution from
PyPI, checked against the digest PyPI publishes; for the project, the Git
archive of the built commit. The receipts go to <cache>/inputs.json, next to
the downloads, with paths relative to it.

Nothing here is trusted on its own: collect_sources.py checks the MSYS2
signatures against the pinned public keyring, ties PKGBUILD to the binary's
BUILDINFO, every declared source to its checksum, and every bundled file to
the binary it came from. This module only fetches, by name and version, from
fixed origins, and checks the binaries against the lock the build installed
them from.
"""

from __future__ import annotations

import argparse
import json
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from urllib.parse import quote, unquote, urlsplit
from urllib.request import Request, urlopen
from zipfile import ZipFile

from collect_sources import relative_path, stream_digest, tar_reader, wanted_components
from package_inventory import sha256

BINARY_REPO = "https://repo.msys2.org/mingw/ucrt64"
SOURCE_REPO = "https://repo.msys2.org/mingw/sources"
PYPI = "https://pypi.org/pypi"
# msys2.gpg from msys2-keyring 1~20260814-1 (package SHA-256
# a9a02c41bc14eb0965fb23b7e7d43a1d0eb20d9e70cbfeb193fcbf68bb0dc5d0), as installed
# by MSYS2 and kept in build-aux/windows/msys2-keyring/.
KEYRING_SHA256 = "1257d4ccc536c53333445a618039af4c3ea3f56b96601de9af89151ea529c19a"
CHUNK = 1 << 20
ATTEMPTS = 3


def check_keyring(path):
    """The keyring collect_sources.py will use is the pinned one."""
    if sha256(path) != KEYRING_SHA256:
        raise ValueError(f"the MSYS2 keyring differs from the pinned one: {path}")


def read_lock(path):
    """{archive name: SHA-256} from a lock of 'checksum  file' lines."""
    pins = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        checksum, name = line.split()
        pins[name] = checksum.lower()
    return pins


_LOCKS: dict[Path, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _lock(target):
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(Path(target).resolve(), threading.Lock())


def fetch(url, target, checksum=None):
    """Download url to target, once: two components built from the same
    MSYS2 base share a source package, and wait for each other here."""
    with _lock(target):
        return _fetch(url, target, checksum)


def _fetch(url, target, checksum):
    if not target.exists():
        part = target.with_name(target.name + ".part")
        for attempt in range(1, ATTEMPTS + 1):
            try:
                request = Request(url, headers={"User-Agent": "source-collection"})
                with urlopen(request, timeout=300) as response, part.open("wb") as output:
                    shutil.copyfileobj(response, output, CHUNK)
                break
            except OSError:
                part.unlink(missing_ok=True)
                if attempt == ATTEMPTS:
                    raise
                time.sleep(5 * attempt)
        part.replace(target)
    if checksum is not None and sha256(target) != checksum:
        raise ValueError(f"download checksum differs: {target.name}")
    return target


def msys2_files(component, binary_repo=BINARY_REPO, source_repo=SOURCE_REPO):
    """(binary name, binary URL, source name, source URL) of an MSYS2 component."""
    name, base, version = component["name"], component["base"], component["version"]
    binary = f"{name}-{version}-any.pkg.tar.zst"
    source = f"{base}-{version}.src.tar.zst"
    return binary, f"{binary_repo}/{quote(binary)}", source, f"{source_repo}/{quote(source)}"


def msys2_receipt(component, folder, pins, binary_repo=BINARY_REPO, source_repo=SOURCE_REPO):
    binary, binary_url, source, source_url = msys2_files(component, binary_repo, source_repo)
    if binary not in pins:
        raise ValueError(f"the bundled MSYS2 package is not in the lock: {binary}")
    fetch(binary_url, folder / binary, pins[binary])
    fetch(binary_url + ".sig", folder / (binary + ".sig"))
    fetch(source_url, folder / source)
    fetch(source_url + ".sig", folder / (source + ".sig"))
    return {"version": component["version"], "binary": binary, "binary_signature": binary + ".sig",
            "source": source, "source_signature": source + ".sig"}


def archive_members(path, zstd="zstd"):
    """{member: SHA-256} of every regular file in a source archive."""
    found = {}
    if path.suffix == ".zip":
        with ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                name = str(relative_path(info.filename))
                if name in found:
                    raise ValueError(f"duplicate archive member: {name}")
                with archive.open(info) as stream:
                    found[name] = stream_digest(stream)
        return found
    with tar_reader(path, zstd) as archive:
        for entry in archive:
            if not entry.isfile():
                continue
            name = str(relative_path(entry.name))
            if name in found:
                raise ValueError(f"duplicate archive member: {name}")
            with archive.extractfile(entry) as stream:
                found[name] = stream_digest(stream)
    return found


def adapter_receipt(component, rows, source, zstd="zstd"):
    """A wheel's or the project's receipt: the source archive, the bundled
    files it accounts for, and the archive's members."""
    members = archive_members(source, zstd)
    if not members:
        raise ValueError(f"empty source archive: {source.name}")
    return {"version": component["version"], "source": source.name, "source_sha256": sha256(source),
            "build_inputs": {row["source"]: row["sha256"] for row in rows},
            "required_members": members}


def pypi_sdist(name, version, folder, index=PYPI):
    """The single source distribution PyPI publishes for name==version."""
    with urlopen(f"{index}/{quote(name)}/{quote(version)}/json", timeout=60) as response:
        files = json.load(response)["urls"]
    sdists = [item for item in files if item["packagetype"] == "sdist"]
    if len(sdists) != 1:
        raise ValueError(f"expected one source distribution on PyPI: {name} {version}")
    sdist = sdists[0]
    filename = Path(unquote(urlsplit(sdist["url"]).path)).name
    if filename != sdist["filename"] or PurePosixPath(filename).name != filename:
        raise ValueError(f"unexpected source distribution name: {filename}")
    return fetch(sdist["url"], folder / filename, sdist["digests"]["sha256"].lower())


def receipts(inventory, folder, pins, project_archive, *, zstd="zstd", index=PYPI,
             binary_repo=BINARY_REPO, source_repo=SOURCE_REPO, workers=6):
    """{component: receipt} for every component the source collection wants."""
    wanted = wanted_components(inventory)
    rows = {}
    for row in inventory["files"]:
        rows.setdefault(row["component"], []).append(row)

    def one(item):
        key, component = item
        kind = component["kind"]
        if kind == "msys2":
            return key, msys2_receipt(component, folder, pins, binary_repo, source_repo)
        if kind == "wheel":
            source = pypi_sdist(component["name"], component["version"], folder, index)
        elif kind == "project":
            source = folder / project_archive.name
            if source.resolve() != project_archive.resolve():
                shutil.copyfile(project_archive, source)
        else:
            raise ValueError(f"no source adapter for {key} ({kind})")
        return key, adapter_receipt(component, rows.get(key, []), source, zstd)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(pool.map(one, sorted(wanted.items())))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True, help="the bundle's licenses/inventory.json")
    parser.add_argument("--msys2-lock", type=Path, required=True, help="the MSYS2 archives the build installed")
    parser.add_argument("--project-archive", type=Path, required=True, help="git archive --format=zip of the commit")
    parser.add_argument("--keyring", type=Path, required=True, help="the pinned MSYS2 public keyring")
    parser.add_argument("--cache", type=Path, required=True, help="a new folder for the downloads and inputs.json")
    parser.add_argument("--zstd", default="zstd")
    args = parser.parse_args(argv)
    check_keyring(args.keyring)
    inventory = json.loads(args.inventory.read_bytes())
    args.cache.mkdir(parents=True)
    found = receipts(inventory, args.cache, read_lock(args.msys2_lock), args.project_archive, zstd=args.zstd)
    (args.cache / "inputs.json").write_text(
        json.dumps({"schema_version": 1, "components": found}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    kinds = {}
    for key in found:
        kinds[key.split(":", 1)[0]] = kinds.get(key.split(":", 1)[0], 0) + 1
    print("receipts:", ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
