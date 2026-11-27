#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assemble the verified source download, or publish a complete draft."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from collect_sources import INVENTORY, verify_archive
from package_inventory import sha256, verify_portable
from release_inventory import SUFFIX, read_report

INDEX = "release-sources.json"
NOTES = "release-notes.it.md"
PLATFORMS = {"windows": "windows-x64", "linux": "flatpak", "linux-portable": "linux-x64"}


def names(slug, tag):
    if not re.fullmatch(r"[a-z][a-z0-9-]*", slug) or not re.fullmatch(r"v\d+(?:\.\d+){1,3}", tag):
        raise ValueError("invalid product slug or stable tag")
    return {
        "installer": f"{slug}-setup-{tag}-windows-x64.exe",
        "portable": f"{slug}-{tag}-windows-x64-portable.zip",
        "flatpak": f"{slug}-{tag}-linux-x64.flatpak",
        "linux-portable": f"{slug}-{tag}-linux-x64-portable.tar.gz",
        "sources": f"{slug}-{tag}-sources.zip",
    }


def verify_linux_binary(archive, record, name, checksum):
    entry = record["components"]["linux:build"]
    source, = entry["files"]
    with ZipFile(archive) as outer, tempfile.TemporaryDirectory(prefix="linux-release-sources-") as work:
        nested = Path(work) / "build-sources.zip"
        with outer.open(source) as incoming, nested.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing)
        with ZipFile(nested) as zipped:
            provenance = json.loads(zipped.read("build-provenance.json"))
        if (provenance["bundle"] != name or provenance["sha256"] != checksum
                or provenance["commit"] != entry["version"]):
            raise ValueError(f"{name} differs from its source collection")


def assemble(slug, tag, binaries, archives, output):
    wanted = names(slug, tag)
    if output.name != wanted["sources"]:
        raise ValueError(f"the source archive must be named {wanted['sources']}")
    for role, file in binaries.items():
        if file.name != wanted[role]:
            raise ValueError(f"expected {wanted[role]}")
    for platform, archive in archives.items():
        if verify_archive(archive)["platform"] != PLATFORMS[platform]:
            raise ValueError(f"wrong source inventory platform: {platform}")
    with ZipFile(archives["windows"]) as archive:
        verify_portable(binaries["portable"], archive.read(INVENTORY))
    record = {"schema_version": 1, "slug": slug, "tag": tag,
              "binaries": {path.name: sha256(path) for path in binaries.values()},
              "platforms": {platform + ".zip": sha256(path) for platform, path in archives.items()}}
    with ZipFile(output, "x") as result:
        result.writestr(INDEX, json.dumps(record, indent=2) + "\n")
        for platform, file in archives.items():
            result.write(file, platform + ".zip")
    return verify_download(output, slug, tag)


def verify_download(path, slug, tag):
    expected = names(slug, tag)
    with ZipFile(path) as source, tempfile.TemporaryDirectory(prefix="release-sources-") as work:
        record = json.loads(source.read(INDEX))
        files = {platform + ".zip" for platform in PLATFORMS}
        binaries = set(expected.values()) - {expected["sources"]}
        if (record.get("schema_version") != 1 or record.get("slug") != slug or record.get("tag") != tag
                or set(record["binaries"]) != binaries or set(record["platforms"]) != files
                or sorted(source.namelist()) != sorted(files | {INDEX})):
            raise ValueError("source download does not cover the complete release")
        revision = None
        for platform, format_name in PLATFORMS.items():
            member = platform + ".zip"
            local = Path(work) / member
            with source.open(member) as stream, local.open("xb") as output:
                shutil.copyfileobj(stream, output)
            verified = verify_archive(local)
            if sha256(local) != record["platforms"][member] or verified["platform"] != format_name:
                raise ValueError(f"invalid corresponding sources: {platform}")
            if platform == "windows":
                revision = verified["components"]["project:project"]["version"]
            else:
                if verified["components"]["linux:build"]["version"] != revision:
                    raise ValueError(f"source revision differs for {platform}")
                binary = expected["flatpak" if platform == "linux" else platform]
                verify_linux_binary(local, verified, binary, record["binaries"][binary])
    return record


def finish(client, slug, tag, public_key):
    """Evaluate the draft, returning a message and editing it only when complete."""
    release = client.view()
    if not release.get("draft", False):
        return "already published"
    expected = names(slug, tag)
    binaries = set(expected.values()) - {expected["sources"]}
    signed = binaries | {expected["sources"]} | {name + SUFFIX for name in binaries}
    mandatory = signed | {name + ".minisig" for name in signed} | {NOTES}
    assets = {asset["name"]: asset for asset in release["assets"] if asset.get("state", "uploaded") == "uploaded"}
    missing = mandatory - assets.keys()
    if missing:
        return "the release stays a draft, still missing " + ", ".join(sorted(missing))
    try:
        with tempfile.TemporaryDirectory(prefix="release-draft-") as work:
            sources, notes = (client.download(name, Path(work)) for name in (expected["sources"], NOTES))
            signature = client.download(expected["sources"] + ".minisig", Path(work))
            subprocess.run(["minisign", "-V", "-P", public_key, "-m", str(sources), "-x", str(signature)],
                           check=True)
            manifest = verify_download(sources, slug, tag)
            for name, checksum in manifest["binaries"].items():
                if assets[name].get("digest") != "sha256:" + checksum:
                    raise ValueError(f"release checksum differs from sources for {name}")
                inventory = client.download(name + SUFFIX, Path(work))
                signature = client.download(name + SUFFIX + ".minisig", Path(work))
                subprocess.run(["minisign", "-V", "-P", public_key, "-m", str(inventory), "-x", str(signature)],
                               check=True)
                read_report(inventory, name, checksum)
            text = notes.read_text(encoding="utf-8")
            header, _, body = text.partition("\n")
            if header != f"<!-- release-notes: it {tag} -->" or not re.search(r"^[-*] +\S", body, re.M):
                raise ValueError("Italian notes do not match the release")
    except (OSError, ValueError, KeyError, BadZipFile, subprocess.CalledProcessError) as error:
        return f"the release stays a draft, {error}"
    client.publish()
    return f"release {tag} published"


def pick_release(pages, tag):
    """The one release (draft or published) with this tag, from the API's pages."""
    found = [release for page in pages for release in page if release.get("tag_name") == tag]
    if len(found) != 1:
        raise ValueError(f"expected one release for {tag}, found {len(found)}")
    return found[0]


class GitHub:
    def __init__(self, repo, tag):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("invalid GitHub repository")
        self.repo, self.tag = repo, tag

    def view(self):
        # GitHub's "release by tag" answers for published releases only: a
        # draft is found in the list of releases, by its tag name.
        pages = json.loads(subprocess.check_output(
            ["gh", "api", "--paginate", "--slurp", f"repos/{self.repo}/releases?per_page=100"]))
        return pick_release(pages, self.tag)

    def download(self, name, folder):
        subprocess.run(["gh", "release", "download", self.tag, "--repo", self.repo,
                        "--pattern", name, "--dir", str(folder)], check=True)
        return folder / name

    def publish(self):
        subprocess.run(["gh", "release", "edit", self.tag, "--repo", self.repo,
                        "--draft=false", "--latest"], check=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="command", required=True)
    collect = modes.add_parser("assemble", help="combine already verified platform source archives and binary digests")
    publish = modes.add_parser("publish-if-complete")
    for mode in (collect, publish):
        mode.add_argument("--slug", required=True)
        mode.add_argument("--tag", required=True)
    for key in ("windows", "linux", "installer", "portable", "flatpak", "linux-portable", "linux-portable-sources",
                "output"):
        collect.add_argument("--" + key, type=Path, required=True)
    publish.add_argument("--repo", required=True)
    publish.add_argument("--public-key", required=True)
    args = parser.parse_args(argv)
    try:
        names(args.slug, args.tag)
        if args.command == "assemble":
            binaries = {key: getattr(args, key) for key in ("installer", "portable", "flatpak")}
            binaries["linux-portable"] = args.linux_portable
            archives = {"windows": args.windows, "linux": args.linux, "linux-portable": args.linux_portable_sources}
            assemble(args.slug, args.tag, binaries, archives, args.output)
            print(f"Source download SHA-256 {sha256(args.output)}")
        else:
            print(finish(GitHub(args.repo, args.tag), args.slug, args.tag, args.public_key))
    except (OSError, ValueError, KeyError, BadZipFile, subprocess.CalledProcessError) as error:
        print(f"Release check failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
