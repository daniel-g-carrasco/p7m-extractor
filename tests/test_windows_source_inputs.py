# SPDX-License-Identifier: GPL-3.0-or-later
"""The receipts that tie the Windows bundle to its sources, without the network."""

import hashlib
import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _setup

with mock.patch.object(sys, "path", [str(_setup.ROOT / "tools"), *sys.path]):
    import collect_sources as cs
    import release_gate
    import windows_source_inputs as wsi

KEYRING = _setup.ROOT / "build-aux/windows/msys2-keyring/msys2.gpg"


def sdist(path, contents):
    with tarfile.open(path, "w:gz") as archive:
        for name, data in contents.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))


class WindowsSourceInputsTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def test_the_msys2_files_are_named_after_the_inventory(self):
        component = {"name": "mingw-w64-ucrt-x86_64-cairo", "base": "mingw-w64-cairo", "version": "1.18.6-2"}
        binary, binary_url, source, source_url = wsi.msys2_files(component)
        self.assertEqual(binary, "mingw-w64-ucrt-x86_64-cairo-1.18.6-2-any.pkg.tar.zst")
        self.assertEqual(binary_url, "https://repo.msys2.org/mingw/ucrt64/" + binary)
        self.assertEqual(source, "mingw-w64-cairo-1.18.6-2.src.tar.zst")
        self.assertEqual(source_url, "https://repo.msys2.org/mingw/sources/" + source)
        epoch = dict(component, version="1~2.0-1")
        self.assertEqual(wsi.msys2_files(epoch)[1].rsplit("/", 1)[1],
                         "mingw-w64-ucrt-x86_64-cairo-1~2.0-1-any.pkg.tar.zst")

    def test_the_lock_is_read_and_a_package_outside_it_is_refused(self):
        lock = self.tmp / "msys2-packages.lock"
        lock.write_text("# comment\n\nABCDEF  a-1-1-any.pkg.tar.zst\n", encoding="utf-8")
        self.assertEqual(wsi.read_lock(lock), {"a-1-1-any.pkg.tar.zst": "abcdef"})
        component = {"name": "b", "base": "b", "version": "1-1"}
        with mock.patch.object(wsi, "fetch") as fetch, self.assertRaisesRegex(ValueError, "not in the lock"):
            wsi.msys2_receipt(component, self.tmp, wsi.read_lock(lock))
        fetch.assert_not_called()

    def test_a_download_with_another_checksum_is_refused(self):
        target = self.tmp / "file"
        target.write_bytes(b"something else")
        with self.assertRaisesRegex(ValueError, "checksum differs"):
            wsi.fetch("https://example.invalid/file", target, hashlib.sha256(b"expected").hexdigest())

    def test_the_keyring_is_the_pinned_one(self):
        wsi.check_keyring(KEYRING)
        other = self.tmp / "msys2.gpg"
        other.write_bytes(KEYRING.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "pinned"):
            wsi.check_keyring(other)

    def test_a_wheel_receipt_is_accepted_by_collect_sources(self):
        source = self.tmp / "certifi-1.0.tar.gz"
        sdist(source, {"certifi-1.0/LICENSE": b"licence", "certifi-1.0/certifi/core.py": b"code"})
        component = {"kind": "wheel", "name": "certifi", "version": "1.0"}
        rows = [{"target": "_internal/certifi/core.py", "component": "wheel:certifi",
                 "source": "certifi/core.py", "sha256": hashlib.sha256(b"compiled").hexdigest()}]
        receipt = wsi.adapter_receipt(component, rows, source)
        self.assertEqual(set(receipt["required_members"]), {"certifi-1.0/LICENSE", "certifi-1.0/certifi/core.py"})
        self.assertEqual(receipt["build_inputs"], {"certifi/core.py": rows[0]["sha256"]})
        found, signature, detail = cs.verify_adapter(component, rows, self.tmp, receipt, "zstd")
        self.assertEqual((found, signature), (source, None))
        self.assertEqual(len(detail["members"]), 2)

    def test_only_known_kinds_get_a_receipt_and_generated_files_none(self):
        inventory = {"components": {"generated:staging": {"kind": "generated", "name": "staging"},
                                    "other:thing": {"kind": "other", "name": "thing", "version": "1"}},
                     "files": []}
        with self.assertRaisesRegex(ValueError, "no source adapter"):
            wsi.receipts(inventory, self.tmp, {}, self.tmp / "project.zip", workers=1)


class DraftLookupTest(unittest.TestCase):
    def test_a_draft_is_found_by_its_tag_in_the_list(self):
        pages = [[{"tag_name": "v2.0.0", "draft": True}, {"tag_name": "v1.0.0", "draft": False}]]
        self.assertTrue(release_gate.pick_release(pages, "v2.0.0")["draft"])

    def test_no_release_or_two_with_the_same_tag_are_refused(self):
        with self.assertRaises(ValueError):
            release_gate.pick_release([[{"tag_name": "v1.0.0"}]], "v2.0.0")
        with self.assertRaises(ValueError):
            release_gate.pick_release([[{"tag_name": "v2.0.0"}], [{"tag_name": "v2.0.0"}]], "v2.0.0")


if __name__ == "__main__":
    unittest.main()
