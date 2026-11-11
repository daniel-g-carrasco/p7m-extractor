#!/usr/bin/env python3
"""The verification of signatures: what is said of each outcome (plain
values, always run), and the checking itself on envelopes signed here with
a certifier made for the purpose (run where pyHanko is installed). Nothing
here uses the network: what needs the European trusted lists and a
certifier's revocation server is tried by hand on public documents.

    python tests/test_verify.py --make-sample out.pdf.p7m.p7m

writes a document signed by Anna Bianchi and then, around it, by Bruno
Verdi: what the builds are tried on (their certifier is in no trusted list,
so no build may call them valid).

The rule the tests hold: nothing is called valid unless the revocation was
checked, and a library error is never a pass.
"""

import asyncio
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from p7m_extractor.app import verify  # noqa: E402
from p7m_extractor.core import verdict  # noqa: E402
from p7m_extractor.core.verdict import FAILED, INDETERMINATE, INTEGRITY_ONLY, PASSED, Signer  # noqa: E402

NOW = datetime.now(timezone.utc)


class WordsTest(unittest.TestCase):
    """core/verdict.py: values in, words out."""

    def test_a_pass_says_what_kind_of_certificate(self):
        base = dict(name="Anna Bianchi", intact=True, status=PASSED)
        self.assertIn("qualified certificate on a secure device",
                      verdict.summary(Signer(**base, listed=True, declares_qualified=True, declares_device=True)))
        self.assertTrue(verdict.summary(Signer(**base, listed=True, declares_qualified=True)).endswith("qualified certificate"))
        # a certificate that calls itself qualified, from a certifier that is not in the lists, is not
        self.assertIn("not with a qualified", verdict.summary(Signer(**base, listed=False, declares_qualified=True)))

    def test_every_other_outcome_says_why(self):
        changed = Signer(name="x", status=FAILED, reason="HASH_FAILURE")
        self.assertIn("changed after it was signed", verdict.summary(changed))
        expired = Signer(name="x", intact=True, status=INDETERMINATE, reason="OUT_OF_BOUNDS_NO_POE")
        self.assertTrue(verdict.summary(expired).startswith("Not established"))
        self.assertIn("no time stamp", verdict.summary(expired))
        self.assertIn("something new", verdict.summary(Signer(name="x", status=INDETERMINATE, reason="SOMETHING_NEW")))

    def test_without_the_network_nothing_is_called_valid(self):
        offline = Signer(name="x", intact=True, status=INTEGRITY_ONLY, declares_qualified=True)
        self.assertNotIn("Valid", verdict.summary(offline))
        self.assertIn("no network", verdict.summary(offline))
        kept = Signer(name="x", intact=True, status=INTEGRITY_ONLY, listed=True)
        self.assertIn("trusted lists kept", verdict.summary(kept))
        self.assertNotIn("Valid", verdict.summary(kept))

    def test_the_report_tells_a_proven_time_from_a_written_one(self):
        when = datetime(2026, 3, 4, 10, 30, tzinfo=timezone.utc)
        written = "\n".join(verdict.lines(Signer(name="Anna", intact=True, claimed_time=when)))
        self.assertIn("not proven by a time stamp", written)
        proven = "\n".join(verdict.lines(Signer(name="Anna", intact=True, claimed_time=when, proven_time=when)))
        self.assertIn("proven by a time stamp", proven)
        self.assertNotIn("not proven", proven)
        self.assertIn("Time of signing: not in the file", "\n".join(verdict.lines(Signer(name="Anna", intact=True))))
        self.assertEqual(verdict.details(Signer(name="Anna", intact=True))[0], ("Signed by", "Anna"))

    def test_the_headline_counts_and_gives_the_worst(self):
        good = Signer(name="Anna", intact=True, status=PASSED, listed=True, declares_qualified=True)
        unsure = Signer(name="Bruno", intact=True, status=INDETERMINATE, reason="OUT_OF_BOUNDS_NO_POE")
        self.assertEqual(verdict.headline([[good]]), ("One signature", "Valid"))
        self.assertEqual(verdict.headline([[good, good]]), ("2 signatures, side by side", "All valid"))
        title, outcome = verdict.headline([[good], [unsure]])
        self.assertEqual(title, "2 signatures, one inside the other")
        self.assertTrue(outcome.startswith("Bruno: Not established"))
        self.assertIn("3 signatures in 2 envelopes", verdict.headline([[good, good], [good]])[0])
        self.assertEqual([verdict.state_word(s) for s in (good, unsure, Signer(name="x"), Signer(name="y", intact=True))],
                         ["Valid", "Not established", "Not valid", "Intact"])

    def test_the_worst_signature_is_the_files_state(self):
        good, unsure = Signer(name="a", intact=True, status=PASSED), Signer(name="b", intact=True, status=INDETERMINATE)
        bad = Signer(name="c", status=FAILED, reason="HASH_FAILURE")
        self.assertEqual(verdict.worst([good, good]), PASSED)
        self.assertEqual(verdict.worst([good, unsure]), INDETERMINATE)
        self.assertEqual(verdict.worst([good, unsure, bad]), FAILED)
        self.assertEqual(verdict.worst([good, Signer(name="d", intact=True)]), INTEGRITY_ONLY)
        self.assertEqual(verdict.worst([]), FAILED)


class CommandLineTest(unittest.TestCase):
    def test_a_name_the_console_cannot_write_does_not_stop_the_command(self):
        import io

        from p7m_extractor.__main__ import never_failing
        written = io.BytesIO()
        stream = io.TextIOWrapper(written, encoding="cp1252")       # Windows' code page, when the output goes to a file
        with self.assertRaises(UnicodeEncodeError):
            print("Signed by: Łukasz", file=stream)
            stream.flush()
        written = io.BytesIO()
        stream = io.TextIOWrapper(written, encoding="cp1252")
        never_failing(stream)
        print("Signed by: Łukasz Żółć → può", file=stream)
        stream.flush()
        self.assertEqual(written.getvalue().decode("cp1252").strip(), "Signed by: ?ukasz ?ó?? ? può")
        never_failing(io.BytesIO())                                 # what is no text stream is left alone


def certifier_and_signers():
    """A certifier of the tests' own and two people it certifies, one with
    a certificate that expired a year ago: (root, [(cert, key), ...]) as
    asn1crypto values."""
    from asn1crypto import keys
    from asn1crypto import x509 as asn1_x509
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    def name(common, **more):
        parts = [x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"), x509.NameAttribute(NameOID.COMMON_NAME, common)]
        if "org" in more:
            parts.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, more["org"]))
        if "serial" in more:
            parts.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, more["serial"]))
        return x509.Name(parts)

    def key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def as_asn1(cert, private):
        der = private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER)), keys.PrivateKeyInfo.load(der)

    root_key = key()
    root_name = name("Certifier of the Tests", org="P7M Extractor tests")
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name).public_key(root_key.public_key())
            .serial_number(1).not_valid_before(NOW - timedelta(days=3650)).not_valid_after(NOW + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(root_key, hashes.SHA256()))
    people = []
    for number, (common, start, end) in enumerate((
            ("Anna Bianchi", NOW - timedelta(days=30), NOW + timedelta(days=700)),
            ("Bruno Verdi", NOW - timedelta(days=800), NOW - timedelta(days=365))), 2):
        person_key = key()
        cert = (x509.CertificateBuilder().subject_name(name(common, org="Studio", serial=f"TINIT-TEST{number}"))
                .issuer_name(root_name).public_key(person_key.public_key()).serial_number(number)
                .not_valid_before(start).not_valid_after(end)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(False, True, False, False, False, False, False, False, False), critical=True)
                .sign(root_key, hashes.SHA256()))
        people.append(as_asn1(cert, person_key))
    return as_asn1(root, root_key)[0], people


def envelope(content: bytes, root, people) -> bytes:
    """A .p7m with the document inside, signed by each of those people."""
    from asn1crypto import cms
    from pyhanko.sign import signers
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    signed = None
    for cert, private in people:
        signer = signers.SimpleSigner(signing_cert=cert, signing_key=private,
                                      cert_registry=SimpleCertificateStore.from_certs([root]))
        one = asyncio.run(signer.async_sign_general_data(content, "sha256", detached=False, use_cades=True))["content"]
        if signed is None:
            signed = one
        else:       # a second signature next to the first: its SignerInfo and its certificate join the envelope
            signed["signer_infos"] = cms.SignerInfos([*signed["signer_infos"], one["signer_infos"][0]])
            signed["certificates"] = cms.CertificateSet([*signed["certificates"], *one["certificates"]])
    return cms.ContentInfo({"content_type": "signed_data", "content": signed}).dump()


@unittest.skipUnless(verify.available(), "pyHanko is not installed")
class CheckingTest(unittest.TestCase):
    CONTENT = b"%PDF-1.4 the document that was signed\n" * 50

    @classmethod
    def setUpClass(cls):
        from pyhanko_certvalidator.registry import SimpleTrustManager
        cls.root, cls.people = certifier_and_signers()
        cls.trust = SimpleTrustManager.build([cls.root])
        cls.anna = envelope(cls.CONTENT, cls.root, cls.people[:1])
        cls.both = envelope(cls.CONTENT, cls.root, cls.people)

    def test_without_the_network_only_the_integrity_is_claimed(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))      # no lists kept there
        (signer,), = verify.verify_bytes(self.anna, online=False, lists_folder=folder)
        self.assertTrue(signer.intact)
        self.assertEqual((signer.status, signer.listed), (INTEGRITY_ONLY, None))
        self.assertEqual((signer.name, signer.organisation, signer.identifier), ("Anna Bianchi", "Studio", "TINIT-TEST2"))
        self.assertEqual(signer.issuer, "Certifier of the Tests")
        self.assertLess(abs(signer.claimed_time - NOW), timedelta(minutes=5))
        self.assertFalse(signer.declares_qualified)
        self.assertEqual(list(folder.iterdir()), [])                         # and nothing was written

    def test_a_document_changed_after_the_signature_fails(self):
        changed = self.anna.replace(b"the document that was signed", b"the document that was forged", 1)
        self.assertNotEqual(changed, self.anna)
        for online in (False, True):
            (signer,), = verify.verify_bytes(changed, online=online, trust=self.trust)
            self.assertEqual((signer.status, signer.reason, signer.intact), (FAILED, "HASH_FAILURE", False))
            self.assertEqual(signer.name, "Anna Bianchi")                    # who it claims to be from is still said

    def test_a_chain_in_order_is_not_a_pass_without_the_revocation(self):
        # the tests' certificates name no revocation server: with the network
        # "on" the revocation cannot be had, and the outcome is not a pass
        (signer,), = verify.verify_bytes(self.anna, online=True, trust=self.trust)
        self.assertTrue(signer.intact)
        self.assertEqual((signer.status, signer.reason), (INDETERMINATE, "REVOCATION_UNKNOWN"), signer.detail)
        self.assertIn("revoked could not be established", verdict.summary(signer))
        # offline the chain is followed and still nothing is called valid
        (signer,), = verify.verify_bytes(self.anna, online=False, trust=self.trust)
        self.assertEqual(signer.status, INTEGRITY_ONLY)
        self.assertIs(signer.listed, False)                                  # a chain, but to no qualified certifier

    def test_a_certifier_that_is_not_trusted(self):
        from pyhanko_certvalidator.registry import SimpleTrustManager
        other_root, _people = certifier_and_signers()
        for online in (False, True):
            (signer,), = verify.verify_bytes(self.anna, online=online, trust=SimpleTrustManager.build([other_root]))
            self.assertTrue(signer.intact)
            self.assertEqual((signer.status, signer.reason, signer.listed),
                             (INDETERMINATE, "NO_CERTIFICATE_CHAIN_FOUND", False))

    def test_every_signature_of_the_envelope_is_checked(self):
        (anna, bruno), = verify.verify_bytes(self.both, online=False, trust=self.trust)
        self.assertEqual((anna.name, bruno.name), ("Anna Bianchi", "Bruno Verdi"))
        self.assertTrue(anna.intact and bruno.intact)
        self.assertLess(bruno.valid_until, NOW)                              # his certificate expired a year ago
        self.assertEqual(verdict.worst([anna, bruno]), INTEGRITY_ONLY)

    def test_an_expired_certificate_is_not_established_and_not_a_forgery(self):
        (_anna, bruno), = verify.verify_bytes(self.both, online=True, trust=self.trust)
        self.assertEqual(bruno.status, INDETERMINATE, (bruno.reason, bruno.detail))
        self.assertTrue(bruno.intact)
        self.assertFalse(bruno.held_at_claimed_time)        # he "signed" today, a year after his certificate ended

    def test_an_envelope_inside_another_is_checked_layer_by_layer(self):
        # file.pdf.p7m.p7m: Bruno signed the file Anna had signed
        nested = envelope(self.anna, self.root, self.people[1:])
        outer, inner = verify.verify_bytes(nested, online=False, trust=self.trust)
        self.assertEqual([s.name for s in outer], ["Bruno Verdi"])
        self.assertEqual([s.name for s in inner], ["Anna Bianchi"])
        self.assertTrue(outer[0].intact and inner[0].intact)
        title, _outcome = verdict.headline([outer, inner])
        self.assertIn("one inside the other", title)
        self.assertIn("Outermost", verdict.layer_caption(0, 2))
        self.assertIn("Innermost", verdict.layer_caption(1, 2))
        # the document changed inside the inner envelope: the inner signature
        # fails, and so does the outer one, which signed the inner envelope as it was
        forged = nested.replace(b"the document that was signed", b"the document that was forged", 1)
        outer, inner = verify.verify_bytes(forged, online=False, trust=self.trust)
        self.assertEqual((outer[0].status, inner[0].status), (FAILED, FAILED))

    def test_five_envelopes_deep(self):
        deep = self.anna
        for _again in range(4):
            deep = envelope(deep, self.root, self.people[:1])
        layers = verify.verify_bytes(deep, online=False, trust=self.trust)
        self.assertEqual([len(layer) for layer in layers], [1, 1, 1, 1, 1])
        self.assertTrue(all(layer[0].intact for layer in layers))
        self.assertIn("3 of 5", verdict.layer_caption(2, 5))
        self.assertIn("5 signatures, one inside the other", verdict.headline(layers)[0])

    def test_what_is_no_p7m_is_said_so(self):
        from p7m_extractor.data.cms import BerError
        with self.assertRaises(BerError):
            verify.verify_bytes(b"%PDF-1.4 not an envelope", online=False)

    def test_the_lists_are_kept_byte_for_byte(self):
        # a list with Windows' line ends, as the Italian one has: read back
        # as it was written (pyHanko's own file cache turns them, and the
        # list's signature no longer holds)
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        text = "<?xml version='1.0'?>\r\n<List>\r\n  <Name>café</Name>\n</List>\r\n"
        kept = verify._lists_kept(folder, timedelta(hours=1))
        with self.assertRaises(KeyError):
            kept["https://example/list.xml"]
        kept["https://example/list.xml"] = text
        self.assertEqual(verify._lists_kept(folder, timedelta(hours=1))["https://example/list.xml"], text)
        with self.assertRaises(KeyError):                                    # too old for this caller
            verify._lists_kept(folder, timedelta(0))["https://example/list.xml"]
        self.assertIsNotNone(verify.lists_age(folder))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--make-sample":
        made_root, made_people = certifier_and_signers()
        inner = envelope(CheckingTest.CONTENT, made_root, made_people[:1])
        Path(sys.argv[2]).write_bytes(envelope(inner, made_root, made_people[1:]))
        print(f"sample written: {sys.argv[2]}")
        sys.exit(0)
    unittest.main()
