"""The signatures of a .p7m checked, as far as a program that is no
qualified validation service can go (docs: the README's "Verifying").

With the network: the European list of trusted lists and, from it, the
national ones (each one's own signature checked), the certificate's chain
up to a certifier listed there as qualified, its revocation asked of the
certifier (OCSP or CRL), the time stamps, and the outcome ETSI EN 319 102-1
gives. Without it: that the document is what was signed and that the
signature is the certificate's own, and nothing more is claimed.

The checking is pyHanko's (MIT), not ours: a wrong "valid" is the worst
thing this program could say, and that code is read by more eyes. It is
imported inside the functions, so the program starts without it and says
plainly when it is missing.

No document leaves the computer: the lists come from the Commission and
the national bodies, and the certifier is asked about a certificate by its
serial number.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from p7m_extractor.core.verdict import FAILED, INDETERMINATE, INTEGRITY_ONLY, PASSED, Signer
from p7m_extractor.data.cms import BerError, decode_container, extract_econtent

LISTS_FRESH = timedelta(hours=24)       # the trusted lists are asked for again after a day
LISTS_KEPT = timedelta(days=3650)       # without the network the copy kept is used, however old, and its age is said
NETWORK_ERRORS = (OSError, asyncio.TimeoutError)
# not established because of time alone: a certificate expired or revoked since, and no time stamp
TIME_REASONS = ("OUT_OF_BOUNDS_NO_POE", "OUT_OF_BOUNDS_NOT_REVOKED", "REVOKED_NO_POE", "REVOKED_CA_NO_POE")


class ListNotKept(OSError):
    """Offline, and a trusted list that is needed is not among those kept."""


class VerifyUnavailable(Exception):
    """The library that checks signatures is not installed."""


def available() -> bool:
    try:
        import pyhanko.sign.validation.ades  # noqa: F401
        import pyhanko.sign.validation.qualified.eutl_fetch  # noqa: F401
    except ImportError:
        return False
    return True


def verify_file(path: Path, online: bool = True, lists_folder: Path | None = None,
                trust=None) -> list[list[Signer]]:
    return verify_bytes(Path(path).read_bytes(), online, lists_folder, trust)


def verify_bytes(raw: bytes, online: bool = True, lists_folder: Path | None = None,
                 trust=None) -> list[list[Signer]]:
    """Every signature of the file, checked: one list per envelope, the
    outermost first (a file.pdf.p7m.p7m is an envelope inside another, each
    signing the file as the one inside it left it), and in each the
    signatures that stand side by side. lists_folder keeps the trusted lists
    between runs; trust is a trust manager to use instead of the European
    lists (the tests' own certifier). BerError when the file is no .p7m;
    VerifyUnavailable without the library."""
    if not available():
        raise VerifyUnavailable("pyHanko")
    _bundled_certificates()
    envelopes = []
    der = decode_container(raw)
    while True:
        content = extract_econtent(der)
        envelopes.append((der, content))
        try:                                    # what was signed is an envelope too?
            der = decode_container(content)
            extract_econtent(der)
        except BerError:
            break
    with _library_quiet():
        return asyncio.run(_verify(envelopes, online, lists_folder, trust))


async def _verify(envelopes, online: bool, lists_folder: Path | None, trust) -> list[list[Signer]]:
    from asn1crypto import cms

    parsed = [(cms.ContentInfo.load(der)["content"], content) for der, content in envelopes]
    countries = set().union(*(_countries(signed) for signed, _content in parsed))
    lists_problem = ""
    if trust is None:
        try:
            trust = await _trusted_lists(countries, online, lists_folder)
        except Exception as e:      # no network, a list that does not parse, a library without the lists
            trust, lists_problem = None, f"{type(e).__name__}: {e}"
            if online:
                # the fallback: the lists kept from an earlier run, if any,
                # and from here on the rules of a check without the network
                # (nothing is called valid)
                online = False
                try:
                    trust = await _trusted_lists(countries, False, lists_folder)
                except Exception:
                    trust = None
    return [await _envelope(signed, content, trust, online, lists_problem) for signed, content in parsed]


async def _envelope(signed, content: bytes, trust, online: bool, lists_problem: str) -> list[Signer]:
    """The signatures of one envelope."""
    from asn1crypto import cms

    digests: dict[str, bytes] = {}
    out = []
    for signer_info in signed["signer_infos"]:
        algorithm = signer_info["digest_algorithm"]["algorithm"].native
        if algorithm not in digests:
            digests[algorithm] = hashlib.new(algorithm, content).digest()
        # the library reads one signature per envelope: each gets an envelope
        # of its own, without the document (its digest is given instead)
        one = cms.SignedData({
            "version": signed["version"], "digest_algorithms": signed["digest_algorithms"],
            "encap_content_info": {"content_type": signed["encap_content_info"]["content_type"]},
            "certificates": signed["certificates"], "signer_infos": [signer_info]})
        signer = _integrity(one, signer_info, digests[algorithm])
        if signer.intact and trust is not None:
            signer = await _with_trust(signer, one, digests[algorithm], trust, online)
        elif signer.intact and online:
            signer = _replace(signer, status=INDETERMINATE, reason="NO_TRUSTED_LISTS", detail=lists_problem)
        out.append(signer)
    return out


def _integrity(one, signer_info, digest: bytes) -> Signer:
    """What the file alone says: who, and whether the document is what was signed."""
    from pyhanko.sign.validation import generic_cms

    try:
        cert = generic_cms.extract_certs_for_validation(one).signer_cert
    except Exception as e:
        return Signer(name="", status=FAILED, reason="NO_SIGNING_CERTIFICATE_FOUND", detail=str(e))
    subject, issuer = cert.subject.native, cert.issuer.native
    qualified, device = _declared(cert)
    signer = Signer(
        name=_text(subject.get("common_name")) or " ".join(
            x for x in (_text(subject.get("given_name")), _text(subject.get("surname"))) if x),
        organisation=_text(subject.get("organization_name")),
        identifier=_text(subject.get("serial_number")),
        issuer=_text(issuer.get("common_name")) or _text(issuer.get("organization_name")),
        valid_from=cert.not_valid_before, valid_until=cert.not_valid_after,
        claimed_time=generic_cms.extract_self_reported_ts(signer_info),
        declares_qualified=qualified, declares_device=device)
    try:
        intact, valid = generic_cms.validate_sig_integrity(
            signer_info, cert, expected_content_type=one["encap_content_info"]["content_type"].native,
            actual_digest=digest)
    except Exception as e:
        return _replace(signer, status=FAILED, reason="FORMAT_FAILURE", detail=str(e))
    if not intact:
        return _replace(signer, status=FAILED, reason="HASH_FAILURE")
    if not valid:
        return _replace(signer, status=FAILED, reason="SIG_CRYPTO_FAILURE")
    return _replace(signer, intact=True, status=INTEGRITY_ONLY)


async def _with_trust(signer: Signer, one, digest: bytes, trust, online: bool) -> Signer:
    """The certificate's chain, its revocation and the time stamps, by ETSI EN 319 102-1."""
    from pyhanko.sign.ades.report import AdESFailure, AdESPassed
    from pyhanko.sign.validation import ades
    from pyhanko_certvalidator.ltv.types import ValidationTimingInfo

    stamped = _has_time_stamp(one)
    try:
        if stamped:         # 5.5: with the time a time stamp proves
            result = await ades.ades_with_time_validation(one, _spec(trust, online), raw_digest=digest)
        else:               # 5.3: as of now, the only time that is sure
            result = await ades.ades_basic_validation(one, _spec(trust, online), raw_digest=digest)
    except NETWORK_ERRORS as e:
        return _replace(signer, status=INDETERMINATE, reason="TRY_LATER", detail=f"{type(e).__name__}: {e}")
    except Exception as e:      # what the library did not foresee is never a pass, and not our verdict of a forgery
        return _replace(signer, status=INDETERMINATE, reason="GENERIC", detail=f"{type(e).__name__}: {e}")
    listed, proven = _listed(result.api_status), None
    stamp = getattr(result.api_status, "timestamp_validity", None)
    if stamp is not None and getattr(stamp, "valid", False) and getattr(stamp, "trusted", False):
        proven = stamp.timestamp
    verdict = result.ades_subindic
    if isinstance(verdict, AdESPassed):
        state = PASSED if online else INTEGRITY_ONLY        # without the revocation nothing is called valid
    elif isinstance(verdict, AdESFailure):
        state = FAILED
    else:
        state = INDETERMINATE
    reason = verdict.name
    if reason in ("NO_CERTIFICATE_CHAIN_FOUND", "CERTIFICATE_CHAIN_GENERAL_FAILURE"):
        # the library gives one answer for "no chain to a trusted certifier"
        # and for "the revocation could not be had": the chain alone is
        # asked again, without the revocation, to tell them apart
        chain_holds, chain_listed = await _chain_alone(one, digest, trust)
        if chain_holds:
            reason, listed = "REVOCATION_UNKNOWN", chain_listed
        else:
            reason, listed = "NO_CERTIFICATE_CHAIN_FOUND", False
    if not online and state == INDETERMINATE and reason != "NO_CERTIFICATE_CHAIN_FOUND":
        state = INTEGRITY_ONLY
    then = None
    if state == INDETERMINATE and reason in TIME_REASONS and signer.claimed_time is not None:
        # a certificate expired or revoked since, and no time stamp: the
        # outcome stays "not established" (a time the signer's computer
        # wrote proves nothing). What can be added, as information: whether
        # at that time the certificate was within its dates and its
        # certifier in the lists
        moment = signer.claimed_time
        try:
            past = await ades.ades_basic_validation(
                one, _spec(trust, online=False), raw_digest=digest,
                timing_info=ValidationTimingInfo(validation_time=moment, best_signature_time=moment,
                                                 point_in_time_validation=True))
            then = isinstance(past.ades_subindic, AdESPassed)
            if listed is None:
                listed = _listed(past.api_status)
        except Exception:
            then = None
    return _replace(signer, status=state, reason="" if state in (PASSED, INTEGRITY_ONLY) else reason,
                    listed=listed, proven_time=proven, held_at_claimed_time=then, detail=result.failure_msg or "")


async def _chain_alone(one, digest: bytes, trust) -> tuple[bool, bool | None]:
    """Whether the certificate chains to a trusted certifier, the revocation
    left aside: (it does, the certifier is listed as qualified)."""
    from pyhanko.sign.ades.report import AdESPassed
    from pyhanko.sign.validation import ades

    try:
        result = await ades.ades_basic_validation(one, _spec(trust, online=False), raw_digest=digest)
    except Exception:
        return False, None
    return isinstance(result.ades_subindic, AdESPassed), _listed(result.api_status)


def _spec(trust, online: bool):
    from pyhanko.sign.validation.policy_decl import SignatureValidationSpec
    from pyhanko_certvalidator.context import CertValidationPolicySpec
    from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy, RevocationCheckingPolicy, RevocationCheckingRule

    rule = RevocationCheckingRule.CRL_OR_OCSP_REQUIRED if online else RevocationCheckingRule.NO_CHECK
    return SignatureValidationSpec(cert_validation_policy=CertValidationPolicySpec(
        trust_manager=trust, revinfo_policy=CertRevTrustPolicy(RevocationCheckingPolicy(rule, rule))))


def _listed(status) -> bool | None:
    """Whether the chain ends at a certifier the lists call qualified; None when no chain was built."""
    if status is None:
        return None
    qualification = getattr(status, "qualification_result", None)
    if qualification is not None:
        return qualification.service_definition is not None and qualification.status.qualified
    return False if getattr(status, "trusted", False) else None


def _has_time_stamp(one) -> bool:
    unsigned = one["signer_infos"][0]["unsigned_attrs"]
    try:
        return any(attribute["type"].native == "signature_time_stamp_token" for attribute in unsigned)
    except (TypeError, ValueError):
        return False


async def _trusted_lists(countries: set[str], online: bool, folder: Path | None):
    """The trust manager made of the European trusted lists of those
    countries, each list's signature checked on the way. Online the lists
    are asked for again when the copy kept is a day old; offline the copy
    kept is used whatever its age, and without one this raises."""
    import aiohttp
    from pyhanko.sign.validation.qualified.eutl_fetch import InMemoryTLCache, lotl_to_registry
    from pyhanko.sign.validation.qualified.tsp import TSPTrustManager

    if folder is not None:
        cache = _lists_kept(folder, LISTS_FRESH if online else LISTS_KEPT, may_fetch=online)
    elif online:
        cache = InMemoryTLCache()
    else:
        raise OSError("no network and no trusted lists kept")
    timeout = aiohttp.ClientTimeout(total=60 if online else 3)
    async with aiohttp.ClientSession(timeout=timeout) as client:
        registry, _errors = await lotl_to_registry(None, client, cache=cache, only_territories=countries)
    return TSPTrustManager(registry)


def _lists_kept(folder: Path, fresh_for: timedelta, may_fetch: bool = True):
    """The trusted lists kept in a folder, each as it came, byte for byte.
    pyHanko's own file cache (0.38.1) reads and writes them as text, which
    turns the line ends of a list that has Windows' ones, as Italy's has.
    On Linux they come back as plain line ends and the list still
    validates; on Windows each is written doubled, the list read back is
    no longer the list that was signed, its signature fails, the country
    is dropped without a word and every certifier of it becomes "not in
    the trusted lists" (seen on 10/11/2026: right the first time, wrong
    from the second). Reported as pyHanko issue 924 and corrected in its
    sources the same day (commit 0b27455, after 0.38.1); this cache stays
    all the same: it also writes a list whole or not at all, and without
    the network it does not ask for a list that is not kept."""
    from pyhanko.sign.validation.qualified.eutl_fetch import TLCache

    class Kept(TLCache):
        def _file(self, url: str) -> Path:
            return folder / (hashlib.sha256(url.encode("utf-8")).hexdigest() + ".xml")

        def __getitem__(self, url: str) -> str:
            path = self._file(url)
            try:
                age = datetime.now(timezone.utc) - datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
                if age <= fresh_for:
                    return path.read_bytes().decode("utf-8")
            except OSError:
                pass
            if not may_fetch:           # offline: a list that is not kept is not asked for
                raise ListNotKept(url)
            raise KeyError(url)

        def __setitem__(self, url: str, text: str) -> None:
            folder.mkdir(parents=True, exist_ok=True)
            path = self._file(url)
            partial = path.with_suffix(".part")
            partial.write_bytes(text.encode("utf-8"))
            partial.replace(path)           # whole or not at all

    return Kept()


def _countries(signed) -> set[str]:
    """The countries whose lists are needed: the certifiers' own, as their
    certificates name them, and Italy's in any case."""
    found = {"IT"}
    for choice in signed["certificates"]:
        if choice.name != "certificate":
            continue
        for names in (choice.chosen.issuer.native, choice.chosen.subject.native):
            country = _text(names.get("country_name"))
            if len(country) == 2 and country.isalpha():
                found.add(country.upper())
    return found


def _declared(cert) -> tuple[bool, bool]:
    """What the certificate says of itself: qualified, and on a secure device."""
    try:
        from pyhanko.sign.ades.qualified_asn1 import get_qc_statements
        kinds = {statement["statement_id"].native for statement in get_qc_statements(cert)}
    except Exception:
        return False, False
    return "qc_compliance" in kinds, "qc_compliance" in kinds and "qc_sscd" in kinds


def lists_age(folder: Path) -> timedelta | None:
    """How old the trusted lists kept are (the newest file's age); None with none."""
    try:
        newest = max(p.stat().st_mtime for p in Path(folder).iterdir() if p.is_file())
    except (OSError, ValueError):
        return None
    return datetime.now(timezone.utc) - datetime.fromtimestamp(newest, timezone.utc)


class _library_quiet:
    """The library logs every failed path with the signer's name and tax
    code in it: not on our stderr, not in a log somebody sends along. What
    went wrong is in the outcome."""

    NAMES = ("pyhanko", "pyhanko_certvalidator")

    def __enter__(self):
        import logging
        self.before = {name: logging.getLogger(name).level for name in self.NAMES}
        for name in self.NAMES:
            logging.getLogger(name).setLevel(logging.CRITICAL + 1)

    def __exit__(self, *_exc):
        import logging
        for name, level in self.before.items():
            logging.getLogger(name).setLevel(level)


def _bundled_certificates() -> None:
    """A frozen build carries its own OpenSSL, which looks for the
    certificates where the machine it was built on keeps them: MSYS2's does
    not always see Windows' store (as for the update check), Ubuntu's finds
    nothing on a distribution that keeps them elsewhere. OpenSSL is told
    where the ones in the build are (the bundle the Windows build ships, or
    certifi's, which comes with pyHanko), so that every connection the
    library opens for the lists and the revocations can check its server."""
    import os
    import sys
    if not getattr(sys, "frozen", False) or os.environ.get("SSL_CERT_FILE"):
        return
    bundled = Path(getattr(sys, "_MEIPASS", "")) / "certs" / "ca-bundle.crt"
    if not bundled.is_file():
        try:
            import certifi
            bundled = Path(certifi.where())
        except ImportError:
            return
    if bundled.is_file():
        os.environ["SSL_CERT_FILE"] = str(bundled)


def _text(value) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return "" if value is None else str(value)


def _replace(signer: Signer, **changes) -> Signer:
    from dataclasses import replace
    return replace(signer, **changes)
