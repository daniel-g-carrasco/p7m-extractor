"""What can be said of one signature, and how it is said. Values in, words
out: nothing here reads a file, asks the network or knows the library that
did the checking (app/verify.py).

The outcome has the three states of ETSI EN 319 102-1 and one of our own:

    PASSED          every check was made and held;
    INDETERMINATE   the signature is not wrong, but something could not be
                    established (a certificate revoked or expired with no
                    proof of when the signature was made, a certifier not in
                    the trusted lists, a revocation server that did not answer);
    FAILED          something is wrong: the document was changed, the
                    signature is not of that certificate, the certificate was
                    already revoked;
    INTEGRITY_ONLY  without the network: the document is what was signed and
                    the signature is the certificate's own, and no more was
                    checked. Not a verdict on the signature's validity.

This program is not a qualified validation service (Regulation (EU)
910/2014, article 33): it says what it checked, when, and against which
lists, and never calls its own answer "qualified".
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from p7m_extractor.i18n import _

PASSED, INDETERMINATE, FAILED, INTEGRITY_ONLY = "passed", "indeterminate", "failed", "integrity-only"


@dataclass(frozen=True)
class Signer:
    """One signature of the envelope, as far as it was checked."""
    name: str                               # who signed, as the certificate says
    organisation: str = ""
    identifier: str = ""                    # the certificate's serialNumber (in Italy "TINIT-" and the tax code)
    issuer: str = ""                        # the certifier
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    claimed_time: datetime | None = None    # what the signer's computer wrote: proves nothing
    proven_time: datetime | None = None     # a time stamp's: the signature existed by then
    intact: bool = False                    # the document is what was signed, by that certificate's key
    declares_qualified: bool = False        # the certificate says of itself: qualified
    declares_device: bool = False           # ... and: key in a qualified signature creation device
    listed: bool | None = None              # the certifier is in the trusted lists as qualified; None: not looked up
    held_at_claimed_time: bool | None = None    # at the time the signer wrote, certificate and certifier were in order
    status: str = INTEGRITY_ONLY
    reason: str = ""                        # the ETSI sub-indication, or a word of ours
    detail: str = ""                        # what the library said, for a report of a problem


def summary(signer: Signer) -> str:
    """The outcome in one line."""
    if signer.status == PASSED:
        if signer.listed and signer.declares_qualified and signer.declares_device:
            return _("Valid signature, with a qualified certificate on a secure device")
        if signer.listed and signer.declares_qualified:
            return _("Valid signature, with a qualified certificate")
        return _("Valid signature (not with a qualified certificate)")
    if signer.status == FAILED:
        return _("Not valid: {why}").format(why=why(signer))
    if signer.status == INDETERMINATE:
        return _("Not established: {why}").format(why=why(signer))
    if signer.intact and signer.listed:
        return _("Intact, and the certifier is in the trusted lists kept; whether the certificate was revoked "
                 "was not checked (no network)")
    if signer.intact:
        return _("Intact; the certificate and its certifier were not checked (no network)")
    return _("Not valid: {why}").format(why=why(signer))


def why(signer: Signer) -> str:
    """The reason of an outcome that is not a plain pass, in the user's words."""
    reasons = {
        "HASH_FAILURE": _("the document was changed after it was signed"),
        "SIG_CRYPTO_FAILURE": _("the signature does not match the certificate"),
        "FORMAT_FAILURE": _("the signature is not written as the standard asks"),
        "REVOKED": _("the certificate had been revoked when the signature was made"),
        "REVOKED_NO_POE": _("the certificate was revoked, and no time stamp proves the signature is older"),
        "REVOKED_CA_NO_POE": _("the certifier's certificate was revoked, and no time stamp proves the signature is older"),
        "EXPIRED": _("the certificate had expired when the signature was made"),
        "OUT_OF_BOUNDS_NO_POE": _("the certificate has expired, and no time stamp proves the signature is older"),
        "OUT_OF_BOUNDS_NOT_REVOKED": _("the certificate has expired, and no time stamp proves the signature is older"),
        "NOT_YET_VALID": _("the certificate was not valid yet when the signature was made"),
        "NO_CERTIFICATE_CHAIN_FOUND": _("the certifier is not in the trusted lists"),
        "NO_SIGNING_CERTIFICATE_FOUND": _("the signer's certificate is not in the file"),
        "TRY_LATER": _("the certifier did not say whether the certificate is revoked: try again later"),
        "CERTIFICATE_CHAIN_GENERAL_FAILURE": _("the certificate's chain could not be checked"),
        "CRYPTO_CONSTRAINTS_FAILURE": _("the signature uses an algorithm no longer held safe"),
        "CRYPTO_CONSTRAINTS_FAILURE_NO_POE": _("the signature uses an algorithm no longer held safe"),
        "NO_TRUSTED_LISTS": _("the trusted lists could not be had"),
        "REVOCATION_UNKNOWN": _("whether the certificate was revoked could not be established"),
    }
    return reasons.get(signer.reason) or signer.reason.replace("_", " ").lower() or _("unknown reason")


def state_word(signer: Signer) -> str:
    """The outcome in a word or two, for a label next to a name."""
    if signer.status == PASSED:
        return _("Valid")
    if signer.status == INDETERMINATE:
        return _("Not established")
    if signer.status == FAILED or not signer.intact:
        return _("Not valid")
    return _("Intact")


def details(signer: Signer) -> list[tuple[str, str]]:
    """What is known of one signature, as (what, value) pairs in the order
    they are shown; the outcome itself is `summary`."""
    out = [(_("Signed by"), signer.name or _("(no name in the certificate)"))]
    if signer.organisation:
        out.append((_("Organisation"), signer.organisation))
    if signer.identifier:
        out.append((_("Identifier"), signer.identifier))
    if signer.issuer:
        out.append((_("Certifier"), signer.issuer))
    if signer.valid_from and signer.valid_until:
        out.append((_("Certificate valid"), _("from {start} to {end}").format(start=_day(signer.valid_from),
                                                                              end=_day(signer.valid_until))))
    if signer.proven_time:
        out.append((_("Time of signing"), _("{when}, proven by a time stamp").format(when=_minute(signer.proven_time))))
    elif signer.claimed_time:
        when = _("{when}, written by the signer and not proven by a time stamp").format(
            when=_minute(signer.claimed_time))
        if signer.held_at_claimed_time:
            when += _("; at that time the certificate was within its dates")
        out.append((_("Time of signing"), when))
    else:
        out.append((_("Time of signing"), _("not in the file")))
    if signer.listed is None:
        if signer.declares_qualified:
            out.append((_("Trusted lists"), _("the certificate calls itself qualified; its certifier could not be "
                                              "looked up")))
    elif signer.listed:
        out.append((_("Trusted lists"), _("certifier found in the European lists, as qualified for signatures")))
    else:
        out.append((_("Trusted lists"), _("certifier not found in the European lists")))
    return out


def lines(signer: Signer) -> list[str]:
    """What a report says of one signature, line by line."""
    return [summary(signer)] + [f"{what}: {value}" for what, value in details(signer)]


def layer_caption(index: int, total: int) -> str:
    """What the envelope number `index` (0 the outermost) of `total` nested
    ones is: each signs the file as the one inside it left it."""
    if total == 1:
        return _("Signature on the document")
    if index == total - 1:
        return _("Innermost signature · on the document")
    if index == 0:
        return _("Outermost signature · on the file already signed")
    return _("Signature {n} of {total} from the outside · on the file already signed").format(n=index + 1, total=total)


def headline(layers) -> tuple[str, str]:
    """(how many signatures and how they stand, the outcome of them all)
    for the top of a report on a file's envelopes, outermost first."""
    signers = [signer for layer in layers for signer in layer]
    if len(layers) > 1:
        title = _("{n} signatures, one inside the other").format(n=len(signers)) if len(signers) == len(layers) \
            else _("{n} signatures in {layers} envelopes, one inside the other").format(n=len(signers), layers=len(layers))
    elif len(signers) == 1:
        title = _("One signature")
    else:
        title = _("{n} signatures, side by side").format(n=len(signers))
    state = worst(signers)
    if state == PASSED:
        return title, (_("Valid") if len(signers) == 1 else _("All valid"))
    first = next((s for s in signers if (s.status if s.intact or s.status != INTEGRITY_ONLY else FAILED) == state),
                 signers[0] if signers else None)
    if first is None:
        return title, _("No signature found")
    text = summary(first)
    return title, (text if len(signers) == 1 else _("{name}: {summary}").format(name=first.name or "?", summary=text))


def worst(signers) -> str:
    """One state for a file with several signatures: the worst of them."""
    order = (FAILED, INDETERMINATE, INTEGRITY_ONLY, PASSED)
    states = {signer.status if signer.intact or signer.status != INTEGRITY_ONLY else FAILED for signer in signers}
    return next((state for state in order if state in states), FAILED)


def _day(moment: datetime) -> str:
    return moment.strftime("%d/%m/%Y")


def _minute(moment: datetime) -> str:
    return moment.strftime("%d/%m/%Y %H:%M %Z").strip()
