"""Validation and extraction of v3 onion addresses.

A v3 onion address is the base32 encoding of 35 bytes (Tor rend-spec-v3,
"Encoding onion addresses"):

    PUBKEY (32 bytes, ed25519) || CHECKSUM (2 bytes) || VERSION (1 byte, 0x03)

    CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || VERSION)[:2]

A random 56-character base32 string passes the checksum and version checks with
probability 1 / (65536 * 256), so validating them removes nearly all false
positives from regex matching. That is what lets us accept "bare" addresses
(written without the ``.onion`` suffix) found in page text.

Everything in this module is pure and does no I/O.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from enum import IntEnum, StrEnum

ONION_V3_LEN = 56
ONION_SUFFIX = ".onion"
V3_VERSION = 3
PUBKEY_LEN = 32

_CHECKSUM_PREFIX = b".onion checksum"
_B32_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")


class Invalid(StrEnum):
    """Why a candidate is not a valid v3 onion label."""

    LENGTH = "bad_length"
    CHARSET = "bad_charset"
    VERSION = "bad_version"
    CHECKSUM = "bad_checksum"


@dataclass(frozen=True, slots=True)
class OnionCheck:
    """Result of validating one candidate label."""

    label: str
    valid: bool
    reason: Invalid | None = None

    @property
    def hostname(self) -> str:
        return f"{self.label}{ONION_SUFFIX}"


def _checksum(pubkey: bytes, version: int) -> bytes:
    return hashlib.sha3_256(_CHECKSUM_PREFIX + pubkey + bytes([version])).digest()[:2]


def onion_address_from_pubkey(pubkey: bytes) -> str:
    """Encode a 32-byte ed25519 public key as a v3 onion label (no suffix).

    Used to build checksum-valid fixture addresses in tests and mock sites.
    """
    if len(pubkey) != PUBKEY_LEN:
        raise ValueError(f"pubkey must be {PUBKEY_LEN} bytes, got {len(pubkey)}")
    raw = pubkey + _checksum(pubkey, V3_VERSION) + bytes([V3_VERSION])
    return base64.b32encode(raw).decode("ascii").lower()


def check_label(value: str) -> OnionCheck:
    """Validate a v3 label. Accepts ``label`` or ``label.onion``, any case.

    Only ASCII is accepted. Unicode case folding would otherwise map lookalikes
    such as KELVIN SIGN (U+212A) onto ``k``.
    """
    label = value.strip()
    if not label.isascii():
        return OnionCheck(label, False, Invalid.CHARSET)
    label = label.lower().removesuffix(".").removesuffix(ONION_SUFFIX)
    if len(label) != ONION_V3_LEN:
        return OnionCheck(label, False, Invalid.LENGTH)
    if not _B32_ALPHABET.issuperset(label):
        return OnionCheck(label, False, Invalid.CHARSET)
    raw = base64.b32decode(label.upper())  # 56 * 5 bits = 35 bytes, no padding
    pubkey, checksum, version = raw[:PUBKEY_LEN], raw[PUBKEY_LEN:-1], raw[-1]
    if version != V3_VERSION:
        return OnionCheck(label, False, Invalid.VERSION)
    if checksum != _checksum(pubkey, version):
        return OnionCheck(label, False, Invalid.CHECKSUM)
    return OnionCheck(label, True)


def is_valid_v3(value: str) -> bool:
    """True for a valid ``label``, ``label.onion`` or ``sub.label.onion``."""
    if "." in value.strip().rstrip("."):
        check = parse_onion_host(value)
        return check is not None and check.valid
    return check_label(value).valid


def parse_onion_host(host: str) -> OnionCheck | None:
    """Validate the service label of an onion hostname.

    Returns ``None`` when ``host`` is not under ``.onion`` at all. Subdomains
    (``www.<label>.onion``) and a trailing root dot are accepted: they reach
    the same service. ``host`` must not carry a scheme, port or path.
    """
    labels = host.strip().rstrip(".").split(".")
    if len(labels) < 2 or labels[-1].lower() != "onion":
        return None
    return check_label(labels[-2])


def service_key(host: str) -> str | None:
    """The 56-character service label for a valid onion hostname, else ``None``."""
    check = parse_onion_host(host)
    return check.label if check is not None and check.valid else None


# --------------------------------------------------------------------------- #
# Extraction from free text, JavaScript strings, attribute values, etc.
# --------------------------------------------------------------------------- #


class MentionForm(IntEnum):
    """How an address was written. A lower value wins when a label repeats."""

    PLAIN = 0  # <label>.onion
    DEFANGED = 1  # <label>[.]onion, <label> dot onion, <label>(.)onion, ...
    BARE = 2  # <label> alone; kept only when checksum and version are valid

    @property
    def slug(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class OnionMention:
    """One distinct onion label found in a piece of text."""

    label: str
    valid: bool
    form: MentionForm
    reason: Invalid | None = None

    @property
    def hostname(self) -> str:
        return f"{self.label}{ONION_SUFFIX}"


# Invisible characters sometimes inserted to break naive scrapers.
_INVISIBLE = dict.fromkeys(map(ord, "\u00ad\u200b\u200c\u200d\u2060\ufeff"), None)

# re.ASCII matters: with IGNORECASE alone, [a-z] also matches U+017F and U+212A.
_FLAGS = re.IGNORECASE | re.ASCII
_LABEL = r"[a-z2-7]{56}"
_BEFORE = r"(?<![a-z0-9])"
_AFTER = r"(?![a-z0-9])"
_WS = "[\\s\u00a0\u2009\u202f]"
_DOTS = "[.\u3002\uff0e\uff61]"  # ASCII, ideographic, fullwidth, halfwidth
_DEFANG_SEP = (
    rf"(?:{_WS}*(?:\[{_DOTS}\]|\({_DOTS}\)|\{{{_DOTS}\}}|\[dot\]|\(dot\)|\{{dot\}}|<dot>){_WS}*"
    rf"|{_WS}+dot{_WS}+"
    rf"|{_WS}+{_DOTS}{_WS}*"
    rf"|{_WS}*{_DOTS}{_WS}+"
    rf"|[\u3002\uff0e\uff61])"
)

_PLAIN_RE = re.compile(rf"{_BEFORE}({_LABEL})\.onion{_AFTER}", _FLAGS)
_DEFANGED_RE = re.compile(rf"{_BEFORE}({_LABEL}){_DEFANG_SEP}onion{_AFTER}", _FLAGS)
_BARE_RE = re.compile(rf"{_BEFORE}({_LABEL}){_AFTER}", _FLAGS)


def find_onion_mentions(text: str) -> list[OnionMention]:
    """Find distinct onion labels in ``text``, in order of first appearance.

    Plain and defanged mentions are returned even if their checksum fails, so
    callers can record checksum validity (typos, lookalike phishing addresses).
    Invalid candidates must never be fetched. Bare 56-character tokens are
    returned only when valid, since otherwise they are almost always noise.
    """
    text = text.translate(_INVISIBLE)
    found: dict[str, tuple[int, MentionForm, OnionCheck]] = {}
    for form, pattern in (
        (MentionForm.PLAIN, _PLAIN_RE),
        (MentionForm.DEFANGED, _DEFANGED_RE),
        (MentionForm.BARE, _BARE_RE),
    ):
        for match in pattern.finditer(text):
            label = match.group(1).lower()
            prev = found.get(label)
            if prev is not None:
                if match.start() < prev[0]:
                    found[label] = (match.start(), prev[1], prev[2])
                continue
            check = check_label(label)
            if form is MentionForm.BARE and not check.valid:
                continue
            found[label] = (match.start(), form, check)

    ordered = sorted(found.values(), key=lambda item: item[0])
    return [
        OnionMention(label=check.label, valid=check.valid, form=form, reason=check.reason)
        for _, form, check in ordered
    ]
