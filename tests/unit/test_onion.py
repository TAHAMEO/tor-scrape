from __future__ import annotations

import base64
import hashlib
import random

import pytest

from tests.conftest import fake_onion
from torscrape.onion import (
    ONION_V3_LEN,
    Invalid,
    MentionForm,
    check_label,
    find_onion_mentions,
    is_valid_v3,
    onion_address_from_pubkey,
    parse_onion_host,
    service_key,
)

# Example addresses from Tor's rend-spec-v3, "Encoding onion addresses".
SPEC_VECTORS = [
    "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd",
    "sp3k262uwy4r2k3ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd",
    "xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd",
]
# Long-published public services (The Tor Project, DuckDuckGo).
PUBLIC_VECTORS = [
    "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid",
    "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad",
]
B32 = "abcdefghijklmnopqrstuvwxyz234567"
L1 = SPEC_VECTORS[0]
L2 = SPEC_VECTORS[1]


def _encode(pubkey: bytes, version: int, *, checksum_version: int | None = None) -> str:
    """Independent re-implementation of the spec encoding, for crafting bad inputs."""
    cv = version if checksum_version is None else checksum_version
    checksum = hashlib.sha3_256(b".onion checksum" + pubkey + bytes([cv])).digest()[:2]
    return base64.b32encode(pubkey + checksum + bytes([version])).decode().lower()


def _swap_char(label: str, index: int) -> str:
    replacement = "a" if label[index] != "a" else "b"
    return label[:index] + replacement + label[index + 1 :]


class TestCheckLabel:
    @pytest.mark.parametrize("label", SPEC_VECTORS + PUBLIC_VECTORS)
    def test_known_addresses_are_valid(self, label: str) -> None:
        result = check_label(label)
        assert result.valid
        assert result.reason is None
        assert result.label == label
        assert result.hostname == f"{label}.onion"

    def test_accepts_suffix_case_whitespace_and_root_dot(self) -> None:
        result = check_label(f"  {L1.upper()}.ONION.  ")
        assert result.valid
        assert result.label == L1

    @pytest.mark.parametrize(
        "value",
        ["", L1[:-1], L1 + "a", "expyuzz4wqqyqhjn", f"{L1}{L1}"],
        ids=["empty", "55-chars", "57-chars", "v2-address", "double"],
    )
    def test_wrong_length(self, value: str) -> None:
        result = check_label(value)
        assert not result.valid
        assert result.reason is Invalid.LENGTH

    @pytest.mark.parametrize("bad_char", ["0", "1", "8", "9", "-", "_", "="])
    def test_characters_outside_base32(self, bad_char: str) -> None:
        value = L1[:20] + bad_char + L1[21:]
        result = check_label(value)
        assert not result.valid
        assert result.reason is Invalid.CHARSET

    def test_unicode_lookalike_is_not_folded_to_ascii(self) -> None:
        # "\u212a" (KELVIN SIGN) lowercases to ASCII "k" in Python.
        lookalike = L2.replace("k", "\u212a", 1)
        assert lookalike.lower() == L2
        result = check_label(lookalike)
        assert not result.valid
        assert result.reason is Invalid.CHARSET

    def test_wrong_version_byte(self) -> None:
        pubkey = bytes(range(32))
        result = check_label(_encode(pubkey, version=4))
        assert not result.valid
        assert result.reason is Invalid.VERSION

    def test_checksum_over_wrong_version(self) -> None:
        pubkey = bytes(range(32))
        result = check_label(_encode(pubkey, version=3, checksum_version=4))
        assert not result.valid
        assert result.reason is Invalid.CHECKSUM

    @pytest.mark.parametrize("index", [0, 10, 30, 51])
    def test_single_character_typo_breaks_checksum(self, index: int) -> None:
        result = check_label(_swap_char(L1, index))
        assert not result.valid
        assert result.reason is Invalid.CHECKSUM


class TestEncoding:
    def test_roundtrip_random_pubkeys(self) -> None:
        rng = random.Random(1234)
        for _ in range(200):
            pubkey = rng.randbytes(32)
            label = onion_address_from_pubkey(pubkey)
            assert len(label) == ONION_V3_LEN
            assert label.endswith("d")  # low 5 bits of version byte 0x03
            assert check_label(label).valid
            assert base64.b32decode(label.upper())[:32] == pubkey

    def test_matches_independent_encoder(self) -> None:
        pubkey = bytes(range(100, 132))
        assert onion_address_from_pubkey(pubkey) == _encode(pubkey, version=3)

    @pytest.mark.parametrize("length", [0, 31, 33, 64])
    def test_rejects_wrong_pubkey_length(self, length: int) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            onion_address_from_pubkey(bytes(length))

    def test_random_base32_strings_are_rejected(self) -> None:
        # Chance of a random string passing is 1 / (65536 * 256) per try.
        rng = random.Random(99)
        for _ in range(5000):
            candidate = "".join(rng.choice(B32) for _ in range(ONION_V3_LEN))
            assert not check_label(candidate).valid

    def test_fixture_helper_is_deterministic_and_valid(self) -> None:
        assert fake_onion(1) == fake_onion(1)
        assert fake_onion(1) != fake_onion(2)
        assert check_label(fake_onion("x")).valid


class TestHostParsing:
    @pytest.mark.parametrize(
        "host",
        [
            f"{L1}.onion",
            f"www.{L1}.onion",
            f"a.b.{L1}.onion",
            f"{L1}.onion.",
            f"{L1.upper()}.ONION",
        ],
    )
    def test_valid_service_hosts(self, host: str) -> None:
        result = parse_onion_host(host)
        assert result is not None
        assert result.valid
        assert result.label == L1
        assert service_key(host) == L1
        assert is_valid_v3(host)

    @pytest.mark.parametrize(
        "host",
        ["example.com", "onion", "", f"{L1}.onion.example.com", f"{L1}.onion2", L1 + ".on1on"],
    )
    def test_non_onion_hosts(self, host: str) -> None:
        assert parse_onion_host(host) is None
        assert service_key(host) is None
        assert not is_valid_v3(host)

    def test_invalid_onion_host_reports_reason(self) -> None:
        result = parse_onion_host("tooshort.onion")
        assert result is not None
        assert not result.valid
        assert result.reason is Invalid.LENGTH
        assert service_key("tooshort.onion") is None

    def test_invalid_checksum_host(self) -> None:
        host = f"{_swap_char(L1, 5)}.onion"
        result = parse_onion_host(host)
        assert result is not None
        assert result.reason is Invalid.CHECKSUM
        assert service_key(host) is None

    def test_non_ascii_host(self) -> None:
        result = parse_onion_host(f"{L2.replace('k', chr(0x212A), 1)}.onion")
        assert result is not None
        assert result.reason is Invalid.CHARSET

    def test_is_valid_v3_bare_label(self) -> None:
        assert is_valid_v3(L1)
        assert is_valid_v3(L1.upper())
        assert not is_valid_v3(_swap_char(L1, 3))


class TestFindMentions:
    def test_plain_mentions_in_prose_urls_and_ports(self) -> None:
        text = (
            f"Visit {L1}.onion today, or http://www.{L2}.onion:8080/path?q=1. "
            f"Mirror: <a href='http://{PUBLIC_VECTORS[0]}.onion/'>x</a>"
        )
        mentions = find_onion_mentions(text)
        assert [m.label for m in mentions] == [L1, L2, PUBLIC_VECTORS[0]]
        assert all(m.valid and m.form is MentionForm.PLAIN for m in mentions)
        assert mentions[0].hostname == f"{L1}.onion"

    def test_uppercase_is_lowercased(self) -> None:
        (mention,) = find_onion_mentions(f"{L1.upper()}.ONION")
        assert mention.label == L1
        assert mention.form is MentionForm.PLAIN

    @pytest.mark.parametrize(
        "separator",
        [
            "[.]",
            "(.)",
            "{.}",
            "[dot]",
            "(dot)",
            "{dot}",
            "<dot>",
            " [.] ",
            " dot ",
            " DOT ",
            " . ",
            " .",
            ". ",
            "\uff0e",
            "\u3002",
            "\u00a0dot\u00a0",
        ],
    )
    def test_defanged_forms(self, separator: str) -> None:
        (mention,) = find_onion_mentions(f"address: {L1}{separator}onion (new)")
        assert mention.label == L1
        assert mention.valid
        assert mention.form is MentionForm.DEFANGED

    @pytest.mark.parametrize(
        "invisible", ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"]
    )
    def test_invisible_characters_are_stripped(self, invisible: str) -> None:
        obfuscated = invisible.join(L1[i : i + 7] for i in range(0, len(L1), 7))
        (mention,) = find_onion_mentions(f"go to {obfuscated}.onion")
        assert mention.label == L1
        assert mention.form is MentionForm.PLAIN

    def test_bare_valid_label_is_accepted(self) -> None:
        (mention,) = find_onion_mentions(f'var mirror = "{L1}";')
        assert mention.label == L1
        assert mention.valid
        assert mention.form is MentionForm.BARE
        assert mention.form.slug == "bare"

    def test_bare_invalid_label_is_dropped(self) -> None:
        assert find_onion_mentions(f"token={_swap_char(L1, 7)} end") == []

    def test_plain_invalid_label_is_reported(self) -> None:
        typo = _swap_char(L1, 7)
        (mention,) = find_onion_mentions(f"http://{typo}.onion/")
        assert mention.label == typo
        assert not mention.valid
        assert mention.reason is Invalid.CHECKSUM
        assert mention.form is MentionForm.PLAIN

    @pytest.mark.parametrize(
        "text",
        [f"a{L1}.onion", f"8{L1}.onion", f"{L1}a.onion", f"{L1}8", f"x{L1}", f"{L1}{L1}"],
    )
    def test_labels_embedded_in_longer_tokens_are_ignored(self, text: str) -> None:
        assert find_onion_mentions(text) == []

    def test_v2_addresses_are_ignored(self) -> None:
        assert find_onion_mentions("old: expyuzz4wqqyqhjn.onion") == []

    def test_distinct_labels_in_first_appearance_order_with_best_form(self) -> None:
        text = f"bare {L2} then {L1}.onion then {L2}.onion and {L1}[.]onion"
        mentions = find_onion_mentions(text)
        assert [(m.label, m.form) for m in mentions] == [
            (L2, MentionForm.PLAIN),
            (L1, MentionForm.PLAIN),
        ]

    def test_defanged_beats_bare(self) -> None:
        (mention,) = find_onion_mentions(f"{L1} or {L1} dot onion")
        assert mention.form is MentionForm.DEFANGED

    def test_empty_and_noise(self) -> None:
        assert find_onion_mentions("") == []
        assert find_onion_mentions("no addresses here .onion onion.onion") == []
