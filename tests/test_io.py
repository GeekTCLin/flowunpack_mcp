"""输入归一化测试 —— 上游（Wireshark MCP）交付形态各异，这里保证都能吃下。"""

import pytest

from flowunpack.io_utils import (
    InputError,
    coerce_bytes,
    coerce_packet_list,
    hexdump,
    join_packets,
    parse_base64,
    parse_hex,
    to_ascii,
    to_hex,
)


class TestHex:
    def test_compact(self):
        assert parse_hex("aabbcc") == b"\xaa\xbb\xcc"

    def test_with_spaces_and_colons(self):
        assert parse_hex("aa bb cc") == b"\xaa\xbb\xcc"
        assert parse_hex("aa:bb:cc") == b"\xaa\xbb\xcc"

    def test_with_0x_prefix(self):
        assert parse_hex("0xaa, 0xbb") == b"\xaa\xbb"

    def test_uppercase(self):
        assert parse_hex("AABB") == b"\xaa\xbb"

    def test_empty(self):
        assert parse_hex("") == b""

    def test_odd_length_raises(self):
        with pytest.raises(InputError):
            parse_hex("aab")

    def test_non_hex_raises(self):
        with pytest.raises(InputError):
            parse_hex("zzzz")


class TestBase64:
    def test_roundtrip(self):
        assert parse_base64("qrvM") == b"\xaa\xbb\xcc"


class TestCoerce:
    def test_bytes_passthrough(self):
        assert coerce_bytes(b"\x01\x02") == b"\x01\x02"

    def test_int_list(self):
        assert coerce_bytes([1, 2, 3]) == b"\x01\x02\x03"

    def test_auto_detects_hex(self):
        assert coerce_bytes("0011") == b"\x00\x11"

    def test_force_base64(self):
        assert coerce_bytes("qrvM", encoding="base64") == b"\xaa\xbb\xcc"

    def test_bad_type(self):
        with pytest.raises(InputError):
            coerce_bytes(object())


class TestPacketList:
    def test_multiline(self):
        got = coerce_packet_list("aabb\nccdd")
        assert got == [b"\xaa\xbb", b"\xcc\xdd"]

    def test_list_of_hex(self):
        got = coerce_packet_list(["aabb", "ccdd"])
        assert got == [b"\xaa\xbb", b"\xcc\xdd"]

    def test_single_blob(self):
        assert coerce_packet_list(b"\xaa\xbb") == [b"\xaa\xbb"]

    def test_dict_wrapper(self):
        assert coerce_packet_list({"packets": ["aabb"]}) == [b"\xaa\xbb"]

    def test_join(self):
        assert join_packets([b"ab", b"cd"]) == b"abcd"


class TestRender:
    def test_to_hex(self):
        assert to_hex(b"\xaa\xbb") == "aabb"
        assert to_hex(b"\xaa\xbb", sep=" ") == "aa bb"

    def test_to_ascii_replaces_nonprintable(self):
        assert to_ascii(b"AB\x00") == "AB."

    def test_hexdump_has_offset_and_ascii(self):
        out = hexdump(b"HELLO", width=8)
        assert out.startswith("00000000")
        assert "HELLO" in out
