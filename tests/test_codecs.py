"""编解码器测试 —— 重点是历史实现中 varint 的 shift 未递增缺陷。"""

import pytest

from flowunpack.codecs import (
    DecodeError,
    FORMATS,
    available_formats,
    decode_at,
    decode_sleb128,
    decode_uleb128,
    decode_varint,
    decode_varint_be,
    decode_zigzag,
    encode_varint,
    encode_zigzag,
    min_width,
    try_decode_all,
)


class TestVarint:
    def test_single_byte(self):
        assert decode_varint(b"\x7f") == (127, 1)

    @pytest.mark.parametrize("value,expected", [
        (0, b"\x00"),
        (127, b"\x7f"),
        (128, b"\x80\x01"),      # 历史实现因 shift 未递增会解成 1
        (300, b"\xac\x02"),
        (16383, b"\xff\x7f"),
        (16384, b"\x80\x80\x01"),
        (65535, b"\xff\xff\x03"),
    ])
    def test_roundtrip(self, value, expected):
        assert encode_varint(value) == expected
        assert decode_varint(expected) == (value, len(expected))

    def test_multi_byte_shift_is_applied(self):
        """回归测试：低 7 位组必须按 7*index 左移。"""
        assert decode_varint(bytes([0x80, 0x01])) == (128, 2)
        assert decode_varint(bytes([0xFF, 0x7F])) == (16383, 2)

    def test_offset_is_respected(self):
        data = b"\xaa" + encode_varint(300)
        assert decode_varint(data, 1) == (300, 2)

    def test_truncated_raises(self):
        with pytest.raises(DecodeError):
            decode_varint(b"\x80\x80")   # 未遇到结束字节

    def test_uleb128_is_alias_of_varint(self):
        assert decode_uleb128(b"\x80\x01") == decode_varint(b"\x80\x01")

    def test_varint_be_is_msb_first(self):
        assert decode_varint_be(bytes([0x81, 0x00])) == (128, 2)

    def test_zigzag_roundtrip(self):
        for v in (0, -1, 1, -2, 2, -127, 128):
            assert decode_zigzag(encode_zigzag(v)) == (v, len(encode_zigzag(v)))

    def test_sleb128_negative(self):
        assert decode_sleb128(b"\x7f")[0] == -1


class TestFixedWidth:
    @pytest.mark.parametrize("fmt,data,expected", [
        ("uint8", b"\x2a", 42),
        ("uint16_be", b"\x00\x2a", 42),
        ("uint16_le", b"\x2a\x00", 42),
        ("uint24_be", b"\x00\x00\x2a", 42),
        ("uint32_be", b"\x00\x00\x00\x2a", 42),
        ("uint32_le", b"\x2a\x00\x00\x00", 42),
        ("uint64_le", b"\x2a" + b"\x00" * 7, 42),
    ])
    def test_decode(self, fmt, data, expected):
        assert decode_at(data, 0, fmt) == (expected, len(data))

    def test_insufficient_bytes_returns_none(self):
        assert decode_at(b"\x00", 0, "uint32_be") is None

    def test_offset_beyond_data_returns_none(self):
        assert decode_at(b"\x00", 5, "uint8") is None

    def test_unknown_format_returns_none(self):
        assert decode_at(b"\x00", 0, "no_such_format") is None


class TestRegistry:
    def test_all_formats_have_decoder(self):
        for name, fmt in FORMATS.items():
            assert callable(fmt.decoder)
            assert fmt.width is None or fmt.width >= 1

    def test_min_width(self):
        assert min_width("uint32_be") == 4
        assert min_width("varint") == 1
        with pytest.raises(KeyError):
            min_width("nope")

    def test_available_formats_contains_core(self):
        names = available_formats()
        for core in ("uint8", "uint16_be", "uint32_le", "varint", "uleb128"):
            assert core in names

    def test_try_decode_all_skips_impossible(self):
        results = try_decode_all(b"\x2a", 0)
        names = {r["format"] for r in results}
        assert "uint8" in names
        assert "uint32_be" not in names
