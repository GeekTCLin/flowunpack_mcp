"""MCP 服务层测试：直接调用工具函数（不经过 stdio，快且稳定）。"""

import json

import pytest

from flowunpack_mcp import server as mcp_server
from flowunpack.synth import (
    make_length_prefixed_stream,
    make_magic_length_stream,
    random_stream,
)


class TestAnalyzeStreamTool:
    def test_detects_magic_length_protocol(self):
        data, expected = make_magic_length_stream()
        out = mcp_server.tool_analyze_stream(data.hex())

        assert out["ok"] is True
        assert out["detected"] is True
        spec = out["length_field"]
        assert spec["format"] == expected.format
        assert spec["offset"] == expected.offset
        assert spec["overhead"] == expected.overhead
        assert out["unit_count"] == 12
        assert out["protocol_hint"] == "Magic + Length-Prefix"

    def test_accepts_spaced_hex_and_prefix(self):
        data, _ = make_length_prefixed_stream("uint16_be")
        spaced = " ".join(data[i:i + 2].hex() for i in range(0, len(data), 2))
        out = mcp_server.tool_analyze_stream(spaced)
        assert out["detected"] is True

    def test_rejects_random(self):
        out = mcp_server.tool_analyze_stream(random_stream(1024).hex())
        assert out["ok"] is True
        assert out["detected"] is False

    def test_json_serializable(self):
        data, _ = make_magic_length_stream()
        out = mcp_server.tool_analyze_stream(data.hex(), verbose=True)
        json.dumps(out, ensure_ascii=False)      # 不应抛异常

    def test_verbose_flag_trims_output(self):
        data, _ = make_magic_length_stream()
        slim = mcp_server.tool_analyze_stream(data.hex())
        full = mcp_server.tool_analyze_stream(data.hex(), verbose=True)
        assert len(slim["byte_profile"]) <= len(full["byte_profile"])

    def test_text_report_available(self):
        data, _ = make_magic_length_stream()
        out = mcp_server.tool_analyze_stream(data.hex(), include_text_report=True)
        assert "帧结构" in out["text_report"]


class TestDecodeStreamTool:
    def test_roundtrip_with_detected_spec(self):
        data, _ = make_magic_length_stream()
        detected = mcp_server.tool_analyze_stream(data.hex())["length_field"]
        out = mcp_server.tool_decode_stream(
            data.hex(), offset=detected["offset"], format=detected["format"],
            overhead=detected["overhead"],
            variable_overhead=detected["variable_overhead"],
            header_len=detected["header_len"])
        assert out["ok"] is True
        assert out["frame_count"] == 12
        assert out["leftover"] == 0

    def test_unknown_format_rejected(self):
        assert mcp_server.tool_decode_stream(
            "aabb", offset=0, format="uint7", overhead=0)["ok"] is False


class TestAnalyzePacketsTool:
    def test_packet_list(self):
        data, _ = make_length_prefixed_stream("uint16_be")
        frames = [f.header + f.body
                  for f in __import__("flowunpack").analyze_stream(data).frames]
        out = mcp_server.tool_analyze_packets([f.hex() for f in frames])
        assert out["detected"] is True

    def test_empty_input(self):
        assert mcp_server.tool_analyze_packets([])["ok"] is False


class TestMiscTools:
    def test_list_formats(self):
        assert "uint16_be" in mcp_server.tool_list_formats()["formats"]

    def test_service_info(self):
        info = mcp_server.tool_service_info()
        assert info["ok"] and info["service"] == "flowunpack"
        assert info["version"]

    def test_hexdump(self):
        out = mcp_server.tool_hexdump("48656c6c6f")
        assert out["length"] == 5 and "Hello" in out["hexdump"]

    def test_explain_spec(self):
        out = mcp_server.tool_explain_spec(
            {"offset": 4, "format": "uint16_be", "overhead": 6,
             "semantics": "body_length", "header_len": 6, "body_offset": 6})
        assert out["ok"] is True
        assert "frame_len" in out["formula"]


class TestServerAssembly:
    def test_create_server_exposes_functions(self):
        srv = mcp_server.create_server()
        assert set(srv.fn) >= {"analyze_stream", "decode_stream", "service_info"}
