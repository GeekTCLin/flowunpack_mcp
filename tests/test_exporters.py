"""exporters 模块测试：boofuzz / AFLNet 切分脚本 / Lua dissector 导出。

核心不变量：

* 产物是**独立**脚本 —— AFLNet 切分脚本的 ``split_messages`` 能在
  不导入 flowunpack 的命名空间里对同一条流切出与分析结果一致的帧；
* 产物是**可执行/可解析**的 —— boofuzz 脚本过 AST，Lua 关键结构齐全；
* 无法表达的模板**显式拒绝**（变长编码 vs 定宽 s_size、非长度前缀 vs
  boofuzz），而不是生成错误的模板。
"""

from __future__ import annotations

import ast

import pytest

from flowunpack import analyze_stream, synth
from flowunpack.exporters import (
    SUPPORTED_KINDS,
    UnsupportedTemplateError,
    export_template,
    to_aflnet_splitter,
    to_boofuzz,
    to_lua_dissector,
)


def _run_splitter(script: str, data: bytes):
    """执行生成的切分脚本（不落盘、不导入 flowunpack）。"""
    ns: dict = {"__name__": "split_messages"}
    exec(compile(script, "<generated-splitter>", "exec"), ns)
    return ns["split_messages"](data)


# ---------------------------------------------------------------------------
# boofuzz 后端
# ---------------------------------------------------------------------------

class TestBoofuzz:

    def test_basic_length_prefixed(self):
        data, _ = synth.make_magic_length_stream()
        r = analyze_stream(data)
        assert r.detected and r.framing.kind == "length_prefixed"
        text = to_boofuzz(r)
        ast.parse(text)                              # 必须是合法 Python
        assert 's_size("payload", length=2' in text  # uint16_be
        assert "ENDIAN.BIG" in text
        assert "fuzzable=True" in text
        assert "math=lambda n: n // 1" in text       # body_length 语义
        assert "PKTM" in text                        # 魔数进了固定前缀
        assert 's_initialize("frame")' in text

    def test_total_length_math(self):
        data, _ = synth.make_total_length_stream()
        r = analyze_stream(data)
        assert r.detected
        text = to_boofuzz(r)
        # total_length：value = (固定头 + 载荷) // scale
        assert "math=lambda n: (n + " in text
        assert "total_length" in text

    def test_scaled(self):
        data, _ = synth.make_scaled_length_stream(scale=4)
        r = analyze_stream(data)
        assert r.detected and r.length_field.scale == 4
        text = to_boofuzz(r)
        if r.length_field.semantics == "total_length":
            # 长度字段在 offset=0 时计入计数：value = (固定头 + 载荷) // scale
            assert "math=lambda n: (n + 2) // 4" in text
        else:
            assert "math=lambda n: n // 4" in text

    def test_little_endian(self):
        data, _ = synth.make_length_prefixed_stream("uint16_le")
        r = analyze_stream(data)
        assert r.detected
        assert "ENDIAN.LITTLE" in to_boofuzz(r)

    def test_crc_trailer_becomes_s_checksum(self):
        data, _ = synth.make_crc_length_stream()
        r = analyze_stream(data)
        assert r.detected
        text = to_boofuzz(r)
        assert 's_checksum("payload"' in text
        assert '"crc32"' in text

    def test_varint_rejected(self):
        data, _ = synth.make_varint_stream()
        r = analyze_stream(data)
        assert r.detected
        with pytest.raises(UnsupportedTemplateError):
            to_boofuzz(r)

    def test_delimited_rejected(self):
        data = synth.make_delimited_stream()
        r = analyze_stream(data)
        assert r.framing is not None and r.framing.kind == "delimited"
        with pytest.raises(UnsupportedTemplateError):
            to_boofuzz(r)

    def test_ascii_length_rejected(self):
        data = synth.make_chunked_stream()          # 默认参数：ascii_length 定案
        r = analyze_stream(data)
        assert r.framing is not None and r.framing.kind == "ascii_length"
        with pytest.raises(UnsupportedTemplateError):
            to_boofuzz(r)


# ---------------------------------------------------------------------------
# AFLNet / ProFuzzBench 切分脚本（四种模板全支持，产物独立可执行）
# ---------------------------------------------------------------------------

class TestAflnetSplitter:

    def test_roundtrip_length_prefixed(self):
        data, _ = synth.make_magic_length_stream(frames=10)
        r = analyze_stream(data)
        assert r.detected
        frames, leftover = _run_splitter(to_aflnet_splitter(r), data)
        assert leftover == 0
        assert [len(f) for f in frames] == [f.length for f in r.frames]

    def test_roundtrip_total_length(self):
        data, _ = synth.make_total_length_stream()
        r = analyze_stream(data)
        assert r.detected
        frames, leftover = _run_splitter(to_aflnet_splitter(r), data)
        assert leftover == 0
        assert [len(f) for f in frames] == [f.length for f in r.frames]

    def test_roundtrip_varint(self):
        data, _ = synth.make_varint_stream(frames=10)
        r = analyze_stream(data)
        assert r.detected
        frames, leftover = _run_splitter(to_aflnet_splitter(r), data)
        assert leftover == 0
        assert [len(f) for f in frames] == [f.length for f in r.frames]

    def test_roundtrip_scaled(self):
        data, _ = synth.make_scaled_length_stream(scale=4)
        r = analyze_stream(data)
        assert r.detected
        frames, leftover = _run_splitter(to_aflnet_splitter(r), data)
        assert leftover == 0
        assert [len(f) for f in frames] == [f.length for f in r.frames]

    def test_roundtrip_ascii_chunked(self):
        data = synth.make_chunked_stream()          # 默认参数：ascii_length 定案
        r = analyze_stream(data)
        assert r.framing is not None and r.framing.kind == "ascii_length"
        script = to_aflnet_splitter(r)
        frames, leftover = _run_splitter(script, data)
        assert [len(f) for f in frames] == [f.length for f in r.frames]
        assert b"".join(frames) == data[:len(data) - leftover]

    def test_roundtrip_delimited(self):
        data = synth.make_delimited_stream()
        r = analyze_stream(data)
        assert r.framing is not None and r.framing.kind == "delimited"
        frames, leftover = _run_splitter(to_aflnet_splitter(r), data)
        assert [len(f) for f in frames] == [f.length for f in r.frames]
        # 分隔符留在帧尾，可无损拼回
        assert b"".join(frames) == data[:len(data) - leftover]

    def test_roundtrip_fixed_length(self):
        data = synth.make_fixed_length_stream(frame_len=16, frames=12)
        r = analyze_stream(data)
        if r.framing is None or r.framing.kind != "fixed_length":
            pytest.skip("该样本未以 fixed_length 定案（见 README §5.1 定长不可自证）")
        frames, leftover = _run_splitter(to_aflnet_splitter(r), data)
        assert [len(f) for f in frames] == [f.length for f in r.frames]


# ---------------------------------------------------------------------------
# Lua dissector
# ---------------------------------------------------------------------------

class TestLua:

    def test_structure(self):
        data, _ = synth.make_magic_length_stream()
        r = analyze_stream(data)
        text = to_lua_dissector(r)
        assert 'Proto("inferred", "Inferred Protocol (flowunpack)")' in text
        assert "ProtoField.uint16" in text
        assert "function p_inferred.dissector(buf, pinfo, tree)" in text
        # equals_at 必须定义在 find_bytes 之前（Lua 局部函数作用域）
        assert text.index("local function equals_at") < text.index(
            "local function find_bytes")

    def test_custom_proto_name(self):
        data, _ = synth.make_magic_length_stream()
        r = analyze_stream(data)
        text = to_lua_dissector(r, proto_name="myproto")
        assert 'Proto("myproto"' in text
        assert "p_myproto.dissector" in text
        assert "p_inferred" not in text             # 不应残留默认 proto 名

    def test_chunked_framing(self):
        data = synth.make_chunked_stream()          # 默认参数：ascii_length 定案
        r = analyze_stream(data)
        assert r.framing is not None and r.framing.kind == "ascii_length"
        text = to_lua_dissector(r)
        assert "tonumber(tok, radix)" in text
        assert "equals_at" in text

    def test_varint_rejected(self):
        data, _ = synth.make_varint_stream()
        r = analyze_stream(data)
        with pytest.raises(UnsupportedTemplateError):
            to_lua_dissector(r)

    def test_bind_port(self):
        data, _ = synth.make_magic_length_stream()
        r = analyze_stream(data)
        bound = to_lua_dissector(r, bind_port=7777)
        unbound = to_lua_dissector(r)
        assert 'DissectorTable.get("tcp.port"):add(7777' in bound
        assert "-- 端口绑定（已启用）" in bound
        assert 'DissectorTable.get("tcp.port"):add(7777' not in unbound
        assert 'DissectorTable.get("tcp.port"):add(12345' in unbound


# ---------------------------------------------------------------------------
# 统一入口
# ---------------------------------------------------------------------------

def test_export_template_dispatch():
    data, _ = synth.make_magic_length_stream()
    r = analyze_stream(data)
    for kind in SUPPORTED_KINDS:
        out = export_template(r, kind)
        assert isinstance(out, str) and out
    with pytest.raises(ValueError):
        export_template(r, "nope")
