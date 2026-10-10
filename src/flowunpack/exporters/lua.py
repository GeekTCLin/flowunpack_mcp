"""Wireshark Lua dissector 导出。

把分帧模板 + 字段标注翻译成可在 Wireshark 里
``tshark -X lua_script:<本文件>`` 或放入插件目录加载的独立 dissector。
四种模板全支持（varint 族长度字段除外，明确拒绝）；字段来自
:class:`AnalysisResult` 的字段模板（有消息分簇时取最大簇）。

语义映射：

* ``FieldSpec.kind`` → ``ProtoField`` 类型
  （magic/constant/binary/random → bytes；length/integer/counter/enum →
  uint8/16/24/32/64；checksum → uint32/bytes；ipv4 / float / text 直接映射；
  timestamp 输出为整数字段并加 "unix" 注释）；
* 负 offset（距帧尾的 trailer）在 dissector 里按 ``帧长 + offset`` 解析；
* 分帧循环与本库探测器语义一致：``<数字><term><数据><term>``
  （ascii_length，``0`` 为终止块）、分隔符留在帧尾（delimited）、
  ``frame_len = scale*value + overhead``（length_prefixed）。

推断结果不保证正确 —— 生成的字段名都带 ``inferred`` 前缀、Proto 名
默认 ``inferred``，并在头部注明来源，避免与真实 dissector 混淆。
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from ..models import AnalysisResult, FieldSpec, MessageType
from . import UnsupportedTemplateError

_LUA_UINT = {1: "uint8", 2: "uint16", 3: "uint24", 4: "uint32", 8: "uint64"}


def _pick_fields(result: AnalysisResult) -> Tuple[str, List[FieldSpec]]:
    """选字段模板：最大消息簇优先，否则整体模板。"""
    mts: Optional[List[MessageType]] = result.message_types or None
    if mts:
        best = max(mts, key=lambda m: m.count)
        if best.fields:
            return f"最大消息簇（{best.describe()}）", best.fields
    return "整体字段模板", list(result.fields)


def _protofield(kind: str, length: int) -> str:
    if kind == "checksum":
        return "ProtoField.uint32" if length == 4 else "ProtoField.bytes"
    if kind in ("length", "integer", "counter", "enum", "timestamp"):
        return "ProtoField." + _LUA_UINT.get(length, "uint32")
    if kind == "ipv4":
        return "ProtoField.ipv4"
    if kind == "float":
        return "ProtoField.double" if length == 8 else "ProtoField.float"
    if kind == "text":
        return "ProtoField.string"
    return "ProtoField.bytes"          # magic / constant / binary / random


def _lua_str(b: bytes) -> str:
    out = []
    for byte in b:
        ch = chr(byte)
        if ch in ('"', "\\"):
            out.append("\\" + ch)
        elif 32 <= byte < 127:
            out.append(ch)
        else:
            out.append("\\%d" % byte)
    return '"' + "".join(out) + '"'


def _framing_code(framing) -> List[str]:
    """生成分帧循环体（Lua，函数体内，缩进 4）。"""
    k = framing.kind
    if k == "fixed_length":
        return [
            f"    local flen = {int(framing.frame_len)}",
            "    while off + flen <= buf:len() do",
            "        emit_frame(buf, tree, off, flen)",
            "        off = off + flen",
            "    end",
        ]
    if k == "delimited":
        d = _lua_str(bytes(framing.delimiter))
        return [
            f"    local delim = {d}",
            "    while off < buf:len() do",
            "        local endpos = find_bytes(buf, delim, off)",
            "        if endpos < 0 then break end",
            "        local flen = endpos + delim:len() - off  -- 分隔符留在帧尾",
            "        emit_frame(buf, tree, off, flen)",
            "        off = off + flen",
            "    end",
        ]
    if k == "ascii_length":
        t = _lua_str(bytes(framing.ascii_terminator or b"\r\n"))
        return [
            f"    local radix = {int(framing.ascii_radix)}",
            f"    local term = {t}",
            "    local tl = term:len()",
            "    while off < buf:len() do",
            "        local eol = find_bytes(buf, term, off)",
            "        if eol < 0 then break end",
            "        local tok = buf(off, eol - off):string()",
            "        local value = tonumber(tok, radix)",
            "        if value == nil or eol - off > 16 then break end",
            "        local body_start = eol + tl",
            "        if value == 0 then                        -- 终止块（chunked 结束）",
            "            local flen = body_start - off",
            "            if equals_at(buf, body_start, term) then flen = flen + tl end",
            "            emit_frame(buf, tree, off, flen)",
            "            break",
            "        end",
            "        if not equals_at(buf, body_start + value, term) then break end",
            "        local flen = body_start + value + tl - off",
            "        emit_frame(buf, tree, off, flen)",
            "        off = off + flen",
            "    end",
        ]
    if k == "length_prefixed":
        spec = framing.length_field
        if spec is None or spec.width is None or spec.variable_overhead:
            raise UnsupportedTemplateError(
                "变长编码（varint 族）暂不支持 Lua 导出。")
        endian = "true" if spec.endian == "big" else "false"
        return [
            f"    local lfoff, lwidth = {int(spec.offset)}, {int(spec.width)}",
            f"    local scale, overhead = {int(spec.scale)}, {int(spec.overhead)}",
            f"    local big_endian = {endian}",
            "    while off + lfoff + lwidth <= buf:len() do",
            "        local range = buf(off + lfoff, lwidth)",
            "        local value = big_endian and range:uint() or range:le_uint()",
            "        local flen = scale * value + overhead",
            "        if flen <= 0 or off + flen > buf:len() then break end",
            "        emit_frame(buf, tree, off, flen)",
            "        off = off + flen",
            "    end",
        ]
    raise UnsupportedTemplateError(f"未知分帧模板 {k!r}")


def to_lua_dissector(result: AnalysisResult, proto_name: str = "inferred",
                     bind_port: Optional[int] = None) -> str:
    """生成独立 Lua dissector 文本。

    :param bind_port: 给出时直接把 dissector 注册到 TCP/UDP 该端口；
        省略时输出注释形式的注册代码，由用户改端口后启用。
    """
    framing = result.framing
    if framing is None:
        raise UnsupportedTemplateError("结果中没有分帧结论，无法导出 dissector。")
    src, fields = _pick_fields(result)
    if not fields:
        raise UnsupportedTemplateError("结果中没有字段模板，无法导出 dissector。")

    # 字段声明与解析语句（Lua 变量名去重）
    decls: List[str] = []
    adds: List[str] = []
    names: List[str] = []
    used = set()
    for f in fields:
        base = f.kind if f.kind not in ("binary", "random") else "data"
        name, j = base, 2
        while name in used:
            name, j = f"{base}{j}", j + 1
        used.add(name)
        names.append(name)
        decls.append(f'local f_{name} = {_protofield(f.kind, f.length)}'
                     f'("{proto_name}.{name}", "{f.label}")')
        if f.offset >= 0:
            guard = f"off + {f.offset} + {f.length} <= flen"
            take = (f"buf(off + {f.offset}, {f.length}))"
                    f"  -- 帧首+{f.offset}")
        else:
            guard = f"flen + ({f.offset}) >= 0"
            take = (f"buf(off + flen + ({f.offset}), {f.length}))"
                    f"  -- 帧尾{f.offset}")
        adds += [f"    if {guard} then",
                 f"        subtree:add(f_{name}, {take})",
                 "    end"]

    lines = [
        "-- 由 flowunpack 自动生成的 Wireshark Lua dissector —— 推断结果，需人工核对。",
        f"-- 协议推断: {result.protocol_hint}（置信度 {result.confidence:.0%}）",
        f"-- 模板    : {framing.describe()}",
        f"-- 字段来源: {src}（{len(fields)} 个字段）",
        "-- 用法: tshark -X lua_script:<本文件> -r capture.pcap",
        "--       或放入 Wireshark 插件目录后重启。",
        "",
        f'local p_{proto_name} = Proto("{proto_name}", "Inferred Protocol (flowunpack)")',
        "",
        *decls,
        "",
        f"p_{proto_name}.fields = {{ "
        + ", ".join(f"f_{n}" for n in names) + " }",
        "",
        "-- 在 tvb 中查找字节序列",
        "local function equals_at(buf, pos, pattern)",
        "    if pos < 0 or pos + pattern:len() > buf:len() then return false end",
        "    for j = 0, pattern:len() - 1 do",
        "        if buf(pos + j, 1):uint() ~= pattern:byte(j + 1) then",
        "            return false",
        "        end",
        "    end",
        "    return true",
        "end",
        "",
        "local function find_bytes(buf, pattern, from)",
        "    local plen = pattern:len()",
        "    for i = from, buf:len() - plen do",
        "        if equals_at(buf, i, pattern) then return i end",
        "    end",
        "    return -1",
        "end",
        "",
        "local function emit_frame(buf, tree, off, flen)",
        f"    local subtree = tree:add(p_{proto_name}, buf(off, flen),",
        '                            "Inferred frame (%d bytes)", flen)',
        *adds,
        "end",
        "",
        f"function p_{proto_name}.dissector(buf, pinfo, tree)",
        f'    pinfo.cols.protocol = "{proto_name.upper()}"',
        f"    local off = {int(framing.start_offset)}",
        *_framing_code(framing),
        "end",
        "",
    ]
    if bind_port is None:
        lines += [
            "-- 端口绑定（按需修改端口后取消注释并加入文件末尾）：",
            f'-- DissectorTable.get("tcp.port"):add(12345, p_{proto_name})',
            f'-- DissectorTable.get("udp.port"):add(12345, p_{proto_name})',
        ]
    else:
        lines += [
            "-- 端口绑定（已启用）：",
            f'DissectorTable.get("tcp.port"):add({bind_port}, p_{proto_name})',
            f'DissectorTable.get("udp.port"):add({bind_port}, p_{proto_name})',
        ]
    return "\n".join(lines) + "\n"
