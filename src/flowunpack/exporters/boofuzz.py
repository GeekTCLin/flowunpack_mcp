"""boofuzz 模板导出。

帧结构与 boofuzz block 的映射（``length_prefixed``）::

    [固定前缀][长度字段][固定中段][载荷块][trailer]
     s_static   s_size   s_static  s_block  s_checksum / s_static

* 长度字段 → ``s_size("payload", ..., math=...)``，
  ``math`` 表达 ``frame_len = scale*value + overhead`` 的反解：
  - ``body_length``:   value = len(payload) // scale
  - ``total_length``:  value = (固定头 + len(payload) + trailer) // scale
* 检出 ``checksum`` 字段（距帧尾、算法含 crc32）时 → ``s_checksum``；
  其它算法输出静态字节 + "需按协议重算"注释。
* 变长编码（varint 族）与三种非长度前缀模板无法用定宽 ``s_size`` 表达，
  抛 :class:`UnsupportedTemplateError`。

产物是独立脚本，只依赖 boofuzz；默认只 fuzz 长度字段（帧结构的要害），
载荷以首帧样本作静态默认值，使用者可自行替换为协议原语。
"""

from __future__ import annotations

from typing import List

from ..codecs import FORMATS
from ..models import AnalysisResult, FieldSpec
from . import UnsupportedTemplateError

_FIXED_ENDIAN = {"big": "ENDIAN.BIG", "little": "ENDIAN.LITTLE"}


def _checksum_field(fields: List[FieldSpec]) -> FieldSpec:
    for f in fields:
        if f.kind == "checksum" and f.offset < 0:
            return f
    raise StopIteration


def _frame_bytes(result: AnalysisResult) -> bytes:
    f0 = result.frames[0]
    return bytes(f0.header) + bytes(f0.body)


def to_boofuzz(result: AnalysisResult, host: str = "127.0.0.1",
               port: int = 9999, proto_name: str = "inferred") -> str:
    """生成 boofuzz 模板脚本。参数与用法见模块 docstring。"""
    spec = result.length_field
    if result.framing is None or result.framing.kind != "length_prefixed" \
            or spec is None:
        kind = result.framing.kind if result.framing else "unknown"
        raise UnsupportedTemplateError(
            f"boofuzz 模板仅支持 length_prefixed（当前 {kind}）。"
            "分隔符/定长/ASCII 长度请用 aflnet 或 lua 导出。")
    fmt = FORMATS.get(spec.format)
    if fmt is None or fmt.variable or spec.width is None:
        raise UnsupportedTemplateError(
            f"变长编码 {spec.format} 无法用定宽 s_size 表达，"
            "boofuzz 模板仅支持定宽编码。")
    if not result.frames:
        raise UnsupportedTemplateError("结果中没有帧，无法取默认字节。")

    full = _frame_bytes(result)
    off, width = spec.offset, spec.width
    if off + width > len(full):
        raise UnsupportedTemplateError("长度字段越界，结果异常。")
    if spec.semantics == "unknown":
        raise UnsupportedTemplateError(
            "长度语义无法确定（semantics=unknown），导出的模板会是错的；"
            "请先用 analyze_stream 复核该流。")

    # 布局由公式推导（header_len/body_offset 在等价族下只是近似，不可靠）：
    #   body_length : frame_len = scale*value + overhead
    #                 overhead = 定长头（含长度字段）+ trailer
    #                 → header_total = overhead - T，mid = [off+width, header_total)
    #   total_length: frame_len = scale*value，长度字段计入计数
    #                 → header_total = off + width，mid 为空
    trailer_len = 0
    ck_algo = ""
    try:
        ck = _checksum_field(result.fields)
        ck_algo = str(ck.evidence.get("algorithm", ""))
        if -ck.offset <= len(full) - (off + width):
            trailer_len = -ck.offset
    except StopIteration:
        pass

    if spec.semantics == "total_length":
        header_total = off + width
    else:
        header_total = spec.overhead - trailer_len
    prefix = full[:off]
    mid_end = max(header_total, off + width)
    mid = full[off + width:mid_end]
    payload_all = full[mid_end:]
    payload = payload_all[:len(payload_all) - trailer_len]
    trailer: List[str] = []
    if trailer_len:
        tail = payload_all[len(payload_all) - trailer_len:]
        if "crc32" in ck_algo:
            trailer = [
                "# trailer：校验和 @帧尾-%d（%s）—— 由 boofuzz 重算"
                % (trailer_len, ck_algo),
                's_checksum("payload", length=%d, algorithm="crc32", '
                'endianness=ENDIAN.BIG)' % trailer_len,
            ]
        else:
            trailer = [
                "# trailer：校验和 @帧尾-%d（%s）—— boofuzz 未内置该算法，"
                "变异时需自行重算" % (trailer_len, ck_algo or "unknown"),
                "s_static(%s)" % repr(bytes(tail)),
            ]

    if spec.semantics == "total_length":
        math_expr = f"(n + {off + width + trailer_len}) // {spec.scale}"
        math_note = (f"value = (固定头 {off + width + trailer_len}B + 载荷) "
                     f"// {spec.scale}（total_length 语义）")
    else:
        math_expr = f"n // {spec.scale}"
        math_note = f"value = 载荷 // {spec.scale}（body_length 语义）"

    lines = [
        "#!/usr/bin/env python3",
        '"""由 flowunpack 自动生成的 boofuzz 模板 —— 推断结果，需人工核对。',
        "",
        f"协议推断   : {result.protocol_hint}"
        f"（置信度 {result.confidence:.0%}）",
        f"帧长公式   : {spec.formula()}",
        f"长度字段   : {spec.format} @offset={off} ({spec.endian}-endian, "
        f"{width} 字节)",
        f"size 语义  : {math_note}",
        "",
        "用法: 修改 HOST/PORT 后运行 python <本文件>",
        '"""',
        "from boofuzz import *",
        "",
        f'HOST, PORT = {host!r}, {port!r}',
        "",
        "",
        "def build_request():",
        '    s_initialize("frame")',
        "    s_static(%s)  # 固定前缀（长度字段之前）" % repr(bytes(prefix)),
        "    # 长度字段: %s @%d，作用于下方 payload 块" % (spec.format, off),
        '    s_size("payload", length=%d, endianness=%s,' % (width, _FIXED_ENDIAN[spec.endian]),
        "           math=lambda n: %s, fuzzable=True)" % math_expr,
    ]
    if mid:
        lines.append("    s_static(%s)  # 长度字段之后的固定头部字节"
                     % repr(bytes(mid)))
    lines += [
        '    s_block_start("payload")',
        "    s_static(%s)  # 默认载荷（取自首帧样本）" % repr(bytes(payload)),
        "    s_block_end()",
    ]
    lines += trailer if trailer else []
    lines += [
        "",
        "",
        "def main():",
        "    session = Session(target=Target(Connection(HOST, PORT)))",
        '    session.connect(s_get("frame"))',
        "    session.fuzz()",
        "",
        "",
        'if __name__ == "__main__":',
        "    main()",
    ]
    return "\n".join(lines) + "\n"
