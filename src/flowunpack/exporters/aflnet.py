"""AFLNet / ProFuzzBench 消息切分脚本导出。

背景：AFLNet 五年复盘（IEEE TSE 2025）指出，**消息边界识别**是协议
fuzzing 唯一强制人工输入。本导出把 flowunpack 的分帧结果变成一个
独立、零依赖的切分脚本，消除这一环节。

四种模板全支持，生成的脚本不依赖本库：

* ``length_prefixed`` —— 按帧长公式逐帧走查（varint 族内联 LEB128 解码）；
* ``fixed_length``    —— 等长切分；
* ``delimited``       —— 按终止字节序列切分（分隔符留在帧尾）；
* ``ascii_length``    —— ``<数字><term><数据><term>`` 块状解析
  （HTTP chunked 语义，``value==0`` 为终止块）。

用法（生成脚本头部亦有说明）::

    python split_messages.py <input.bin|.pcap> <out_dir>

pcap 输入需 scapy（可选依赖）；原始流输入无任何依赖。
切分在剩余字节不足/越界处停止，剩余量写进 stderr —— 与本库
``leftover`` 判据一致的诚实报告。
"""

from __future__ import annotations

from ..models import AnalysisResult
from . import UnsupportedTemplateError


def to_aflnet_splitter(result: AnalysisResult) -> str:
    """生成独立的 ``split_messages.py`` 脚本文本。"""
    framing = result.framing
    if framing is None:
        raise UnsupportedTemplateError("结果中没有分帧结论，无法导出切分脚本。")

    kind = framing.kind
    if kind == "length_prefixed":
        split_code = _split_length_prefixed(framing.length_field)  # type: ignore[arg-type]
    elif kind == "fixed_length":
        split_code = _split_fixed(framing.frame_len)
    elif kind == "delimited":
        split_code = _split_delimited(framing.delimiter)
    elif kind == "ascii_length":
        split_code = _split_ascii(framing)
    else:
        raise UnsupportedTemplateError(f"未知分帧模板 {kind!r}")

    if kind == "length_prefixed":
        lf = framing.length_field
        assert lf is not None
        spec_line = (lf.formula() + f"（{lf.format} @offset={lf.offset}，"
                     f"{lf.semantics}）")
    elif kind == "fixed_length":
        spec_line = f"每帧 {framing.frame_len} 字节"
    elif kind == "delimited":
        spec_line = f"以 {framing.delimiter.hex()!r} 结尾"
    else:  # ascii_length
        spec_line = (f"{framing.ascii_radix} 进制文本长度 @offset="
                     f"{framing.ascii_offset}，终止符 "
                     f"{framing.ascii_terminator.hex()!r}")

    return "\n".join([
        "#!/usr/bin/env python3",
        '"""由 flowunpack 自动生成的消息切分脚本 —— 供 AFLNet / ProFuzzBench 使用。',
        "",
        f"分帧模板: {kind} —— {spec_line}",
        f"推断置信度: {result.confidence:.0%}（推断结果，建议抽帧人工核对）",
        "",
        "用法:",
        "    python split_messages.py <input.bin> <out_dir>   # 原始流文件（零依赖）",
        "    python split_messages.py <input.pcap> <out_dir>  # pcap（需 scapy）",
        "",
        "输出: <out_dir>/msg_0001.bin ...（按序切出的消息）",
        '"""',
        "import os",
        "import sys",
        "",
        "",
        "def read_stream(path):",
        '    if path.lower().endswith((".pcap", ".pcapng")):',
        "        try:",
        "            from scapy.utils import rdpcap",
        "        except ImportError:",
        '            sys.exit("读取 pcap 需要 scapy: pip install scapy")',
        '        blobs = []',
        "        for pkt in rdpcap(path):",
        "            # 取传输层载荷：优先 TCP/UDP，否则整包",
        "            layer = pkt.getlayer(\"TCP\") or pkt.getlayer(\"UDP\")",
        "            blobs.append(bytes(layer.payload) if layer is not None else bytes(pkt))",
        "        return b\"\".join(blobs)",
        "    with open(path, \"rb\") as fh:",
        "        return fh.read()",
        "",
        "",
        "def split_messages(data):",
        '    """按帧切分；返回 (帧列表, 剩余字节数)。"""',
        split_code,
        "",
        "",
        "def main():",
        "    if len(sys.argv) != 3:",
        '        sys.exit(__doc__)',
        "    data = read_stream(sys.argv[1])",
        "    out_dir = sys.argv[2]",
        "    os.makedirs(out_dir, exist_ok=True)",
        "    frames, leftover = split_messages(data)",
        "    for i, fr in enumerate(frames, 1):",
        '        with open(os.path.join(out_dir, "msg_%04d.bin" % i), "wb") as fh:',
        "            fh.write(fr)",
        '    print("%d frames -> %s; leftover=%d bytes" % (len(frames), out_dir, leftover))',
        "    if leftover:",
        '        print("warning: %d trailing bytes could not be framed" % leftover,',
        "              file=sys.stderr)",
        "",
        "",
        'if __name__ == "__main__":',
        "    main()",
    ]) + "\n"


# ---------------------------------------------------------------------------
# 各模板的切分函数体（生成到独立脚本里，零依赖）
# ---------------------------------------------------------------------------

def _split_length_prefixed(spec) -> str:
    from ..codecs import FORMATS
    fmt = FORMATS.get(spec.format)
    if fmt is None:
        raise UnsupportedTemplateError(f"未知编码格式 {spec.format!r}")
    off = spec.offset
    scale, overhead = spec.scale, spec.overhead
    extra = " + width" if spec.variable_overhead else ""
    if fmt.variable:
        if spec.format == "varint_be":
            reader = (
                "        # varint_be: 大端 LEB128（高 7 位组在前）\n"
                "        value = 0\n"
                "        width = 0\n"
                "        while True:\n"
                "            if off2 >= len(data):\n"
                "                return frames, len(data) - start\n"
                "            b = data[off2]; off2 += 1; width += 1\n"
                "            value = (value << 7) | (b & 0x7F)\n"
                "            if not b & 0x80:\n"
                "                break"
            )
        else:
            reader = (
                "        # LEB128: 低 7 位组在前，最高位为续传标志\n"
                "        value = 0\n"
                "        shift = 0\n"
                "        width = 0\n"
                "        while True:\n"
                "            if off2 >= len(data):\n"
                "                return frames, len(data) - start\n"
                "            b = data[off2]; off2 += 1; width += 1\n"
                "            value |= (b & 0x7F) << shift\n"
                "            if not b & 0x80:\n"
                "                break\n"
                "            shift += 7"
            )
        width_expr = " + width"
    else:
        reader = (
            "        width = %d\n"
            "        if off2 + width > len(data):\n"
            "            return frames, len(data) - start\n"
            "        value = int.from_bytes(data[off2:off2 + width], %r)"
            % (fmt.width, "big" if spec.endian == "big" else "little")
        )
        width_expr = ""
    return (
        "    frames = []\n"
        "    start = 0\n"
        "    n = len(data)\n"
        "    while start < n:\n"
        f"        off2 = start + {off}\n"
        + reader + "\n"
        f"        frame_len = {scale} * value + {overhead}{width_expr}\n"
        "        if frame_len <= 0 or start + frame_len > n:\n"
        "            return frames, n - start\n"
        "        frames.append(data[start:start + frame_len])\n"
        "        start += frame_len\n"
        "    return frames, 0"
    )


def _split_fixed(frame_len) -> str:
    if not frame_len or frame_len <= 0:
        raise UnsupportedTemplateError(f"定长模板的帧长无效: {frame_len}")
    return (
        "    frames = []\n"
        "    n = len(data)\n"
        "    start = 0\n"
        f"    flen = {int(frame_len)}\n"
        "    while start + flen <= n:\n"
        "        frames.append(data[start:start + flen])\n"
        "        start += flen\n"
        "    return frames, n - start"
    )


def _split_delimited(delimiter: bytes) -> str:
    if not delimiter:
        raise UnsupportedTemplateError("分隔符为空，无法切分。")
    return (
        "    frames = []\n"
        "    n = len(data)\n"
        "    start = 0\n"
        f"    delim = {delimiter!r}\n"
        "    dl = len(delim)\n"
        "    while start < n:\n"
        "        end = data.find(delim, start)\n"
        "        if end < 0:\n"
        "            return frames, n - start\n"
        "        frames.append(data[start:end + dl])   # 分隔符留在帧尾（可无损拼回）\n"
        "        start = end + dl\n"
        "    return frames, 0"
    )


def _split_ascii(framing) -> str:
    radix = framing.ascii_radix
    term = framing.ascii_terminator or b"\r\n"
    return (
        "    frames = []\n"
        "    n = len(data)\n"
        "    pos = 0\n"
        f"    term = {term!r}\n"
        f"    digits = set(b'0123456789abcdefABCDEF') if {radix} == 16"
        f" else set(b'0123456789')\n"
        "    tl = len(term)\n"
        "    while pos < n:\n"
        "        eol = data.find(term, pos)\n"
        "        if eol < 0:\n"
        "            return frames, n - pos\n"
        "        token = data[pos:eol]\n"
        "        if not token or len(token) > 16 or any(c not in digits for c in token):\n"
        "            return frames, n - pos\n"
        "        value = int(token.decode('latin1'), %d)\n" % radix
        +
        "        body_start = eol + tl\n"
        "        if value == 0:                       # HTTP chunked 终止块\n"
        "            end = body_start\n"
        "            if data[end:end + tl] == term:\n"
        "                end += tl\n"
        "            frames.append(data[pos:end])\n"
        "            return frames, n - end\n"
        "        body_end = body_start + value\n"
        "        if body_end + tl > n or data[body_end:body_end + tl] != term:\n"
        "            return frames, n - pos\n"
        "        frames.append(data[pos:body_end + tl])\n"
        "        pos = body_end + tl\n"
        "    return frames, 0"
    )
