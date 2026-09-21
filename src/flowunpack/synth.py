"""合成测试数据生成器：覆盖各种长度前缀协议形态，供测试与演示使用。

所有生成函数返回 ``(stream_bytes, expected_spec)``，便于断言检测是否准确。
"""

from __future__ import annotations

import random
import struct
import zlib
from typing import Tuple

from .codecs import encode_varint
from .models import LengthFieldSpec

__all__ = [
    "make_length_prefixed_stream",
    "make_magic_length_stream",
    "make_varint_stream",
    "make_total_length_stream",
    "make_scaled_length_stream",
    "make_delimited_stream",
    "make_chunked_stream",
    "make_fixed_length_stream",
    "make_crc_length_stream",
    "make_typed_fields_stream",
    "make_multi_type_stream",
    "make_header_body_stream",
    "make_header_varint_stream",
    "make_deep_length_stream",
    "make_zero_filled_header_stream",
    "make_variable_header_stream",
    "make_bcd_length_stream",
    "make_text_stream",
    "make_no_delimiter_text",
    "random_stream",
]


def _payload(n: int, rng: random.Random, kind: str = "ascii") -> bytes:
    """生成载荷。

    ``kind`` 的选择对检测难度有决定性影响，测试时务必区分：

    * ``"ascii"`` —— 36 字符字母表，熵约 5.2 bit/byte。低熵载荷会让"任意偏移读出
      的字节都落在窄区间"，从而产生大量能完整切分流的**必然伪解**（见
      :func:`flowunpack.segmentation._payload_alias`）。HTTP/SMTP/SIP 等文本协议的
      真实 body 就是这种性质。
    * ``"bytes"`` —— 均匀随机字节，熵 8 bit/byte。二进制协议的典型形态，伪解少得多。
    """
    if kind == "ascii":
        alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return bytes(rng.choice(alphabet) for _ in range(n))
    return bytes(rng.randrange(256) for _ in range(n))


def _uint(value: int, fmt: str) -> bytes:
    width = {"uint8": 1, "uint16_be": 2, "uint16_le": 2,
             "uint24_be": 3, "uint24_le": 3,
             "uint32_be": 4, "uint32_le": 4,
             "uint64_be": 8, "uint64_le": 8}[fmt]
    order = "little" if fmt.endswith("_le") else "big"
    return value.to_bytes(width, order)


def make_length_prefixed_stream(fmt: str = "uint16_be", *, frames: int = 12,
                                min_body: int = 4, max_body: int = 40,
                                seed: int = 1, payload: str = "ascii"
                                ) -> Tuple[bytes, LengthFieldSpec]:
    """``[len(width)][body]`` —— 长度字段只描述包体，位于帧首。"""
    rng = random.Random(seed)
    out = bytearray()
    for _ in range(frames):
        body = _payload(rng.randint(min_body, max_body), rng, payload)
        out += _uint(len(body), fmt) + body
    width = len(_uint(0, fmt))
    spec = LengthFieldSpec(offset=0, format=fmt, width=width, overhead=width,
                           semantics="body_length", header_len=width,
                           body_offset=width,
                           endian="little" if fmt.endswith("_le") else "big")
    return bytes(out), spec


def make_magic_length_stream(magic: bytes = b"PKTM", fmt: str = "uint16_be",
                             *, frames: int = 12, min_body: int = 4,
                             max_body: int = 40, seed: int = 2,
                             payload: str = "ascii"
                             ) -> Tuple[bytes, LengthFieldSpec]:
    """``[magic(4)][len(width)][body]`` —— 魔数 + 长度前缀。"""
    rng = random.Random(seed)
    out = bytearray()
    for _ in range(frames):
        body = _payload(rng.randint(min_body, max_body), rng, payload)
        out += magic + _uint(len(body), fmt) + body
    width = len(_uint(0, fmt))
    header_len = len(magic) + width
    spec = LengthFieldSpec(offset=len(magic), format=fmt, width=width,
                           overhead=header_len, semantics="body_length",
                           header_len=header_len, body_offset=header_len,
                           endian="little" if fmt.endswith("_le") else "big")
    return bytes(out), spec


def make_varint_stream(*, frames: int = 14, min_body: int = 4,
                       max_body: int = 200, seed: int = 3,
                       payload: str = "ascii"
                       ) -> Tuple[bytes, LengthFieldSpec]:
    """``[varint len][body]`` —— 变长长度字段。"""
    rng = random.Random(seed)
    # 必须混合 1/2/3 字节宽度的 varint，否则 uint8 之类的定长假设也能解释
    sizes = [4, 130, 20, 400, 70, 20000, 9, 300, 16383, 16384, 45, 900]
    out = bytearray()
    for i in range(frames):
        body = _payload(sizes[i % len(sizes)], rng, payload)
        out += encode_varint(len(body)) + body
    spec = LengthFieldSpec(offset=0, format="varint", width=None, overhead=0,
                           semantics="body_length", header_len=1, body_offset=1,
                           endian="leb128", variable_overhead=True)
    return bytes(out), spec


def make_total_length_stream(fmt: str = "uint32_be", *, frames: int = 10,
                             min_body: int = 4, max_body: int = 60,
                             seed: int = 4, payload: str = "ascii"
                             ) -> Tuple[bytes, LengthFieldSpec]:
    """``[total_len][body]`` —— 长度字段把自身也算进去（overhead=0）。"""
    rng = random.Random(seed)
    out = bytearray()
    width = len(_uint(0, fmt))
    for _ in range(frames):
        body = _payload(rng.randint(min_body, max_body), rng, payload)
        out += _uint(width + len(body), fmt) + body
    spec = LengthFieldSpec(offset=0, format=fmt, width=width, overhead=0,
                           semantics="total_length", header_len=width,
                           body_offset=width,
                           endian="little" if fmt.endswith("_le") else "big")
    return bytes(out), spec


def make_scaled_length_stream(scale: int = 4, fmt: str = "uint16_be", *,
                              frames: int = 24, min_body: int = 8,
                              max_body: int = 60, seed: int = 7,
                              payload: str = "bytes"
                              ) -> Tuple[bytes, LengthFieldSpec]:
    """``[len_in_units][body]`` —— 长度字段以 ``scale`` 字节为单位计数。

    对应真实协议里"长度以字/双字计"的形态：IPv4 的 IHL 以 4 字节字为单位，
    部分工控与音视频协议同样按字计数。帧长公式 ``frame_len = scale * value``。

    只支持 ``scale=1`` 的实现对这类协议**完全检测不到**（实测 2/4/8 全部失败）。

    两个设计取舍，都是为了不让"scale 支持度"这一个变量被其它难点掩盖：

    * 对齐填充用**随机字节**而非零字节。零填充是极强的结构伪影（会造出"某偏移
      恒为 0"的假特征），真实协议里帧尾填充通常是内容无意义的字节。
    * 默认载荷用高熵 ``"bytes"``。若用低熵 ASCII，伪解问题会先于 scale 问题暴露，
      导致无法归因；低熵场景由 ``payload="ascii"`` 单独覆盖。
    """
    rng = random.Random(seed)
    width = len(_uint(0, fmt))
    out = bytearray()
    for _ in range(frames):
        body = _payload(rng.randint(min_body, max_body), rng, payload)
        total = width + len(body)
        pad = (-total) % scale
        if pad:
            body += _payload(pad, rng, payload)     # 对齐填充（随机字节）
            total += pad
        out += _uint(total // scale, fmt) + body
    spec = LengthFieldSpec(offset=0, format=fmt, width=width, overhead=0,
                           semantics="total_length", header_len=width,
                           body_offset=width, scale=scale,
                           endian="little" if fmt.endswith("_le") else "big")
    return bytes(out), spec


def make_delimited_stream(delim: bytes = b"\r\n", *, frames: int = 10,
                          min_len: int = 6, max_len: int = 40,
                          seed: int = 11, prefix: bytes = b"") -> bytes:
    """``[prefix][内容][delim]`` 重复 —— 分隔符分帧（CRLF 文本 / RESP 类）。

    内容只从**不含分隔符字节**的字母表里取，保证分隔符只出现在帧尾，
    否则切分位置会污染真值。
    """
    rng = random.Random(seed)
    banned = set(delim)
    alphabet = bytes(b for b in
                     b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                     b"0123456789 .,:;=+-_/()[]{}"
                     if b not in banned)
    out = bytearray(prefix)
    for _ in range(frames):
        out += bytes(rng.choice(alphabet)
                     for _ in range(rng.randint(min_len, max_len))) + delim
    return bytes(out)


def make_chunked_stream(*, chunks: int = 8, min_len: int = 4, max_len: int = 30,
                        radix: int = 16, term: bytes = b"\r\n", seed: int = 12,
                        final: bool = True, prefix: bytes = b"") -> bytes:
    """HTTP chunked 形态：``<文本长度><term><数据><term>`` 重复。

    ``radix=16`` 对应 HTTP chunked 的十六进制长度，``radix=10`` 覆盖十进制文本长度；
    ``final=True`` 时以 ``0<term><term>`` 结尾（chunked 的结束标记）。
    块数据同样避开终止符字节。
    """
    rng = random.Random(seed)
    banned = set(term)
    alphabet = bytes(b for b in
                     b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                     b"0123456789 !?*#$%&@~^"
                     if b not in banned)
    out = bytearray(prefix)
    for _ in range(chunks):
        n = rng.randint(min_len, max_len)
        token = format(n, "x") if radix == 16 else str(n)
        out += token.encode("ascii") + term
        out += bytes(rng.choice(alphabet) for _ in range(n)) + term
    if final:
        out += b"0" + term + term
    return bytes(out)


def make_fixed_length_stream(*, frame_len: int = 16, frames: int = 12,
                             magic: bytes = b"FX", const_bytes: int = 6,
                             seed: int = 13) -> bytes:
    """定长帧：``[magic][常量][随机载荷]``，每帧等长。

    定长**无法从整除性自证**（流的任意因子都成立），因此这里特意给每帧一个
    **刚性包头**（``len(magic) + const_bytes`` 个恒定字节），作为整除性之外的
    独立证据——对应真实世界里"定长记录 + 固定头"的协议形态。

    要求 ``len(magic) + const_bytes < frame_len``（要留出随机载荷）。
    """
    rng = random.Random(seed)
    fixed = magic + bytes([0xC0] * const_bytes)
    pad = frame_len - len(fixed)
    if pad <= 0:
        raise ValueError("frame_len 必须大于 len(magic)+const_bytes")
    out = bytearray()
    for _ in range(frames):
        out += fixed + bytes(rng.randrange(256) for _ in range(pad))
    return bytes(out)


def make_crc_length_stream(*, frames: int = 12, magic: bytes = b"PKTM",
                           min_body: int = 6, max_body: int = 40,
                           seed: int = 21, payload: str = "bytes"
                           ) -> Tuple[bytes, LengthFieldSpec]:
    """``[magic(4)][cmd(1)][len(2,BE)][body][crc32(4)]`` —— 带尾部校验和。

    用于验证两件事：

    * 长度字段语义（``frame_len = value + 11``，overhead 把魔数、命令字、
      长度字段自身与 CRC 尾部都算进去）；
    * **CRC 能被反算验证**：CRC32 覆盖"本字段之前的全部字节"，这是
      :func:`flowunpack.fields.classify_field` 判定 ``checksum`` 的依据，
      也是识别 trailer（而非把它算进 body）的关键。

    金标准字段：magic@0+4(常量) / cmd@4+1(枚举) / length@5+2 /
    body@7+v / crc@7+v+4(校验和)。
    """
    rng = random.Random(seed)
    out = bytearray()
    for _ in range(frames):
        body = _payload(rng.randint(min_body, max_body), rng, payload)
        head = magic + bytes([rng.choice((1, 2, 3))]) + _uint(len(body),
                                                              "uint16_be")
        frame = head + body
        frame += zlib.crc32(frame).to_bytes(4, "big")
        out += frame
    spec = LengthFieldSpec(offset=5, format="uint16_be", width=2, overhead=11,
                           semantics="body_length", header_len=7, body_offset=7,
                           endian="big")
    return bytes(out), spec


def make_typed_fields_stream(*, frames: int = 16, seed: int = 22
                             ) -> Tuple[bytes, LengthFieldSpec]:
    """包头里塞满可判类型的字段：magic / len / cmd / seq / ts / ipv4 / float。

    ``[magic(2)][len(2,BE)][cmd(1)][seq(2,BE)][ts(4,BE)][ipv4(4)][float(4)][body]``

    用来验证字段语义标注能认出哪些类型，以及**类型驱动的合并**能否把
    "IP 的前两字节恒定、后两字节变化"重新拼回一个 IPv4 字段
    （纯熵边界会把它切碎，见 :func:`flowunpack.fields.refine_by_type`）。

    ``frame_len = value + 19``。
    """
    rng = random.Random(seed)
    out = bytearray()
    base_ts = 1_700_000_000
    for i in range(frames):
        body = bytes(rng.randrange(256) for _ in range(rng.randint(8, 40)))
        head = (b"\xca\xfe"
                + _uint(len(body), "uint16_be")
                + bytes([rng.choice((1, 2, 3))])
                + (i & 0xFFFF).to_bytes(2, "big")
                + (base_ts + i * 7).to_bytes(4, "big")
                + bytes([192, 168, rng.randrange(1, 20), rng.randrange(1, 254)])
                + struct.pack(">f", rng.uniform(1.0, 1000.0)))
        out += head + body
    spec = LengthFieldSpec(offset=2, format="uint16_be", width=2, overhead=19,
                           semantics="body_length", header_len=19, body_offset=19,
                           endian="big")
    return bytes(out), spec


def make_multi_type_stream(*, rounds: int = 5, seed: int = 23
                           ) -> Tuple[bytes, LengthFieldSpec]:
    """同一条流里混杂**三种消息类型**（由命令字区分）。

    ``[magic(2)][cmd(1)][len(1)][body]``，``frame_len = value + 4``。
    三种类型的 body 长度区间互不相交（约 8-9 / 24-26 / 4），
    因此 ``cmd`` 是一个理想的 keyword：取值少、会重复、且与帧长强耦合。

    用于验证 :func:`flowunpack.fields.infer_message_types` 能否自动找到
    keyword 并把消息分簇 —— 这是写 dissector / 做 fuzzing 的前置步骤。
    """
    rng = random.Random(seed)
    kinds = ((1, 8, 2), (2, 24, 3), (3, 4, 1))     # (cmd, 基础长度, 浮动)
    out = bytearray()
    for _ in range(rounds):
        for cmd, base, jitter in kinds:
            n = base + rng.randrange(jitter)
            body = bytes(rng.randrange(256) for _ in range(n))
            out += b"\xab\xcd" + bytes([cmd]) + bytes([len(body)]) + body
    spec = LengthFieldSpec(offset=3, format="uint8", width=1, overhead=4,
                           semantics="body_length", header_len=4, body_offset=4,
                           endian="big")
    return bytes(out), spec


def make_header_body_stream(*, header_len: int = 16, len_offset: int = 12,
                            fmt: str = "uint16_be", frames: int = 10,
                            magic: bytes = b"PK", filler: str = "const",
                            trailer: int = 0, semantics: str = "body_length",
                            min_body: int = 8, max_body: int = 40,
                            seed: int = 31, payload: str = "bytes"
                            ) -> Tuple[bytes, LengthFieldSpec]:
    """**【包头】【包体】** 布局的通用生成器：包头定长，长度字段埋在包头中间。

    这是现实中最常见的一类自定义协议。关键在于：长度字段在包头里的**位置**
    由 ``len_offset`` 表达，包头长度则折进 ``overhead`` —— 两者独立，互不干扰。

    :param filler: 包头除长度字段外的填充，对检测难度**有决定性影响**：

        * ``"const"`` —— 常量字节 ``0xAA``。包头跨帧恒定，是最容易的情形；
        * ``"zeros"`` —— 零字节。**真实协议的保留字段几乎都填 0，但这会致命**：
          零区让"任意偏移读出的值都很小"，从而产生大量伪解。实测同一布局下
          填 0 会给出 30 帧伪解且置信度 0.83，填 0xAA 则完全正确；
        * ``"random"`` —— 逐帧随机（模拟序列号 / 会话 ID / 随机数）。真解通常
          仍在候选里但排在伪解之后，结论不稳定。
    :param trailer: 尾部字节数（>0 时填充 CRC32）。``overhead`` 会把尾部算进去。
    :param semantics: ``"body_length"`` → ``overhead = header_len + trailer``；
        ``"total_length"`` → ``overhead = 0``。

    长度字段必须是**定宽**编码。变长（``varint``）请用
    :func:`make_header_varint_stream` —— varint 的宽度随值变化，包头总长也随之
    变化，"定长包头"这个前提不成立，``overhead`` 的取值规则不同。
    """
    if fmt in ("varint", "varint_be"):
        raise ValueError("变长编码请用 make_header_varint_stream")
    width = len(_uint(0, fmt))
    if len_offset + width > header_len:
        raise ValueError("长度字段放不进包头：len_offset + width > header_len")
    if len(magic) > header_len:
        raise ValueError("magic 比包头还长")

    rng = random.Random(seed)
    out = bytearray()
    for _ in range(frames):
        body = _payload(rng.randint(min_body, max_body), rng, payload)
        head = bytearray(header_len)
        head[0:len(magic)] = magic
        for k in range(len(magic), header_len):
            if len_offset <= k < len_offset + width:
                continue
            if filler == "zeros":
                head[k] = 0x00
            elif filler == "random":
                head[k] = rng.randrange(256)
            else:
                head[k] = 0xAA
        value = (len(body) if semantics == "body_length"
                 else header_len + len(body) + trailer)
        head[len_offset:len_offset + width] = _uint(value, fmt)
        frame = bytes(head) + body
        if trailer:
            frame += zlib.crc32(frame).to_bytes(trailer, "big")
        out += frame

    overhead = (header_len + trailer) if semantics == "body_length" else 0
    return bytes(out), LengthFieldSpec(
        offset=len_offset, format=fmt, width=width, overhead=overhead,
        semantics=semantics, header_len=header_len, body_offset=header_len,
        endian="little" if fmt.endswith("_le") else "big")


def make_header_varint_stream(*, prefix_len: int = 3, suffix_len: int = 1,
                              frames: int = 12, min_body: int = 8,
                              max_body: int = 200, magic: bytes = b"PK",
                              seed: int = 34, payload: str = "bytes"
                              ) -> Tuple[bytes, LengthFieldSpec]:
    """包头里放 **varint 长度字段**：``[prefix][varint][suffix][body]``。

    与 :func:`make_header_body_stream` 的区别：varint 宽度 ``w`` 随值变化，
    包头总长 ``prefix + w + suffix`` 也随之变化。帧长

    ``frame_len = w + prefix_len + suffix_len + len(body)``

    对应公式 ``frame_len = value + overhead + width``，因此
    **``overhead = prefix_len + suffix_len``**（常量），``variable_overhead=True``。
    若把包头做成定长（用填充凑齐），``overhead`` 就得随 ``w`` 变化，模型反而无解——
    真实协议里长度字段是 varint 时，包头本来就是变长的。

    ``min_body``/``max_body`` 跨度要跨过 128，否则 varint 恒为 1 字节宽，
    定宽假设也能解释，测不出 varint 这一路。
    """
    rng = random.Random(seed)
    out = bytearray()
    for _ in range(frames):
        body = _payload(rng.randint(min_body, max_body), rng, payload)
        prefix = bytearray(prefix_len)
        if magic:
            prefix[0:min(len(magic), prefix_len)] = magic[:prefix_len]
        for k in range(len(magic), prefix_len):
            prefix[k] = 0xAA
        suffix = bytes([0xAA]) * suffix_len
        out += bytes(prefix) + encode_varint(len(body)) + suffix + body
    overhead = prefix_len + suffix_len
    return bytes(out), LengthFieldSpec(
        offset=prefix_len, format="varint", width=None, overhead=overhead,
        semantics="body_length", header_len=overhead + 1,
        body_offset=overhead + 1, endian="leb128", variable_overhead=True)


def make_deep_length_stream(**kw) -> Tuple[bytes, LengthFieldSpec]:
    """长度字段深埋在包头（offset=12，包头 16B）—— 常量填充，应当被正确识别。"""
    kw.setdefault("header_len", 16)
    kw.setdefault("len_offset", 12)
    kw.setdefault("filler", "const")
    return make_header_body_stream(**kw)


def make_zero_filled_header_stream(**kw) -> Tuple[bytes, LengthFieldSpec]:
    """同 :func:`make_deep_length_stream`，但包头填充 0x00。

    **已知会导致误判**（给出远多于真实帧数的伪解且置信度偏高）。保留在此是为了
    把这个失败模式固定成回归用例，而不是让它在文档里慢慢腐烂。
    """
    kw.setdefault("header_len", 16)
    kw.setdefault("len_offset", 12)
    kw.setdefault("filler", "zeros")
    return make_header_body_stream(**kw)


def make_variable_header_stream(*, frames: int = 12, seed: int = 32,
                                min_body: int = 8, max_body: int = 40,
                                payload: str = "bytes") -> bytes:
    """**变长包头** —— 包头长度随命令字变化（6B / 10B 混用）。

    命令字 ``0x01`` 用 6 字节包头，``0x02`` 用 10 字节包头（多 4 字节可选字段），
    长度字段都在 offset 2、语义都是 body_length。

    **当前模型无法表达**：``frame_len = a·v + b`` 里的 ``b`` 是常量，而这里
    需要的是"随命令字变化的 b"。实测穷举全部 ``(offset, overhead)`` 组合，
    能走完 12 帧的方案数为 **0** —— 不是参数没调对，是模型层面无解。
    """
    rng = random.Random(seed)
    out = bytearray()
    for i in range(frames):
        body = _payload(rng.randint(min_body, max_body), rng, payload)
        if i % 2 == 0:
            head = b"PK" + bytes([0x01]) + _uint(len(body), "uint16_be") + b"\x00"
        else:
            head = (b"PK" + bytes([0x02]) + _uint(len(body), "uint16_be")
                    + bytes(rng.randrange(256) for _ in range(4)) + b"\x00")
        out += head + body
    return bytes(out)


def make_bcd_length_stream(*, frames: int = 10, seed: int = 33,
                           min_body: int = 10, max_body: int = 40,
                           payload: str = "bytes") -> bytes:
    """长度字段用 **BCD 编码**（十进制 12 → 字节 ``0x12``）。

    不在 ``config.formats`` 支持的编码列表内。**注意失败方式是"给出错误答案"
    而不是"拒绝回答"** —— 这比漏检更危险，因此单独留作回归用例。
    """
    rng = random.Random(seed)
    out = bytearray()
    for _ in range(frames):
        n = rng.randint(min_body, max_body)
        body = _payload(n, rng, payload)
        bcd = bytes([(n // 10) * 16 + (n % 10)])
        out += b"PK" + bytes([0x01]) + bcd + b"\x00\x00\x00\x00" + body
    return bytes(out)


def make_text_stream(*, lines: int = 8, seed: int = 5) -> bytes:
    """纯文本流（CRLF 分行，**不含长度字段**）。

    注意：自 P0-2 起，CRLF 分行本身就是一个合法的**分隔符分帧**模板，
    因此本函数生成的流会被 ``delimited`` 模板识别 —— 这是预期行为，
    它不再是"必须被拒绝"的负样本。真正无结构的负样本请用
    :func:`random_stream` 或 :func:`make_no_delimiter_text`。
    """
    rng = random.Random(seed)
    return b"\r\n".join(_payload(rng.randint(10, 40), rng) for _ in range(lines))


def make_no_delimiter_text(*, length: int = 400, seed: int = 15) -> bytes:
    """无任何结构性分隔符的文本 —— 负样本。

    字母表刻意排除 ``\\r``、``\\n`` 与其它常见分隔符字节，且足够长以使任何
    2 字节序列的出现次数都接近随机期望（不通过显著性门槛）。
    """
    rng = random.Random(seed)
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,"
    return bytes(rng.choice(alphabet) for _ in range(length))


def random_stream(n: int = 512, seed: int = 6) -> bytes:
    """随机字节流 —— 用作负样本。

    注意：``Random`` 必须只实例化一次；若在生成表达式内构造，
    每次都会取到同一个"首个随机数"，得到的是常量字节流。
    """
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(n))
