"""诊断：【包头】【包体】型协议的支持边界。

覆盖三类问题：
  1. 包头定长、长度字段在包头中间 —— 应当支持
  2. 长度字段语义是 total_length / 存在 trailer —— 应当支持
  3. 包头**变长**（长度字段偏移或包头长度随命令字变）—— 当前公式无法表达

每例都给出期望的 (offset, format, scale, overhead) 与实测结果。
"""

from __future__ import annotations

import os
import random
import sys
from typing import Callable, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from flowunpack import analyze_stream                       # noqa: E402
from flowunpack.config import DEFAULT_CONFIG                # noqa: E402

rng = random.Random(20260921)


def payload(n: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(n))


# ---------------------------------------------------------------------------
# 用例构造
# ---------------------------------------------------------------------------

def build(frames_spec: List[Tuple[bytes, bytes, bytes]]) -> bytes:
    """frames_spec: 每项 (头部前缀, 头部后缀, 包体) —— 长度字段由调用方拼进中间。"""
    out = bytearray()
    for pre, suf, body in frames_spec:
        out += pre + suf + body
    return bytes(out)


def case_fixed_header_mid() -> Tuple[bytes, dict]:
    """定长包头 8 字节：[magic2][cmd1][len2][seq2][rsv1]，长度字段在中间 offset=3。"""
    out = bytearray()
    for i in range(10):
        body = payload(rng.randint(8, 40))
        out += b"PK" + bytes([0x01]) + len(body).to_bytes(2, "big") \
            + i.to_bytes(2, "big") + b"\x00" + body
    return bytes(out), {"offset": 3, "format": "uint16_be", "scale": 1,
                        "overhead": 8, "note": "包头 8B 定长，len 在 offset 3"}


def case_len_at_head() -> Tuple[bytes, dict]:
    """[len2][magic2][cmd1][rsv1] —— 长度字段在最前，包头 6B。"""
    out = bytearray()
    for i in range(10):
        body = payload(rng.randint(8, 40))
        out += len(body).to_bytes(2, "big") + b"PK" + bytes([0x01]) + b"\x00" + body
    return bytes(out), {"offset": 0, "format": "uint16_be", "scale": 1,
                        "overhead": 6, "note": "包头 6B 定长，len 在 offset 0"}


def case_deep_offset() -> Tuple[bytes, dict]:
    """长度字段靠后：offset=12，包头 16B。"""
    out = bytearray()
    for i in range(10):
        body = payload(rng.randint(8, 40))
        head = bytearray(16)
        head[0:2] = b"PK"
        head[2] = 0x01
        head[12:14] = len(body).to_bytes(2, "big")
        head[14:16] = i.to_bytes(2, "big")
        out += bytes(head) + body
    return bytes(out), {"offset": 12, "format": "uint16_be", "scale": 1,
                        "overhead": 16, "note": "包头 16B 定长，len 在 offset 12"}


def case_total_length() -> Tuple[bytes, dict]:
    """total_length 语义：value = 包头+包体，overhead=0。"""
    out = bytearray()
    for i in range(10):
        body = payload(rng.randint(8, 40))
        total = 8 + len(body)
        out += b"PK" + bytes([0x01]) + total.to_bytes(2, "big") \
            + i.to_bytes(2, "big") + b"\x00" + body
    return bytes(out), {"offset": 3, "format": "uint16_be", "scale": 1,
                        "overhead": 0, "note": "value 含包头 → overhead=0"}


def case_with_trailer() -> Tuple[bytes, dict]:
    """包头 8B + 包体 + 4B CRC 尾部：overhead = 8 + 4 = 12。"""
    import zlib
    out = bytearray()
    for i in range(10):
        body = payload(rng.randint(8, 40))
        core = b"PK" + bytes([0x01]) + len(body).to_bytes(2, "big") \
            + i.to_bytes(2, "big") + b"\x00" + body
        out += core + zlib.crc32(core).to_bytes(4, "big")
    return bytes(out), {"offset": 3, "format": "uint16_be", "scale": 1,
                        "overhead": 12, "note": "包头 8B + 尾部 CRC 4B → overhead=12"}


def case_varint_len() -> Tuple[bytes, dict]:
    """包头 4B，长度字段是 varint（自身宽度可变）→ variable_overhead=True。"""
    def enc(n: int) -> bytes:
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)

    out = bytearray()
    for i in range(12):
        body = payload(rng.randint(8, 200))
        out += b"PK" + bytes([0x01]) + enc(len(body)) + b"\x00" + body
    # 包头 = 2(magic) + 1(cmd) + varint(w) + 1(rsv) = 4 + w - 1
    return bytes(out), {"offset": 3, "format": "varint", "scale": 1,
                        "overhead": 3, "variable_overhead": True,
                        "note": "varint 长度字段 → 公式再加字段实际宽度"}


def case_variable_header_len() -> Tuple[bytes, dict]:
    """**变长包头**：cmd=0x01 包头 6B，cmd=0x02 包头 10B（多 4 字节可选字段）。

    长度字段都在 offset 2，但 overhead 随 cmd 变（6 vs 10）——
    frame_len = v + overhead 里的 overhead 是常量，无法同时满足。
    """
    out = bytearray()
    for i in range(12):
        body = payload(rng.randint(8, 40))
        if i % 2 == 0:
            # 6B 包头
            out += b"PK" + bytes([0x01]) + len(body).to_bytes(2, "big") + b"\x00" + body
        else:
            # 10B 包头：长度字段之后多 4 字节可选字段
            out += b"PK" + bytes([0x02]) + len(body).to_bytes(2, "big") \
                + bytes(rng.randrange(256) for _ in range(4)) + b"\x00" + body
    return bytes(out), {"offset": 2, "format": "uint16_be", "scale": 1,
                        "overhead": None, "note": "包头 6B/10B 混用 → 无单一 overhead"}


def case_variable_len_offset() -> Tuple[bytes, dict]:
    """**长度字段偏移不固定**：cmd=0x01 时 len 在 offset 2，cmd=0x02 时在 offset 6。"""
    out = bytearray()
    for i in range(12):
        body = payload(rng.randint(8, 40))
        if i % 2 == 0:
            out += b"PK" + bytes([0x01]) + len(body).to_bytes(2, "big") + b"\x00" + body
        else:
            out += b"PK" + bytes([0x02]) + bytes(rng.randrange(256) for _ in range(4)) \
                + len(body).to_bytes(2, "big") + b"\x00" + body
    return bytes(out), {"offset": None, "format": "uint16_be", "scale": 1,
                        "overhead": None, "note": "长度字段偏移随 cmd 变 → 无单一 offset"}


def case_offset_beyond_max() -> Tuple[bytes, dict]:
    """长度字段在 offset=40，超出默认 max_offset=32。"""
    out = bytearray()
    for i in range(10):
        body = payload(rng.randint(8, 40))
        head = bytearray(48)
        head[0:2] = b"PK"
        head[40:42] = len(body).to_bytes(2, "big")
        out += bytes(head) + body
    return bytes(out), {"offset": 40, "format": "uint16_be", "scale": 1,
                        "overhead": 48, "note": "offset 40 > max_offset 32；"
                                                "overhead 48 也在 max_overhead 内"}


def case_bcd_length() -> Tuple[bytes, dict]:
    """长度字段是 BCD 编码（十进制 12 → 0x12）—— 非标准整数编码。"""
    out = bytearray()
    for i in range(10):
        n = rng.randint(10, 40)
        body = payload(n)
        bcd = bytes([(n // 10) * 16 + (n % 10)])
        out += b"PK" + bytes([0x01]) + bcd + b"\x00\x00\x00\x00" + body
    return bytes(out), {"offset": 3, "format": None, "scale": None,
                        "overhead": None, "note": "BCD 编码长度 → 不在 formats 列表内"}


CASES: List[Tuple[str, Callable[[], Tuple[bytes, dict]]]] = [
    ("定长包头 len@3", case_fixed_header_mid),
    ("定长包头 len@0", case_len_at_head),
    ("定长包头 len@12", case_deep_offset),
    ("total_length 语义", case_total_length),
    ("带 CRC 尾部", case_with_trailer),
    ("varint 长度字段", case_varint_len),
    ("变长包头(6/10B)", case_variable_header_len),
    ("长度字段偏移不固定", case_variable_len_offset),
    ("offset 40 超默认上限", case_offset_beyond_max),
    ("BCD 编码长度", case_bcd_length),
]


def main() -> int:
    print("=" * 78)
    print("【包头】【包体】型协议支持边界诊断")
    print("=" * 78)
    for name, fn in CASES:
        data, exp = fn()
        res = analyze_stream(data)
        got = res.length_field
        if got is None:
            g = "None"
            ok = exp["offset"] is None   # 期望不支持
            detail = f"detected={res.detected}"
        else:
            g = (f"offset={got.offset} {got.format} scale={got.scale} "
                 f"overhead={got.overhead} var={got.variable_overhead}")
            ok = (exp["offset"] is not None
                  and got.offset == exp["offset"]
                  and got.format == exp["format"]
                  and got.scale == exp["scale"]
                  and (exp["overhead"] is None or got.overhead == exp["overhead"]))
            detail = f"frames={res.unit_count} conf={res.confidence:.2f}"
        mark = "支持" if ok else ("不支持" if exp["offset"] is None
                                  else "**不符**")
        print(f"\n[{mark}] {name}")
        print(f"    期望  {exp['note']}")
        print(f"    实测  {g}")
        print(f"    {detail}")
        if not ok and res.framing is not None:
            print(f"    判定  framing.kind={res.framing.kind}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
