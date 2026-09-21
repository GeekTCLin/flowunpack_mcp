"""追查 diag_header_body.py 里三个"不符"的根因。

1. len@12 那例：包头里 9 个 0x00 —— 是零填充导致的伪解，还是偏移本身的问题？
2. offset=40 那例：放宽 max_offset 后能否命中真解？
3. BCD 那例：为何随机载荷被判成 delimited？是真阳性还是魔数被当分隔符？
"""

from __future__ import annotations

import os
import random
import sys
from typing import List

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from flowunpack import analyze_stream                       # noqa: E402
from flowunpack.config import DEFAULT_CONFIG                # noqa: E402
from flowunpack.detectors import split_by_delimiter         # noqa: E402

rng = random.Random(7)


def payload(n: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(n))


def hdr16(filler: bytes, i: int, blen: int) -> bytes:
    """16B 包头：PK + cmd + filler(9B) + len(2B) + seq(2B) + rsv(1B)"""
    h = bytearray(16)
    h[0:2] = b"PK"
    h[2] = 0x01
    h[3:12] = filler
    h[12:14] = blen.to_bytes(2, "big")
    h[14:16] = i.to_bytes(2, "big")
    return bytes(h)


def main() -> int:
    print("=" * 78)
    print("追查一：len@12 —— 零填充 vs 随机填充")
    print("=" * 78)
    for label, fill in (("零填充 0x00", b"\x00" * 9),
                        ("常量 0xAA", b"\xAA" * 9),
                        ("随机字节", bytes(rng.randrange(256) for _ in range(9 * 12)))):
        out = bytearray()
        j = 0
        for i in range(10):
            body = payload(rng.randint(8, 40))
            f = fill if len(fill) == 9 else fill[j:j + 9]
            j += 9
            out += hdr16(f, i, len(body)) + body
        res = analyze_stream(bytes(out))
        lf = res.length_field
        got = (f"offset={lf.offset} {lf.format} overhead={lf.overhead}"
               if lf else "None")
        # 判据看帧头长度与帧数，不看 offset：零填充让长度字段的高位字节变成
        # 常量，offset/width 落入等价族（见 README §11）。
        ok = bool(lf and lf.overhead == 16 and res.unit_count == 10)
        print(f"  {'正确' if ok else '错误'}  {label:<12} -> {got}"
              f"  frames={res.unit_count} conf={res.confidence:.2f}")

    print()
    print("=" * 78)
    print("追查二：offset=40 —— 放宽 max_offset / max_overhead")
    print("=" * 78)
    out = bytearray()
    for i in range(10):
        body = payload(rng.randint(8, 40))
        h = bytearray(48)
        h[0:2] = b"PK"
        for k in range(2, 40):
            h[k] = rng.randrange(256)
        h[40:42] = len(body).to_bytes(2, "big")
        h[42:48] = i.to_bytes(6, "big")
        out += bytes(h) + body
    data = bytes(out)
    for label, cfg in (("默认 max_offset=32", DEFAULT_CONFIG),
                       ("max_offset=64", DEFAULT_CONFIG.overridden(max_offset=64)),
                       ("max_offset=64, overhead=128",
                        DEFAULT_CONFIG.overridden(max_offset=64, max_overhead=128))):
        res = analyze_stream(data, cfg)
        lf = res.length_field
        got = (f"offset={lf.offset} {lf.format} overhead={lf.overhead}"
               if lf else "None")
        # 真值是 offset=40 / overhead=48；同族等价编码（如 uint32_le@41）也算对，
        # 因此判据只看"是否切出真实的 10 帧"。
        ok = bool(lf and res.unit_count == 10)
        print(f"  {'正确' if ok else '错误'}  {label:<32} -> {got}"
              f"  frames={res.unit_count}")

    print()
    print("=" * 78)
    print("追查三：BCD 长度 —— 为何判成 delimited")
    print("=" * 78)
    out = bytearray()
    for i in range(10):
        n = rng.randint(10, 40)
        body = payload(n)
        bcd = bytes([(n // 10) * 16 + (n % 10)])
        out += b"PK" + bytes([0x01]) + bcd + b"\x00\x00\x00\x00" + body
    data = bytes(out)
    res = analyze_stream(data)
    print(f"  framing.kind = {res.framing.kind if res.framing else None}")
    print(f"  detected={res.detected} frames={res.unit_count}")
    spans, leftover, trunc = split_by_delimiter(data, b"PK")
    print(f"  按 b'PK' 切分 -> {len(spans)} 段，前 3 段起点 "
          f"{[s[0] for s in spans[:3]]}，末尾剩余 {leftover}")
    # 真实边界
    print()
    print("=" * 78)
    print("追查四：变长包头 —— 真解是否根本不存在")
    print("=" * 78)
    out = bytearray()
    truth: List[int] = []
    for i in range(12):
        body = payload(rng.randint(8, 40))
        if i % 2 == 0:
            h = b"PK" + bytes([0x01]) + len(body).to_bytes(2, "big") + b"\x00"
        else:
            h = (b"PK" + bytes([0x02]) + len(body).to_bytes(2, "big")
                 + bytes(rng.randrange(256) for _ in range(4)) + b"\x00")
        truth.append(len(out))
        out += h + body
    data = bytes(out)
    print(f"  真实帧起点 {truth[:6]} ...")
    res = analyze_stream(data)
    lf = res.length_field
    print(f"  实测   {(lf.offset, lf.format, lf.scale, lf.overhead) if lf else None}"
          f" frames={res.unit_count} conf={res.confidence:.2f}")
    # 检查是否存在任何 (offset, overhead) 能同时满足两种包头
    from flowunpack.codecs import value_at
    found = []
    for off in range(0, 32):
        for ov in range(0, 65):
            pos, cnt, okall = 0, 0, True
            for _ in range(12):
                v = value_at(data, pos + off, "uint16_be")
                if v is None:
                    okall = False
                    break
                fl = v + ov
                if fl <= 0 or pos + fl > len(data):
                    okall = False
                    break
                pos += fl
                cnt += 1
            if okall and pos == len(data) and cnt == 12:
                found.append((off, ov))
    print(f"  穷举 (offset,overhead) 能走完 12 帧的组合："
          f"{found[:8]}{' ...' if len(found) > 8 else ''}  共 {len(found)} 个")

    print()
    print("=" * 78)
    print("追查五：定长包头但包头含随机字段 —— 真解是否还在候选里")
    print("=" * 78)
    out = bytearray()
    for i in range(10):
        body = payload(rng.randint(8, 40))
        h = bytearray(16)
        h[0:2] = b"PK"
        h[2] = 0x01
        for k in range(3, 12):                       # 9 字节逐帧随机的"序列号/随机数"
            h[k] = rng.randrange(256)
        h[12:14] = len(body).to_bytes(2, "big")
        h[14:16] = i.to_bytes(2, "big")
        out += bytes(h) + body
    data = bytes(out)
    res = analyze_stream(data)
    lf = res.length_field
    print(f"  实测   {(lf.offset, lf.format, lf.overhead) if lf else None}"
          f"  frames={res.unit_count}")
    hit = [(c.offset, c.format, c.overhead, round(c.score, 3))
           for c in res.candidates if c.offset == 12 and c.overhead == 16]
    print(f"  真解 (offset=12, overhead=16) 是否在候选里："
          f"{hit if hit else '不在'}")
    print(f"  rank-0 候选："
          f"{(res.candidates[0].offset, res.candidates[0].format, res.candidates[0].overhead) if res.candidates else None}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
