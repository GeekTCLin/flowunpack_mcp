"""包头零填充：伪解成因、修复验证与残留歧义。

背景（README §11）：一个 16 字节包头、长度字段在 offset 12 的协议，包头中间
9 字节填 ``0x00`` 时曾被判成 ``offset=2 uint16_le overhead=5`` 的 **30 帧伪解**
（conf 0.83），而真解（10 帧）**根本不在候选列表里**。同样的布局填 ``0xAA``
则完全正确。

本脚本做四件事：

1. **复现历史伪解** —— 用修复前的走查判据（``frame_len < offset+width+1``
   才中断）重走一遍，确认它确实能把流切成 30 段；
2. **验证修复** —— 当前判据（帧长必须容纳整个帧头 + 1 字节载荷）下伪解消失、
   真解族胜出，且帧边界与金标准逐帧一致；
3. **列出等价族** —— 同一帧边界签名组里的全部编码写法，以及各自覆盖了多少个
   "跨帧恒定字节"（= 宽度被高估的程度，用来解释为什么代表选择会偏宽）；
4. **对照填充方式** —— ``0x00`` / ``0xAA`` / ``random`` 三种填充下的最终结论。
"""

from __future__ import annotations

import os
import random
import sys
from collections import defaultdict
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from flowunpack import analyze_stream                        # noqa: E402
from flowunpack.codecs import FORMATS, decode_at, min_width  # noqa: E402
from flowunpack.config import DEFAULT_CONFIG as C            # noqa: E402
from flowunpack.segmentation import (apply_spec,             # noqa: E402
                                     _collect_successes, _tightness)
from flowunpack.synth import (make_deep_length_stream,       # noqa: E402
                              make_header_body_stream,
                              make_zero_filled_header_stream)

HEADER_LEN = 16
LEN_OFFSET = 12
MAGIC = b"PK"
CMD = 0x01


def header(filler: bytes, seq: int, body_len: int) -> bytes:
    """16B 包头：magic2 + cmd1 + x9 + len2 + seq2。"""
    h = bytearray(HEADER_LEN)
    h[0:len(MAGIC)] = MAGIC
    h[len(MAGIC)] = CMD
    h[3:12] = filler
    h[LEN_OFFSET:LEN_OFFSET + 2] = body_len.to_bytes(2, "big")
    h[LEN_OFFSET + 2:HEADER_LEN] = seq.to_bytes(2, "big")
    return bytes(h)


def build(filler: bytes, frames: int = 10, seed: int = 7,
          seq: bool = True) -> bytes:
    """按给定填充造一条流。``seq=True`` 时包头尾部两字节是递增序号。"""
    rng = random.Random(seed)
    out = bytearray()
    for i in range(frames):
        body = bytes(rng.randrange(256) for _ in range(rng.randint(8, 40)))
        out += header(filler, i if seq else 0, len(body)) + body
    return bytes(out)


def legacy_walk(data: bytes, offset: int, fmt: str, overhead: int,
                start: int = 0, count_width: bool = False, scale: int = 1
                ) -> Tuple[List[Tuple[int, int]], List[int]]:
    """复现**修复前**的走查判据，仅用于对照。

    与当前 ``segmentation.walk`` 的唯一差别：中断条件是
    ``frame_len < offset + width + 1``（而不是"必须容纳整个帧头"），
    因此 ``frame_len == overhead`` 的零载荷帧被放行。
    """
    frames: List[Tuple[int, int]] = []
    values: List[int] = []
    pos, total = start, len(data)
    width_hint = min_width(fmt)
    while pos < total:
        if total - pos < offset + width_hint:
            break
        got = decode_at(data, pos + offset, fmt)
        if got is None:
            break
        value, width = got
        frame_len = scale * value + overhead + (width if count_width else 0)
        if frame_len <= 0 or frame_len < offset + width + 1:   # <-- 旧判据
            break
        if pos + frame_len > total:
            break
        frames.append((pos, frame_len))
        values.append(value)
        pos += frame_len
    return frames, values


def constant_bytes(data: bytes, spans: List[Tuple[int, int]], offset: int,
                   width: int) -> Tuple[int, List[int]]:
    """长度字段覆盖范围内跨帧恒定的字节数，以及这些列的列号。

    ``spans`` 是 ``[(帧起点, 帧长), ...]``。
    """
    cols = []
    for i in range(offset, offset + width):
        vals = {data[pos + i] for pos, _ in spans if pos + i < len(data)}
        if len(vals) <= 1:
            cols.append(i)
    return len(cols), cols


def signature_groups(data: bytes):
    pool, _ = _collect_successes(data, C)
    groups: Dict[tuple, list] = defaultdict(list)
    for r in pool:
        groups[r.signature].append(r)
    if not groups:
        return None
    return max(groups.values(), key=lambda ms: len(ms[0].frames))


def report(title: str, data: bytes, gold_offsets: List[int] | None) -> None:
    res = analyze_stream(data)
    lf = res.length_field
    print(f"  {title}")
    print(f"    detected={res.detected}  kind="
          f"{res.framing.kind if res.framing else None}  "
          f"帧数={res.unit_count}  置信度={res.confidence:.3f}")
    if lf is not None:
        print(f"    长度字段: offset={lf.offset} {lf.format} "
              f"width={lf.width} overhead={lf.overhead} "
              f"scale={lf.scale} semantics={lf.semantics}")
    if gold_offsets is not None:
        spans = [(f.offset, f.length) for f in res.frames]
        same = [f.offset for f in res.frames] == gold_offsets
        print(f"    帧边界与金标准一致: {same}")
        if lf is not None:
            n = constant_bytes(data, spans, lf.offset, lf.width or 1)[0]
            print(f"    字段覆盖的跨帧恒定字节: {n}/{lf.width or 1}")


def main() -> int:
    sample_synth, spec = make_zero_filled_header_stream()
    sample_seq = build(b"\x00" * 9, seq=True)
    gold_seq = [f.offset for f in apply_spec(
        sample_seq, spec, C)[0]]
    gold_synth = [f.offset for f in apply_spec(sample_synth, spec, C)[0]]

    print("=" * 78)
    print("一、历史伪解复现（修复前的走查判据）")
    print("=" * 78)
    frames, values = legacy_walk(sample_seq, offset=2, fmt="uint16_le",
                                 overhead=5)
    print(f"  样本：含递增序号的零填充包头（{len(sample_seq)}B，真解 10 帧）")
    print(f"  旧判据下 offset=2 uint16_le overhead=5 -> {len(frames)} 帧，"
          f"帧长 {min(f for _, f in frames)}..{max(f for _, f in frames)}，"
          f"末尾剩余 {len(sample_seq) - sum(f for _, f in frames)}")
    print(f"  长度值序列: {values}")
    zero_frames = sum(1 for _, f in frames if f <= 5)
    print(f"  其中帧长 == 帧头(5) 的零载荷帧: {zero_frames}/{len(frames)}"
          f"  <- 正是新判据拦掉的那批")
    print()

    print("=" * 78)
    print("二、修复后的最终结论")
    print("=" * 78)
    report("样本 A（synth 生成器：包头剩余字节填 0）", sample_synth, gold_synth)
    print()
    report("样本 B（包头含递增序号）", sample_seq, gold_seq)
    print()

    print("=" * 78)
    print("三、同签名组里的等价族（为什么代表会偏宽）")
    print("=" * 78)
    for tag, data in (("样本 A", sample_synth), ("样本 B", sample_seq)):
        members = signature_groups(data)
        if not members:
            print(f"  {tag}: 无成功走查")
            continue
        print(f"  {tag}：帧数 {len(members[0].frames)}，"
              f"成员 {len(members)} 个"
              f"（各自覆盖的恒定字节越多，宽度被高估越厉害）")
        rows = []
        for r in members:
            w = FORMATS[r.format].width or 1
            n, cols = constant_bytes(data, r.frames, r.offset, w)
            structural, _ = _tightness(r, w)
            rows.append((n, r.offset, r.format, r.overhead, w, structural, cols))
        for n, off, fmt, oh, w, structural, cols in sorted(rows):
            mark = "  <- 实测代表" if (off, fmt, oh) == (10, "uint32_be", 16) \
                else ""
            print(f"    off={off:<3} {fmt:<10} oh={oh:<3} width={w} "
                  f"恒定字节={n}/{w} 紧致={structural:.2f} 列={cols}{mark}")
        print("    注：这些写法数值相同、帧边界相同，信息上无法区分；"
              "偏宽是 _dedup_key 的有意取向（见 segmentation._dedup_key）。")
        print()

    print("=" * 78)
    print("四、填充方式对照")
    print("=" * 78)
    cases = [
        ("0x00 零填充", sample_synth),
        ("0xAA 常量填充", build(b"\xAA" * 9, seq=False)),
        ("随机填充", make_header_body_stream(
            header_len=HEADER_LEN, len_offset=LEN_OFFSET, filler="random")[0]),
        ("0x00 + 递增序号", sample_seq),
    ]
    for tag, data in cases:
        res = analyze_stream(data)
        lf = res.length_field
        print(f"  {tag:<16} 帧数={res.unit_count:<3} "
              f"offset={lf.offset if lf else '-':<3} "
              f"{lf.format if lf else '-':<10} "
              f"overhead={lf.overhead if lf else '-':<3} "
              f"conf={res.confidence:.3f}")

    # 0xAA 对照样本的帧边界校验用同布局生成器
    const_data, const_spec = make_deep_length_stream()
    print()
    print("  对照组（const，同布局，共 10 帧）:", end=" ")
    r = analyze_stream(const_data)
    print(f"detected={r.detected} 帧数={r.unit_count} "
          f"帧边界一致="
          f"{[f.offset for f in r.frames] == [f.offset for f in apply_spec(const_data, const_spec, C)[0]]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
