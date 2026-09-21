"""剖析 _search 的耗时构成：假设数 / 各级存活数 / 走查步数。"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from flowunpack import synth                                       # noqa: E402
from flowunpack.codecs import FORMATS, decode_at, min_width        # noqa: E402
from flowunpack.config import DEFAULT_CONFIG                       # noqa: E402
from flowunpack.segmentation import _overhead_range                # noqa: E402

CFG = DEFAULT_CONFIG


def count_steps(data, offset, fmt, overhead, start, count_width, scale, cap):
    """模拟一次走查，返回步数（不构造对象，纯计数）。"""
    pos = start
    total = len(data)
    steps = 0
    while pos < total and steps < cap:
        got = decode_at(data, pos + offset, fmt)
        if got is None:
            break
        value, width = got
        flen = scale * value + overhead + (width if count_width else 0)
        if flen <= 0 or flen < offset + width + 1:
            break
        if pos + flen > total:
            break
        steps += 1
        pos += flen
    return steps


def profile(name, data):
    print(f"===== {name}  len={len(data)} =====")
    max_offset = min(CFG.max_offset, len(data) - 1)
    combos = 0
    stage1_pass = 0
    stage1_steps = 0
    stage2_steps = 0
    for offset in range(0, max_offset + 1):
        for fmt in CFG.formats:
            if offset + min_width(fmt) > len(data):
                continue
            variable = FORMATS[fmt].variable
            for scale in CFG.scales:
                for overhead in _overhead_range(data, offset, fmt, CFG, 0,
                                                variable, scale):
                    combos += 1
                    s1 = count_steps(data, offset, fmt, overhead, 0, variable,
                                     scale, CFG.probe_stage1_frames)
                    stage1_steps += s1
                    if s1 < CFG.probe_stage1_frames:
                        continue          # 没走满一级上限 -> 淘汰
                    stage1_pass += 1
                    stage2_steps += count_steps(data, offset, fmt, overhead, 0,
                                                variable, scale,
                                                CFG.max_probe_frames)
    print(f"  (offset,fmt,scale,overhead) 组合数 : {combos}")
    print(f"  一级(4帧)存活                     : {stage1_pass} "
          f"({stage1_pass/max(combos,1):.1%})")
    print(f"  一级走查总步数                    : {stage1_steps}")
    print(f"  二级(96帧)走查总步数              : {stage2_steps}")
    print(f"  合计步数                          : {stage1_steps+stage2_steps}")
    print()


if __name__ == "__main__":
    t = time.time()
    profile("varint", synth.make_varint_stream()[0])
    profile("ascii-200f", synth.make_length_prefixed_stream(
        "uint16_be", frames=200, payload="ascii")[0])
    profile("random65536", synth.random_stream(65536))
    print("total %.1fs" % (time.time() - t))
