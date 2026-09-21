"""P2-8 双向流联合推断诊断：三条耦合证据各自能否成立、能否被关掉。

用法：``python bench/diag_bidir.py``
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from flowunpack import analyze_bidirectional, synth  # noqa: E402
from flowunpack.config import DEFAULT_CONFIG  # noqa: E402


def show(title: str, c2s: bytes, s2c: bytes, expect_note: str = "") -> None:
    t0 = time.perf_counter()
    r = analyze_bidirectional(c2s, s2c, DEFAULT_CONFIG)
    dt = time.perf_counter() - t0
    c = r.coupling
    print(f"--- {title}  ({dt:.2f}s)")
    print(f"    c2s: det={r.c2s.detected} frames={r.c2s.unit_count} "
          f"spec={r.c2s.length_field.formula() if r.c2s.length_field else None}")
    print(f"    s2c: det={r.s2c.detected} frames={r.s2c.unit_count} "
          f"spec={r.s2c.length_field.formula() if r.s2c.length_field else None}")
    print(f"    耦合: 可迁移={c.structure_transferable}({c.transfer_direction}) "
          f"字段一致={c.length_field_match} r={c.length_correlation} "
          f"类型双射={c.type_mapping_consistent} 强度={c.strength}")
    print(f"    联合置信度 {r.joint_confidence:.3f}   {r.message}")
    for n in c.notes:
        print(f"      · {n}")
    for x in c.repaired:
        print(f"      [修复] {x}")
    for x in c.conflicts:
        print(f"      [分歧] {x}")
    if expect_note:
        print(f"    期望: {expect_note}")
    print()


def main() -> int:
    # 1) 完整耦合：同结构 + 类型双射 + 长度相关
    c2s, s2c, sc, ss = synth.make_request_response_pair(pairs=8)
    show("同结构请求/响应（8 对）", c2s, s2c,
         "三条证据全成立，可迁移 both")

    # 2) 关掉"结构可迁移"：响应包头更长 → overhead 不同
    c2s, s2c, _, _ = synth.make_request_response_pair(
        pairs=8, header_len=4, response_header_len=6)
    show("响应包头更长（关掉迁移）", c2s, s2c,
         "可迁移=False，但类型双射与长度相关仍应成立")

    # 3) 关掉"类型映射"：每个请求命令字都不同 → 无法形成双射
    c2s, s2c, _, _ = synth.make_request_response_pair(
        pairs=8, cmd_cycle=(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08))
    show("命令字全不同（关掉双射）", c2s, s2c,
         "类型双射=False（取值不重复，分不出簇）")

    # 4) 负样本：两条无关的随机流
    show("两条无关随机流", synth.random_stream(2048, seed=1),
         synth.random_stream(2048, seed=2),
         "三条证据全不成立")

    # 5) 一侧样本极少：自身证据不足，靠迁移补上
    c2s, s2c, _, _ = synth.make_request_response_pair(pairs=4)
    print("--- 一侧仅 4 帧")
    from flowunpack import analyze_stream  # noqa: E402
    a = analyze_stream(c2s, DEFAULT_CONFIG)
    b = analyze_stream(s2c, DEFAULT_CONFIG)
    print(f"    单独分析: c2s det={a.detected}({a.unit_count}帧) "
          f"s2c det={b.detected}({b.unit_count}帧)")
    r = analyze_bidirectional(c2s, s2c, DEFAULT_CONFIG)
    print(f"    联合分析: c2s det={r.c2s.detected} s2c det={r.s2c.detected} "
          f"迁移={r.coupling.transfer_direction} 强度={r.coupling.strength}")
    print()

    # 6) 请求/响应结构完全不同（一个是长度前缀，一个是分隔符）
    c2s = synth.make_length_prefixed_stream("uint16_be", frames=10)[0]
    s2c = synth.make_delimited_stream(b"\r\n", frames=10)
    show("异构：长度前缀 ↔ 分隔符", c2s, s2c,
         "可迁移=False，联合置信度应被下调")

    # 7) 冲突裁决：响应侧恒定帧长 → 自身搜索被自信伪解锁定，靠迁移纠正
    for rb in (12, 24):
        c2s, s2c, spec = synth.make_constant_length_pair(response_body=rb)
        sole = analyze_stream(s2c, DEFAULT_CONFIG)
        print(f"--- 冲突裁决：响应恒定帧长 body={rb}"
              f"（真解 10 帧，s2c 单独分析得到 {sole.unit_count} 帧"
              f" {sole.length_field.formula() if sole.length_field else None}）")
        show(f"    联合（期望修复为 10 帧）", c2s, s2c,
             "s2c 应被迁移修正为 10 帧，迁移=c2s->s2c")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
