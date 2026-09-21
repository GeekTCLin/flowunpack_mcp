"""P2-10 状态机推断的诊断：符号化 → PTA + k-Tail → 环，逐用例核对。

运行::

    python bench/diag_statemachine.py        # 全部通过时 exit 0

关注点不是"某个数字"，而是三条方法论边界：

* **环必须真实**：推断出的环要能在原始符号序列里连续找到。
* **拒绝要有理由**：单符号 / 样本不足 / 符号互不重复三种情形必须拒绝，
  且给出人能看懂的原因 —— 不给结论比给错结论好。
* **k 不可唯一确定**：每次都打印 k=1..4 的状态数，让人看到这个不确定性。
"""

from __future__ import annotations

import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from flowunpack import analyze_stream, synth                      # noqa: E402
from flowunpack.config import DEFAULT_CONFIG                      # noqa: E402
from flowunpack.statemachine import (                             # noqa: E402
    explain_skip,
    infer_state_machine,
)

_OK = 0
_BAD = 0


def _build(cmds, seed: int = 1, magic: bytes = b"\xab\xcd") -> bytes:
    rng = random.Random(seed)
    out = bytearray()
    for c in cmds:
        n = 12 + rng.randrange(8)
        out += magic + bytes([c & 0xFF]) + bytes([n])
        out += bytes(rng.randrange(256) for _ in range(n))
    return bytes(out)


def check(label: str, ok: bool, detail: str = "") -> None:
    global _OK, _BAD
    if ok:
        _OK += 1
        mark = "ok  "
    else:
        _BAD += 1
        mark = "FAIL"
    print("  [%s] %s%s" % (mark, label, ("  " + detail) if detail else ""))


def show(title: str, data: bytes, expect_states=None,
         expect_cycle=None, expect_reject=None,
         expect_no_cycle: bool = False) -> None:
    result = analyze_stream(data)
    units = [f.header + f.body for f in result.frames]
    print("--- %s" % title)
    if not result.detected:
        print("    分帧未检出，跳过")
        check(title + " / 分帧", False, result.message)
        return

    sm = infer_state_machine(units, result.message_types, result.fields)
    if sm is None:
        reason = explain_skip(units, result.message_types, result.fields)
        print("    拒绝：%s" % reason)
        check(title + " / 应拒绝" if expect_reject else title + " / 推断",
              expect_reject is not None, "期望拒绝但被拒绝" if expect_reject else "")
        return

    seq = sm.sequence
    print("    符号字段 %s  符号 %d 个 / %d 种"
          % (sm.symbol_source, len(seq), len(sm.alphabet)))
    print("    序列：%s" % " ".join(seq))
    print("    %s" % sm.describe())
    print("    转移：%s" % "  ".join("q%d-%s->q%d(%d)"
                                    % (t["src"], t["symbol"], t["dst"], t["count"])
                                    for t in sm.transitions))
    print("    压缩率 %.3f  结构强度 %.3f  冲突 %d  k 敏感性 %s"
          % (sm.compression, sm.confidence, sm.conflicts,
             ", ".join("k=%s:%d态" % (k, v)
                       for k, v in sorted(sm.k_sensitivity.items()))))
    for n in sm.notes:
        print("    note: %s" % n)

    if expect_reject:
        check(title + " / 应拒绝", False, "期望拒绝但给出了结论")
        return
    if expect_states is not None:
        check(title + " / 状态数", sm.states == expect_states,
              "得到 %d，期望 %d" % (sm.states, expect_states))
    if expect_cycle is not None:
        check(title + " / 环长", sm.cycle_lengths == [expect_cycle],
              "得到 %s" % sm.cycle_lengths)
    # 环必须真实出现
    ok = True
    for cyc in sm.cycles:
        n = len(cyc)
        windows = [seq[i:i + n] for i in range(len(seq) - n + 1)]
        if cyc not in windows:
            ok = False
    check(title + " / 环真实存在", ok)
    # 确定性
    pairs = [(t["src"], t["symbol"]) for t in sm.transitions]
    check(title + " / 转移确定", len(pairs) == len(set(pairs)))
    print()


def main() -> int:
    print("=" * 78)
    print("P2-10 状态机推断诊断（PTA + k-Tail 状态合并）")
    print("=" * 78)
    print()

    # 1) 纯周期
    show("纯周期 1,2,3 ×4", _build([1, 2, 3] * 4), expect_states=3,
         expect_cycle=3)
    show("纯周期 1,2 ×8", _build([1, 2] * 8), expect_states=2, expect_cycle=2)
    show("纯周期 1,2,3,4 ×4", _build([1, 2, 3, 4] * 4), expect_states=4,
         expect_cycle=4)

    # 2) 握手前缀（真实协议最常见形态）
    show("握手 0 + (1,2,3)×4", _build([0] + [1, 2, 3] * 4), expect_states=4,
         expect_cycle=3)

    # 3) 带噪声
    noisy = [1, 2, 3] * 4
    noisy[5] = 9
    show("周期 3 + 单点噪声", _build(noisy))

    # 4) 非周期随机命令字（应低置信、无环 —— 凑出的环只走过一遍，要被门槛剔除）
    rng = random.Random(9)
    rand_cmds = [rng.choice((1, 2, 3, 4, 5, 6, 7, 8)) for _ in range(24)]
    show("非周期随机命令字", _build(rand_cmds), expect_no_cycle=True)

    # 5) 引擎级：keyword 路径（多类型流）
    data, _spec = synth.make_multi_type_stream()
    result = analyze_stream(data)
    sm = result.state_machine
    print("--- 引擎级：make_multi_type_stream（keyword 路径）")
    print("    符号字段 %s，%s" % (sm.symbol_source if sm else "-",
                                  sm.describe() if sm else "未推断"))
    check("multi_type / 用 keyword 符号化",
          sm is not None and sm.symbol_source.startswith("keyword@"))
    check("multi_type / 3 状态环", sm is not None and sm.states == 3
          and sm.cycle_lengths == [3])
    print()

    # 6) 引擎级：交互流（field 回退路径）
    data, _spec, cmds = synth.make_interaction_stream()
    result = analyze_stream(data)
    sm = result.state_machine
    print("--- 引擎级：make_interaction_stream（枚举字段回退路径）")
    print("    命令字序列：%s" % (cmds,))
    print("    符号字段 %s，%s" % (sm.symbol_source if sm else "-",
                                  sm.describe() if sm else "未推断"))
    check("interaction / 走字段回退", sm is not None
          and sm.symbol_source.startswith("field@"))
    check("interaction / 握手成初始态",
          sm is not None and sm.states == 4
          and [t["symbol"] for t in sm.initial_transitions()] == ["00"])
    print()

    # 7) 拒绝路径（三种，都必须拒绝）
    print("--- 拒绝路径（宁可少报）")
    cases = [
        ("单符号流", synth.make_length_prefixed_stream()[0]),
        ("样本不足（10 帧）", synth.make_header_body_stream()[0]),
    ]
    for label, data in cases:
        result = analyze_stream(data)
        units = [f.header + f.body for f in result.frames]
        sm = infer_state_machine(units, result.message_types, result.fields)
        reason = explain_skip(units, result.message_types, result.fields)
        check("%s / 拒绝" % label, sm is None, reason[:60])

    # 递增命令字（符号互不重复）
    data = _build(list(range(1, 17)))
    result = analyze_stream(data)
    units = [f.header + f.body for f in result.frames]
    reason = explain_skip(units, result.message_types, result.fields)
    check("递增命令字 / 拒绝", infer_state_machine(
        units, result.message_types, result.fields) is None, reason[:60])
    print()

    print("=" * 78)
    print("通过 %d 项，失败 %d 项" % (_OK, _BAD))
    print("=" * 78)
    return 1 if _BAD else 0


if __name__ == "__main__":
    raise SystemExit(main())
