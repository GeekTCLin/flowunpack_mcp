"""标定脚本：在全部正/负样本上测量两件事，用于选定决策规则。

对每个用例输出：

* ``rank``   —— 真解（正样本）在候选列表中的名次；★ 表示 rank-0 即真解
* ``gapA``   —— 全局 max-vs-max：rank-0 的分数 − 打乱后全假设最高分
                （max 对 max，无偏；用于"有没有结构"的接受判定）
* ``gapB``   —— 假设匹配：同一假设在原始/打乱窗口上的分数差
                （随候选而变；用于"哪个候选是真的"的选择判定）

另打印真解自身的两个 gap，确认真解不会被门槛误杀。
"""

from __future__ import annotations

import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from flowunpack import synth                                        # noqa: E402
from flowunpack.config import DEFAULT_CONFIG                        # noqa: E402
from flowunpack.segmentation import (_best_score, _fit,             # noqa: E402
                                     _perm_window, _search, _shuffle)

CFG = DEFAULT_CONFIG
TRIALS = 10
K = 6


def true_rank(scored, exp):
    for i, (_sc, r, _ag) in enumerate(scored):
        if (r.scale == exp.scale and r.offset == exp.offset
                and r.format == exp.format and r.overhead == exp.overhead
                and r.count_width == exp.variable_overhead):
            return i
    return None


def measure(data: bytes):
    scored, _ = _search(data, CFG)
    if not scored:
        return None
    window = _perm_window(data, scored[0][1], CFG)
    rng = random.Random(0x5EED)
    top = scored[:K]

    obs_a = _best_score(window, CFG)
    null_a = [_best_score(_shuffle(window, rng, (3, 4, 5, 7)[t % 4]), CFG)
              for t in range(TRIALS)]
    # 置换 p 值：打乱后超过观测值的比例（越小越显著）
    p_a = sum(1 for s in null_a if s >= obs_a) / len(null_a)

    rng = random.Random(0x5EED)
    null_b = {i: [] for i in range(len(top))}
    for t in range(TRIALS):
        sh = _shuffle(window, rng, (3, 4, 5, 7)[t % 4])
        for i, (_sc, r, ag) in enumerate(top):
            null_b[i].append(_fit(sh, r, ag, CFG))
    obs_b = [_fit(window, r, ag, CFG) for _sc, r, ag in top]
    gap_b = [obs_b[i] - sum(null_b[i]) / len(null_b[i]) for i in range(len(top))]
    # 匹配 p 值：同一假设在打乱后超过观测的比例
    p_b = [sum(1 for s in null_b[i] if s >= obs_b[i]) / len(null_b[i])
           for i in range(len(top))]

    return {"scored": scored, "top": top, "gapA": obs_a - max(null_a),
            "pA": p_a, "gapB": gap_b, "pB": p_b, "window": len(window),
            "best_i": max(range(len(top)), key=lambda i: gap_b[i])}


def main() -> None:
    POS = [
        ("uint8", synth.make_length_prefixed_stream("uint8")),
        ("uint16_be", synth.make_length_prefixed_stream("uint16_be")),
        ("uint16_le", synth.make_length_prefixed_stream("uint16_le")),
        ("uint32_be", synth.make_length_prefixed_stream("uint32_be")),
        ("uint32_le", synth.make_length_prefixed_stream("uint32_le")),
        ("magic+len", synth.make_magic_length_stream()),
        ("varint", synth.make_varint_stream()),
        ("total-len", synth.make_total_length_stream()),
        ("scale=2", synth.make_scaled_length_stream(2)),
        ("scale=4", synth.make_scaled_length_stream(4)),
        ("scale=8", synth.make_scaled_length_stream(8)),
        ("ascii-20f", synth.make_length_prefixed_stream(
            "uint16_be", frames=20, payload="ascii")),
        ("bin-20f", synth.make_length_prefixed_stream(
            "uint16_be", frames=20, payload="bytes")),
        ("ascii-200f", synth.make_length_prefixed_stream(
            "uint16_be", frames=200, payload="ascii")),
        ("bin-200f", synth.make_length_prefixed_stream(
            "uint16_be", frames=200, payload="bytes")),
    ]
    NEG = [("text", synth.make_text_stream())]
    NEG += [(f"random{n}", synth.random_stream(n))
            for n in (512, 1024, 4096, 8192, 65536)]

    print(f"{'case':<13} {'src':<4} {'rank':>4} {'sel':>4} {'pA':>5} {'pB0':>5} "
          f"{'gapA':>8} {'maxgapB':>8} {'gapB(true)':>10}")
    print("-" * 78)
    posrows, negrows = [], []

    for name, (d, exp) in POS:
        t0 = time.time()
        m = measure(d)
        if m is None:
            print(f"{name:<13} {'pos':<4} 无候选")
            continue
        rk = true_rank(m["scored"], exp)
        gbt = (m["gapB"][rk] if rk is not None and rk < K else float("nan"))
        star = "★" if rk == 0 else " "
        print(f"{name:<13} {'pos':<4} {rk:>3}{star} {m['best_i']:>3}  "
              f"{m['pA']:>5.2f} {m['pB'][0]:>5.2f} {m['gapA']:>+8.4f} "
              f"{max(m['gapB']):>+8.4f} {gbt:>+10.4f}   {time.time()-t0:.1f}s")
        posrows.append((name, rk, m["pA"], max(m["gapB"]),
                        gbt if gbt == gbt else None))

    print()
    for name, d in NEG:
        t0 = time.time()
        m = measure(d)
        if m is None:
            print(f"{name:<13} {'neg':<4} 无候选")
            continue
        print(f"{name:<13} {'neg':<4} {0:>3}  {m['best_i']:>3}  "
              f"{m['pA']:>5.2f} {m['pB'][0]:>5.2f} {m['gapA']:>+8.4f} "
              f"{max(m['gapB']):>+8.4f} {'':>10}   {time.time()-t0:.1f}s")
        negrows.append((name, m["pA"], max(m["gapB"])))

    print()
    print("=== 判定规则可行性 ===")
    bad_rank = [n for n, rk, *_ in posrows if rk != 0]
    print(f"正样本 rank-0 非真解: {bad_rank or '无（全部 rank-0 即真解）'}")
    # sel 列表示"匹配 gap 最大的候选下标"；检查它是否命中真解
    miss = [r[0] for r in posrows if r[1] != 0 and r[4] is not None
            and max(r[3], r[4]) != r[4]]
    print(f"匹配 gap 选择未命中真解的用例: {miss or '无'}")
    ppa = [r[2] for r in posrows]
    npa = [r[1] for r in negrows]
    print(f"pA      正最大 {max(ppa):.2f}   负最小 {min(npa):.2f}")
    pmb = [r[3] for r in posrows]
    nmb = [r[2] for r in negrows]
    print(f"maxgapB 正最小 {min(pmb):+.4f}  负最大 {max(nmb):+.4f}  "
          f"间隔 {min(pmb)-max(nmb):+.4f}")


if __name__ == "__main__":
    main()
