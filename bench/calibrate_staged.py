"""P2-9 标定：两个提速方案是否**安全**（会不会改变结论）。

方案 B —— 分阶段主搜索
    先用 ``scales=(1,)`` + 核心格式搜一遍（假设数约为全量的 1/7）。
    只有阶段 1 没能给出"足够强"的证据时，才用完整假设空间重搜。
    风险：真解是 scale>1 或冷门格式时，阶段 1 可能给出一个**同样自洽的伪解**，
    若门槛不够严就会误定案。所以要量出：正样本阶段 1 的 gap 有多高、
    负样本阶段 1 的 gap 能到多高，看分离度。

方案 C —— 置换检验用精简搜索配置
    ``_perm_global`` 要在采样窗口上跑 ``trials+1`` 次完整搜索，这是负样本的
    主要成本。若两侧（观测 / 打乱）都改用同一套精简配置，max-vs-max 的
    **无偏性保持不变**（同构比较），只是功效下降。要量出阈值还分不分得开。

用法：``python bench/calibrate_staged.py``
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import flowunpack.segmentation as seg  # noqa: E402
from flowunpack import synth  # noqa: E402
from flowunpack.config import DEFAULT_CONFIG  # noqa: E402
import benchmark as bm  # noqa: E402

# 阶段 1 的假设空间：scale=1（绝大多数协议）+ 最常见的 6 种编码
STAGE1 = DEFAULT_CONFIG.overridden(
    scales=(1,),
    formats=("uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le",
             "varint"),
)

# 置换检验专用：更小但两侧同构
PERM_CFG = DEFAULT_CONFIG.overridden(
    scales=(1,),
    formats=("uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le",
             "varint"),
    max_offset=16,
)


def stage1_gap(data: bytes):
    """阶段 1：搜 + 候选级置换检验，返回 (best_gap, 该候选 spec 或 None)。"""
    scored, _ = seg._search(data, STAGE1)
    if not scored:
        return None, None, 0.0
    top = scored[:max(1, DEFAULT_CONFIG.verify_candidates)]
    window = seg._perm_window(data, top[0][1], DEFAULT_CONFIG)
    matched = seg._perm_matched(window, [r for _, r, _ in top],
                                [ag for _, _, ag in top], DEFAULT_CONFIG)
    if not matched:
        return None, None, 0.0
    gaps = [m["gap"] for m in matched]
    i = max(range(len(gaps)), key=lambda k: gaps[k])
    return gaps[i], top[i][1], len(window)


def global_gap(data: bytes, cfg):
    scored, _ = seg._search(data, DEFAULT_CONFIG)
    if not scored:
        return None
    window = seg._perm_window(data, scored[0][1], DEFAULT_CONFIG)
    g = seg._perm_global(window, cfg)
    return None if g is None else g["gap"]


def spec_eq(got, want):
    """与金标准 spec 是否一致；``want is None`` 表示非长度前缀模板，不比较。"""
    if want is None:
        return None
    if got is None:
        return False
    return (got.offset == want.offset and got.format == want.format
            and got.overhead == want.overhead and got.scale == want.scale
            and got.variable_overhead == want.variable_overhead)


def main() -> int:
    pos = bm.positive_cases()
    neg = bm.negative_cases()

    print("=" * 100)
    print("方案 B：阶段 1（scales=(1,) + 6 种格式）的候选级 gap")
    print(f"{'case':<16} {'阶段1 gap':>10} {'是否真解':>9} {'window':>7} {'耗时':>7}")
    print("-" * 100)
    pos_gaps = []
    for name, data, _gold, _kind, want in pos:
        t0 = time.perf_counter()
        gap, res, wlen = stage1_gap(data)
        dt = time.perf_counter() - t0
        sp = res.to_spec() if res is not None else None
        ok = spec_eq(sp, want)
        mark = "-" if ok is None else ("是" if ok else "否")
        pos_gaps.append((name, gap if gap is not None else -9.0, bool(ok)))
        print(f"{name:<16} {gap if gap is not None else float('nan'):10.3f} "
              f"{mark:>9} {wlen:>7}  {dt:6.2f}s")
    print("-" * 100)
    neg_gaps = []
    for name, data in neg:
        gap, res, wlen = stage1_gap(data)
        neg_gaps.append((name, gap if gap is not None else -9.0))
        print(f"{name:<16} {gap if gap is not None else float('nan'):10.3f}"
              f" {'（负样本）':>9}")

    pv = [g for _, g, _ in pos_gaps]
    nv = [g for _, g in neg_gaps]
    print("-" * 100)
    print(f"正样本阶段1 gap：min {min(pv):.3f}  max {max(pv):.3f}  "
          f"命中真解 {sum(1 for _, _, ok in pos_gaps if ok)}/{len(pos_gaps)}")
    print(f"负样本阶段1 gap：min {min(nv):.3f}  max {max(nv):.3f}")
    print(f"→ 安全门槛区间（>负样本max 且 ≤正样本min）："
          f"{max(nv):.3f} < T ≤ {min(pv):.3f}"
          if min(pv) > max(nv) else "→ 无安全区间，方案 B 不可用")

    print()
    print("=" * 100)
    print("方案 C：置换检验改用精简配置后的全局 gap（负样本必须为负）")
    print(f"{'case':<16} {'完整 cfg':>10} {'精简 cfg':>10}")
    print("-" * 100)
    for name, data in neg:
        g_full = global_gap(data, DEFAULT_CONFIG)
        g_perm = global_gap(data, PERM_CFG)
        f = lambda x: "None" if x is None else f"{x:.3f}"  # noqa: E731
        print(f"{name:<16} {f(g_full):>10} {f(g_perm):>10}")
    print("-" * 100)
    for name, data, _gold, _kind, want in pos[:8]:
        g_full = global_gap(data, DEFAULT_CONFIG)
        g_perm = global_gap(data, PERM_CFG)
        f = lambda x: "None" if x is None else f"{x:.3f}"  # noqa: E731
        print(f"{name:<16} {f(g_full):>10} {f(g_perm):>10}  (正样本)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
