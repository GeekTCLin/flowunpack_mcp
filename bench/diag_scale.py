"""诊断：scale 假设为何被伪解压过；以及搜索耗时构成。

放在 bench/ 下，不属于库本体。
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from flowunpack import synth                                  # noqa: E402
from flowunpack.config import DEFAULT_CONFIG                  # noqa: E402
from flowunpack.segmentation import (_payload_alias, _perm_gap,  # noqa: E402
                                     _score_walk, _search, walk)


def show(scale: int) -> None:
    data, exp = synth.make_scaled_length_stream(scale)
    print(f"===== scale={scale}  len={len(data)}  expected={exp.formula()} =====")
    print("  head:", data[:24].hex())

    t0 = time.time()
    scored, diag = _search(data, DEFAULT_CONFIG)
    dt = time.time() - t0
    print(f"  search: {dt:.2f}s  diag={diag}")

    if not scored:
        print("  no candidate")
        return

    print("  rank  score  hyp                       frames  ag  alias  gap_max")
    for i, (sc, r, ag) in enumerate(scored[:6]):
        t1 = time.time()
        p = _perm_gap(data, r, sc, DEFAULT_CONFIG)
        dtp = time.time() - t1
        alias = _payload_alias(data, r)
        gap = f"{p['gap_max']:+.4f}" if p else "n/a"
        print(f"  {i:>4}  {sc:.3f}  {r.format}@{r.offset}+{r.overhead} scale={r.scale}"
              f" var={int(r.count_width)}  {len(r.frames):>5}  {ag:>2}  {alias:.2f}"
              f"  {gap}  ({dtp:.1f}s)")

    # 真解是否在列表里
    idx = None
    for i, (sc, r, ag) in enumerate(scored):
        if (r.scale == exp.scale and r.offset == exp.offset
                and r.format == exp.format and r.overhead == exp.overhead):
            idx = i
            break
    if idx is None:
        r = walk(data, exp.offset, exp.format, exp.overhead, DEFAULT_CONFIG, 0,
                 count_width=exp.variable_overhead, scale=exp.scale)
        print(f"  TRUE not in scored list; manual walk frames={len(r.frames)} "
              f"leftover={r.leftover} complete={r.complete} "
              f"score={_score_walk(data, r, DEFAULT_CONFIG, 1)}")
    else:
        sc, r, ag = scored[idx]
        print(f"  TRUE at rank {idx}: score={sc:.3f} frames={len(r.frames)} "
              f"ag={ag} alias={_payload_alias(data, r):.3f}")
    print()


if __name__ == "__main__":
    for s in (1, 2, 4, 8):
        show(s)
