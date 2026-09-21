"""P2-9 耗时剖析：分解 analyze_stream 各阶段耗时。

按 **阶段** 计时（而不是只看总时间），才能知道该优化哪里：

    search   —— 枚举全部假设并走查（含 perm_global 内部调用的那些次）
    matched  —— 候选级置换检验（K × trials 次走查）
    global   —— 群体级置换检验（trials+1 次完整搜索）
    best     —— 上者的内部计数（global 里每次 trial 都要跑一次 _search）

包装模块级函数即可生效：``_best_score`` 里写的是全局名 ``_search``，
所以 monkeypatch ``segmentation._search`` 对内部调用同样有效。
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import flowunpack.segmentation as seg  # noqa: E402
from flowunpack import analyze_stream, synth  # noqa: E402
from flowunpack.config import DEFAULT_CONFIG  # noqa: E402

_ACC = {"search": 0.0, "matched": 0.0, "global": 0.0, "best": 0.0,
        "search_n": 0, "best_n": 0, "matched_n": 0, "global_n": 0}

_orig = {
    "search": seg._search,
    "matched": seg._perm_matched,
    "global": seg._perm_global,
    "best": seg._best_score,
}


def _wrap(name, fn):
    def inner(*a, **kw):
        t = time.perf_counter()
        try:
            return fn(*a, **kw)
        finally:
            _ACC[name] += time.perf_counter() - t
            _ACC[name + "_n"] += 1
    return inner


for _k, _fn in _orig.items():
    setattr(seg, "_" + _k, _wrap(_k, _fn))


def cases():
    out = [
        ("varint-54KB", synth.make_varint_stream()),
        ("ascii-200f", synth.make_length_prefixed_stream(
            "uint16_be", frames=200, payload="ascii")),
        ("scale4", synth.make_scaled_length_stream(4)),
        ("hdr-len@12", synth.make_deep_length_stream()[0]),
        ("random-1024", synth.random_stream(1024)),
        ("random-8192", synth.random_stream(8192)),
        ("random-65536", synth.random_stream(65536)),
    ]
    return [(n, d if isinstance(d, bytes) else d[0]) for n, d in out]


def main() -> int:
    print(f"{'case':<14} {'total':>7} {'search':>7} {'matched':>8} "
          f"{'global':>7} {'其它':>7} {'srch#':>6} {'best#':>6}  结论")
    print("-" * 92)
    tot = dict.fromkeys(("search", "matched", "global", "best"), 0.0)
    for name, data in cases():
        for k in _ACC:
            _ACC[k] = 0
        t0 = time.perf_counter()
        res = analyze_stream(data, DEFAULT_CONFIG)
        total = time.perf_counter() - t0
        other = total - _ACC["search"] - _ACC["matched"] - _ACC["global"]
        for k in ("search", "matched", "global", "best"):
            tot[k] += _ACC[k]
        acc = res.statistics.get("diagnostics", {}) or {}
        print(f"{name:<14} {total:7.2f} {_ACC['search']:7.2f} "
              f"{_ACC['matched']:8.2f} {_ACC['global']:7.2f} {other:7.2f} "
              f"{_ACC['search_n']:6d} {_ACC['best_n']:6d}  "
              f"det={res.detected} by={acc.get('accepted_by') or acc.get('rejected_by')}")
    print("-" * 92)
    print("合计  search %.2fs（其中 _best_score %.2fs × %d 次）、matched %.2fs、"
          "global %.2fs"
          % (tot["search"], tot["best"], _ACC["best_n"], tot["matched"],
             tot["global"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
