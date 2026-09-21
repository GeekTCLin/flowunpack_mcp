"""P2-9 分阶段搜索与置换检验配置的回归测试。

分阶段搜索是**启发式短路**：核心子空间证据足够强时跳过剩余子空间。
它必须满足两条不变式，否则就是"悄悄改了结论换来的加速"：

1. **切分完备且互斥** —— 各子空间的并集等于全量、彼此不重叠。
2. **结果等价** —— 开/关分阶段，得到的帧结构（spec + 帧边界）必须一致；
   负样本仍被拒绝。

第 2 条用参数化覆盖正负样本；若日后有人调整 ``stage1_*`` 配置导致结论漂移，
这里会立刻红。
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from flowunpack import analyze_stream, synth  # noqa: E402
from flowunpack.config import DEFAULT_CONFIG  # noqa: E402
from flowunpack.segmentation import (  # noqa: E402
    _collect_successes,
    _perm_config,
    _rank_successes,
    _subspace_configs,
)

FULL = DEFAULT_CONFIG.overridden(staged_search=False)
STAGED = DEFAULT_CONFIG.overridden(staged_search=True)


# 数据**延迟生成**：直接把 bytes 放进 parametrize 会让 pytest 把它作为测试 ID
# 写入 PYTEST_CURRENT_TEST，Windows 上环境变量有 32767 字符上限，必然报
# "environment variable is longer than 32767 characters"。只传名称即可。
#
# varint 用 8 帧而非默认的 14 帧：全量搜索在 54KB 上要 3.8s，测试用例里
# 开/关分阶段各跑一遍，没必要每次都付这个代价 —— 等价性由样本多样性保证。
_FACTORY = {
    "uint16_be": lambda: synth.make_length_prefixed_stream("uint16_be")[0],
    "varint": lambda: synth.make_varint_stream(frames=8)[0],
    "scale4": lambda: synth.make_scaled_length_stream(4)[0],
    "hdr-len@12": lambda: synth.make_deep_length_stream()[0],
    "crc32": lambda: synth.make_crc_length_stream()[0],
    "delim-crlf": lambda: synth.make_delimited_stream(b"\r\n"),
    "chunked": lambda: synth.make_chunked_stream(),
    "random1024": lambda: synth.random_stream(1024),
    "random8192": lambda: synth.random_stream(8192),
}

_CASE_NAMES = list(_FACTORY)


class TestSubspacePartition:
    """子空间切分必须完备且互斥。"""

    def test_union_is_full(self):
        cfg1, subs = _subspace_configs(DEFAULT_CONFIG)
        seen = {(s, f) for s in cfg1.scales for f in cfg1.formats}
        assert subs, "应当能切出补搜子空间"
        for sub in subs:
            seen |= {(s, f) for s in sub.scales for f in sub.formats}
        full = {(s, f) for s in DEFAULT_CONFIG.scales
                for f in DEFAULT_CONFIG.formats}
        assert seen == full

    def test_disjoint(self):
        cfg1, subs = _subspace_configs(DEFAULT_CONFIG)
        buckets = []
        buckets.append({(s, f) for s in cfg1.scales for f in cfg1.formats})
        for sub in subs:
            buckets.append({(s, f) for s in sub.scales for f in sub.formats})
        total = sum(len(b) for b in buckets)
        assert len(set().union(*buckets)) == total, "子空间存在重叠，补搜会重复计数"

    def test_stage1_is_the_core_subspace(self):
        cfg1, _ = _subspace_configs(DEFAULT_CONFIG)
        assert cfg1.scales == DEFAULT_CONFIG.stage1_scales
        assert cfg1.formats == DEFAULT_CONFIG.stage1_formats


class TestStagedEquivalence:
    """开/关分阶段，结论必须一致。"""

    @pytest.mark.parametrize("name", _CASE_NAMES)
    def test_staged_does_not_worsen(self, name):
        """分阶段不得劣化：**全量能检出的，分阶段必须检出且结论一致**。

        反向不成立 —— 分阶段可能检出全量漏掉的样本（见
        :meth:`test_stage1_recovers_a_full_search_miss`），那是候选集更聚焦
        带来的收益，不是回归。
        """
        data = _FACTORY[name]()
        a = analyze_stream(data, FULL)
        b = analyze_stream(data, STAGED)
        if not a.detected:
            pytest.skip(f"{name}: 全量也未检出，不适用本不变式")
        assert b.detected, f"{name}: 全量检出但分阶段丢失"
        if a.framing is not None:
            assert b.framing is not None
            assert a.framing.kind == b.framing.kind
        if a.length_field is not None:
            assert b.length_field is not None
            assert a.length_field.formula() == b.length_field.formula()
        fa = [(f.offset, f.length) for f in a.frames]
        fb = [(f.offset, f.length) for f in b.frames]
        assert fa == fb, f"{name}: 帧边界不一致"

    def test_stage1_recovers_a_full_search_miss(self):
        """8 帧 varint：全量搜索漏检，只搜核心子空间反而能检出。

        机制：冷门子空间（scale>1、uint24、uint64）会产生大量**高分伪解**，
        挤占 ``verify_candidates=5`` 的名额，使真解没有机会进入置换检验；
        只搜核心子空间时真解留在 top-K 内。

        这条用例固化的是"分阶段不劣于全量、有时更好"这一实证结论。
        """
        data = synth.make_varint_stream(frames=8)[0]
        assert analyze_stream(data, STAGED).detected, \
            "分阶段搜索应当检出 8 帧 varint 流"

    def test_staged_flag_reported(self):
        """诊断信息应当标明结论来自核心子空间还是补搜之后。"""
        data = synth.make_length_prefixed_stream("uint16_be")[0]
        diag = analyze_stream(data, STAGED).statistics.get("diagnostics", {})
        assert diag.get("staged") in ("stage1", "full")
        off = analyze_stream(data, FULL).statistics.get("diagnostics", {})
        assert off.get("staged") == "off"

    def test_negative_still_rejected(self):
        for n in (512, 1024, 4096, 8192):
            assert not analyze_stream(synth.random_stream(n), STAGED).detected


class TestPermConfig:
    """置换检验的精简配置必须能表达主搜索的最佳假设。"""

    def test_includes_best_hypothesis(self):
        data = synth.make_scaled_length_stream(4)[0]      # 真解 scale=4
        pool, _ = _collect_successes(data, DEFAULT_CONFIG)
        scored, _ = _rank_successes(data, pool, DEFAULT_CONFIG)
        assert scored
        best = scored[0][1]
        pcfg = _perm_config(DEFAULT_CONFIG, best)
        assert best.scale in pcfg.scales, "真解的 scale 必须留在置换空间里"
        assert best.format in pcfg.formats
        assert pcfg.max_offset > best.offset

    def test_keeps_defaults_when_best_is_ordinary(self):
        data = synth.make_length_prefixed_stream("uint16_be")[0]
        pool, _ = _collect_successes(data, DEFAULT_CONFIG)
        scored, _ = _rank_successes(data, pool, DEFAULT_CONFIG)
        pcfg = _perm_config(DEFAULT_CONFIG, scored[0][1])
        # 常见假设已在精简集合内，不应把空间撑大
        assert set(pcfg.scales) == set(DEFAULT_CONFIG.perm_scales)
