"""P2-8 双向流联合推断（remote coupling）的回归测试。

单条流是**信息不足**的：一条短流常常同时自洽于多种切法。双向推断利用
"请求与响应出自同一份格式定义"这一先验来解歧义。这里锁定三类行为：

1. **三条耦合证据各自可开关** —— 结构可迁移 / 类型双射 / 长度相关。
   每条都被单独构造出来，也被单独关掉，验证它确实是独立的证据而不是
   同一个信号的三种说法。
2. **可迁移性必须可证伪** —— 两条无关的流、异构协议的流，迁移一律
   不成立，且联合置信度被下调（"反面"信息）。
3. **裁决能力（本模块最重要的能力）** —— 一侧因恒定帧长被搜索短路的
   *自信伪解*锁定（实测 5 帧 / 匹配 gap 0.74），只有跨方向的可证伪性
   能把它纠正回真解（10 帧）。这是单方向分析**做不到**的事，也是
   ``analyze_bidirectional`` 存在的核心理由（见 ``bench/diag_bidir.py``）。
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from flowunpack import analyze_bidirectional, analyze_stream, synth  # noqa: E402
from flowunpack.bidir import (  # noqa: E402
    _pearson,
    _spec_signature,
    _type_mapping,
)
from flowunpack.config import DEFAULT_CONFIG  # noqa: E402


# ---------------------------------------------------------------------------
# 单元：耦合证据的底层计算
# ---------------------------------------------------------------------------

class TestPearson:
    def test_perfect_positive(self):
        assert _pearson([1, 2, 3, 4], [2, 4, 6, 8]) == 1.0

    def test_perfect_negative(self):
        assert _pearson([1, 2, 3, 4], [8, 6, 4, 2]) == -1.0

    def test_too_few_samples_returns_none(self):
        """样本 < 3 时相关系数没有意义，必须返回 None 而不是硬算。"""
        assert _pearson([1, 2], [2, 4]) is None

    def test_constant_series_returns_none(self):
        """常数序列方差为 0，相关系数无定义。"""
        assert _pearson([5, 5, 5], [1, 2, 3]) is None


class TestTypeMapping:
    def test_bijection_detected(self):
        fwd, ok = _type_mapping(["01", "02", "01", "02"], ["81", "82", "81", "82"])
        assert ok is True
        assert fwd == {"01": "81", "02": "82"}

    def test_inconsistent_mapping_rejected(self):
        """同一个请求类型映到两个不同响应类型 —— 不是双射。"""
        fwd, ok = _type_mapping(["01", "01", "01"], ["81", "82", "83"])
        assert ok is False

    def test_trivial_single_value_rejected(self):
        """只有一个取值时"双射"是平凡的，不算证据。"""
        _, ok = _type_mapping(["01", "01", "01"], ["81", "81", "81"])
        assert ok is False

    def test_too_short_rejected(self):
        _, ok = _type_mapping(["01"], ["81"])
        assert ok is False


class TestSpecSignature:
    def test_ignores_overhead(self):
        """签名**不含 overhead**：请求与响应包头长度不同是常态，不算不一致。"""
        c2s, s2c, sc, ss = synth.make_request_response_pair(
            pairs=6, header_len=4, response_header_len=8)
        assert sc.overhead != ss.overhead
        assert _spec_signature(sc) == _spec_signature(ss)


# ---------------------------------------------------------------------------
# 证据开关：每条证据都能被单独构造，也能被单独关掉
# ---------------------------------------------------------------------------

class TestCouplingEvidence:
    def test_all_three_evidences_present(self):
        """同结构请求/响应：三条证据全成立，强度应打满。"""
        c2s, s2c, _, _ = synth.make_request_response_pair(pairs=8)
        r = analyze_bidirectional(c2s, s2c, DEFAULT_CONFIG)
        c = r.coupling
        assert c.structure_transferable is True
        assert c.transfer_direction == "both"
        assert c.length_field_match is True
        assert c.type_mapping_consistent is True
        assert c.length_correlation is not None and c.length_correlation > 0.9
        assert c.strength == pytest.approx(1.0)

    def test_longer_response_header_disables_transfer_only(self):
        """响应包头更长 → 迁移走不通，但长度字段身份与类型双射仍然成立。"""
        c2s, s2c, _, _ = synth.make_request_response_pair(
            pairs=8, header_len=4, response_header_len=6)
        r = analyze_bidirectional(c2s, s2c, DEFAULT_CONFIG)
        c = r.coupling
        assert c.structure_transferable is False
        assert c.transfer_direction is None
        assert c.length_field_match is True
        assert c.type_mapping_consistent is True
        # 三条中只剩两条 → 强度应显著低于 1.0，但高于全不成立
        assert 0.3 < c.strength < 1.0
        assert c.repaired == []
        assert c.conflicts == []

    def test_distinct_commands_disable_bijection(self):
        """每个请求命令字都不同 → 形不成簇，类型双射不成立，迁移仍成立。"""
        c2s, s2c, _, _ = synth.make_request_response_pair(
            pairs=8, cmd_cycle=(1, 2, 3, 4, 5, 6, 7, 8))
        r = analyze_bidirectional(c2s, s2c, DEFAULT_CONFIG)
        c = r.coupling
        assert c.structure_transferable is True
        assert c.type_mapping_consistent is False
        assert c.strength == pytest.approx(0.75)


# ---------------------------------------------------------------------------
# 反面信息：不耦合时必须能识别出来并下调置信度
# ---------------------------------------------------------------------------

class TestRejection:
    def test_unrelated_random_streams(self):
        """两条无关随机流：三证据全不成立，联合置信度为 0。"""
        r = analyze_bidirectional(synth.random_stream(2048, seed=1),
                                  synth.random_stream(2048, seed=2),
                                  DEFAULT_CONFIG)
        assert r.detected is False
        assert r.coupling.strength == 0.0
        assert r.joint_confidence == 0.0
        assert "不属于同一协议" in r.message

    def test_heterogeneous_protocols(self):
        """长度前缀 ↔ 分隔符：两条流各自成立，但互不呼应 → 置信度被下调。"""
        c2s = synth.make_length_prefixed_stream("uint16_be", frames=10)[0]
        s2c = synth.make_delimited_stream(b"\r\n", frames=10)
        r = analyze_bidirectional(c2s, s2c, DEFAULT_CONFIG)
        assert r.c2s.detected and r.s2c.detected
        assert r.coupling.structure_transferable is False
        assert r.coupling.length_field_match is False
        assert r.coupling.type_mapping_consistent is False
        assert r.coupling.strength == 0.0
        # 联合置信度必须低于任一侧单独分析的置信度（这就是"反面信息"）
        best_alone = max(r.c2s.confidence, r.s2c.confidence)
        assert r.joint_confidence < best_alone
        assert "不属于同一协议" in r.message

    def test_transfer_failure_never_destroys_own_conclusion(self):
        """迁移失败时原结论必须原样保留（hint 只增不减）。"""
        c2s = synth.make_length_prefixed_stream("uint16_be", frames=10)[0]
        s2c = synth.make_delimited_stream(b"\r\n", frames=10)
        alone_c2s = analyze_stream(c2s, DEFAULT_CONFIG)
        alone_s2c = analyze_stream(s2c, DEFAULT_CONFIG)
        r = analyze_bidirectional(c2s, s2c, DEFAULT_CONFIG)
        assert r.c2s.unit_count == alone_c2s.unit_count
        assert r.s2c.unit_count == alone_s2c.unit_count
        assert r.coupling.repaired == []


# ---------------------------------------------------------------------------
# 裁决能力：单方向做不到、双向才能做到的事
# ---------------------------------------------------------------------------

class TestConflictArbitration:
    """响应侧恒定帧长 → 自身搜索被"自信伪解"锁定，靠跨方向可证伪性纠正。

    这类样本是刻意构造的：响应帧全部等长，于是长度字段取值跨帧恒定，
    块置换检验打乱块顺序**不会改变**这些字节，伪解与真解在置换检验下
    无法区分；stage-1 短路一旦先撞上伪解就直接收工。
    """

    @pytest.mark.parametrize("response_body", [12, 24])
    def test_weak_side_pseudo_solution_is_repaired(self, response_body):
        c2s, s2c, spec = synth.make_constant_length_pair(
            response_body=response_body)

        # 前提：单看响应侧，结论确实是**错的**（不是"没检出"）
        alone = analyze_stream(s2c, DEFAULT_CONFIG)
        assert alone.detected is True
        assert alone.unit_count != 10, "样本失效：响应侧不该自己就切对"
        assert alone.length_field is not None

        r = analyze_bidirectional(c2s, s2c, DEFAULT_CONFIG)
        assert r.s2c.unit_count == 10
        assert r.s2c.length_field is not None
        assert r.s2c.length_field.offset == spec.offset
        assert r.s2c.length_field.overhead == spec.overhead
        assert r.coupling.transfer_direction == "c2s->s2c"
        assert len(r.coupling.repaired) == 1
        assert "修正" in r.message

    def test_repaired_frames_cover_stream_exactly(self):
        """修正后的分帧必须仍是无损的：帧长之和 == 流长，且无剩余。"""
        c2s, s2c, _ = synth.make_constant_length_pair(response_body=12)
        r = analyze_bidirectional(c2s, s2c, DEFAULT_CONFIG)
        assert r.s2c.stream_trailing == 0
        assert sum(f.length for f in r.s2c.frames) == len(s2c)

    def test_already_correct_side_is_left_alone(self):
        """响应帧长有变化时自身就能切对 —— 不该无端触发"修复"。"""
        c2s, s2c, _ = synth.make_constant_length_pair(response_body=16)
        alone = analyze_stream(s2c, DEFAULT_CONFIG)
        assert alone.unit_count == 10
        r = analyze_bidirectional(c2s, s2c, DEFAULT_CONFIG)
        assert r.s2c.unit_count == 10
        assert r.coupling.repaired == []

    def test_repair_is_one_way(self):
        """裁决必须是有方向的：把两参数对调，修复应发生在另一侧。"""
        c2s, s2c, _ = synth.make_constant_length_pair(response_body=12)
        fwd = analyze_bidirectional(c2s, s2c, DEFAULT_CONFIG)
        rev = analyze_bidirectional(s2c, c2s, DEFAULT_CONFIG)
        assert fwd.coupling.transfer_direction == "c2s->s2c"
        assert rev.coupling.transfer_direction == "s2c->c2s"
        # 两个方向观察到的"弱侧"都是恒定帧长的那条流
        assert fwd.s2c.unit_count == rev.c2s.unit_count == 10
        assert len(fwd.coupling.repaired) == len(rev.coupling.repaired) == 1


class TestMonotonicity:
    """联合分析在"检出能力"上必须单调不劣于单方向分析。"""

    @pytest.mark.parametrize("make", [
        lambda: synth.make_request_response_pair(pairs=8)[:2],
        lambda: synth.make_request_response_pair(pairs=4)[:2],
        lambda: synth.make_constant_length_pair(response_body=12)[:2],
        lambda: synth.make_constant_length_pair(response_body=24)[:2],
    ])
    def test_joint_never_detects_less(self, make):
        c2s, s2c = make()
        a = analyze_stream(c2s, DEFAULT_CONFIG)
        b = analyze_stream(s2c, DEFAULT_CONFIG)
        r = analyze_bidirectional(c2s, s2c, DEFAULT_CONFIG)
        if a.detected:
            assert r.c2s.detected
        if b.detected:
            assert r.s2c.detected
        assert r.detected == (r.c2s.detected or r.s2c.detected)

    def test_to_dict_is_json_ready(self):
        c2s, s2c, _ = synth.make_constant_length_pair(response_body=12)
        d = analyze_bidirectional(c2s, s2c, DEFAULT_CONFIG).to_dict()
        assert set(d) >= {"c2s", "s2c", "coupling", "joint_confidence",
                          "detected", "message"}
        assert "repaired" in d["coupling"]
        assert "conflicts" in d["coupling"]
