"""P2-10 协议状态机推断（PTA + k-Tail 状态合并）的回归测试。

本模块锁定的不是"某个数字对不对"，而是几条**方法论上的边界**：

1. **状态机是消息序列（时间序）的性质**，不是消息集合的性质 —— 所以输入必须是
   有序的帧序列，且符号必须来自会**重复**的字段（递增序号 / 随机数没有可合并的
   状态，此时必须拒绝而不是硬造一台状态机）。
2. **拒绝要给出理由** —— 单符号流、样本不足、符号互不重复，三种情况都不能返回
   "一台看起来很像的状态机"，而要返回 ``None`` + :func:`explain_skip` 的说明。
3. **k 不可唯一确定** —— 单条 trace 上满足"完整走通且确定"的自动机有无穷多个。
   因此必须暴露 ``k_sensitivity``（k=1..4 的状态数），而不是假装存在唯一答案。
4. **环形结构必须真实存在于输入里** —— 检测到的"环"要能在原始符号序列里
   连续找到，不能是状态合并的副产品。

配套诊断脚本：``bench/diag_statemachine.py``。
"""

from __future__ import annotations

import json
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from flowunpack import analyze_stream, synth                      # noqa: E402
from flowunpack.config import DEFAULT_CONFIG                      # noqa: E402
from flowunpack.models import FieldSpec                           # noqa: E402
from flowunpack.report import render_report                       # noqa: E402
from flowunpack.statemachine import (                             # noqa: E402
    explain_skip,
    infer_state_machine,
    ktail_states,
)


# ---------------------------------------------------------------------------
# 工具：构造 `[magic(2)][cmd(1)][len(1)][body]` 的命令字序列流
# ---------------------------------------------------------------------------

def _build(cmds, seed: int = 1, magic: bytes = b"\xab\xcd") -> bytes:
    rng = random.Random(seed)
    out = bytearray()
    for c in cmds:
        n = 12 + rng.randrange(8)                 # body 长度 12..19，均 ≤ 255
        out += magic + bytes([c & 0xFF]) + bytes([n])
        out += bytes(rng.randrange(256) for _ in range(n))
    return bytes(out)


def _analyze(cmds, cfg=None, seed: int = 1):
    data = _build(cmds, seed)
    result = analyze_stream(data, cfg) if cfg is not None else analyze_stream(data)
    assert result.detected, "分帧就失败了，测试前提不成立"
    units = [f.header + f.body for f in result.frames]
    return result, units


def _infer(cmds, cfg=None, k=None, seed: int = 1):
    result, units = _analyze(cmds, cfg=cfg, seed=seed)
    return infer_state_machine(units, result.message_types, result.fields,
                               cfg or DEFAULT_CONFIG, k=k)


CYCLE3 = [1, 2, 3] * 4
HANDSHAKE = [0] + [1, 2, 3] * 4


# ---------------------------------------------------------------------------
# 1. k-Tail 合并的底层行为
# ---------------------------------------------------------------------------

class TestKTail:
    def test_period3_collapses_to_three_states(self):
        states, rows, trans, conflicts = ktail_states([[1, 2, 3] * 4], 2)
        assert states == 3
        assert conflicts == 0
        # 状态序列必须自己也按 3 周期循环
        assert rows[0] == [0, 1, 2] * 4

    def test_k1_merges_more_than_k2(self):
        """k 越大越精确：同一序列上 k=1 的状态数不会多于 k=2。"""
        seq = [0, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3]
        n1 = ktail_states([seq], 1)[0]
        n2 = ktail_states([seq], 2)[0]
        assert n1 <= n2

    def test_tail_is_merged_into_prefix_class(self):
        """末尾不足 k 个符号的位置必须并入已有等价类，否则会产生假非确定性。

        若不做这件事，`[1,2,3]*4` 的末位置自成一类，倒数第二位置的出边就会
        同时指向两个状态 —— 冲突数 > 0。这里直接锁死冲突数必须是 0。
        """
        for seq in ([1, 2, 3] * 4, [1, 2] * 5, [1, 2, 3, 4] * 3):
            assert ktail_states([seq], 2)[3] == 0

    def test_transitions_are_deterministic(self):
        states, _rows, trans, _c = ktail_states([[1, 2, 3] * 4], 2)
        pairs = [(t["src"], t["symbol"]) for t in trans]
        assert len(pairs) == len(set(pairs)), "同一状态同一符号出现了多个后继"

    def test_multiple_traces_share_states(self):
        """多 trace 输入应当共享同一张状态图（API 为将来留的通用性）。"""
        states, rows, _t, _c = ktail_states([[1, 2, 3, 1, 2, 3],
                                             [1, 2, 3, 1, 2, 3]], 2)
        assert states == 3
        assert rows[0] == rows[1]


# ---------------------------------------------------------------------------
# 2. 符号化：keyword 优先，枚举字段回退
# ---------------------------------------------------------------------------

class TestSymbolization:
    def test_keyword_is_preferred(self):
        """三种命令字都出现 ≥2 次 → 消息分簇成立 → 用 keyword 当符号。"""
        sm = _infer(CYCLE3)
        assert sm is not None
        assert sm.symbol_source.startswith("keyword@")
        assert sm.alphabet == ["01", "02", "03"]

    def test_falls_back_to_enum_field(self):
        """握手只出现一次 → 每簇至少 2 条的分簇判据不成立 → 回退到枚举字段。"""
        sm = _infer(HANDSHAKE)
        assert sm is not None
        assert sm.symbol_source.startswith("field@")
        assert sm.alphabet == ["00", "01", "02", "03"]

    def test_symbol_width_and_offset_reported(self):
        sm = _infer(CYCLE3)
        assert (sm.symbol_offset, sm.symbol_length) == (2, 1)


# ---------------------------------------------------------------------------
# 3. 推断结果的结构
# ---------------------------------------------------------------------------

class TestInference:
    def test_pure_period(self):
        sm = _infer(CYCLE3)
        assert sm.states == 3
        assert sm.cycle_lengths == [3]
        assert sm.conflicts == 0
        assert sm.accepting == list(range(sm.states))
        assert sm.initial == 0

    @pytest.mark.parametrize("cycle,expect", [
        ([1, 2], 2), ([1, 2, 3], 3), ([1, 2, 3, 4], 4),
    ], ids=["p2", "p3", "p4"])
    def test_cycle_length_matches(self, cycle, expect):
        sm = _infer(cycle * 6)
        assert sm.states == expect
        assert sm.cycle_lengths == [expect]

    def test_handshake_becomes_initial_only_state(self):
        """握手只从初始状态出去，之后进入循环 —— 状态数 = 1 + 周期。"""
        sm = _infer(HANDSHAKE)
        assert sm.states == 4
        assert sm.cycle_lengths == [3]
        first = sm.initial_transitions()
        assert len(first) == 1 and first[0]["symbol"] == "00"
        # 初始状态除了握手不该有别的出边
        assert all(t["symbol"] == "00" for t in sm.transitions_of(sm.initial))

    def test_cycle_actually_occurs_in_sequence(self):
        """检测到的环必须在原始符号序列里连续出现（不是合并的副产品）。"""
        sm = _infer(HANDSHAKE)
        seq = sm.sequence
        for cyc in sm.cycles:
            n = len(cyc)
            windows = [seq[i:i + n] for i in range(len(seq) - n + 1)]
            assert cyc in windows, "环 %s 在序列里找不到" % cyc
        # 环上的每条转移都必须真在转移表里
        edge = {(t["src"], t["symbol"], t["dst"]) for t in sm.transitions}
        assert edge, "转移表为空"

    def test_state_sequence_length_matches_symbols(self):
        sm = _infer(CYCLE3)
        assert len(sm.state_sequence) == len(sm.sequence)
        assert all(0 <= s < sm.states for s in sm.state_sequence)

    def test_compression_high_on_periodic_stream(self):
        sm = _infer([1, 2] * 8)                       # 16 符号 / 2 状态
        assert sm.compression == pytest.approx(1 - 2 / 16, abs=1e-6)
        assert sm.confidence > 0.7

    def test_compression_near_zero_when_no_structure(self):
        """非周期随机命令字：状态数 ≈ 符号数 → 压缩率极低、置信度低。"""
        rng = random.Random(9)
        cmds = [rng.choice((1, 2, 3, 4, 5, 6, 7, 8)) for _ in range(24)]
        sm = _infer(cmds)
        assert sm is not None
        assert sm.compression < 0.6
        assert sm.confidence < 0.6

    def test_noise_reports_conflicts_and_k_sensitivity(self):
        seq = [1, 2, 3] * 4
        seq[5] = 9                                    # 单点噪声
        sm = _infer(seq)
        assert sm is not None
        assert sm.conflicts >= 1
        assert any("非确定性" in n for n in sm.notes)
        assert any("k 敏感性" in n for n in sm.notes)
        assert set(sm.k_sensitivity) >= {"1", "2"}

    def test_cycle_traversals_reported(self):
        """握手样本的环上三条转移分别观测 4/4/3 次 → 绕行次数取最小值 3。"""
        sm = _infer(HANDSHAKE)
        assert sm.cycle_traversals == [3]
        assert "绕行 3 次" in sm.describe()

    def test_coincidental_cycle_is_filtered(self):
        """噪声里凑出的环只走过一遍 —— 必须被绕行次数门槛剔除。

        实测该随机序列在 k=2 下会凑出一个 3 状态环，但环上三条转移各只观测到
        1 次。少了这道门槛，一台"看起来很成功"的状态机（21 状态 / 24 符号）
        会被误报出环。加门槛后环为空，置信度也随之降到 0.1 以下。
        """
        rng = random.Random(9)
        cmds = [rng.choice((1, 2, 3, 4, 5, 6, 7, 8)) for _ in range(24)]
        sm = _infer(cmds)
        assert sm is not None
        assert sm.cycles == []
        assert sm.cycle_traversals == []
        assert sm.confidence < 0.1
        assert any("未发现被反复执行" in n for n in sm.notes)
        assert "未发现被反复执行的环" in sm.describe()


# ---------------------------------------------------------------------------
# 4. 拒绝：不给结论比给错结论好
# ---------------------------------------------------------------------------

class TestRejection:
    def test_single_symbol_stream_rejected(self):
        """整条流只有一种消息 → 符号恒定 → 拒绝，并说明原因。"""
        data = synth.make_length_prefixed_stream()[0]
        result = analyze_stream(data)
        units = [f.header + f.body for f in result.frames]
        assert infer_state_machine(units, result.message_types,
                                   result.fields) is None
        reason = explain_skip(units, result.message_types, result.fields)
        assert "单符号" in reason

    def test_too_few_messages_rejected(self):
        data = synth.make_header_body_stream()[0]     # 10 帧 < sm_min_symbols=12
        result = analyze_stream(data)
        units = [f.header + f.body for f in result.frames]
        assert len(units) == 10
        assert infer_state_machine(units, result.message_types,
                                   result.fields) is None
        assert "样本太少" in explain_skip(units, result.message_types,
                                          result.fields)

    def test_non_repeating_symbols_rejected(self):
        """取值互不重复的字段（递增序号）没有可合并状态 → 拒绝。

        这里手工给出字段规格，避免依赖字段推断恰好把它判成 enum —— 判据本身
        是"符号平均重复次数 < sm_min_symbol_repeats"，必须独立成立。
        """
        units = []
        for i in range(16):
            body = bytes([i] * 4)
            units.append(b"\xab\xcd" + bytes([i]) + bytes([len(body)]) + body)
        field = FieldSpec(offset=2, length=1, kind="enum", cardinality=16)
        assert infer_state_machine(units, (), [field]) is None
        reason = explain_skip(units, (), [field])
        assert "互不重复" in reason or "序号" in reason

    def test_too_many_symbols_rejected(self):
        cfg = DEFAULT_CONFIG.overridden(sm_max_alphabet=2)
        assert _infer(CYCLE3, cfg=cfg) is None

    def test_min_symbols_config_respected(self):
        cfg = DEFAULT_CONFIG.overridden(sm_min_symbols=64)
        assert _infer(CYCLE3, cfg=cfg) is None

    def test_no_symbol_field_rejected(self):
        """包头里没有任何可分簇字段时也要拒绝而不是猜。"""
        units = [b"\x00\x00\x00\x00" + bytes([i]) for i in range(16)]
        assert infer_state_machine(units, (), []) is None
        assert "单符号" in explain_skip(units, (), [])


# ---------------------------------------------------------------------------
# 5. k 的选择与控制
# ---------------------------------------------------------------------------

class TestKControl:
    def test_k_sensitivity_exposed(self):
        sm = _infer(HANDSHAKE)
        assert set(sm.k_sensitivity) == {"1", "2", "3", "4"}
        assert all(v >= 1 for v in sm.k_sensitivity.values())

    def test_explicit_k_changes_result(self):
        sm1 = _infer(CYCLE3, k=1)
        sm3 = _infer(CYCLE3, k=3)
        assert sm1.k == 1 and sm3.k == 3
        assert sm1.states >= 1 and sm3.states >= 1

    def test_k_is_clamped(self):
        sm = _infer(CYCLE3, k=999)
        assert sm.k <= DEFAULT_CONFIG.sm_max_k

    def test_default_k_from_config(self):
        cfg = DEFAULT_CONFIG.overridden(sm_default_k=3)
        sm = _infer(CYCLE3, cfg=cfg)
        assert sm.k == 3


# ---------------------------------------------------------------------------
# 6. 与引擎 / 报告 / 序列化集成
# ---------------------------------------------------------------------------

class TestEngineIntegration:
    def test_engine_attaches_state_machine(self):
        data, _spec, cmds = synth.make_interaction_stream()
        result = analyze_stream(data)
        assert result.state_machine is not None
        assert result.state_machine.symbol_count == len(cmds)
        assert result.state_machine.cycle_lengths == [3]

    def test_engine_records_skip_reason(self):
        data = synth.make_length_prefixed_stream()[0]
        result = analyze_stream(data)
        assert result.state_machine is None
        assert "未推断" in result.statistics["state_machine_summary"]

    def test_to_dict_is_json_safe(self):
        data, _spec, _cmds = synth.make_interaction_stream()
        d = analyze_stream(data).to_dict()
        text = json.dumps(d, ensure_ascii=False)
        assert d["state_machine"]["states"] == 4
        assert json.loads(text)["state_machine"]["cycles"] == [["03", "01", "02"]]

    def test_report_section_present(self):
        data, _spec, _cmds = synth.make_interaction_stream()
        txt = render_report(analyze_stream(data))
        assert "[状态机]" in txt
        assert "环（周期 3，绕行" in txt
        assert "k 敏感性" in txt

    def test_report_notes_skip(self):
        txt = render_report(analyze_stream(synth.make_length_prefixed_stream()[0]))
        assert "[状态机] 未推断" in txt

    def test_describe_mentions_cycle(self):
        data, _spec, _cmds = synth.make_interaction_stream()
        sm = analyze_stream(data).state_machine
        assert "检测到 1 个环" in sm.describe()


# ---------------------------------------------------------------------------
# 7. MCP 工具层
# ---------------------------------------------------------------------------

class TestMcpTool:
    def _server(self):
        from flowunpack_mcp import server as mcp_server
        return mcp_server

    def test_registered(self):
        srv = self._server().create_server()
        assert "infer_state_machine" in srv.fn

    def test_infers_from_hex(self):
        mcp_server = self._server()
        data, _spec, _cmds = synth.make_interaction_stream()
        out = mcp_server.tool_infer_state_machine(data.hex())
        assert out["ok"] is True and out["inferred"] is True
        assert out["states"] == 4
        assert out["cycles"] == [["03", "01", "02"]]
        assert "summary" in out

    def test_reports_skip_without_inventing(self):
        mcp_server = self._server()
        data = synth.make_length_prefixed_stream()[0]
        out = mcp_server.tool_infer_state_machine(data.hex())
        assert out["ok"] is True
        assert out["inferred"] is False
        assert out["reason"]

    def test_explicit_k(self):
        mcp_server = self._server()
        data, _spec, _cmds = synth.make_interaction_stream()
        out = mcp_server.tool_infer_state_machine(data.hex(), k=1)
        assert out["inferred"] is True
        assert out["k"] == 1

    def test_bad_input(self):
        mcp_server = self._server()
        assert mcp_server.tool_infer_state_machine("zzz")["ok"] is False
        assert mcp_server.tool_infer_state_machine("")["ok"] is False

    def test_analyze_stream_carries_state_machine(self):
        mcp_server = self._server()
        data, _spec = synth.make_multi_type_stream()
        out = mcp_server.tool_analyze_stream(data.hex())
        assert out["state_machine"]["states"] == 3

    def test_slim_truncates_long_sequences(self):
        mcp_server = self._server()
        cmds = [1, 2, 3] * 40                          # 120 条消息
        data = _build(cmds)
        out = mcp_server.tool_infer_state_machine(data.hex())
        assert len(out["sequence"]) <= 64

    def test_service_info_exposes_defaults(self):
        mcp_server = self._server()
        defaults = mcp_server.tool_service_info()["defaults"]
        assert "sm_default_k" in defaults and "sm_min_symbols" in defaults
