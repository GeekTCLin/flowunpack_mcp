"""检测能力测试：合成正样本必须识别准确，负样本必须拒绝。

这是整个项目最核心的一组断言——它同时约束了"召回"和"误报"。
"""

import pytest

from flowunpack import analyze_packets, analyze_stream
from flowunpack.config import DEFAULT_CONFIG
from flowunpack.detectors import (
    choose_framing,
    detect_ascii_length,
    detect_delimited,
    detect_fixed_length,
    parse_ascii_length,
    split_by_delimiter,
)
from flowunpack.engine import resolve_spec
from flowunpack.models import KIND_PRIORITY
from flowunpack.segmentation import apply_spec, segment_stream, walk
from flowunpack.synth import (
    make_bcd_length_stream,
    make_chunked_stream,
    make_crc_length_stream,
    make_deep_length_stream,
    make_delimited_stream,
    make_fixed_length_stream,
    make_header_body_stream,
    make_header_varint_stream,
    make_length_prefixed_stream,
    make_magic_length_stream,
    make_multi_type_stream,
    make_no_delimiter_text,
    make_scaled_length_stream,
    make_text_stream,
    make_total_length_stream,
    make_typed_fields_stream,
    make_variable_header_stream,
    make_varint_stream,
    make_zero_filled_header_stream,
    random_stream,
)

# (生成器, 期望的 offset/format/overhead/variable_overhead)
POSITIVE_CASES = [
    ("uint8", lambda: make_length_prefixed_stream("uint8"), 0, "uint8", 1, False),
    ("uint16_be", lambda: make_length_prefixed_stream("uint16_be"), 0, "uint16_be", 2, False),
    ("uint16_le", lambda: make_length_prefixed_stream("uint16_le"), 0, "uint16_le", 2, False),
    ("uint32_be", lambda: make_length_prefixed_stream("uint32_be"), 0, "uint32_be", 4, False),
    ("uint32_le", lambda: make_length_prefixed_stream("uint32_le"), 0, "uint32_le", 4, False),
    ("magic_len", lambda: make_magic_length_stream(), 4, "uint16_be", 6, False),
    ("varint", lambda: make_varint_stream(), 0, "varint", 0, True),
    ("total_len", lambda: make_total_length_stream(), 0, "uint32_be", 0, False),
    # "长度以字/双字计"（frame_len = scale * value）。只支持 scale=1 的实现
    # 对这三类**完全检测不到**（实测），因此它们是 scale 能力的守卫用例。
    ("scale2", lambda: make_scaled_length_stream(2), 0, "uint16_be", 0, False),
    ("scale4", lambda: make_scaled_length_stream(4), 0, "uint16_be", 0, False),
    ("scale8", lambda: make_scaled_length_stream(8), 0, "uint16_be", 0, False),
]

# 需要额外校验 scale 的用例
SCALED_CASES = [
    ("scale2", lambda: make_scaled_length_stream(2), 2),
    ("scale4", lambda: make_scaled_length_stream(4), 4),
    ("scale8", lambda: make_scaled_length_stream(8), 8),
]

# 只关心生成器本身的用例
FACTORY_ONLY = [(name, factory) for name, factory, *_ in POSITIVE_CASES]


class TestStreamMode:
    @pytest.mark.parametrize(
        "name,factory,offset,fmt,overhead,variable", POSITIVE_CASES)
    def test_detects_expected_spec(self, name, factory, offset, fmt, overhead, variable):
        data, expected = factory()
        result = analyze_stream(data)

        assert result.detected, f"{name}: 未检测到结构 -> {result.message}"
        spec = result.length_field
        assert spec is not None
        assert (spec.offset, spec.format, spec.overhead, spec.variable_overhead) \
            == (offset, fmt, overhead, variable), \
            f"{name}: 得到 {spec.format}@{spec.offset}+{spec.overhead}" \
            f"(variable={spec.variable_overhead})"

    @pytest.mark.parametrize("name,factory", FACTORY_ONLY)
    def test_segmentation_consumes_whole_stream(self, name, factory):
        data, _ = factory()
        result = analyze_stream(data)
        assert result.stream_trailing == 0
        assert result.unit_count >= DEFAULT_CONFIG.min_frames

    @pytest.mark.parametrize("name,factory", FACTORY_ONLY)
    def test_frames_roundtrip(self, name, factory):
        """切出的帧拼回去必须等于原流。"""
        data, _ = factory()
        result = analyze_stream(data)
        rebuilt = b"".join(f.header + f.body for f in result.frames)
        assert rebuilt == data

    @pytest.mark.parametrize("n", [512, 1024, 4096])
    def test_random_stream_is_rejected(self, n):
        result = analyze_stream(random_stream(n))
        assert not result.detected, f"随机流 {n} 字节被误判为有结构"

    def test_crlf_text_is_recognized_as_delimited(self):
        """CRLF 分行自 P0-2 起是一个合法的分隔符分帧模板。

        这条断言在 P0-2 之前正好相反（当时它被当作必须拒绝的负样本）。
        把 ``\\r\\n`` 文本切成行是**有意义且可自证**的分帧，因此改为正向断言；
        真正无结构的文本负样本见下一条。
        """
        result = analyze_stream(make_text_stream())
        assert result.detected
        assert result.framing is not None
        assert result.framing.kind == "delimited"
        assert result.framing.delimiter == b"\r\n"

    def test_text_stream_without_delimiter_is_rejected(self):
        """无结构性分隔符的文本必须仍是负样本。"""
        assert not analyze_stream(make_no_delimiter_text()).detected

    def test_tiny_input(self):
        result = analyze_stream(b"\x01\x02")
        assert not result.detected
        assert "过短" in result.message

    def test_confidence_in_range(self):
        data, _ = make_length_prefixed_stream("uint16_be")
        result = analyze_stream(data)
        assert 0.0 < result.confidence <= 1.0


class TestLengthFieldScale:
    """帧长公式 ``frame_len = scale*value + overhead`` 的斜率支持。

    这是相对早期实现的能力扩展：斜率恒为 1 时，所有"长度以字/双字计"的协议
    （IPv4 的 IHL 以 4 字节字为单位、部分工控与音视频协议）都检测不到。
    """

    @pytest.mark.parametrize("name,factory,scale", SCALED_CASES)
    def test_detects_scale(self, name, factory, scale):
        data, _ = factory()
        result = analyze_stream(data)
        assert result.detected, f"{name}: 未检测到 -> {result.message}"
        assert result.length_field.scale == scale

    @pytest.mark.parametrize("scale", [2, 4, 8])
    def test_scale_walk_is_exact(self, scale):
        """带 scale 的走查必须精确铺满整条流。"""
        data, exp = make_scaled_length_stream(scale)
        res = walk(data, exp.offset, exp.format, exp.overhead, DEFAULT_CONFIG,
                   count_width=exp.variable_overhead, scale=exp.scale)
        assert res.complete
        assert res.leftover == 0
        assert len(res.frames) >= DEFAULT_CONFIG.min_frames

    def test_scale_one_is_preferred_when_equivalent(self):
        """同一套帧边界能用 scale=1 解释时，不应报告更复杂的 scale（Occam）。"""
        data, _ = make_length_prefixed_stream("uint16_be")
        result = analyze_stream(data)
        assert result.length_field.scale == 1

    def test_scaled_stream_is_not_claimed_as_scale_one(self):
        """scale=4 的流不应被解释成 scale=1 的同名结构。"""
        data, _ = make_scaled_length_stream(4)
        result = analyze_stream(data)
        assert result.detected
        spec = result.length_field
        # 用 scale=1 解释同一偏移/格式应当走不通
        wrong = walk(data, spec.offset, spec.format, spec.overhead,
                     DEFAULT_CONFIG, count_width=spec.variable_overhead, scale=1)
        assert not wrong.complete


class TestDecisionRule:
    """两条独立证据的决策规则（见 segmentation.segment_stream）。"""

    def test_matched_gap_selects_true_candidate(self):
        """匹配 gap 最大的候选应命中真解——这是"谁是真的"的判据。"""
        data, exp = make_scaled_length_stream(8)
        _, _, _, diag = segment_stream(data, DEFAULT_CONFIG)
        assert "matched" in diag
        assert diag["accepted_by"] in ("matched", "global", "score")
        chosen = diag.get("chosen_rank", 0)
        entry = diag["matched"][chosen]
        assert (entry["format"], entry["offset"], entry["overhead"],
                entry["scale"]) == (exp.format, exp.offset, exp.overhead,
                                    exp.scale)

    def test_diagnostics_expose_both_evidence_channels(self):
        data, _ = make_length_prefixed_stream("uint16_be")
        _, _, _, diag = segment_stream(data, DEFAULT_CONFIG)
        assert diag.get("accepted_by")
        assert "max_matched_gap" in diag
        assert diag["matched"] and "gap" in diag["matched"][0]

    def test_random_stream_reports_rejection_channel(self):
        _, candidates, best, diag = segment_stream(random_stream(2048),
                                                   DEFAULT_CONFIG)
        assert best is None
        assert diag.get("rejected_by") == "permutation"
        assert diag.get("global") is not None or diag.get("matched") is not None


class TestFramingTemplates:
    """长度前缀之外的分帧模板（delimiter / ascii_length / fixed_length）。

    P0-2 的能力扩展：此前只搜索 ``frame_len = a·v + b`` 一种模板，
    定长帧、分隔符分帧（``\\r\\n``、RESP）、HTTP chunked 的 ASCII 文本长度全部漏检。
    """

    @pytest.mark.parametrize("name,delim,kw", [
        ("crlf", b"\r\n", {}),
        ("nul2", b"\x00\x00", {"frames": 16, "min_len": 16, "max_len": 60}),
    ])
    def test_detects_delimiter(self, name, delim, kw):
        data = make_delimited_stream(delim, **kw)
        result = analyze_stream(data)
        assert result.detected, f"{name}: 未检测到 -> {result.message}"
        assert result.framing.kind == "delimited"
        assert result.framing.delimiter == delim
        assert result.unit_count >= DEFAULT_CONFIG.delim_min_frames

    def test_delimiter_frames_are_exact(self):
        data = make_delimited_stream(b"\r\n", frames=10)
        result = analyze_stream(data)
        assert result.detected
        assert result.unit_count == 10
        # body 为整帧（含结尾分隔符），保证可无损拼回原流
        assert all(f.body.endswith(b"\r\n") for f in result.frames)
        assert all(f.length == len(f.body) for f in result.frames)

    def test_delimiter_reports_significance_evidence(self):
        data = make_delimited_stream(b"\r\n")
        det = detect_delimited(data, DEFAULT_CONFIG)
        assert det is not None and det.self_verified
        ev = det.evidence
        assert ev["occurrences"] >= DEFAULT_CONFIG.delim_min_frames
        assert ev["p_value"] < DEFAULT_CONFIG.delim_alpha
        assert ev["coverage"] > 0.9

    def test_single_byte_delimiter_is_not_detectable(self):
        """单字节分隔符 lift 恒为 1，不可自证 —— 不应产生检测。"""
        data = b"a\x00bb\x00ccc\x00dddd\x00eeeee\x00ffffff\x00ggggggg\x00"
        assert detect_delimited(data, DEFAULT_CONFIG) is None

    @pytest.mark.parametrize("radix", [16, 10])
    def test_detects_ascii_length(self, radix):
        data = make_chunked_stream(radix=radix)
        result = analyze_stream(data)
        assert result.detected, result.message
        assert result.framing.kind == "ascii_length"
        assert result.framing.ascii_radix == radix

    def test_ascii_length_beats_delimiter_on_chunked(self):
        """chunked 流的 ``\\r\\n`` 也能切出更多帧，但粒度更粗、证据更弱。"""
        data = make_chunked_stream()
        result = analyze_stream(data)
        assert result.framing.kind == "ascii_length"
        delim = detect_delimited(data, DEFAULT_CONFIG)
        assert delim is not None
        assert len(delim.frames) > result.unit_count
        assert KIND_PRIORITY["ascii_length"] > KIND_PRIORITY["delimited"]

    def test_ascii_length_parse_is_exact(self):
        data = make_chunked_stream(chunks=5, final=True)
        got = parse_ascii_length(data, 0, 16, b"\r\n")
        assert got is not None
        spans, leftover, truncated = got
        assert len(spans) == 6                 # 5 个数据块 + 1 个 "0" 终止块
        assert leftover == 0 and not truncated
        assert spans[-1][0] + spans[-1][1] == len(data)

    def test_detects_fixed_length_with_rigid_header(self):
        """刚性包头是整除性之外的独立证据，才允许提升为结论。"""
        data = make_fixed_length_stream(frame_len=16, const_bytes=6)
        result = analyze_stream(data)
        assert result.detected, result.message
        assert result.framing.kind == "fixed_length"
        assert result.framing.frame_len == 16
        assert result.confidence < 0.6          # 定长本就是低置信结论

    def test_fixed_length_without_header_is_only_a_hypothesis(self):
        """纯随机载荷的定长流没有独立证据 —— 不得自证。"""
        hyps = detect_fixed_length(random_stream(512), DEFAULT_CONFIG)
        assert hyps
        assert not any(h.self_verified for h in hyps)

    @pytest.mark.parametrize("name,factory", [
        ("delim", lambda: make_delimited_stream(b"\r\n")),
        ("nul2", lambda: make_delimited_stream(b"\x00\x00", frames=16,
                                              min_len=16, max_len=60)),
        ("chunked16", lambda: make_chunked_stream(radix=16)),
        ("chunked10", lambda: make_chunked_stream(radix=10)),
        ("fixed", lambda: make_fixed_length_stream()),
    ])
    def test_new_template_frames_roundtrip(self, name, factory):
        data = factory()
        result = analyze_stream(data)
        assert result.detected, f"{name}: 未检测到"
        assert b"".join(f.header + f.body for f in result.frames) == data

    def test_alternatives_are_surfaced_not_hidden(self):
        """chunked 流同时自洽于分隔符模板 —— 应并列暴露，而不是藏起来。"""
        data = make_chunked_stream()
        result = analyze_stream(data)
        kinds = {h["kind"] for h in result.framing_hypotheses}
        assert "delimited" in kinds
        assert any("也可被其它模板" in w for w in result.warnings)


class TestDelimiterStatistics:
    """分隔符探测的统计判据（Bonferroni 校正不可省）。"""

    def test_split_by_delimiter_includes_delimiter(self):
        spans, leftover, truncated = split_by_delimiter(b"ab\r\ncd\r\n", b"\r\n")
        assert spans == [(0, 4), (4, 4)]
        assert leftover == 0 and not truncated

    def test_split_reports_trailing_bytes(self):
        spans, leftover, truncated = split_by_delimiter(b"ab\r\ncd", b"\r\n")
        assert spans == [(0, 4)]
        assert leftover == 2 and truncated

    @pytest.mark.parametrize("n", [512, 1024, 2048, 4096, 8192])
    def test_random_streams_have_no_delimiter(self, n):
        """朴素 lift 会被短流随机尖峰击穿，必须被多重比较校正拦住。

        实测 ``random_stream(8192)`` 上必然存在某个 2-gram 出现 4~5 次
        （朴素 lift 高达 32），但 Bonferroni 校正后的 p 值不显著。
        """
        assert detect_delimited(random_stream(n), DEFAULT_CONFIG) is None

    def test_choose_framing_prefers_coverage_then_kind(self):
        from flowunpack.detectors import Detection
        from flowunpack.models import FramingSpec

        def mk(kind, frames, total, verified=True):
            return Detection(kind=kind, frames=frames,
                             spec=FramingSpec(kind=kind), score=0.5,
                             self_verified=verified)

        full = [(0, 100)]
        partial = [(0, 60)]
        a = mk("fixed_length", full, 100)
        b = mk("delimited", partial, 100)
        assert choose_framing([a, b], 100) is a        # 覆盖率优先

        c = mk("delimited", full, 100)
        d = mk("ascii_length", full, 100)
        assert choose_framing([c, d], 100) is d        # 覆盖率相同看证据类型

        e = mk("delimited", full, 100, verified=False)
        assert choose_framing([e], 100) is None        # 未自证不参与裁决


class TestHeaderBodyLayout:
    """【包头】【包体】布局：包头定长，长度字段埋在包头中间。

    这是现实中最常见的一类自定义协议。关键点：长度字段在包头里的**位置**由
    ``offset`` 表达，包头长度折进 ``overhead``，两者独立。因此"长度字段在包头
    中间"不是特殊情形，而是常态。
    """

    @pytest.mark.parametrize("label,kw,offset,fmt,overhead", [
        ("len@0-6B", dict(header_len=6, len_offset=0, magic=b""),
         0, "uint16_be", 6),
        ("len@3-8B", dict(header_len=8, len_offset=3),
         3, "uint16_be", 8),
        ("len@12-16B", dict(header_len=16, len_offset=12),
         12, "uint16_be", 16),
        ("total-len", dict(header_len=8, len_offset=3,
                           semantics="total_length"),
         3, "uint16_be", 0),
        ("with-trailer", dict(header_len=8, len_offset=3, trailer=4),
         3, "uint16_be", 12),
    ])
    def test_fixed_header_layouts(self, label, kw, offset, fmt, overhead):
        data, spec = make_header_body_stream(**kw)
        assert (spec.offset, spec.overhead) == (offset, overhead)   # 生成器自洽

        res = analyze_stream(data)
        assert res.detected, f"{label} 未检出"
        assert res.framing.kind == "length_prefixed"
        lf = res.length_field
        assert (lf.offset, lf.format, lf.overhead) == (offset, fmt, overhead)
        # 帧边界必须与金标准完全一致
        gold = [f.offset for f in apply_spec(data, spec, DEFAULT_CONFIG)[0]]
        assert [f.offset for f in res.frames] == gold
        assert res.stream_trailing == 0

    def test_varint_length_in_header(self):
        """varint 长度字段：包头长度随 varint 宽度变化，overhead = prefix+suffix。"""
        data, spec = make_header_varint_stream()
        assert spec.overhead == 4 and spec.variable_overhead

        res = analyze_stream(data)
        assert res.detected
        lf = res.length_field
        assert lf.format == "varint" and lf.variable_overhead
        assert lf.overhead == 4

    def test_deep_offset_requires_widened_max_offset(self):
        """长度字段在 offset=40（> max_offset=32），放宽后应切出正确边界。

        允许以同族等价编码给出（实测是 ``uint32_le@41`` 而非 ``uint16_be@40``），
        只要**帧边界一致**即可。
        """
        data, spec = make_header_body_stream(header_len=48, len_offset=40,
                                             filler="random")
        gold = [f.offset for f in apply_spec(data, spec, DEFAULT_CONFIG)[0]]

        res = analyze_stream(data, DEFAULT_CONFIG.overridden(max_offset=64))
        assert res.detected
        assert [f.offset for f in res.frames] == gold

    # ---- 已知失败：用 xfail 固定住，避免这条边界在文档里腐烂 ----

    @pytest.mark.xfail(strict=False, reason=(
        "包头零填充（保留字段填 0）会产生远多于真解的伪解，且置信度偏高。"
        "实测同布局填 0xAA 完全正确、填 0x00 给出 30 帧伪解 conf=0.83。"
        "见 README §11。"))
    def test_zero_filled_header(self):
        data, spec = make_zero_filled_header_stream()
        res = analyze_stream(data)
        assert res.detected
        assert (res.length_field.offset, res.length_field.overhead) == (12, 16)
        assert res.unit_count == 10

    @pytest.mark.xfail(strict=False, reason=(
        "变长包头（包头长度随命令字变）在 frame_len = a·v + b 模型里无解："
        "穷举全部 (offset, overhead) 组合，能走完 12 帧的方案数为 0。"
        "当前会给出低置信的错误答案；理想行为是拒绝（宁可少报）。"))
    def test_variable_header_should_be_rejected(self):
        res = analyze_stream(make_variable_header_stream())
        assert not res.detected

    @pytest.mark.xfail(strict=False, reason=(
        "BCD 编码的长度字段不在 config.formats 内。当前会给出错误答案"
        "（4 帧）而非拒绝；失败方式比漏检更危险。"))
    def test_bcd_length_should_be_rejected(self):
        res = analyze_stream(make_bcd_length_stream())
        assert not res.detected


class TestPacketMode:
    def test_detects_length_field(self):
        data, expected = make_length_prefixed_stream("uint16_be")
        # 把每帧当作一个 TCP 包
        frames = [f.header + f.body for f in analyze_stream(data).frames]
        result = analyze_packets(frames)
        assert result.detected
        assert result.length_field.offset == 0
        assert result.length_field.format == "uint16_be"

    def test_insufficient_packets(self):
        assert not analyze_packets([b"\x00\x01"]).detected

    def test_empty_packets_filtered(self):
        assert not analyze_packets([b"", b""]).detected


class TestSegmentationInternals:
    def test_apply_spec_with_known_spec(self):
        data, spec = make_magic_length_stream()
        frames, leftover, truncated = apply_spec(data, spec, DEFAULT_CONFIG)
        assert leftover == 0
        assert not truncated
        assert len(frames) == 12

    def test_segment_stream_returns_candidates_even_when_rejected(self):
        """被拒绝时仍应返回候选，便于人工复核。"""
        _, candidates, best, diag = segment_stream(random_stream(1024), DEFAULT_CONFIG)
        assert best is None
        assert candidates, "即使拒绝也应保留候选供排查"
        assert diag.get("rejected_by") == "permutation"

    def test_truncated_tail_is_reported(self):
        data, spec = make_length_prefixed_stream("uint16_be")
        frames, leftover, truncated = apply_spec(data[:-3], spec, DEFAULT_CONFIG)
        assert truncated
        assert leftover > 0


class TestResolveSpec:
    def test_resolve_ok(self):
        data, spec = make_varint_stream()
        out = resolve_spec(data, spec, DEFAULT_CONFIG)
        assert out["ok"] is True
        assert out["frame_count"] == 14
        assert out["leftover"] == 0
        assert out["frames"][0]["body_hex"]


# ---------------------------------------------------------------------------
# P1：字段级语义推断 + 消息类型聚类
# ---------------------------------------------------------------------------

class TestFieldInference:
    """字段边界与语义类型标注（``fields.py``）。

    判据全部要求"对所有样本成立"，所以这里断言的是**每种类型都能被认出来**，
    以及两条容易回归的边界：CRC trailer 与帧首魔数不能被吞掉。
    """

    def test_magic_length_payload(self):
        data, _ = make_magic_length_stream()
        res = analyze_stream(data)
        by_offset = {f.offset: f for f in res.fields}
        assert by_offset[0].kind == "magic"
        assert by_offset[4].kind == "length"
        assert any(f.kind == "text" for f in res.fields)

    def test_crc32_trailer(self):
        """CRC32 尾部必须被认出来 —— 它是识别 trailer 的唯一依据。

        注意 trailer 的位置随帧长变化，在"帧首对齐"的坐标系里根本看不到，
        必须单独按帧尾对齐去找。
        """
        data, _ = make_crc_length_stream()
        res = analyze_stream(data)
        trailers = [f for f in res.fields if f.kind == "checksum"]
        assert trailers, "带 CRC32 的协议必须识别出尾部校验和"
        t = trailers[0]
        assert (t.offset, t.length) == (-4, 4), "offset 为负表示距帧尾"
        assert "crc32" in t.evidence["algorithm"]
        assert res.statistics["field_summary"]["trailer_len"] == 4

    def test_typed_header_fields(self):
        data, _ = make_typed_fields_stream()
        by_offset = {f.offset: f for f in analyze_stream(data).fields}
        assert by_offset[2].kind == "length"
        assert by_offset[7].kind == "timestamp"
        assert by_offset[11].kind == "ipv4"

    def test_header_len_covers_the_length_field(self):
        """熵判据会把"长度字段的高熵低位字节"误判成载荷起点。"""
        for maker in (make_crc_length_stream, make_typed_fields_stream):
            data, spec = maker()
            res = analyze_stream(data)
            summ = res.statistics["field_summary"]
            assert summ["inferred_header_len"] >= spec.offset + spec.width

    def test_frame_head_constant_is_not_swallowed(self):
        """回归：帧首魔数曾被一个 4 字节的"IPv4"整体吞掉。"""
        data, _ = make_multi_type_stream()
        fields = analyze_stream(data).fields
        assert fields, "应当推断出字段"
        assert fields[0].kind in ("constant", "magic")

    def test_random_stream_has_no_spurious_fields(self):
        assert analyze_stream(random_stream(2048)).fields == []

    def test_too_few_samples_yields_no_fields(self):
        assert analyze_stream(b"\x00\x01\x02\x03").fields == []


class TestMessageTypes:
    """按 keyword 字段的消息类型聚类。"""

    def test_multi_type_stream_is_clustered(self):
        data, _ = make_multi_type_stream()
        res = analyze_stream(data)
        assert len(res.message_types) == 3
        assert all(t.count == 5 for t in res.message_types)
        assert {t.keyword_offset for t in res.message_types} == {2}
        assert sorted(t.keyword_values[0] for t in res.message_types) == [
            "01", "02", "03"]
        # 三个簇的帧长区间互不相交 —— keyword 确实决定了结构
        spans = [(min(t.lengths), max(t.lengths))
                 for t in res.message_types]
        spans.sort()
        assert spans[0][1] < spans[1][0] <= spans[1][1] < spans[2][0]

    def test_single_type_stream_is_not_split(self):
        data, _ = make_magic_length_stream()
        types = analyze_stream(data).message_types
        assert len(types) == 1
        assert types[0].count == 12
        assert types[0].keyword_offset is None

    def test_random_stream_has_single_untyped_group(self):
        types = analyze_stream(random_stream(2048)).message_types
        assert len(types) <= 1
