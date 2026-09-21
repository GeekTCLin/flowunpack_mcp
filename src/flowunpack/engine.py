"""分析编排层：把输入归一化为「单元」，跑各分析器，产出 :class:`AnalysisResult`。

对外只暴露三个函数：

* :func:`analyze_stream`  —— 输入一条连续流（Wireshark 重组流 / tshark -z follow）
* :func:`analyze_packets` —— 输入逐包 payload（已知包边界）
* :func:`analyze`         —— 自动二选一
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

from .analyzers import (
    byte_profile,
    detect_length_field,
    entropy_profile,
    find_magic,
    fixed_bytes,
    guess_protocol,
    header_consistency,
)
from .config import AnalysisConfig, DEFAULT_CONFIG
from .detectors import Detection, choose_framing, detect_templates
from .fields import (infer_fields, infer_message_types, split_header_payload)
from .io_utils import join_packets
from .models import AnalysisResult, Frame, FramingSpec, LengthFieldSpec
from .segmentation import apply_spec, segment_stream, walk
from .segmentation import _score_walk

__all__ = ["analyze_stream", "analyze_packets", "analyze", "resolve_spec"]


#: 各分帧模板对应的协议提示（长度前缀由 guess_protocol 推断，不走这里）
_KIND_HINT = {
    "delimited": "Delimiter-Framed（分隔符分帧）",
    "ascii_length": "Text-Length-Framed（ASCII 文本长度，chunked 风格）",
    "fixed_length": "Fixed-Length（定长分帧，低置信）",
}


def _confidence_from_samples(score: float, n: int, distinct_len: int) -> float:
    """把原始分数折算为置信度：样本越少、长度越单一，置信度打折越多。"""
    conf = score
    conf *= 0.60 + 0.40 * min(1.0, n / 8.0)
    if distinct_len <= 1:
        conf *= 0.55
    elif distinct_len == 2:
        conf *= 0.85
    return round(max(0.0, min(1.0, conf)), 4)


def _attach_fields(result: AnalysisResult, units: Sequence[bytes],
                   cfg: AnalysisConfig) -> None:
    """字段级推断（P1）：在已切出的帧上标注字段边界与语义类型，并做消息分簇。

    这一步**不改变分帧结论**，只在其上叠加字段级解释，因此失败（样本不足 /
    找不到 keyword）时静默留空，不影响 ``detected``。
    """
    units = [u for u in units if u]
    if len(units) < cfg.field_min_units:
        return
    fields, stats = infer_fields(units, cfg, result.length_field)
    header_len, payload_offset, trailer_len = split_header_payload(
        stats, fields, cfg)
    result.fields = fields
    result.message_types = infer_message_types(units, fields, cfg, header_len)
    summary: Dict[str, Any] = {
        "inferred_header_len": header_len,
        "payload_offset": payload_offset,
        "trailer_len": trailer_len,
        "field_count": len(fields),
        "units_used": len(units),
    }
    if result.length_field is not None:
        summary["spec_header_len"] = result.length_field.header_len
        if header_len != result.length_field.header_len:
            result.warnings.append(
                "字段推断给出的包头长度为 %d，与长度字段公式推出的 %d 不一致；"
                "以字段推断为准（后者是 offset+overhead 的粗糙近似）"
                % (header_len, result.length_field.header_len))
    result.statistics["field_summary"] = summary


def _attach_structure(result: AnalysisResult, units: Sequence[bytes],
                      cfg: AnalysisConfig, has_length_field: bool) -> None:
    """填充字节画像 / 魔数 / 协议提示 / 统计信息。"""
    profiles = byte_profile(units, cfg)
    result.byte_profile = profiles
    result.magic = find_magic(profiles, cfg)
    result.protocol_hint = guess_protocol(profiles, units, has_length_field)
    lengths = [len(u) for u in units]
    result.statistics.update({
        "fixed_bytes": fixed_bytes(profiles),
        "entropy": entropy_profile(units, cfg),
        "mean_length": round(sum(lengths) / len(lengths), 2) if lengths else 0,
        "min_length": min(lengths, default=0),
        "max_length": max(lengths, default=0),
    })
    if result.length_field is not None:
        result.statistics["header_consistency"] = round(
            header_consistency(units, result.length_field.header_len), 4)


def _build_frames(data: bytes, det: "Detection", cfg: AnalysisConfig
                  ) -> Tuple[List[Frame], int, bool]:
    """把胜出检测的帧区间物化成 :class:`Frame` 列表。

    约定 ``header + body == 原始帧字节``，保证分帧结果可无损拼回原流：

    * 长度前缀：header = 包头，body = 包体（沿用既往语义）
    * 分隔符：  header = 空，body = 整帧（**含结尾分隔符** —— 分隔符是帧的终止
      标记而非独立内容，把它拆出去会让 ``header + body`` 无法复原原流）
    * ASCII 长度：header = ``<长度><终止符>``，body = 块数据 + 尾部终止符
    * 定长：    header = 空，body = 整帧
    """
    n = len(data)
    frames: List[Frame] = []
    for i, (pos, flen) in enumerate(det.frames):
        raw = data[pos:pos + flen]
        header = b""
        body = raw
        declared: Optional[int] = None
        if det.kind == "ascii_length":
            term = det.spec.ascii_terminator
            eol = raw.find(term)
            if eol >= 0:
                header = raw[:eol + len(term)]
                body = raw[eol + len(term):]
                try:
                    declared = int(raw[:eol].decode("latin1"),
                                   det.spec.ascii_radix)
                except ValueError:
                    declared = None
        frames.append(Frame(index=i, offset=pos, length=flen,
                            declared_value=declared, header=header, body=body))

    end = ((det.frames[-1][0] + det.frames[-1][1]) if det.frames
           else det.spec.start_offset)
    leftover = max(0, n - end)
    if leftover:
        frames.append(Frame(index=len(frames), offset=end, length=leftover,
                            declared_value=None, header=data[end:], body=b"",
                            truncated=True))
    return frames, leftover, leftover > 0


def _reject_reason(result: AnalysisResult, diag: Dict, cfg: AnalysisConfig,
                   fixed_hyps: Sequence["Detection"]) -> None:
    """填充"未检测到结构"时的说明与提示。"""
    reason = diag.get("rejected_by")
    if reason == "permutation":
        perm = diag.get("global") or {}
        result.message = ("未检测到协议结构：候选分帧在置换检验中与随机数据无异"
                          "（gap=%.3f < %.3f，匹配 gap 最大 %.3f < %.3f）"
                          % (perm.get("gap", 0.0), cfg.min_perm_gap,
                             diag.get("max_matched_gap") or 0.0,
                             cfg.min_matched_gap))
    elif reason == "agreement":
        result.message = "未检测到协议结构：候选假设缺乏一致性证据"
    else:
        partial = diag.get("best_partial_frames", 0)
        if partial:
            result.message = ("未检测到协议结构：最佳候选仅切出 %d 帧，"
                              "低于 min_frames=%d（样本太少，不足以排除巧合）"
                              % (partial, cfg.min_frames))
        else:
            result.message = ("未找到能完整切分整条流的长度前缀 / 分隔符 / "
                              "ASCII 长度结构")
    result.warnings.append("可尝试：提高 max_offset / max_overhead，"
                           "或开启 scan_start_offsets 跳过流首部非协议字节")
    if fixed_hyps:
        top = fixed_hyps[0]
        result.warnings.append(
            "存在 %d 个“定长分帧”假设（最大帧长 %d，恒定列比例 %.0f%%）；"
            "整除性无法自证，未作为结论"
            % (len(fixed_hyps), top.spec.frame_len or 0,
               100.0 * float(top.evidence.get("constant_ratio", 0.0))))


def analyze_stream(data: bytes, cfg: AnalysisConfig = DEFAULT_CONFIG,
                   hint: Optional[LengthFieldSpec] = None) -> AnalysisResult:
    """分析一条连续流。

    先跑**长度前缀**搜索（``segment_stream``，含置换检验），再跑**分隔符 /
    ASCII 长度 / 定长**三个探测器，最后按"覆盖率优先、证据强度次之"集成裁决
    （见 :func:`flowunpack.detectors.choose_framing`）。

    :param hint: 已知的长度字段结构（例如从**另一个方向**迁移过来的）。
        给出时先尝试直接用它切分：能完整走完且无剩余即采纳（``accepted_by``
        为 ``"hint"``），省掉整轮搜索；**迁移失败则退回正常搜索**，因此这个
        参数只会让结果更好，不会更差。双向流联合推断（:mod:`.bidir`）据此实现。
    """
    result = AnalysisResult(
        mode="stream", ok=False, message="", input_bytes=len(data),
        unit_count=0, unit_lengths=[], unique_lengths=[],
    )

    if len(data) < 4:
        result.message = "输入过短（< 4 字节），无法分析"
        return result

    # ---- 模板 0：已知结构迁移（双向联合推断 / 用户指定）----
    detections: List[Detection] = []
    lp_frames: Optional[List[Frame]] = None
    _lp_left = 0
    _lp_trunc = False
    candidates: List = []
    diag: Dict[str, Any] = {}
    if hint is not None:
        w = walk(data, hint.offset, hint.format, hint.overhead, cfg,
                 count_width=hint.variable_overhead, scale=hint.scale)
        if w.complete and len(w.frames) >= cfg.min_frames:
            score = _score_walk(data, w, cfg, 1)
            lp_frames, _lp_left, _lp_trunc = apply_spec(data, hint, cfg)
            detections.append(Detection(
                kind="length_prefixed",
                frames=[(p, l) for p, l in w.frames],
                spec=FramingSpec(kind="length_prefixed", length_field=hint,
                                 confidence=score),
                score=score, self_verified=True,
                evidence={"accepted_by": "hint", "frames": len(w.frames)}))
            diag = {"accepted_by": "hint", "chosen_rank": 0,
                    "source": "hint", "frames": len(w.frames)}
        else:
            hint = None                 # 迁移失败 → 退回常规搜索

    if hint is None:
        # ---- 模板 1：长度前缀（唯一需要完整搜索 + 置换检验的模板）----
        spec, candidates, best_walk, diag = segment_stream(data, cfg)
        result.candidates = candidates
        result.statistics["diagnostics"] = diag

        chosen = diag.get("chosen_rank", 0)
        raw_score = (candidates[chosen].score
                     if candidates and chosen < len(candidates)
                     else (candidates[0].score if candidates else 0.0))
        if spec is not None and best_walk is not None:
            lp_frames, _lp_left, _lp_trunc = apply_spec(data, spec, cfg)
            spans = [(f.offset, f.length) for f in lp_frames if not f.truncated]
            detections.append(Detection(
                kind="length_prefixed", frames=spans,
                spec=FramingSpec(kind="length_prefixed", length_field=spec,
                                 confidence=raw_score),
                score=raw_score, self_verified=True,
                evidence={"accepted_by": diag.get("accepted_by"),
                          "frames": len(spans)}))

    result.statistics["diagnostics"] = diag

    # ---- 模板 2/3/4：分隔符 / ASCII 长度 / 定长 ----
    template_dets, fixed_hyps = detect_templates(data, cfg)
    detections.extend(template_dets)
    # 只报告有证据（至少一个恒定列）的定长假设，避免纯随机流刷出一堆噪声
    reportable = [d for d in fixed_hyps
                  if int(d.evidence.get("constant_columns", 0)) >= 1]
    if reportable:
        result.framing_hypotheses = [d.to_dict() for d in reportable[:8]]

    winner = choose_framing(detections, len(data))
    if winner is None:
        _reject_reason(result, diag, cfg, reportable)
        _attach_structure(result, [data[:cfg.scan_bytes]], cfg, False)
        return result

    # ---- 物化胜出方案 ----
    if winner.kind == "length_prefixed" and lp_frames is not None:
        frames, leftover, truncated = lp_frames, _lp_left, _lp_trunc
    else:
        frames, leftover, truncated = _build_frames(data, winner, cfg)

    # 并列自洽：其它模板也完整解释了这条流。不做无依据的取舍，而是并列暴露，
    # 让用户看到"同一流还可以这样切"（见 detectors.choose_framing 的说明）。
    win_cov = winner.coverage(len(data))
    alternatives = [d for d in detections
                    if d is not winner and d.self_verified
                    and d.kind != winner.kind
                    and d.coverage(len(data)) >= win_cov - 1e-9]
    if alternatives:
        result.framing_hypotheses = (result.framing_hypotheses
                                     + [d.to_dict() for d in alternatives[:3]])

    result.framing = winner.spec
    result.length_field = winner.spec.length_field
    result.detected = True
    result.ok = True
    result.frames = frames
    result.unit_count = len(frames)
    result.unit_lengths = [f.length for f in frames]
    result.unique_lengths = sorted(set(result.unit_lengths))
    result.stream_trailing = leftover
    result.statistics["framing"] = winner.to_dict()

    distinct_len = len(result.unique_lengths)
    result.confidence = _confidence_from_samples(winner.score, len(frames),
                                                distinct_len)
    winner.spec.confidence = result.confidence
    label = winner.spec.label()
    result.message = ("分帧成功：切出 %d 帧（模板：%s），末尾剩余 %d 字节"
                      % (len(frames), label, leftover))
    if truncated:
        result.warnings.append("流尾部存在不完整帧（可能抓包被截断）")
    if winner.kind == "fixed_length":
        result.warnings.append("定长分帧仅由整除性 + 刚性包头佐证，"
                               "请人工确认帧长")
    if winner.kind != "length_prefixed":
        result.warnings.append("长度前缀模板未通过显著性检验；"
                               "本结论来自 %s 模板" % label)
    if alternatives:
        result.warnings.append("同一流也可被其它模板完整解释：" + "；".join(
            "%s（%d 帧）" % (d.spec.label(), len(d.frames))
            for d in alternatives[:3]))

    _attach_structure(result, [f.header + f.body for f in frames], cfg,
                      winner.kind == "length_prefixed")
    _attach_fields(result, [f.header + f.body for f in frames], cfg)
    if winner.kind != "length_prefixed":
        result.protocol_hint = _KIND_HINT.get(winner.kind, label)
    return result


def analyze_packets(packets: Sequence[bytes],
                    cfg: AnalysisConfig = DEFAULT_CONFIG) -> AnalysisResult:
    """分析逐包 payload：包边界已知，直接做长度字段检测 + 结构统计。"""
    packets = [p for p in packets if p]
    joined = join_packets(packets)
    result = AnalysisResult(
        mode="packets", ok=False, message="", input_bytes=len(joined),
        unit_count=len(packets),
        unit_lengths=[len(p) for p in packets],
        unique_lengths=sorted({len(p) for p in packets}),
    )

    if len(packets) < cfg.min_packets:
        result.message = "样本不足：至少需要 %d 个非空包" % cfg.min_packets
        return result

    spec, candidates = detect_length_field(packets, cfg)
    result.candidates = candidates

    # 流模式交叉验证：TCP 拼接流若每包一帧，两者结论应一致；
    # 若一包多帧，则只有流模式能给出正确分帧。
    stream_spec, _stream_cands, best_walk, stream_diag = segment_stream(joined, cfg)
    result.statistics["stream_diagnostics"] = stream_diag

    chosen: Optional[LengthFieldSpec] = None
    if spec is not None:
        chosen = spec
        evidence = candidates[0].evidence if candidates else {}
        raw_score = candidates[0].score if candidates else 0.0
        if stream_spec is not None and stream_spec.offset == spec.offset \
                and stream_spec.format == spec.format:
            raw_score = min(1.0, raw_score + 0.10)
            result.warnings.append("流级分帧与逐包检测结论一致，置信度上调")
        elif stream_spec is not None:
            result.warnings.append(
                "流级分帧给出不同结论 (offset=%d, %s)；若一个 TCP 包承载多帧，"
                "请以流模式结果为准" % (stream_spec.offset, stream_spec.format))
    elif stream_spec is not None:
        chosen = stream_spec
        raw_score = 0.6
        result.warnings.append("逐包检测未收敛，采用流级分帧结论")

    if chosen is None:
        result.message = "未检测到可靠的长度字段"
        _attach_structure(result, packets, cfg, False)
        return result

    result.length_field = chosen
    result.detected = True
    result.ok = True
    result.confidence = _confidence_from_samples(
        raw_score, len(packets), len(result.unique_lengths))

    frames: List[Frame] = []
    for i, pkt in enumerate(packets):
        header = pkt[:chosen.header_len]
        body = pkt[chosen.header_len:]
        declared = None
        if len(pkt) > chosen.offset:
            from .codecs import value_at
            declared = value_at(pkt, chosen.offset, chosen.format)
        frames.append(Frame(index=i, offset=0, length=len(pkt),
                            declared_value=declared, header=header, body=body))
    result.frames = frames
    result.message = "已识别长度字段"
    _attach_structure(result, packets, cfg, True)
    _attach_fields(result, packets, cfg)
    return result


def resolve_spec(data: bytes, spec: LengthFieldSpec,
                 cfg: AnalysisConfig = DEFAULT_CONFIG) -> Dict[str, object]:
    """用给定帧结构切分流，返回 ``{"frames": [...], "leftover": n, "ok": bool}``。"""
    frames, leftover, truncated = apply_spec(data, spec, cfg)
    return {
        "ok": bool(frames) and leftover == 0,
        "frames": [f.to_dict() for f in frames[:cfg.max_frames_output]],
        "frame_count": len(frames),
        "leftover": leftover,
        "truncated": truncated,
        "spec": spec.to_dict(),
    }


def analyze(data: bytes | Sequence[bytes],
            cfg: AnalysisConfig = DEFAULT_CONFIG) -> AnalysisResult:
    """自动选择模式：``bytes`` 走流模式，序列走逐包模式。"""
    if isinstance(data, (bytes, bytearray, memoryview)):
        return analyze_stream(bytes(data), cfg)
    return analyze_packets(list(data), cfg)
