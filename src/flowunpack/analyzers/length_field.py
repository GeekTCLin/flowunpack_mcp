"""长度字段启发式检测 —— 逐包模式。

判定思路（相比旧实现的三处关键改进）
------------------------------------
1. **以「帧长公式」为核心**：对每个 ``(offset, format)`` 计算 ``overhead = len(pkt) - value``，
   取其众数，再统计精确命中率。旧实现靠一堆互相叠加的 if 分支硬编码关系，难以解释。
2. **引入结构自洽约束** ``overhead >= offset + width``（长度字段只描述包体）或
   ``overhead == 0``（长度字段描述整帧）。旧实现完全没有这一约束，导致大量误判。
3. **排除两类经典误报**：常量字段（包长变但值不变）、前导 0 填充区（值恒为 0）。
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

from ..codecs import FORMATS, decode_at, min_width
from ..config import AnalysisConfig
from ..models import Candidate, LengthFieldSpec

__all__ = ["detect_length_field", "evaluate_candidate", "explain"]


def _offset_prior(offset: int) -> float:
    """偏移先验：协议长度字段多在帧首部，且常按字对齐。"""
    if offset == 0:
        return 1.0
    if offset <= 4:
        return 0.95
    if offset <= 8:
        return 0.85
    if offset <= 16:
        return 0.75
    return 0.65


def _is_leading_zero_area(packets: Sequence[bytes], offset: int) -> bool:
    """该偏移之前是否在所有包里都是 0x00（典型的前导填充区）。"""
    if offset == 0:
        return False
    return all(all(p[i] == 0 for i in range(min(offset, len(p)))) for p in packets)


def evaluate_candidate(packets: Sequence[bytes], offset: int, fmt: str,
                       cfg: AnalysisConfig) -> Optional[Candidate]:
    """评估一个 ``(offset, format)`` 组合是否像长度字段。"""
    samples: List[Tuple[int, int, int]] = []   # (packet_len, value, width)
    for pkt in packets:
        if len(pkt) <= offset:
            return None
        got = decode_at(pkt, offset, fmt)
        if got is None:
            return None
        value, width = got
        samples.append((len(pkt), value, width))

    n = len(samples)
    if n == 0:
        return None

    # --- 等长包 -> 值必须一致 ---
    groups: Dict[int, set] = defaultdict(set)
    for plen, value, _ in samples:
        groups[plen].add(value)
    consistent = sum(1 for s in groups.values() if len(s) == 1) / len(groups)

    # --- 帧长公式: frame_len = scale*value + overhead ---
    # 对每个候选 scale 求 (plen - scale*value) 的众数，取精确命中率最高的组合。
    # 用严格大于比较，保证平局时 scale=1（更简单的计数单位）胜出。
    best_fit = None                                  # (exact_ratio, scale, overhead)
    for scale in cfg.scales:
        scaled = [plen - scale * value for plen, value, _ in samples]
        oh, hits = Counter(scaled).most_common(1)[0]
        ratio = hits / n
        if best_fit is None or ratio > best_fit[0]:
            best_fit = (ratio, scale, int(oh))
    exact_ratio, scale, overhead = best_fit

    coverage = sum(1 for plen, value, _ in samples
                   if 0 < scale * value <= plen) / n

    # --- 判别力: 值必须随包长变化 ---
    distinct_len = len({plen for plen, _, _ in samples})
    distinct_val = len({value for _, value, _ in samples})
    if distinct_len > 1:
        discriminative = min(1.0, (distinct_val - 1) / (distinct_len - 1))
    else:
        discriminative = 0.3      # 单一长度无法证明判别力

    # --- 结构自洽: 长度字段必须位于它不描述的那部分里 ---
    min_ow = offset + min(w for _, _, w in samples)
    if overhead >= min_ow:
        structural, semantics = 1.0, "body_length"
    elif overhead == 0:
        structural, semantics = 0.7, "total_length"
    elif overhead > 0:
        structural, semantics = 0.25, "body_length"
    else:
        structural, semantics = 0.05, "unknown"

    score = (cfg.w_exact * exact_ratio
             + cfg.w_consistent * consistent
             + cfg.w_discriminative * discriminative
             + cfg.w_coverage * coverage
             + cfg.w_structural * structural)
    score *= _offset_prior(offset)

    # --- 惩罚项 ---
    penalties = []
    if distinct_val == 1 and distinct_len > 1:
        score *= cfg.penalty_constant_value
        penalties.append("constant_value")
    if distinct_val == 1 and next(iter({v for _, v, _ in samples})) == 0 \
            and _is_leading_zero_area(packets, offset):
        score *= cfg.penalty_zero_padding
        penalties.append("zero_padding")

    width = FORMATS[fmt].width
    head = "value" if scale == 1 else f"{scale}*value"
    return Candidate(
        offset=offset,
        format=fmt,
        width=width,
        overhead=overhead,
        semantics=semantics,
        score=round(max(0.0, min(1.0, score)), 4),
        scale=scale,
        evidence={
            "exact_ratio": round(exact_ratio, 4),
            "consistent": round(consistent, 4),
            "discriminative": round(discriminative, 4),
            "coverage": round(coverage, 4),
            "structural": structural,
            "packet_count": n,
            "distinct_lengths": distinct_len,
            "distinct_values": distinct_val,
            "penalties": penalties,
            "scale": scale,
            "formula": f"frame_len = {head} + {overhead}",
        },
    )


def detect_length_field(packets: Sequence[bytes], cfg: AnalysisConfig
                        ) -> Tuple[Optional[LengthFieldSpec], List[Candidate]]:
    """枚举所有 ``(offset, format)``，返回最佳长度字段与候选排行。"""
    if len(packets) < cfg.min_packets:
        return None, []

    max_offset = min(cfg.max_offset, min(len(p) for p in packets))
    candidates: List[Candidate] = []

    for offset in range(max_offset):
        for fmt in cfg.formats:
            if offset + min_width(fmt) > min(len(p) for p in packets):
                continue
            cand = evaluate_candidate(packets, offset, fmt, cfg)
            if cand is not None and cand.score > 0:
                candidates.append(cand)

    candidates.sort(key=lambda c: (c.score, -c.offset, -len(c.format)), reverse=False)
    candidates = sorted(candidates, key=lambda c: c.score, reverse=True)

    if not candidates:
        return None, []

    best = candidates[0]
    spec = LengthFieldSpec(
        offset=best.offset,
        format=best.format,
        width=best.width,
        overhead=best.overhead,
        semantics=best.semantics,
        header_len=best.overhead if best.semantics == "body_length"
        else best.offset + (best.width or 1),
        body_offset=best.overhead if best.semantics == "body_length"
        else best.offset + (best.width or 1),
        endian=FORMATS[best.format].endian,
        scale=best.scale,
    )
    return spec, candidates[:cfg.top_candidates]


def explain(spec: LengthFieldSpec, packets: Sequence[bytes]) -> List[str]:
    """生成人类可读的判定理由。"""
    reasons = [f"长度字段位于偏移 {spec.offset}，编码 {spec.format}（{spec.endian} 端序）"]
    reasons.append("帧总长 " + spec.formula())
    if spec.semantics == "body_length":
        reasons.append(f"该字段只描述包体，包头长度 {spec.header_len} 字节，"
                       f"包体从偏移 {spec.body_offset} 开始")
    else:
        reasons.append("该字段描述整帧长度（含自身）")
    lengths = sorted({len(p) for p in packets})
    reasons.append(f"样本包长集合: {lengths[:12]}{' ...' if len(lengths) > 12 else ''}")
    return reasons
