"""长度前缀之外的**分帧模板探测器**（BinaryInferno 式"探测器集成"）。

背景
----
``segmentation.py`` 只搜索一种模板 ``frame_len = scale*value + overhead``。
因此定长帧、分隔符分帧（``\\r\\n``、Redis RESP）、HTTP chunked 的 ASCII 文本长度
全部漏检。本模块补齐另外三种模板，每个模板是一个独立探测器，各自从字节里
给出一个**完整分帧假设**：

* :func:`detect_delimited`    —— 重复出现的**多字节**分隔符
* :func:`detect_ascii_length`  —— 文本长度前缀 ``<hex>\\r\\n<data>\\r\\n``
* :func:`detect_fixed_length`  —— 所有帧等长

集成规则（:func:`choose_framing`）：**最大化被解释的字节数（覆盖率）**，
覆盖率相同时按证据强度排序（``models.KIND_PRIORITY``：长度前缀 > ASCII 长度 >
分隔符 > 定长）。

可自证性——本模块最关键的一条设计约束
--------------------------------------
四个模板里只有两个能"从字节自身验证"：

* **ASCII 长度**：声明的长度必须与后续字节**恰好吻合**，再紧跟一个终止符。
  这是强约束，几乎不可能偶然成立。
* **多字节分隔符**：随机数据里 ``k`` 字节序列的出现次数按各字节频率的乘积衰减。
  ``\\r\\n`` 在随机字节流里的期望出现次数 ≈ ``n/65536``，观测到几十次是极强的结构信号。
  判据用**泊松尾概率 + Bonferroni 多重比较校正**（而不是朴素 lift）：
  朴素 lift 在短流上会被"随机尖峰"击穿，实测 ``random_stream(8192)``
  上必然存在某个 2-gram 出现 4 次，朴素 lift 高达 32 —— 会造成误报。

另外两个**不可自证**，只作为低置信假设列出，绝不进入 ``detected=True`` 结论：

* **单字节分隔符**：它的"随机期望出现次数"就是它自己的出现次数，lift 恒为 1。
* **定长帧**：任意能整除流长的 ``N`` 都构成一个合法分帧
  （``random_stream(4096)`` 对 1/2/4/8/…/4096 全部成立）。
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .config import AnalysisConfig
from .models import KIND_PRIORITY, FramingSpec

__all__ = [
    "Detection",
    "detect_delimited",
    "detect_ascii_length",
    "detect_fixed_length",
    "detect_templates",
    "choose_framing",
    "split_by_delimiter",
    "parse_ascii_length",
]

#: (offset, length) —— 与 segmentation 的帧表示一致
FrameSpan = Tuple[int, int]

#: 各进制下的合法数字字符（按 int 值存，便于对 bytes 逐元素判断）
_DIGIT_BYTES: Dict[int, frozenset] = {
    16: frozenset(b"0123456789abcdefABCDEF"),
    10: frozenset(b"0123456789"),
}


# ---------------------------------------------------------------------------
# 公共数据结构
# ---------------------------------------------------------------------------

@dataclass
class Detection:
    """一个模板给出的**完整分帧假设**。

    ``self_verified`` 表示"这条假设能从字节自身验证"。只有它为 ``True``
    的检测才允许参与 :func:`choose_framing` 的最终裁决。
    """

    kind: str
    frames: List[FrameSpan]
    spec: FramingSpec
    score: float
    self_verified: bool
    evidence: Dict = field(default_factory=dict)

    @property
    def covered(self) -> int:
        return sum(l for _, l in self.frames)

    def coverage(self, total: int) -> float:
        return (self.covered / total) if total else 0.0

    def to_dict(self) -> Dict:
        return {
            "kind": self.kind,
            "score": round(self.score, 4),
            "frames": len(self.frames),
            "covered": self.covered,
            "self_verified": self.self_verified,
            "spec": self.spec.to_dict(),
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------

def _norm_log(x: float, ref: float) -> float:
    """把非负量归一化到 0~1（对数刻度，``ref`` 处饱和）。"""
    if x <= 0:
        return 0.0
    return min(1.0, math.log(1.0 + x) / math.log(1.0 + ref))


def _poisson_sf(k: int, lam: float) -> float:
    """``P(X >= k)``，``X ~ Poisson(lam)``。"""
    if k <= 0:
        return 1.0
    if lam <= 0:
        return 0.0
    # 累加 P(X = 0..k-1) 后取补，递推项 term_i = term_{i-1} * lam / i
    cdf = 0.0
    term = math.exp(-lam)
    for i in range(0, k):
        cdf += term
        if cdf >= 1.0:
            return 0.0
        term *= lam / (i + 1)
    return max(0.0, 1.0 - cdf)


def _p_to_score(p: float) -> float:
    """把 p 值折算成 0~1 的证据强度：``p <= 1e-12`` 记满分。"""
    if p <= 0.0:
        return 1.0
    return min(1.0, max(0.0, math.log10(1.0 / p) / 12.0))


def _column_stats(data: bytes, spans: Sequence[FrameSpan],
                  max_cols: int = 0) -> Tuple[int, int]:
    """跨帧"恒定列"计数。

    列宽取所有帧的最小长度，保证每列在所有帧里都存在（否则"缺失"会被
    误当成"取值不同"）；``max_cols`` 进一步把统计限制在每帧前若干列
    （包头区域），把代价压到 ``O(列数 · 帧数)``。

    :return: ``(恒定列数, 参与统计的列数)``
    """
    if len(spans) < 2:
        return 0, 0
    width = min(l for _, l in spans)
    if max_cols:
        width = min(width, max_cols)
    if width <= 0:
        return 0, 0
    constant = 0
    base = spans[0][0]
    for i in range(width):
        first = data[base + i]
        for o, _ in spans:
            if data[o + i] != first:
                break
        else:
            constant += 1
    return constant, width


# ---------------------------------------------------------------------------
# 分隔符分帧
# ---------------------------------------------------------------------------

def split_by_delimiter(data: bytes,
                       delim: bytes) -> Tuple[List[FrameSpan], int, bool]:
    """在 ``delim`` 的每一次出现处切分，分隔符**计入前缀帧**。

    首帧从 0 开始，因此流首部的非协议前导字节会并入首帧。

    :return: ``(帧区间, 末尾剩余字节数, 是否截断)``
    """
    spans: List[FrameSpan] = []
    pos = 0
    n = len(data)
    dl = len(delim)
    while pos < n:
        idx = data.find(delim, pos)
        if idx < 0:
            break
        end = idx + dl
        spans.append((pos, end - pos))
        pos = end
    return spans, n - pos, (n - pos) > 0


def _iter_delimiter_candidates(data: bytes, cfg: AnalysisConfig
                               ) -> Counter:
    """统计 2..``delim_max_len`` 字节候选序列的出现次数（只扫前若干字节）。"""
    scan = data[:cfg.delim_scan_bytes]
    n = len(scan)
    counts: Counter = Counter()
    for k in range(2, cfg.delim_max_len + 1):
        if n < k:
            break
        for i in range(0, n - k + 1):
            counts[scan[i:i + k]] += 1
    # 结构性分隔符无论出现几次都参与评估（即使被上面截断漏掉）
    for d in cfg.delim_extra:
        if len(d) >= 2:
            counts.setdefault(d, scan.count(d))
    return counts


def detect_delimited(data: bytes, cfg: AnalysisConfig
                     ) -> Optional[Detection]:
    """探测多字节分隔符分帧。

    显著性判据（对每个候选分隔符 ``d``）：

    1. ``lam`` = 在"各字节独立"零假设下 ``d`` 的期望出现次数
       = ``(#位置) · Π freq(byte)``；
    2. ``p = P(X >= count)``，``X ~ Poisson(lam)``；
    3. **Bonferroni 校正**：``p · M`` 才是最终 p 值，``M`` 为参与比较的候选数
       （这一步不可省 —— 见模块 docstring 中 ``random_stream(8192)`` 的反例）。

    只有 ``p · M <= cfg.delim_alpha`` 且 ``count >= delim_min_frames``
    且 ``lift = count/lam >= delim_min_lift`` 的候选才被接受。

    :return: 最佳 :class:`Detection`，无显著分隔符时返回 ``None``。
    """
    n = len(data)
    if n < cfg.delim_min_frames * 2:
        return None
    scan = data[:cfg.delim_scan_bytes]
    sn = len(scan)
    counts = _iter_delimiter_candidates(data, cfg)
    if not counts:
        return None
    freq = Counter(scan)
    candidates = counts.most_common(cfg.delim_max_candidates)
    # M：参与多重比较的候选数量（Bonferroni）。必须用**全部被检验过的**候选数，
    # 而不是截断后的候选数 —— 用后者会把校正量算小、把显著性算大。
    m_eff = max(1, len(counts))

    best: Optional[Detection] = None
    for delim, cnt in candidates:
        if cnt < cfg.delim_min_frames:
            continue
        lam = 1.0
        for b in delim:
            c = freq.get(b, 0)
            if c == 0:
                lam = 0.0
                break
            lam *= c / sn
        if lam <= 0.0:
            continue
        lam *= max(1, sn - len(delim) + 1)
        lift = cnt / lam
        if lift < cfg.delim_min_lift:
            continue
        p = _poisson_sf(cnt, lam) * m_eff
        if p > cfg.delim_alpha:
            continue

        spans, leftover, truncated = split_by_delimiter(data, delim)
        if len(spans) < cfg.delim_min_frames:
            continue
        cov = sum(l for _, l in spans) / n
        if cov < cfg.delim_min_coverage:
            continue
        # 分数**不乘覆盖率**：覆盖率由 choose_framing 作为独立的第一裁决维度，
        # 这里只衡量"这条分隔符有多可信 + 切出了多少帧"。
        score = 0.5 * _p_to_score(p) + 0.5 * _norm_log(len(spans), 32.0)
        if best is not None and score <= best.score:
            continue
        best = Detection(
            kind="delimited",
            frames=spans,
            spec=FramingSpec(kind="delimited", delimiter=delim,
                             confidence=score),
            score=round(score, 4),
            self_verified=True,
            evidence={
                "delimiter_hex": delim.hex(),
                "delimiter_ascii": "".join(
                    chr(b) if 32 <= b < 127 else "." for b in delim),
                "delimiter_len": len(delim),
                "occurrences": cnt,
                "expected_chance": round(lam, 6),
                "lift": (round(lift, 2) if math.isfinite(lift) else "inf"),
                "p_value": float("%.3g" % p),
                "coverage": round(cov, 4),
            })
    return best


# ---------------------------------------------------------------------------
# ASCII 文本长度分帧（HTTP chunked 形态）
# ---------------------------------------------------------------------------

def parse_ascii_length(data: bytes, start: int, radix: int, term: bytes
                       ) -> Optional[Tuple[List[FrameSpan], int, bool]]:
    """从 ``start`` 起按 ``<数字><term><数据><term>`` 逐块解析。

    对 HTTP chunked：``<hex>\\r\\n<数据>\\r\\n``，结尾是 ``0\\r\\n\\r\\n``。
    每一块的"声明长度"必须与后续字节**恰好吻合**再跟一个终止符，这是本模板
    能自证的全部依据。

    :return: ``(帧区间, 末尾剩余字节数, 是否截断)``；首块就不成立时返回 ``None``。
    """
    digits = _DIGIT_BYTES.get(radix)
    if digits is None:
        return None
    spans: List[FrameSpan] = []
    pos = start
    n = len(data)
    tl = len(term)
    while pos < n:
        eol = data.find(term, pos)
        if eol < 0:
            return (spans, n - pos, True) if spans else None
        token = data[pos:eol]
        if not token or len(token) > 16:
            return (spans, n - pos, True) if spans else None
        for ch in token:
            if ch not in digits:
                return (spans, n - pos, True) if spans else None
        value = int(token.decode("latin1"), radix)
        body_start = eol + tl
        if value == 0:
            # 终止块（HTTP chunked 的 "0\r\n"）：若后面还有 term 一并计入
            end = body_start
            if data[end:end + tl] == term:
                end += tl
            spans.append((pos, end - pos))
            return spans, n - end, False
        body_end = body_start + value
        if body_end > n:
            return (spans, n - pos, True) if spans else None
        if data[body_end:body_end + tl] != term:
            return (spans, n - pos, True) if spans else None
        spans.append((pos, body_end + tl - pos))
        pos = body_end + tl
    return (spans, 0, False) if spans else None


def _ascii_starts(data: bytes, radix: int, term: bytes,
                  scan_limit: int) -> List[int]:
    """找出所有"像是一个数字 token 后紧跟终止符"的起始位置（用于容忍前导字节）。"""
    digits = _DIGIT_BYTES.get(radix)
    if digits is None:
        return []
    tl = len(term)
    n = len(data)
    starts: List[int] = []
    i = 0
    hi = min(n, scan_limit)
    while i < hi:
        if data[i] in digits:
            j = i
            while j < n and (j - i) < 16 and data[j] in digits:
                j += 1
            if j > i and data[j:j + tl] == term:
                starts.append(i)
            i = j if j > i else i + 1
        else:
            i += 1
    return starts


def detect_ascii_length(data: bytes, cfg: AnalysisConfig
                        ) -> Optional[Detection]:
    """探测文本长度前缀分帧（HTTP chunked 的十六进制长度等）。"""
    n = len(data)
    if n < cfg.min_frames * 2:
        return None

    best: Optional[Detection] = None
    best_rank: Tuple = ()
    for radix in cfg.ascii_radices:
        for term in cfg.ascii_terminators:
            starts = _ascii_starts(data, radix, term, cfg.ascii_scan_start)
            if not starts:
                continue
            for start in starts:
                got = parse_ascii_length(data, start, radix, term)
                if got is None:
                    continue
                spans, leftover, truncated = got
                if len(spans) < cfg.min_frames:
                    continue
                cov = sum(l for _, l in spans) / n
                if cov < cfg.ascii_min_coverage:
                    continue
                # 终止块（value==0）是 HTTP chunked 的结束标记，额外加分
                terminator_block = False
                if spans:
                    tok_end = data.find(term, spans[-1][0])
                    if tok_end > spans[-1][0]:
                        try:
                            terminator_block = int(
                                data[spans[-1][0]:tok_end].decode("latin1"),
                                radix) == 0
                        except ValueError:
                            terminator_block = False
                score = (0.55 * _norm_log(len(spans), 16.0)
                         + 0.30 * cov
                         + 0.15 * (1.0 if terminator_block else 0.0))
                rank = (score, -leftover, len(spans), -start)
                if best is not None and rank <= best_rank:
                    continue
                best_rank = rank
                best = Detection(
                    kind="ascii_length",
                    frames=spans,
                    spec=FramingSpec(kind="ascii_length", ascii_offset=start,
                                     ascii_radix=radix,
                                     ascii_terminator=term,
                                     start_offset=start,
                                     confidence=round(score, 4)),
                    score=round(score, 4),
                    self_verified=True,
                    evidence={
                        "radix": radix,
                        "terminator_hex": term.hex(),
                        "offset": start,
                        "blocks": len(spans),
                        "coverage": round(cov, 4),
                        "has_terminator_block": terminator_block,
                        "leftover": leftover,
                    })
    return best


# ---------------------------------------------------------------------------
# 定长分帧（不可自证，仅低置信假设）
# ---------------------------------------------------------------------------

def detect_fixed_length(data: bytes, cfg: AnalysisConfig) -> List[Detection]:
    """枚举能整除流长的帧长，按跨帧"恒定列"比例评分。

    **这一模板无法自证**：任意能整除流长的 ``N`` 都构成合法分帧。因此
    ``self_verified`` 要求存在**独立于整除性的证据**——刚性包头，即跨帧
    恒定列同时达到 ``fixed_min_constant_columns`` 与 ``fixed_min_constant_ratio``。
    不满足的候选仍然返回，但 ``self_verified=False``，只会出现在低置信假设表里。

    :return: 按 ``(是否自证, score)`` 降序的假设列表。
    """
    n = len(data)
    out: List[Detection] = []
    if n < cfg.fixed_min_frames * 2 or n > cfg.fixed_scan_max_bytes:
        return out
    max_len = n // cfg.fixed_min_frames
    for flen in range(2, max_len + 1):
        if n % flen:
            continue
        spans = [(i, flen) for i in range(0, n, flen)]
        if len(spans) < cfg.fixed_min_frames:
            continue
        const, cols = _column_stats(data, spans, cfg.fixed_max_columns)
        ratio = (const / cols) if cols else 0.0
        verified = (const >= cfg.fixed_min_constant_columns
                    and ratio >= cfg.fixed_min_constant_ratio)
        score = round(0.6 * ratio + 0.4 * _norm_log(len(spans), 32.0), 4)
        out.append(Detection(
            kind="fixed_length",
            frames=spans,
            spec=FramingSpec(kind="fixed_length", frame_len=flen,
                             confidence=score),
            score=score,
            self_verified=verified,
            evidence={
                "frame_len": flen,
                "frames": len(spans),
                "constant_ratio": round(ratio, 4),
                "constant_columns": const,
                "columns": cols,
                "note": "仅整除性不足以自证；需刚性包头（恒定列）佐证",
            }))
    out.sort(key=lambda d: (d.self_verified, d.score), reverse=True)
    return out


# ---------------------------------------------------------------------------
# 集成与选择
# ---------------------------------------------------------------------------

def detect_templates(data: bytes, cfg: AnalysisConfig,
                     need_fixed: bool = True
                     ) -> Tuple[List[Detection], List[Detection]]:
    """运行长度前缀之外的三个模板探测器。

    :param need_fixed: 是否做定长枚举。定长代价约 ``O(n·d(n))``，且在与
        已接受的长度前缀共存时永远不可能胜出（证据优先级更低），
        因此调用方可在长度前缀已定案时跳过它（``need_fixed=False``）。
    :return: ``(可用于定案的自证检测, 低置信假设)``
    """
    accepted: List[Detection] = []
    for fn in (detect_ascii_length, detect_delimited):
        det = fn(data, cfg)
        if det is not None and det.self_verified \
                and det.score >= cfg.detect_min_score:
            accepted.append(det)

    hypotheses: List[Detection] = []
    if need_fixed:
        hypotheses = detect_fixed_length(data, cfg)
        for det in hypotheses:
            if det.self_verified and det.score >= cfg.detect_min_score:
                accepted.append(det)
    return accepted, hypotheses


def choose_framing(detections: Sequence[Detection],
                   total: int) -> Optional[Detection]:
    """集成裁决：**覆盖率 → 证据类型 → 帧数 → 分数**。

    1. **覆盖率**（解释了多少字节）—— 来自 BinaryInferno "最大化被描述的字节总量"。
    2. **证据类型优先级**（``models.KIND_PRIORITY``）—— 覆盖率相同时，取证据更强的
       模板：长度前缀（完整置换检验）> ASCII 长度（长度与字节精确吻合的自校验）
       > 分隔符（频率显著性）> 定长（仅整除性 + 恒定列）。
    3. **帧数**（多者优先）、4. **分数**。

    为什么不是"帧数优先"：实测凡是存在嵌套解释的流，**更细的分帧常常是更弱模板的
    副产品**——HTTP chunked 流被 ``\\r\\n`` 切成 18 帧（把每个块的"头/体"各切一刀），
    而真正的 ASCII 长度模板只有 9 帧。所以帧数不能压在证据类型前面。

    代价是：当某个流恰好同时存在"嵌套的长度前缀规则"（更粗）与"刚性定长记录"（更细）
    时，会选中更粗的长度前缀。这种情况由调用方通过**并列自洽分帧**的方式暴露给用户，
    而不是在这里做无依据的取舍。

    只有 ``self_verified`` 的检测参与裁决。

    :return: 胜出的检测，或 ``None``。
    """
    ok = [d for d in detections if d.self_verified and d.frames]
    if not ok:
        return None

    def key(d: Detection) -> Tuple:
        return (round(d.coverage(total), 3),
                KIND_PRIORITY.get(d.kind, 0),
                len(d.frames),
                d.score)

    return max(ok, key=key)
