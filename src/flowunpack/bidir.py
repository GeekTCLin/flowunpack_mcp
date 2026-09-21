"""双向流联合推断（P2-8）。

为什么需要它
------------
单条流是**信息不足**的：一条 8 帧的短流可能同时自洽于多种切法，于是只能靠
置换检验这类弱证据做取舍。但真实协议的两个方向是**语义耦合**的（NetPlier
把它叫做 remote coupling）：请求与响应出自同一份格式定义，一方的信息可以
用来解除另一方的歧义。

本模块提供三条**可验证**的耦合证据，按强度排序：

1. **结构可迁移**（最硬）—— 用 A 方向的帧结构去切 B 方向，若能完整走完且
   无剩余，说明两边共用同一套帧长公式。这不是"看起来像"，是**可证伪**的：
   换一条无关的流去切必然走不通。
2. **类型映射一致** —— 第 i 个请求的消息类型与第 i 个响应的消息类型之间
   存在稳定的双射（例如请求 ``cmd=0x01`` 总是换来响应 ``cmd=0x81``）。
   这是协议语义层面的呼应，与字节排列无关。
3. **长度相关** —— 请求帧长序列与响应帧长序列显著相关（响应长度往往是
   请求长度的函数）。

三条都不要求两边"长得一样"：很多协议的请求与响应包头长度不同、字段不同，
但只要共享帧长公式或存在类型映射，耦合就成立。反之，即使两边各自都被
检出，若三条证据全不成立，联合置信度会被下调 —— 这是"双向"能提供的
**反面**信息（两条流可能根本不是同一个协议）。

迁移的两种用途
--------------
``analyze_stream(hint=...)`` 只增不减：迁移失败就退回正常搜索。据此本模块
在两种情形下真的会**改写**某一侧的结论（``Coupling.repaired`` 记录）：

* **补全**：一侧没有可信的长度字段（完全未检出，或只被定长/分隔符这类
  弱模板解释），而另一侧的结构能把它完整切开 —— 采纳迁移结果。
* **裁决**：两侧都有长度字段但**公式不同**且**都自洽**（各自都能完整走完）。
  单看一侧无法分辨真假，但"共同结构"必须对两边都成立：若 A 的结构能解释
  B、而 B 的结构解释不了 A，则共同结构是 A 的。实测（见
  ``bench/diag_bidir.py`` 用例 7）这正是双向推断最有用的一处 —— 恒定帧长
  的一侧会被搜索短路的**自信伪解**锁定（5 帧，匹配 gap 0.74），只有跨方向
  的可证伪性才能把它纠正回真解（10 帧）。

唯一不裁的情况是两侧互相都能解释（都自洽且对称），此时信息不足以取舍，
记录为 ``conflicts`` 交由人工复核，不做无依据的改写。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .config import AnalysisConfig
from .engine import analyze_stream
from .models import AnalysisResult, LengthFieldSpec

__all__ = ["Coupling", "BidirectionalResult", "analyze_bidirectional"]


@dataclass
class Coupling:
    """两个方向之间的耦合证据。"""

    structure_transferable: bool = False      # 结构可迁移（最强证据）
    transfer_direction: Optional[str] = None  # "c2s->s2c" / "s2c->c2s" / "both"
    length_field_match: bool = False          # 长度字段的 offset/format/scale 一致
    length_correlation: Optional[float] = None
    type_mapping: Optional[Dict[str, str]] = None
    type_mapping_consistent: bool = False
    frame_count_ratio: float = 0.0            # min/max，1.0 表示帧数相同
    strength: float = 0.0                     # 综合耦合强度 0~1
    repaired: List[str] = field(default_factory=list)   # 被迁移改写的结论
    conflicts: List[str] = field(default_factory=list)  # 无法裁决的分歧
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "structure_transferable": self.structure_transferable,
            "transfer_direction": self.transfer_direction,
            "length_field_match": self.length_field_match,
            "length_correlation": self.length_correlation,
            "type_mapping": self.type_mapping,
            "type_mapping_consistent": self.type_mapping_consistent,
            "frame_count_ratio": round(self.frame_count_ratio, 4),
            "strength": round(self.strength, 4),
            "repaired": self.repaired,
            "conflicts": self.conflicts,
            "notes": self.notes,
        }


@dataclass
class BidirectionalResult:
    """双向分析的完整输出。"""

    c2s: AnalysisResult
    s2c: AnalysisResult
    coupling: Coupling
    joint_confidence: float = 0.0
    message: str = ""

    @property
    def detected(self) -> bool:
        return bool(self.c2s.detected or self.s2c.detected)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "c2s": self.c2s.to_dict(),
            "s2c": self.s2c.to_dict(),
            "coupling": self.coupling.to_dict(),
            "joint_confidence": round(self.joint_confidence, 4),
            "detected": self.detected,
            "message": self.message,
        }


# ---------------------------------------------------------------------------
# 耦合证据
# ---------------------------------------------------------------------------

def _pearson(xs: Sequence[float], ys: Sequence[float]) -> Optional[float]:
    """皮尔逊相关系数（零依赖实现）。"""
    n = min(len(xs), len(ys))
    if n < 3:
        return None
    xs, ys = list(xs[:n]), list(ys[:n])
    mx = sum(xs) / n
    my = sum(ys) / n
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    if sxx <= 0 or syy <= 0:
        return None
    return round(sxy / math.sqrt(sxx * syy), 4)


def _lengths(result: AnalysisResult) -> List[int]:
    return [f.length for f in result.frames if not f.truncated]


def _type_sequence(data: bytes, result: AnalysisResult) -> Optional[List[str]]:
    """每条帧的 keyword 取值序列；没有可靠 keyword 时返回 ``None``。"""
    mts = result.message_types or []
    if not mts or mts[0].keyword_offset is None:
        return None
    off = mts[0].keyword_offset
    ln = mts[0].keyword_length or 1
    out: List[str] = []
    for f in result.frames:
        if f.truncated:
            continue
        raw = data[f.offset:f.offset + f.length]
        if off + ln <= len(raw):
            out.append(raw[off:off + ln].hex())
    return out or None


def _type_mapping(a: Sequence[str], b: Sequence[str]
                  ) -> Tuple[Optional[Dict[str, str]], bool]:
    """按帧序配对，检查 A→B 是否为**稳定双射**。

    :return: ``(映射, 是否一致且非平凡)``。只检查了前缀 min(len) 对，
        因此一方帧数更多时证据会自动打折（见 :func:`analyze_bidirectional`）。
    """
    n = min(len(a), len(b))
    if n < 2:
        return None, False
    fwd: Dict[str, str] = {}
    ok = True
    for i in range(n):
        x, y = a[i], b[i]
        if fwd.setdefault(x, y) != y:
            ok = False
    rev: Dict[str, str] = {}
    for x, y in fwd.items():
        if rev.setdefault(y, x) != x:
            ok = False
    return fwd, bool(ok and len(fwd) >= 2)


def _spec_signature(spec: Optional[LengthFieldSpec]) -> Optional[Tuple]:
    """长度字段的"身份"：位置 / 编码 / 计数单位。

    **刻意不含 ``overhead``**：请求与响应的包头长度常常不同（响应多带状态码、
    时间戳），但长度字段本身的位置与编码是一致的。把它排除在外，"字段一致"
    这条证据才不会因为包头差异而误判。
    """
    if spec is None:
        return None
    return (spec.offset, spec.format, spec.scale, spec.variable_overhead)


def _has_spec(res: AnalysisResult) -> bool:
    """该方向是否给出了可信的长度字段结论（定长/分隔符模板不算）。"""
    return bool(res.detected and res.length_field is not None)


def _transfer(spec: Optional[LengthFieldSpec], data: bytes,
              cfg: AnalysisConfig) -> Optional[AnalysisResult]:
    """把 ``spec`` 迁移到 ``data`` 上；只有**真的靠迁移走通**才返回结果。

    判据是 ``accepted_by == "hint"``：说明这次分帧既完整又无剩余，且完全由
    迁移来的结构决定（不是退回常规搜索碰巧得到的）。
    """
    if spec is None:
        return None
    res = analyze_stream(data, cfg, hint=spec)
    if res.detected and (res.statistics.get("diagnostics") or {}).get(
            "accepted_by") == "hint":
        return res
    return None


def _describe(res: AnalysisResult) -> str:
    """一句话描述某方向当前的分帧结论（供 repaired / conflicts 文案使用）。"""
    if not res.detected:
        return "未检出"
    kind = res.framing.kind if res.framing else "?"
    if res.length_field is not None:
        return "%d 帧·%s" % (res.unit_count, res.length_field.formula())
    return "%d 帧·%s" % (res.unit_count, kind)


def _measure_coupling(c2s_data: bytes, s2c_data: bytes,
                      c2s: AnalysisResult, s2c: AnalysisResult,
                      cfg: AnalysisConfig, transferable: bool,
                      direction: Optional[str],
                      notes: List[str]) -> Coupling:
    out = Coupling(structure_transferable=transferable,
                   transfer_direction=direction, notes=notes)

    sig_a = _spec_signature(c2s.length_field)
    sig_b = _spec_signature(s2c.length_field)
    out.length_field_match = bool(sig_a and sig_b and sig_a == sig_b)
    if out.length_field_match:
        notes.append("两个方向的长度字段位置/编码/计数单位完全一致")

    la, lb = _lengths(c2s), _lengths(s2c)
    if la and lb:
        out.length_correlation = _pearson(la, lb)
        n = min(len(la), len(lb))
        out.frame_count_ratio = round(n / max(len(la), len(lb)), 4)
        if out.length_correlation is not None \
                and abs(out.length_correlation) >= cfg.coupling_corr_threshold:
            notes.append("请求/响应帧长序列显著相关（r=%.2f）"
                         % out.length_correlation)

    ta = _type_sequence(c2s_data, c2s)
    tb = _type_sequence(s2c_data, s2c)
    if ta and tb:
        out.type_mapping, out.type_mapping_consistent = _type_mapping(ta, tb)
        if out.type_mapping_consistent:
            notes.append("请求类型与响应类型存在稳定双射（%d 组）"
                         % len(out.type_mapping or {}))
        elif out.type_mapping:
            notes.append("类型序列不满足双射，未采信")

    # ---- 综合强度 ----
    s = 0.0
    if transferable:
        s += 0.45
    if out.length_field_match:
        s += 0.20
    if out.type_mapping_consistent:
        s += 0.25
    if out.length_correlation is not None \
            and abs(out.length_correlation) >= cfg.coupling_corr_threshold:
        s += 0.10
    out.strength = round(min(1.0, s), 4)
    return out


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def analyze_bidirectional(c2s_data: bytes, s2c_data: bytes,
                          cfg: AnalysisConfig = None) -> BidirectionalResult:
    """联合分析一对方向相反的流。

    流程：各自独立分析 → **交叉迁移**（把一方的帧结构套到另一方）→ 汇总耦合
    证据 → 给出联合置信度。

    交叉迁移是双向推断唯一"能补上 / 纠正结论"的手段，分三种情形（另见模块
    文档字符串）：

    * **补全** —— 一侧没有可信长度字段，另一侧的结构能完整切开它 → 采纳迁移。
    * **裁决** —— 两侧公式不同且各自自洽，但只有一侧能解释另一侧 → 以能解释
      的一侧为准（共同结构必须对两边都成立）。
    * **互证** —— 两侧公式一致且互相都能解释 → 只是证据叠加，不改写结论。

    迁移失败**不会**破坏该方向原本的结论（``analyze_stream(hint=...)`` 保证只增
    不减）；被改写前的原结论会记入 ``coupling.repaired`` 与 ``warnings``。
    """
    from .config import DEFAULT_CONFIG
    cfg = cfg or DEFAULT_CONFIG

    a = analyze_stream(c2s_data, cfg)
    b = analyze_stream(s2c_data, cfg)

    notes: List[str] = []
    repaired: List[str] = []
    conflicts: List[str] = []
    transfers: List[str] = []
    side_before: Dict[str, str] = {}

    def _remember(side: str, res: AnalysisResult) -> None:
        side_before[side] = _describe(res)

    # ---- 情形 1：补全（一侧缺可信长度字段）----
    if _has_spec(a) and not _has_spec(b):
        r = _transfer(a.length_field, s2c_data, cfg)
        if r is not None:
            _remember("s2c", b)
            b = r
            transfers.append("c2s->s2c")
            repaired.append("s2c：%s → %s（迁移自 c2s）"
                            % (side_before["s2c"], _describe(b)))
            notes.append("s2c 缺少可信长度字段，已采用 c2s 的帧结构迁移分帧")
    if _has_spec(b) and not _has_spec(a):
        r = _transfer(b.length_field, c2s_data, cfg)
        if r is not None:
            _remember("c2s", a)
            a = r
            transfers.append("s2c->c2s")
            repaired.append("c2s：%s → %s（迁移自 s2c）"
                            % (side_before["c2s"], _describe(a)))
            notes.append("c2s 缺少可信长度字段，已采用 s2c 的帧结构迁移分帧")

    # ---- 情形 2/3：两侧都有长度字段 ----
    if _has_spec(a) and _has_spec(b):
        sig_a = _spec_signature(a.length_field)
        sig_b = _spec_signature(b.length_field)
        ta = _transfer(a.length_field, s2c_data, cfg)
        tb = _transfer(b.length_field, c2s_data, cfg)
        if sig_a == sig_b:
            # 长度字段身份相同 —— 互证。互相能迁移则视为最强证据。
            #
            # 注意：这里**不要求** overhead 相同。请求与响应的包头长度不同
            # （响应多带状态码 / 时间戳）是常态，此时迁移必然走不通，
            # 但只要长度字段的位置与编码一致，耦合证据依然成立（强度 0.20）。
            # 把 overhead 差异当成"冲突"会无端下调这类正常协议的置信度。
            if ta is not None:
                transfers.append("c2s->s2c")
            if tb is not None:
                transfers.append("s2c->c2s")
            if transfers:
                notes.append("两侧长度字段的位置/编码一致，且可互相迁移（互证）")
        else:
            # 长度字段身份都不同，却各自自洽 —— 必有一侧是伪解。
            # 用"谁能解释谁"裁决：共同结构必须对两边都成立。
            if ta is not None and tb is None:
                _remember("s2c", b)
                b = ta
                transfers.append("c2s->s2c")
                repaired.append("s2c：%s → %s（c2s 的结构可解释 s2c，反向不成立）"
                                % (side_before["s2c"], _describe(b)))
                notes.append("两侧结论冲突，已按可迁移方向裁定为 c2s 的结构")
            elif tb is not None and ta is None:
                _remember("c2s", a)
                a = tb
                transfers.append("s2c->c2s")
                repaired.append("c2s：%s → %s（s2c 的结构可解释 c2s，反向不成立）"
                                % (side_before["c2s"], _describe(a)))
                notes.append("两侧结论冲突，已按可迁移方向裁定为 s2c 的结构")
            elif ta is not None and tb is not None:
                conflicts.append(
                    "两侧长度字段身份不同但互相都能解释对方（c2s: %s ／ s2c: %s），"
                    "信息不足以取舍，保留各自结论"
                    % (_describe(a), _describe(b)))
                transfers.extend(["c2s->s2c", "s2c->c2s"])
            else:
                conflicts.append(
                    "两侧长度字段身份不同且互不解释（c2s: %s ／ s2c: %s）"
                    % (_describe(a), _describe(b)))

    if transfers:
        transferable = True
        uniq = list(dict.fromkeys(transfers))
        direction = "both" if len(uniq) == 2 else uniq[0]
        if not notes:
            notes.append("帧结构可在两个方向间迁移（%s）" % "+".join(uniq))
    else:
        transferable = False
        direction = None

    coupling = _measure_coupling(c2s_data, s2c_data, a, b, cfg,
                                 transferable, direction, notes)
    coupling.repaired = repaired
    coupling.conflicts = conflicts

    # ---- 联合置信度 ----
    # 双向提供的可能是**反面**证据：两个方向各自成立却互不呼应时，下调置信度。
    best = max(a.confidence if a.detected else 0.0,
               b.confidence if b.detected else 0.0)
    joint = min(1.0, best * (0.85 + 0.25 * coupling.strength))
    if conflicts:
        # 存在无法裁决的分歧 —— 结论不可靠，额外打折。
        joint = round(joint * 0.9, 4)

    if a.detected and b.detected:
        msg = ("双向均已分帧：c2s %d 帧 / s2c %d 帧"
               % (a.unit_count, b.unit_count))
    elif a.detected or b.detected:
        msg = ("仅一个方向独立成立：c2s %s / s2c %s"
               % ("%d 帧" % a.unit_count if a.detected else "未检出",
                  "%d 帧" % b.unit_count if b.detected else "未检出"))
    else:
        msg = "两个方向均未检出可靠结构"
    if repaired:
        msg += "，已按跨方向迁移修正 %d 处" % len(repaired)
    msg += "，耦合强度 %.2f" % coupling.strength
    if not coupling.notes:
        msg += "（三条耦合证据均不成立：两条流可能不属于同一协议）"

    return BidirectionalResult(c2s=a, s2c=b, coupling=coupling,
                               joint_confidence=round(joint, 4), message=msg)
