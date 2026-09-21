"""字段级语义推断（P1）：字段边界、语义类型标注、消息类型聚类。

前置条件
--------
本模块的输入不是连续流，而是**分帧后的一组同类消息** —— 这正是
NEMESYS / NetPlier / FLINT 的设定。所以调用顺序固定为：
``segmentation`` 切帧 → ``fields`` 标注字段。

三件事
------

**1. 字段边界（:func:`field_boundaries`）**
NEMESYS 的判据：相邻列的 **bit-congruence**（按位相似度）跨消息取均值，
再取相邻差分 ∆BC，高斯平滑后的**局部极大**即为字段边界。
但它有一个实测退化：**短流上 ∆BC 几乎平坦**（样本少 → 列熵本来就低 →
相邻列都"很像"），此时一个边界都提不出来。所以叠加第二判据
**列熵突变**（相邻列熵差超过阈值），两者取并集。

**2. 语义类型标注（:func:`classify_field`）**
每个字段按"最具体到最泛"依次尝试，且**判据必须对所有样本成立**
（例如"校验和"要求每条消息都验得上）。这是本模块防止误标的主要手段：
单个样本上看什么都像，全样本一致才可能是真的。

可标注的类型见 :data:`flowunpack.models.FIELD_LABELS`：
``magic / constant / enum / length / checksum / text / ipv4 / timestamp /
float / counter / random / integer / binary``。

**3. 消息类型聚类（:func:`infer_message_types`）**
在包头区找 **keyword** 字段（取值会重复、种类少、且与帧长/结构耦合），
按取值把消息分簇，每簇给出自己的长度分布与字段模板。
NetPlier 用因子图求后验概率；这里用可解释的**纯度评分** —— 因为它不引入
需要标定的超参数，且"为什么选这个字段"可以写进 evidence 给人看。
"""

from __future__ import annotations

import math
import struct
import zlib
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .config import AnalysisConfig
from .models import FieldSpec, LengthFieldSpec, MessageType

__all__ = [
    "ColumnStat",
    "column_stats",
    "bit_congruence",
    "field_boundaries",
    "classify_field",
    "infer_fields",
    "refine_by_type",
    "detect_trailer_checksum",
    "split_header_payload",
    "infer_message_types",
]

#: 视为"结构字段"（而非载荷）的语义类型
_STRUCTURAL = frozenset({
    "magic", "constant", "enum", "length", "checksum",
    "counter", "integer", "timestamp", "float", "ipv4",
})

_POPCOUNT = bytes(bin(i).count("1") for i in range(256))


@dataclass
class ColumnStat:
    """某一列（跨所有消息的同一偏移）的取值统计。"""

    offset: int
    entropy: float        # bits
    variety: int
    samples: int

    def to_dict(self) -> Dict:
        return {"offset": self.offset, "entropy": round(self.entropy, 3),
                "variety": self.variety, "samples": self.samples}


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------

def _entropy(counts: Counter, total: int) -> float:
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts.values():
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def _sample_units(units: Sequence[bytes], cfg: AnalysisConfig) -> List[bytes]:
    """把样本数压到上限（等距抽样，保序）。"""
    units = [u for u in units if u]
    if len(units) <= cfg.field_max_units:
        return units
    m = cfg.field_max_units
    step = len(units) / m
    return [units[int(i * step)] for i in range(m)]


def column_stats(units: Sequence[bytes], width: int) -> List[ColumnStat]:
    """逐列统计熵与取值种类数。"""
    out: List[ColumnStat] = []
    for i in range(width):
        counts: Counter = Counter()
        for u in units:
            if len(u) > i:
                counts[u[i]] += 1
        out.append(ColumnStat(offset=i, entropy=_entropy(counts, sum(counts.values())),
                             variety=len(counts), samples=sum(counts.values())))
    return out


def bit_congruence(units: Sequence[bytes], width: int) -> List[float]:
    """相邻列的 bit-congruence（NEMESYS 的 BC），返回长度 ``width-1``。

    ``BC[i]`` = 所有消息在"第 i 列与第 i+1 列按位相同比例"上的均值。
    同一字段内部两列的取值规律相近，跨字段则突变 → ∆BC 的局部极大即边界。
    """
    out: List[float] = []
    for i in range(width - 1):
        total = 0.0
        n = 0
        for u in units:
            if len(u) > i + 1:
                total += (8 - _POPCOUNT[u[i] ^ u[i + 1]]) / 8.0
                n += 1
        out.append(total / n if n else 0.0)
    return out


def _gauss_smooth(seq: Sequence[float], sigma: float) -> List[float]:
    if sigma <= 0 or len(seq) < 3:
        return list(seq)
    radius = max(1, int(3 * sigma))
    kernel = [math.exp(-(i * i) / (2 * sigma * sigma))
              for i in range(-radius, radius + 1)]
    ksum = sum(kernel)
    n = len(seq)
    out: List[float] = []
    for i in range(n):
        acc = 0.0
        wsum = 0.0
        for j, k in enumerate(kernel):
            idx = i + j - radius
            if 0 <= idx < n:
                acc += seq[idx] * k
                wsum += k
        out.append(acc / wsum if wsum else seq[i])
    return out


def _local_maxima(seq: Sequence[float]) -> List[int]:
    """严格大于左右邻居的位置（端点按单侧比较）。"""
    n = len(seq)
    out: List[int] = []
    for i in range(n):
        left = seq[i - 1] if i > 0 else -1.0
        right = seq[i + 1] if i < n - 1 else -1.0
        if seq[i] > left and seq[i] >= right:
            out.append(i)
    return out


# ---------------------------------------------------------------------------
# 字段边界
# ---------------------------------------------------------------------------

def field_boundaries(units: Sequence[bytes], width: int, cfg: AnalysisConfig,
                     forced_spans: Sequence[Tuple[int, int]] = ()) -> List[int]:
    """推断字段起始位置（含 0，不含 ``width``）。

    两条判据取并集：

    * ∆BC 局部极大且分数超过 ``max(floor, mean + k·std)``；
    * 相邻列熵差 ≥ ``field_entropy_jump``。

    :param forced_spans: **已知字段区间** ``(lo, hi)``。其端点会作为边界加入，
        且落在区间**内部**的候选边界会被丢弃 —— 否则"长度字段高位恒为 0"
        会制造一个熵突变，把 2 字节长度字段切成"常量 + 长度"两段。
    """
    if width <= 1:
        return [0]

    scores: Dict[int, float] = {}

    # 判据 1：∆BC（NEMESYS）
    bc = bit_congruence(units, width)
    if len(bc) >= 3:
        dbc = [abs(bc[i] - bc[i - 1]) for i in range(1, len(bc))]
        sm = _gauss_smooth(dbc, cfg.field_sigma)
        if sm:
            mean = sum(sm) / len(sm)
            var = sum((x - mean) ** 2 for x in sm) / len(sm)
            std = math.sqrt(var)
            thresh = max(cfg.field_dbc_floor, mean + cfg.field_dbc_k * std)
            for i in _local_maxima(sm):
                if sm[i] >= thresh:
                    # dbc 的下标 i 对应原列下标 i+1 —— 边界落在第 i+1 列之前
                    scores[i + 1] = max(scores.get(i + 1, 0.0), sm[i])

    # 判据 2：列熵突变
    stats = column_stats(units, width)
    for i in range(1, width):
        jump = abs(stats[i].entropy - stats[i - 1].entropy)
        if jump >= cfg.field_entropy_jump:
            scores[i] = max(scores.get(i, 0.0), jump / 8.0)

    forced_pts = {p for lo, hi in forced_spans for p in (lo, hi)}
    for p in forced_pts:
        if 0 < p < width:
            scores.setdefault(p, 0.0)

    def inside_forced(p: int) -> bool:
        return any(lo < p < hi for lo, hi in forced_spans)

    ranked = sorted(((p, s) for p, s in scores.items()
                     if not inside_forced(p)),
                    key=lambda kv: (-kv[1], kv[0]))
    keep = [p for p, _ in ranked]
    if len(keep) > cfg.field_max_fields - 1:
        keep = sorted(keep[:cfg.field_max_fields - 1])
    return sorted({0} | set(keep))


# ---------------------------------------------------------------------------
# 语义类型标注
# ---------------------------------------------------------------------------

def _slices(units: Sequence[bytes], start: int, end: int) -> List[bytes]:
    return [u[start:end] for u in units if len(u) >= end]


def _printable_ratio(bs: bytes) -> float:
    if not bs:
        return 0.0
    good = sum(1 for b in bs if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(bs)


def _int_variants(bs: bytes) -> List[Tuple[str, int]]:
    """把定长字节按常见宽度/端序解释成整数（宽度不符时返回空）。"""
    w = len(bs)
    if w == 1:
        return [("u8", bs[0])]
    if w == 2:
        return [("u16_be", int.from_bytes(bs, "big")),
                ("u16_le", int.from_bytes(bs, "little"))]
    if w == 4:
        return [("u32_be", int.from_bytes(bs, "big")),
                ("u32_le", int.from_bytes(bs, "little"))]
    if w == 8:
        return [("u64_be", int.from_bytes(bs, "big")),
                ("u64_le", int.from_bytes(bs, "little"))]
    return []


def _length_relation(units: Sequence[bytes], start: int, end: int
                     ) -> Optional[Tuple[int, int, str]]:
    """检验"该字段值与帧长线性相关"。

    :return: ``(scale, overhead, 端序)`` —— ``frame_len == scale*value + overhead``
        对全部样本成立；否则 ``None``。

    两条必要的护栏（缺了会在 DP 里选出荒谬解）：

    * 字段宽度只认 1/2/4/8 字节 —— 否则``任意宽度都能凑出一条线性关系``
      （实测：6 字节的"魔数+长度"整段被当成"长度字段"，overhead = −8.8e13）。
    * ``overhead`` 必须落在 ``[0, 最短帧长]`` —— 负值或超过帧长都不是帧长公式。
    """
    w = end - start
    if w not in (1, 2, 4, 8):
        return None
    pair = _slices(units, start, end)
    if len(pair) < 2:
        return None
    min_len = min(len(u) for u in units if len(u) >= end) if units else 0
    for name, base in (("be", "big"), ("le", "little")):
        for scale in (1, 2, 4, 8):
            const: Optional[int] = None
            ok = True
            for u, sl in zip(units, pair):
                if len(u) < end:
                    ok = False
                    break
                v = int.from_bytes(sl, base)
                c = len(u) - scale * v
                if const is None:
                    const = c
                elif c != const:
                    ok = False
                    break
            if ok and const is not None and 0 <= const <= min_len:
                return scale, const, name
    return None


def _checksum_match(units: Sequence[bytes], start: int, end: int
                    ) -> Optional[Tuple[str, str, float]]:
    """尝试把该字段验证为前面字节的校验和。

    必须**每条消息都验得上**，且参与校验的数据至少有 2 种不同取值
    （否则一个常量字段配上空前缀会假阳性）。

    :return: ``(算法, 端序, 置信度)``
    """
    w = end - start
    if w not in (1, 2, 4) or start < 1:
        return None
    sources = {
        "prefix": [(u[:start]) for u in units],
        "excluding_field": [(u[:start] + u[end:]) for u in units],
    }
    for src_name, datas in sources.items():
        if len(set(datas)) < 2 or any(len(u) < end for u in units):
            continue
        for endian in ("big", "little"):
            targets = [int.from_bytes(u[start:end], endian) for u in units]
            for algo, fn, conf in (
                ("crc32", lambda d: zlib.crc32(d), 0.95),
                ("crc32_raw", lambda d: zlib.crc32(d) ^ 0xFFFFFFFF, 0.90),
                ("sum", lambda d: sum(d) & ((1 << (8 * w)) - 1), 0.70),
                ("xor", lambda d: _xor_reduce(d), 0.65),
            ):
                if algo.startswith("crc32") and w != 4:
                    continue
                if algo in ("sum", "xor") and w not in (1, 2, 4):
                    continue
                if all(fn(d) == t for d, t in zip(datas, targets)):
                    return "%s(%s)" % (algo, src_name), endian, conf
    return None


def _xor_reduce(data: bytes) -> int:
    r = 0
    for b in data:
        r ^= b
    return r


def _is_counter(values: Sequence[int]) -> bool:
    """是否构成（允许回绕的）递增序列。"""
    if len(values) < 3 or len(set(values)) != len(values):
        return False
    mod = 1 << (8 * 8)
    diffs = [(values[i + 1] - values[i]) % mod for i in range(len(values) - 1)]
    return max(diffs) < mod // 2 and len(set(diffs)) <= max(1, len(diffs) // 2)


def _is_float(slices: Sequence[bytes]) -> bool:
    """是否能被解释为"合理量级"的 IEEE 754 浮点（对全部样本成立）。"""
    w = len(slices[0])
    fmts = (">f", "<f") if w == 4 else ((">d", "<d") if w == 8 else ())
    if not fmts:
        return False
    for fmt in fmts:
        ok = True
        for sl in slices:
            try:
                x = struct.unpack(fmt, sl)[0]
            except struct.error:
                ok = False
                break
            if not math.isfinite(x) or x == 0.0:
                ok = False
                break
            if not (1e-6 <= abs(x) <= 1e9):
                ok = False
                break
        if ok:
            return True
    return False


def _in_ts_range(v: int, cfg: AnalysisConfig) -> bool:
    return cfg.timestamp_min <= v <= cfg.timestamp_max


def _is_ipv4(slices: Sequence[bytes], cfg: AnalysisConfig) -> bool:
    """是否像 IPv4 地址（排除"更像时间戳"的情形以降低歧义）。"""
    for sl in slices:
        if len(sl) != 4 or sl[0] == 0 or sl[0] > 223:
            return False
        if len(set(sl)) == 1:
            return False
        if _in_ts_range(int.from_bytes(sl, "big"), cfg):
            return False
    return True


def classify_field(units: Sequence[bytes], start: int, end: int,
                   cfg: AnalysisConfig, stats: Sequence[ColumnStat],
                   length_field: Optional[LengthFieldSpec] = None
                   ) -> FieldSpec:
    """给 ``[start, end)`` 这段标注语义类型。"""
    width = end - start
    slices = _slices(units, start, end)
    cardinality = len(set(slices))
    n = len(slices)
    col_ent = [stats[i].entropy for i in range(start, min(end, len(stats)))]
    mean_ent = (sum(col_ent) / len(col_ent)) if col_ent else 0.0
    samples = [sl.hex() for sl in list(dict.fromkeys(slices))[:4]]

    def make(kind: str, conf: float, **ev) -> FieldSpec:
        return FieldSpec(offset=start, length=width, kind=kind,
                         confidence=round(conf, 3), cardinality=cardinality,
                         entropy=round(mean_ent, 3), samples=samples,
                         evidence=ev)

    if n == 0:
        return make("binary", 0.0, note="样本不足")

    # 1) 长度字段：要么来自已定案的 LengthFieldSpec，要么与帧长精确线性相关
    if length_field is not None and start == length_field.offset \
            and width == (length_field.width or width):
        return make("length", 1.0, source="LengthFieldSpec",
                    formula=length_field.formula())
    rel = _length_relation(units, start, end)
    if rel is not None:
        scale, overhead, endian = rel
        return make("length", 0.8, scale=scale, overhead=overhead,
                    endian=endian,
                    formula="frame_len = %d*value + %d" % (scale, overhead),
                    note="与帧长精确线性相关（未定案，可能是计数器等与长度同变的字段）")

    # 2) 校验和：必须每条消息都验得上
    cks = _checksum_match(units, start, end)
    if cks is not None:
        algo, endian, conf = cks
        return make("checksum", conf, algorithm=algo, endian=endian,
                    note="对全部 %d 条消息均验证通过" % n)

    # 3) 常量 / 魔数
    if cardinality == 1:
        raw = slices[0]
        printable = _printable_ratio(raw) >= cfg.text_printable_ratio
        if start == 0 and printable and width >= 2:
            return make("magic", 1.0, ascii=raw.decode("latin1"),
                        value_hex=raw.hex())
        return make("constant", 1.0, value_hex=raw.hex(),
                    printable=printable)

    # 4) 文本
    ratios = [_printable_ratio(sl) for sl in slices]
    if min(ratios) >= cfg.text_printable_ratio:
        multibyte = any(b >= 0x80 for sl in slices for b in sl)
        return make("text", 0.85,
                    encoding=("utf8" if multibyte else "ascii"),
                    printable_ratio=round(sum(ratios) / len(ratios), 3))

    ints_be = [int.from_bytes(sl, "big") for sl in slices]

    # 5) IPv4 / 时间戳 / 浮点 —— 都排在"计数器"之前：
    #    单调递增的时间戳既能解释成计数器也能解释成时间戳，
    #    前者信息量更低（specificity 5 < 6），取信息量大的那个。
    if width == 4 and _is_ipv4(slices, cfg):
        return make("ipv4", 0.5,
                    note="首字节 1..223 且非时间戳区间（与整数/时间戳存在歧义）")
    if width == 4 and all(_in_ts_range(v, cfg) for v in ints_be):
        return make("timestamp", 0.6, unit="s", endian="big")
    if width == 8 and all(cfg.timestamp_min <= v // 1000 <= cfg.timestamp_max
                          for v in ints_be):
        return make("timestamp", 0.55, unit="ms", endian="big")
    if width in (4, 8) and _is_float(slices):
        return make("float", 0.5, ieee754="f32" if width == 4 else "f64",
                    note="与整数解释存在歧义，按浮点更合理时采信")

    # 6) 计数器：全不重复 + 递增
    if width in (1, 2, 4, 8) and _is_counter(ints_be):
        return make("counter", 0.7, endian="big", step_hint="递增序列")

    # 7) 随机数 / 会话 ID：全不重复 + 高列熵
    #
    # 阈值必须**随样本量自适应**：n 个样本的单列熵上限是 log2(min(n,256))，
    # 用固定的 6.5 bits 会让"12 条消息的随机载荷"（熵上限仅 3.58）永远判不出来。
    cap = 0.9 * math.log2(n) if n > 1 else 8.0
    if (n >= 8 and cardinality == n
            and mean_ent >= min(cfg.random_entropy, cap)):
        return make("random", 0.6,
                    note="逐列熵 %.2f bits ≥ 自适应阈值 %.2f，取值互不重复"
                         % (mean_ent, min(cfg.random_entropy, cap)))

    # 8) 枚举 / 命令字：取值会重复且种类不多
    if 2 <= cardinality <= cfg.enum_max_cardinality and cardinality < n:
        return make("enum", 0.6,
                    values=[sl.hex() for sl in sorted(set(slices))[:8]])

    # 9) 整数
    if width in (1, 2, 4, 8):
        return make("integer", 0.4, endian="big",
                    min=min(ints_be), max=max(ints_be))

    return make("binary", 0.2, note="列熵 %.2f bits，未能归入已知语义" % mean_ent)


#: 语义类型的"具体程度"。类型驱动的合并（:func:`refine_by_type`）只在合并后
#: 得到**更具体**的类型时才发生，因此"魔数+命令字"不会被并成一个枚举。
_SPECIFICITY: Dict[str, int] = {
    "length": 10, "checksum": 9, "magic": 8, "text": 7,
    "ipv4": 6, "timestamp": 6, "float": 6,
    "enum": 5, "counter": 5, "constant": 4,
    "random": 3, "integer": 2, "binary": 1,
}


def refine_by_type(units: Sequence[bytes], fields: List[FieldSpec],
                   cfg: AnalysisConfig, stats: Sequence[ColumnStat],
                   length_field: Optional[LengthFieldSpec] = None
                   ) -> List[FieldSpec]:
    """在候选边界集合上做**全局最优**分割（取代贪心合并）。

    目标函数（越大越好）：

    ``Σ (类型具体程度 + 置信度) × 字段长度  −  字段数 × penalty``

    * **乘以字段长度** —— 这是关键。它让"用 IPv4 解释 4 字节"胜过"用
      「2 字节常量 + 2 字节整数」解释同样的 4 字节"（26 > 13.4），
      也就是 BinaryInferno 那条"最大化被描述的字节数"，只不过目标换成
      "被**有语义地**描述的字节数"。若按字段数计分，切得越碎总分越高，
      会永远选碎分割。
    * **减去字段数惩罚** —— 阻止无意义的细分。
    * **全局最优** —— 候选边界数 ≤ ``field_max_fields``，所以
      ``O(k²)`` 的动态规划代价可以忽略，没必要用贪心。

    一条硬性禁止：起点为 0、且第 0 列恒定的字段，不允许被并成
    ``enum`` / ``random`` / ``binary``。否则"2 字节魔数 + 1 字节命令字"
    会被一个"3 值的 enum"整体吞掉，把最强的特征（帧首魔数）弄丢。
    （已定案的长度字段区间不受此限 —— 它的高位字节本来就是常量 0。）
    """
    if len(fields) < 2:
        return fields

    pts = [f.offset for f in fields]
    pts.append(fields[-1].offset + fields[-1].length)
    m = len(pts)
    forced: Optional[Tuple[int, int]] = None
    if length_field is not None and length_field.width:
        forced = (length_field.offset,
                  length_field.offset + length_field.width)
    first_constant = bool(stats) and stats[0].variety == 1

    #: 起点为 0 的字段不允许被并成的类型（前提：第 0 列本身是常量）。
    #: 帧首的常量字节在协议里几乎总是魔数/版本号，被并进一个"取值字段"
    #: 就把这条最强特征弄丢了。只禁"较弱的取值类型"——IPv4 / 时间戳这类
    #: 结构化取值字段仍允许（真实协议里帧首就是一个地址/时间戳很常见）。
    _WEAK_KINDS = ("enum", "random", "binary", "integer")

    val: Dict[Tuple[int, int], float] = {}
    spec_at: Dict[Tuple[int, int], FieldSpec] = {}
    for i in range(m - 1):
        for j in range(i + 1, m):
            f = classify_field(units, pts[i], pts[j], cfg, stats, length_field)
            banned = (pts[i] == 0 and first_constant
                      and f.kind in _WEAK_KINDS
                      and (pts[i], pts[j]) != forced)
            # 已定案的长度字段必须独立成段：不允许任何跨过它的段。
            # 否则"魔数+命令字+长度"会被一个 4 字节的"IPv4"整体吞掉。
            if forced is not None and (pts[i] < forced[0] < pts[j]
                                       or pts[i] < forced[1] < pts[j]):
                banned = True
            score = ((_SPECIFICITY.get(f.kind, 0) + f.confidence)
                     * (pts[j] - pts[i]))
            val[(i, j)] = (-1e9 if banned else score)
            spec_at[(i, j)] = f

    best: List[Optional[Tuple[float, int]]] = [None] * m
    best[0] = (0.0, -1)
    for j in range(1, m):
        for i in range(j):
            if best[i] is None or val[(i, j)] <= -1e8:
                continue
            cand = best[i][0] + val[(i, j)] - cfg.field_segment_penalty
            if best[j] is None or cand > best[j][0]:
                best[j] = (cand, i)
    if best[m - 1] is None:                      # 理论上不会发生，兜底
        return fields

    path: List[int] = []
    j = m - 1
    while j > 0:
        i = best[j][1]
        path.append((i, j))
        j = i
    path.reverse()
    return [spec_at[(i, j)] for i, j in path]


def detect_trailer_checksum(units: Sequence[bytes], cfg: AnalysisConfig
                            ) -> Optional[FieldSpec]:
    """从**帧尾对齐**的角度找尾部校验和。

    为什么必须单独做一遍：字段边界是按帧首对齐的（第 i 列 = 各帧的第 i 字节），
    而 trailer 的位置**随帧长变化**，在帧首对齐的坐标系里根本不存在。
    实测：一个 ``[magic][cmd][len][body][crc32]`` 的协议，帧首对齐最多只能看到
    最短帧的前 17 列，CRC 完全在视野之外。

    约定：``offset`` 为**负数**表示"距帧尾"，例如 ``offset=-4`` 即最后 4 字节。

    :return: 校验和字段；没有则返回 ``None``。
    """
    n = len(units)
    if n < cfg.checksum_min_units:
        return None
    for w in (4, 2, 1):
        if any(len(u) <= w for u in units):
            continue
        datas = [u[:-w] for u in units]
        if len(set(datas)) < 2:
            continue
        for endian in ("big", "little"):
            targets = [int.from_bytes(u[-w:], endian) for u in units]
            for algo, fn, conf in (
                ("crc32", lambda d: zlib.crc32(d), 0.95),
                ("crc32_raw", lambda d: zlib.crc32(d) ^ 0xFFFFFFFF, 0.90),
                ("sum", lambda d: sum(d) & ((1 << (8 * w)) - 1), 0.70),
                ("xor", lambda d: _xor_reduce(d), 0.65),
            ):
                if algo.startswith("crc32") and w != 4:
                    continue
                if algo == "xor" and w != 1:
                    continue
                if all(fn(d) == t for d, t in zip(datas, targets)):
                    return FieldSpec(
                        offset=-w, length=w, kind="checksum", confidence=conf,
                        cardinality=len(set(targets)), entropy=0.0,
                        samples=[u[-w:].hex() for u in units[:3]],
                        evidence={
                            "algorithm": "%s(trailer)" % algo,
                            "endian": endian,
                            "from_end": True,
                            "note": "帧尾校验和（offset=-%d 表示距帧尾 %d 字节），"
                                    "覆盖本字段之前的全部字节" % (w, w),
                        })
    return None


# ---------------------------------------------------------------------------
# 主入口：字段推断 + head/payload 分离
# ---------------------------------------------------------------------------

def infer_fields(units: Sequence[bytes], cfg: AnalysisConfig,
                 length_field: Optional[LengthFieldSpec] = None
                 ) -> Tuple[List[FieldSpec], List[ColumnStat]]:
    """在一组同类消息上推断字段边界并标注语义类型。

    :return: ``(字段列表, 逐列统计)``；样本不足时两者都为空。
    """
    sampled = _sample_units(units, cfg)
    if len(sampled) < cfg.field_min_units:
        return [], []
    width = min((len(u) for u in sampled), default=0)
    width = min(width, cfg.field_scan_bytes)
    if width <= 0:
        return [], []
    stats = column_stats(sampled, width)

    forced: List[Tuple[int, int]] = []
    if length_field is not None and length_field.offset < width:
        w = length_field.width
        if w and length_field.offset + w <= width:
            forced.append((length_field.offset, length_field.offset + w))

    bounds = field_boundaries(sampled, width, cfg, forced)
    fields = [classify_field(sampled, a, b, cfg, stats, length_field)
              for a, b in zip(bounds, list(bounds[1:]) + [width])]
    fields = refine_by_type(sampled, fields, cfg, stats, length_field)
    trailer = detect_trailer_checksum(sampled, cfg)
    if trailer is not None:
        fields.append(trailer)
    return fields, stats


def split_header_payload(stats: Sequence[ColumnStat],
                         fields: Sequence[FieldSpec],
                         cfg: AnalysisConfig) -> Tuple[int, Optional[int], int]:
    """用熵分离出包头 / 载荷 / 尾部（FLINT 的 head-payload 分离思路）。

    * **载荷起点** = 第一段连续 ``payload_run`` 列且每列熵 ≥ ``payload_entropy``
      的位置。找不到（整帧都是低熵结构）时返回 ``None``。
    * **包头长度** = 载荷起点；无载荷时退化为"从头开始最长的一段结构字段"。
    * **尾部长度** = 末尾连续的校验和字段总长（校验和是最常见的 trailer）。

    :return: ``(header_len, payload_offset, trailer_len)``
    """
    n = stats[0].samples if stats else 0
    # 与 random 判据同理：n 个样本的单列熵上限是 log2(min(n,256))，
    # 固定阈值在样本少时永远触发不了（实测 12 帧的随机载荷熵上限仅 3.58）。
    thresh = cfg.payload_entropy
    if n > 1:
        thresh = min(thresh, 0.9 * math.log2(min(n, 256)))
    payload_offset: Optional[int] = None
    run = 0
    for st in stats:
        if st.entropy >= thresh:
            run += 1
            if run >= cfg.payload_run:
                payload_offset = st.offset - cfg.payload_run + 1
                break
        else:
            run = 0

    trailer_len = 0
    for f in reversed(list(fields)):
        if f.kind == "checksum":
            trailer_len += f.length
        else:
            break

    if payload_offset is not None:
        header_len = payload_offset
    else:
        header_len = 0
    # 取两者较大值：熵判据会把"长度字段的低位字节"（恰好高熵）误当成载荷起点，
    # 而已定案的结构字段（长度字段等）一定在包头里，不能被丢到载荷区。
    for f in fields:
        if f.offset < 0:
            continue
        if f.kind in _STRUCTURAL:
            header_len = max(header_len, f.offset + f.length)
        else:
            break
    return header_len, payload_offset, trailer_len


# ---------------------------------------------------------------------------
# 消息类型聚类（keyword 识别）
# ---------------------------------------------------------------------------

def _group_purity(units: Sequence[bytes], groups: Dict[bytes, List[int]]
                  ) -> Tuple[float, float]:
    """``(长度纯度, 簇间长度可区分度)``。

    纯度：每簇内"等于该簇众数长度"的样本占比（按簇大小加权）。
    可区分度：众数长度在全局唯一的簇占比 —— keyword 若真决定结构，
    不同取值的消息长度分布应当不同。
    """
    modes: Dict[bytes, int] = {}
    for key, idxs in groups.items():
        lens = Counter(len(units[i]) for i in idxs)
        modes[key] = lens.most_common(1)[0][0]
    hits = 0
    total = 0
    for key, idxs in groups.items():
        for i in idxs:
            total += 1
            if len(units[i]) == modes[key]:
                hits += 1
    purity = hits / total if total else 0.0
    counts = Counter(modes.values())
    distinct = sum(1 for k in groups if counts[modes[k]] == 1) / len(groups)
    return purity, distinct


def infer_message_types(units: Sequence[bytes], fields: Sequence[FieldSpec],
                        cfg: AnalysisConfig, header_len: int
                        ) -> List[MessageType]:
    """按 keyword 字段把消息分簇。

    keyword 候选的硬性条件（缺一不可）：

    * 落在包头区（``offset < header_len`` 或帧首）；
    * 取值会重复且种类 ≥ 2（常量字段没法分簇；全不重复的是随机数/计数器）；
    * 分出的簇数在 ``[2, cluster_max_types]``，且每簇至少 ``cluster_min_group`` 条。

    满足硬性条件后按 ``0.7·长度纯度 + 0.3·簇间可区分度`` 排序取最优。
    找不到可靠 keyword 时返回单一类型（覆盖全部消息）。
    """
    units = [u for u in units if u]
    if not units:
        return []

    def single(note: str) -> List[MessageType]:
        lengths = [len(u) for u in units]
        return [MessageType(index=0, count=len(units), lengths=lengths,
                            unique_lengths=sorted(set(lengths)),
                            header_len=header_len, fields=list(fields),
                            sample_index=0, evidence={"note": note})]

    if len(units) < cfg.cluster_min_units:
        return single("样本数 %d < cluster_min_units=%d，未做分簇"
                      % (len(units), cfg.cluster_min_units))

    limit = max(header_len, 1)
    best: Optional[Tuple[float, FieldSpec, Dict[bytes, List[int]]]] = None
    for f in fields:
        if f.offset >= limit:
            continue
        if f.kind not in ("enum", "integer", "constant"):
            continue
        if not (2 <= f.cardinality <= cfg.enum_max_cardinality):
            continue
        groups: Dict[bytes, List[int]] = {}
        for i, u in enumerate(units):
            if len(u) < f.offset + f.length:
                groups.clear()
                break
            groups.setdefault(u[f.offset:f.offset + f.length], []).append(i)
        if not groups or not (2 <= len(groups) <= cfg.cluster_max_types):
            continue
        if any(len(g) < cfg.cluster_min_group for g in groups.values()):
            continue
        purity, distinct = _group_purity(units, groups)
        score = 0.7 * purity + 0.3 * distinct
        # 同分时取更靠前的字段（keyword 通常在包头最前面）
        key = (round(score, 4), -f.offset)
        if best is None or key > (round(best[0], 4), -best[1].offset):
            best = (score, f, groups)

    if best is None:
        return single("未找到可靠 keyword 字段（包头区无可分簇的枚举字段）")

    score, kf, groups = best
    out: List[MessageType] = []
    for idx, (val, idxs) in enumerate(
            sorted(groups.items(), key=lambda kv: -len(kv[1]))):
        sub = [units[i] for i in idxs]
        lengths = [len(u) for u in sub]
        sub_fields: List[FieldSpec] = []
        if len(sub) >= cfg.field_min_units:
            sub_fields, _ = infer_fields(sub, cfg)
        out.append(MessageType(
            index=idx, count=len(idxs),
            keyword_offset=kf.offset, keyword_length=kf.length,
            keyword_values=[val.hex()],
            lengths=lengths, unique_lengths=sorted(set(lengths)),
            header_len=header_len, fields=sub_fields,
            sample_index=idxs[0],
            evidence={
                "keyword_kind": kf.kind,
                "length_purity": round(_group_purity(units, groups)[0], 3),
                "score": round(score, 4),
                "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in val),
            }))
    return out
