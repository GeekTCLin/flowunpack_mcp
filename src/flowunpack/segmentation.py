"""流级自动分帧：给定一条连续流字节，找出能把它完整切开的帧结构。

Wireshark MCP 提取到的通常是一条**重组后的完整流**（``tcp.stream`` 的 payload 拼接），
而不是逐包 payload。此时包边界未知，必须靠「假设 + 走查（walk）」来验证：

    frame_len = scale * value + overhead + (width  if 变长编码  else 0)

``scale`` 是长度字段的计数单位：``scale=1`` 以字节计（绝大多数协议），
``scale=4`` 以 4 字节字计（IPv4 的 IHL、部分工控与音视频协议）。

为什么"走完且无剩余"还不够
--------------------------
实测：对 512~4096 字节的随机流，枚举全部假设后能找到数十个"恰好走完"的方案，
帧数甚至可达 64。因此本模块额外引入两条判据：

1. **假设一致性（agreement）** —— 真实协议会被一族假设同时命中
   （例如 ``uint32_le@0`` 与 ``uint8@0`` 在 body < 256 时给出**完全相同**的帧边界），
   而随机巧合各自为政、边界互不重合。按边界签名分组，组内假设数即为一致性证据。
2. **紧致拟合（tight fit）** —— 同一族假设中优先取 ``offset + width == 帧前缀长度``
   的那一个，即长度字段紧贴包体。这能把 ``uint8`` 误判纠正为真正的 ``uint32_le``。
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from .codecs import FORMATS, decode_at, min_width
from .config import AnalysisConfig
from .models import Candidate, Frame, LengthFieldSpec

__all__ = ["WalkResult", "walk", "segment_stream", "apply_spec"]


_log2 = math.log2


class WalkResult:
    """一次走查的结果。"""

    __slots__ = ("offset", "format", "overhead", "count_width", "scale", "start",
                 "frames", "values", "leftover", "truncated", "complete",
                 "probe_limited")

    def __init__(self, offset: int, fmt: str, overhead: int, count_width: bool,
                 start: int, frames: List[Tuple[int, int]], values: List[int],
                 leftover: int, truncated: bool, complete: bool,
                 probe_limited: bool = False, scale: int = 1):
        self.offset = offset
        self.format = fmt
        self.overhead = overhead          # 长度字段自身之外的固定前缀字节数
        self.count_width = count_width    # True: frame_len 还要加上长度字段实际宽度
        self.scale = scale                # frame_len = scale*value + overhead
        self.start = start
        self.frames = frames              # [(pos, frame_len), ...]
        self.values = values
        self.leftover = leftover
        self.truncated = truncated
        self.complete = complete          # 走完且无剩余
        # 探测模式下"连续走满上限且未出错" —— 不是失败，只是提前收工
        self.probe_limited = probe_limited

    @property
    def signature(self) -> Tuple[Tuple[int, int], ...]:
        """帧边界签名：两个假设给出相同签名 == 描述同一套分帧。"""
        return tuple(self.frames)

    def prefix_len(self, width: int) -> int:
        """长度字段结束位置（= 固定前缀长度，对变长编码按实际宽度算）。"""
        return self.overhead + (width if self.count_width else 0)

    def to_spec(self) -> LengthFieldSpec:
        fmt = FORMATS[self.format]
        w = fmt.width or min_width(self.format)
        prefix = self.prefix_len(w)
        if self.overhead == 0 and not self.count_width:
            semantics = "total_length"
        elif prefix >= self.offset + w:
            semantics = "body_length"
        else:
            semantics = "unknown"
        return LengthFieldSpec(
            offset=self.offset,
            format=self.format,
            width=fmt.width,
            overhead=self.overhead,
            semantics=semantics,
            header_len=prefix,
            body_offset=prefix,
            endian=fmt.endian,
            variable_overhead=self.count_width,
            scale=self.scale,
        )


def walk(data: bytes, offset: int, fmt: str, overhead: int, cfg: AnalysisConfig,
         start: int = 0, probe: Optional[int] = None,
         count_width: bool = False, scale: int = 1,
         probe_bytes: Optional[int] = None) -> WalkResult:
    """按给定假设从 ``start`` 开始切分流。

    :param count_width: 变长编码时，``frame_len = scale*value + width + overhead``。
    :param scale: 长度字段的计数单位（1=字节，4=4 字节字）。
    :param probe: 提前收工的帧数上限（筛查用），到达后标记 ``probe_limited``。
    :param probe_bytes: 提前收工的字节上限（筛查用）。帧很大时帧数上限形同虚设，
        改用字节预算才能把单个假设的代价压住。
    :return: :class:`WalkResult`，``complete=True`` 表示完整走完且无剩余字节。
    """
    frames: List[Tuple[int, int]] = []
    values: List[int] = []
    pos = start
    total = len(data)
    limit = probe or total
    byte_limit = probe_bytes or total
    truncated = False
    width_hint = min_width(fmt)

    while pos < total:
        if probe is not None and len(frames) >= limit:
            # 探测阶段走满上限且全程自洽 —— 标记为"可继续"，不是失败。
            # 早期实现在此处返回 complete=False，导致帧数 > max_probe_frames
            # 的真实协议被整轮误杀（实测 >96 帧即检测不出来）。
            return WalkResult(offset, fmt, overhead, count_width, start,
                              frames, values, total - pos, False, False,
                              probe_limited=True, scale=scale)
        if probe_bytes is not None and pos - start >= byte_limit:
            return WalkResult(offset, fmt, overhead, count_width, start,
                              frames, values, total - pos, False, False,
                              probe_limited=True, scale=scale)
        if total - pos < offset + width_hint:
            truncated = True
            break
        got = decode_at(data, pos + offset, fmt)
        if got is None:
            truncated = True
            break
        value, width = got
        extra = width if count_width else 0
        frame_len = scale * value + overhead + extra
        # 帧必须容纳**整个帧头**（``overhead + extra``，即长度字段之外的固定
        # 前缀 + 长度字段自身）再加至少 1 字节载荷；同时不能短于"长度字段
        # 结束位置"（``offset`` 可以大于 ``overhead``，此时帧头被拉长）。
        #
        # 为什么必须按整个帧头算：当 ``overhead > 0`` 且长度字段埋在帧头中间
        # （``offset + width < overhead``）时，旧判据 ``frame_len >= offset+width+1``
        # 允许 ``frame_len == overhead + extra`` 的病态帧 —— 它等价于
        # ``scale*value == 0``，即"长度字段声明了 0 字节载荷"，帧长恰好退化成
        # 帧头长度。真实协议不会这么设计，但**包头零填充**时极易撞上：零区
        # 里任意偏移读出的值都是 0，于是一条"帧长 = 帧头长"的假链能把整条流
        # 等分成异常多的段（实测 10 真帧 → 30 伪帧，见 README §11）。
        #
        # 新判据等价于 ``scale*value >= 1``：长度值不得为 0。
        if frame_len <= 0 or frame_len <= max(overhead + extra, offset + width):
            break
        if pos + frame_len > total:
            truncated = True
            break
        frames.append((pos, frame_len))
        values.append(value)
        pos += frame_len

    leftover = total - pos
    complete = bool(frames) and leftover == 0 and not truncated
    return WalkResult(offset, fmt, overhead, count_width, start, frames, values,
                      leftover, truncated, complete, scale=scale)


def _overhead_range(data: bytes, offset: int, fmt: str, cfg: AnalysisConfig,
                    start: int, count_width: bool,
                    scale: int = 1) -> Iterator[int]:
    """枚举结构自洽的 overhead 取值（解析式剪枝后再交给走查）。

    除"首帧必须放得下"外，追加一条**第 2 帧也必须放得下**的必要条件。由于
    ``overhead`` 同时进入前两帧的长度，这给出一个远比 ``max_overhead`` 紧的
    解析上界：首帧长 ``L0 = s*v0 + o + extra``，第 2 帧长
    ``L1 = s*v1 + o + extra >= o + extra``，故必须
    ``L0 + L1 <= total``，即 ``2*o <= total - s*v0 - 2*extra``。

    这是一条*必要条件*（第 2 帧放不下则必然无法完整分帧），因此只会剪掉
    不可能成功的假设，不会误杀可行解。

    实测：varint 流上 overhead 候选从 65 个降到十几个，搜索耗时 6.0s → 0.6s。
    """
    got = decode_at(data, start + offset, fmt)
    if got is None:
        return iter(())
    value, width = got
    min_prefix = offset + width                      # 至少容纳长度字段
    extra = width if count_width else 0
    scaled = scale * value
    total = len(data) - start
    if scaled + extra > total:                       # 光是长度值就已超出流长
        return iter(())
    lo = max(0, min_prefix + 1 - scaled - extra)
    hi = min(cfg.max_overhead, total - scaled - extra)
    hi = min(hi, (total - scaled - 2 * extra) // 2)  # 第 2 帧存在性
    if hi < lo:
        return iter(())
    return iter(range(lo, hi + 1))


def _tightness(res: WalkResult, width: int) -> Tuple[float, str]:
    """结构自洽度 + 语义：长度字段是否紧贴包体。

    * 紧致拟合：字段结束处即包体开始（``prefix == offset + width``），或
      字段描述整帧（``overhead == 0``）——两者都是真实协议的常见形态。
    * ``prefix > offset + width``：包头尾部还有其它字段，略降分。
    """
    prefix = res.prefix_len(width)
    if res.overhead == 0 and not res.count_width:
        return 1.00, "total_length"        # 长度字段把自身也计入
    if prefix == res.offset + width:
        return 1.00, "body_length"         # 紧致：字段结束即包体开始
    if prefix > res.offset + width:
        return 0.85, "body_length"         # 包头尾部还有其它字段
    return 0.25, "unknown"


def _truncated_field(data: bytes, res: WalkResult, width: int) -> bool:
    """是否"只读了宽字段的低位字节"。

    判据：字段结束位置到帧前缀之间还有字节，且这些字节在所有帧里恒为 0x00
    —— 典型的「把 uint32 当成 uint8 读」。
    """
    lo = res.offset + width
    hi = res.prefix_len(width)
    if hi <= lo or len(res.frames) < 2:
        return False
    for i in range(lo, hi):
        vals = {data[pos + i] for pos, _ in res.frames if pos + i < len(data)}
        if len(vals) == 1 and 0 in vals:
            return True
    return False


def _payload_alias(data: bytes, res: "WalkResult") -> float:
    """长度字段的取值分布是否只是"载荷字节分布"的翻版。

    在低熵载荷（文本、结构化记录）上，任意偏移读出的字节都落在很窄的区间内，
    于是一个"长度字段 + 合适 overhead"的搭配很容易把整条流走完 —— 这不是
    巧合，是**载荷分布的必然结果**，与协议结构无关。实测：一条 54 KB 的
    ASCII 载荷流上能产生 500+ 帧的伪解，而真解只有 14 帧。

    真长度字段的取值来自独立的长度语义，其分布要么明显偏离载荷字节分布，
    要么干脆超出单字节值域。

    :return: ``0.0`` 明显独立（可信）；``1.0`` 与载荷分布几乎重合（可疑）
    """
    n = len(res.values)
    if n < 3 or not data:
        return 0.0
    in_byte = [v for v in res.values if 0 <= v <= 255]
    if len(in_byte) < n * 0.8:
        return 0.0          # 多数长度值超出字节域 —— 不可能是"读了个载荷字节"

    step = max(1, len(data) // 8192)
    sample = data[::step]
    m = len(sample)
    pc = [0] * 256
    for b in sample:
        pc[b] += 1
    qc = [0] * 256
    for v in in_byte:
        qc[v] += 1
    k = len(in_byte)
    tvd = 0.5 * sum(abs(pc[i] / m - qc[i] / k) for i in range(256))
    # TVD ≥ 0.35 视为分布明显不同
    return round(max(0.0, min(1.0, 1.0 - tvd / 0.35)), 4)


def _shuffle(data: bytes, rng: "random.Random", block: int) -> bytes:
    blocks = [data[i:i + block] for i in range(0, len(data), block)]
    rng.shuffle(blocks)
    return b"".join(blocks)


def _perm_window(data: bytes, res: WalkResult, cfg: AnalysisConfig) -> bytes:
    """置换检验的采样窗口：长度受控，且**对齐到帧边界**。

    窗口不对齐会让窗口内的"走完且无剩余"永不成立，观测分数恒为 0，
    置换检验退化成 0-0=0 并把真实协议全部误杀（早期实现的缺陷）。
    """
    if len(data) <= cfg.perm_sample_bytes:
        return data
    end = len(data)
    for pos, flen in res.frames:
        if pos + flen >= cfg.perm_sample_bytes:
            end = pos + flen
            break
    return data[:end]


def _perm_matched(window: bytes, results: List[WalkResult],
                  agreements: List[int], cfg: AnalysisConfig) -> Optional[List[dict]]:
    """**假设匹配**的置换检验：同一条帧结构在原始窗口与打乱窗口上的分数差。

    代价是 ``trials × len(results)`` 次走查（**不含搜索**），比"每轮重跑整轮搜索"
    低两个数量级；因此可以对前 K 个候选全部做，实现"逐候选验证"。

    实测（``bench/calibrate.py``）：匹配 gap 的最大值在全部正样本上都命中真解
    ——包括真解排在第 2、第 3 名时。这正是"谁是真的"这一问题的答案。

    但匹配 gap **不能作为接受门槛**：随机数据上的巧合分帧同样"打乱就走不通"，
    因此负样本的匹配 gap 也为正。接受与否交给 :func:`_perm_global`。
    """
    if cfg.perm_trials <= 0 or len(window) < cfg.perm_min_bytes:
        return None
    import random as _random

    rng = _random.Random(0x5EED)
    shuffled = [_shuffle(window, rng, (3, 4, 5, 7)[t % 4])
                for t in range(cfg.perm_trials)]
    out = []
    for res, ag in zip(results, agreements):
        observed = _fit(window, res, ag, cfg)
        null = [_fit(sh, res, ag, cfg) for sh in shuffled]
        mean_null = sum(null) / len(null)
        out.append({
            "observed": round(observed, 4),
            "gap": round(observed - mean_null, 4),
            "gap_max": round(observed - max(null), 4),
            "p_value": round(sum(1 for s in null if s >= observed) / len(null), 4),
            "trials": len(null),
        })
    return out


def _perm_global(window: bytes, cfg: AnalysisConfig) -> Optional[dict]:
    """**全局 max-vs-max** 置换检验：窗口最高分 − 打乱后各次搜索的最高分。

    两侧都是"对全部假设取 max"，因此无偏，是回答"这条流里到底有没有结构"的
    有效统计量。代价是 ``trials`` 次完整搜索 —— 因此只在候选级证据不足时才调用。

    缺点：两边都不含候选信息，**无法在多个候选间做选择**（那由 :func:`_perm_matched`
    负责）。早期实现把这个统计量用在 rank-1 上，导致真解排在 rank-1 之后时
    完全没有被检验的机会。
    """
    if cfg.perm_trials <= 0 or len(window) < cfg.perm_min_bytes:
        return None
    import random as _random

    rng = _random.Random(0x5EED)
    null = [_best_score(_shuffle(window, rng, (3, 4, 5, 7)[t % 4]), cfg)
            for t in range(cfg.perm_trials)]
    observed = _best_score(window, cfg)
    return {
        "observed": round(observed, 4),
        "gap": round(observed - max(null), 4),
        "gap_mean": round(observed - sum(null) / len(null), 4),
        "p_value": round(sum(1 for s in null if s >= observed) / len(null), 4),
        "null_scores": [round(s, 3) for s in null],
        "trials": len(null),
    }


def _fit(window: bytes, res: WalkResult, agreement: int,
         cfg: AnalysisConfig) -> float:
    """把**同一个假设**套到给定字节上重新走查并打分。

    必须重新走查，不能复用原来的帧边界 —— 置换检验要问的正是
    "这条规则放到这组字节上还灵不灵"。
    """
    rew = walk(window, res.offset, res.format, res.overhead, cfg, res.start,
               count_width=res.count_width, scale=res.scale)
    return _score_walk(window, rew, cfg, agreement)


def _best_score(data: bytes, cfg: AnalysisConfig) -> float:
    """只取最高分（全局置换检验内部使用）。"""
    scored, _ = _search(data, cfg)
    return scored[0][0] if scored else 0.0


def _perm_gap(data: bytes, res: WalkResult, own_score: float,
              cfg: AnalysisConfig) -> Optional[dict]:
    """单候选置换检验（便捷封装，保留供调试与基准脚本使用）。"""
    window = _perm_window(data, res, cfg)
    got = _perm_matched(window, [res], [1], cfg)
    return got[0] if got else None


def _score_walk(data: bytes, res: WalkResult, cfg: AnalysisConfig,
                agreement: int) -> float:
    """给一次成功走查打分（0~1）。

    ``data`` 可以是整条流，也可以是置换检验用的采样窗口 —— 所有特征都从
    传入的这段字节上重新计算，保证两边分数尺度一致。
    """
    n = len(res.frames)
    if n == 0:
        return 0.0

    width = FORMATS[res.format].width or min_width(res.format)
    # 帧数用对数曲线而非 min(1, n/6)：6 帧饱和会把 24 帧的真解和 8 帧的伪解打平。
    # 每多一帧就多满足一次"长度字段与下一帧起点对齐"的约束，是长度前缀分帧
    # 最硬的证据，必须保持单调可区分。
    frame_score = min(1.0, _log2(1.0 + n) / _log2(1.0 + cfg.frames_saturation))

    # 包头区域跨帧恒定程度（魔数 / 版本 / 命令字等）
    header_len = min(res.prefix_len(width), min(fl for _, fl in res.frames))
    consistency = 0.0
    if header_len > 0 and n >= 2:
        constant = 0
        for i in range(header_len):
            vals = {data[pos + i] for pos, _ in res.frames if pos + i < len(data)}
            if len(vals) <= 1:
                constant += 1
        consistency = constant / header_len

    variety = len(set(res.values)) / n
    variety_score = min(1.0, variety * 2)

    structural, _ = _tightness(res, width)

    offset_prior = 1.0 if res.offset == 0 else (
        0.95 if res.offset <= 4 else 0.85 if res.offset <= 8 else 0.7)

    agreement_score = min(1.0, agreement / 3.0)
    # scale 先验：以字节计（scale=1）是绝大多数协议；以字计需要额外证据支撑，
    # 否则同一套帧边界会被无端升级成更复杂的解释（Occam）。
    scale_prior = 1.0 if res.scale == 1 else 0.9

    score = (cfg.s_frames * frame_score
             + cfg.s_header_consistency * consistency
             + cfg.s_value_variety * variety_score
             + cfg.s_structural * structural
             + cfg.s_offset_prior * offset_prior
             + cfg.s_agreement * agreement_score) * scale_prior
    if res.truncated:
        score *= cfg.penalty_partial_tail
    if res.start != 0:
        score *= 0.8
    if _truncated_field(data, res, width):
        score *= cfg.penalty_truncated_field
    alias = _payload_alias(data, res)
    if alias > 0:
        score *= (1.0 - cfg.penalty_payload_alias * alias)
    return round(max(0.0, min(1.0, score)), 4)


def _dedup_key(res: WalkResult) -> tuple:
    """同一族假设的优选次序：紧致拟合 > 字段更宽 > 单位更简单 > 偏移更小。

    **"字段更宽"在这里是有意保留的偏好**：同一套帧边界往往能被一个窄字段
    （``uint8``）和一个宽字段（``uint16_be``）同时解释 —— 前者读到的值恰好
    等于后者的低字节，差别只是"高位字节恒为常量"。真实协议里"长度字段宽
    2 字节、但取值一直小于 256"极其常见，因此默认报告更宽的字段，避免把
    ``uint16`` 误报成 ``uint8``（与 :func:`_truncated_field` 的取向一致）。

    零填充包头会把这条偏好推得过远：填充区里任意偏移读出的都是 ``0x00``，
    于是 ``uint32_be@10`` 这种"多读 3 个零字节"的等价编码会胜出。实测过
    把"字段覆盖的恒定字节数"提到 width 之前，结果 20 项既有断言从
    ``uint16_be@N`` 翻成 ``uint8@N+1``，且个别样本退化 —— 收益不抵风险，
    故不采用。详见 README §11「零填充包头的等价编码」。

    ``-res.scale`` 让 scale=1（以字节计）优先于 scale=4：同一套帧边界能用
    更简单的计数单位解释时，选简单的那个（Occam）。
    """
    width = FORMATS[res.format].width or 1
    structural, _ = _tightness(res, width)
    return (structural, width, -res.scale, -res.offset, -len(res.format))


def _collect_successes(data: bytes, cfg: AnalysisConfig
                       ) -> Tuple[List[WalkResult], Dict]:
    """枚举假设空间，收集全部"走完且无剩余"的走查结果。

    只负责枚举与走查，**不做分组打分** —— 分阶段搜索需要把多个子空间的结果
    合并后再统一打分（否则一致性证据 agreement 会被拆散）。
    """
    starts = [0]
    if cfg.scan_start_offsets:
        starts.extend(range(1, min(cfg.max_start_offset, len(data))))

    successes: List[WalkResult] = []
    tried = 0
    best_partial_frames = 0      # 已完成走查但帧数不足 min_frames 的最好成绩
    max_offset = min(cfg.max_offset, len(data) - 1)

    for start in starts:
        for offset in range(0, max_offset + 1):
            if start + offset >= len(data):
                break
            for fmt in cfg.formats:
                if start + offset + min_width(fmt) > len(data):
                    continue
                variable = FORMATS[fmt].variable
                for scale in cfg.scales:
                    for overhead in _overhead_range(data, offset, fmt, cfg,
                                                    start, variable, scale):
                        tried += 1
                        # 筛查：在"帧数上限 + 字节预算"里，只要链**未断**就进入终判。
                        # 链断（某帧放不下 / 值非法）的假设必然无法完整分帧，直接淘汰。
                        #
                        # 为什么要字节预算：帧很大时 4 帧的上限形同虚设（走 4 帧
                        # 只消耗 4×帧长），而低熵载荷会产生大量"能连续走 90+ 帧"
                        # 的伪假设。实测 varint 流上单条 2.5M 步里有 95% 花在
                        # 二级 96 帧探测上 —— 而它和随后的完整走查做的是同一件事，
                        # 属于纯冗余，已删除。
                        screen = walk(data, offset, fmt, overhead, cfg, start,
                                      probe=cfg.probe_stage1_frames,
                                      probe_bytes=cfg.probe_stage1_bytes,
                                      count_width=variable, scale=scale)
                        if not screen.frames or screen.truncated:
                            continue
                        full = walk(data, offset, fmt, overhead, cfg, start,
                                    count_width=variable, scale=scale)
                        if full.complete and len(full.frames) >= cfg.min_frames:
                            successes.append(full)
                        elif full.frames:
                            best_partial_frames = max(best_partial_frames,
                                                      len(full.frames))

    diag = {"hypotheses_tried": tried, "best_partial_frames": best_partial_frames}
    return successes, diag


def _rank_successes(data: bytes, successes: Sequence[WalkResult],
                    cfg: AnalysisConfig, diag: Optional[Dict] = None
                    ) -> Tuple[List[Tuple[float, WalkResult, int]], Dict]:
    """按帧边界签名分组 → 每组取最优代表 → 打分排序。"""
    diag = dict(diag or {})
    diag.setdefault("hypotheses_tried", 0)
    diag.setdefault("best_partial_frames", 0)
    if not successes:
        diag.update({"success_groups": 0, "success_walks": 0})
        return [], diag

    # 按帧边界签名分组 —— 组内假设数 = 一致性证据
    groups: Dict[Tuple, List[WalkResult]] = defaultdict(list)
    for res in successes:
        groups[res.signature].append(res)

    # 每组取最优代表并评分
    scored: List[Tuple[float, WalkResult, int]] = []
    for members in groups.values():
        best = max(members, key=_dedup_key)
        scored.append((_score_walk(data, best, cfg, len(members)), best, len(members)))

    scored.sort(key=lambda x: (x[0], _dedup_key(x[1])), reverse=True)
    diag.update({"success_groups": len(groups), "success_walks": len(successes)})
    return scored, diag


def _search(data: bytes, cfg: AnalysisConfig
            ) -> Tuple[List[Tuple[float, WalkResult, int]], Dict]:
    """枚举**全部**假设并打分。返回 ``(得分列表, 诊断信息)``，不做接受判定。"""
    successes, diag = _collect_successes(data, cfg)
    return _rank_successes(data, successes, cfg, diag)


def _subspace_configs(cfg: AnalysisConfig
                      ) -> Tuple[AnalysisConfig, List[AnalysisConfig]]:
    """把假设空间切成「核心子空间」与若干「补搜子空间」。

    切分必须**互不重叠且并集为全量**，否则补搜后的结果与全量搜索不等价。
    核心子空间 = ``stage1_scales × stage1_formats``；剩余部分切成两块：
    ``(scales \\ stage1_scales) × 全部格式`` 与 ``stage1_scales × (formats \\ stage1_formats)``。
    """
    s1_scales = tuple(s for s in cfg.scales if s in cfg.stage1_scales)
    s1_formats = tuple(f for f in cfg.formats if f in cfg.stage1_formats)
    rest_scales = tuple(s for s in cfg.scales if s not in cfg.stage1_scales)
    rest_formats = tuple(f for f in cfg.formats if f not in cfg.stage1_formats)
    cfg1 = cfg.overridden(scales=s1_scales, formats=s1_formats)
    subs: List[AnalysisConfig] = []
    if rest_scales:
        subs.append(cfg.overridden(scales=rest_scales))
    if rest_formats:
        subs.append(cfg.overridden(scales=s1_scales, formats=rest_formats))
    return cfg1, subs


def _search_staged(data: bytes, cfg: AnalysisConfig,
                   accept=None) -> Tuple[List[Tuple[float, WalkResult, int]], Dict]:
    """分阶段搜索：先搜核心子空间，证据不足时**补搜**剩余子空间。

    ``accept(scored, data, cfg) -> bool`` 用于判断阶段 1 的证据是否已足以定案；
    为 ``True`` 时直接短路返回（省掉约 6/7 的假设枚举）。

    补搜**不重复**核心子空间已搜过的部分，因此最坏情况与全量搜索同价 ——
    这是它与"先试一遍不行再重搜"的根本区别。
    """
    if not cfg.staged_search:
        scored, diag = _search(data, cfg)
        diag["staged"] = "off"
        return scored, diag

    cfg1, subs = _subspace_configs(cfg)
    if not subs:                      # 无法切分（配置里核心 == 全量）
        scored, diag = _search(data, cfg)
        diag["staged"] = "off"
        return scored, diag

    pool, diag = _collect_successes(data, cfg1)
    if pool:
        scored, diag = _rank_successes(data, pool, cfg, diag)
        if accept is not None and accept(scored, data, cfg):
            diag["staged"] = "stage1"
            return scored, diag

    # ---- 补搜：只走剩余子空间 ----
    tried = diag.get("hypotheses_tried", 0)
    partial = diag.get("best_partial_frames", 0)
    for sub in subs:
        more, d = _collect_successes(data, sub)
        pool = pool + more
        tried += d.get("hypotheses_tried", 0)
        partial = max(partial, d.get("best_partial_frames", 0))
    diag = {"hypotheses_tried": tried, "best_partial_frames": partial}
    scored, diag = _rank_successes(data, pool, cfg, diag)
    diag["staged"] = "full"
    return scored, diag


def _matched_decision(scored, data: bytes, cfg: AnalysisConfig):
    """用候选级置换检验判断当前候选集是否已足以定案。

    :return: ``(选中下标, 各候选检验结果, 采样窗口)``；证据不足时 ``None``。
    """
    if not scored:
        return None
    top = scored[:max(1, cfg.verify_candidates)]
    window = _perm_window(data, top[0][1], cfg)
    matched = _perm_matched(window, [r for _, r, _ in top],
                            [ag for _, _, ag in top], cfg)
    if not matched:
        return None
    gaps = [m["gap"] for m in matched]
    i = max(range(len(gaps)), key=lambda k: gaps[k])
    if gaps[i] < cfg.min_matched_gap:
        return None
    return i, matched, window


def _perm_config(cfg: AnalysisConfig, res: WalkResult) -> AnalysisConfig:
    """置换检验专用的搜索配置：精简假设空间，但**并入主搜索的最佳假设**。

    观测侧与打乱侧共用本配置，因此 max-vs-max 的无偏性不变；缩小空间只是降低
    "打乱后偶然撞出高分伪解"的机会（实测反而提升了分离度，见 config 注释）。

    并入主搜索最佳假设的 scale / format / offset 是必要的：否则真解是冷门编码
    （如 uint24_be）时，观测侧会搜不到它而用伪解打分，把真实协议误拒。
    """
    scales = tuple(sorted(set(cfg.perm_scales) | {res.scale}))
    formats = tuple(dict.fromkeys(tuple(cfg.perm_formats) + (res.format,)))
    max_offset = max(cfg.perm_max_offset, res.offset + 1)
    return cfg.overridden(scales=scales, formats=formats, max_offset=max_offset)


def segment_stream(data: bytes, cfg: AnalysisConfig
                   ) -> Tuple[Optional[LengthFieldSpec], List[Candidate],
                              Optional[WalkResult], Dict]:
    """对一条流做自动分帧。

    长度前缀分帧是**有歧义**的：一条流上常常存在多个"自洽"的切法（都能完整
    走完、无剩余）。因此需要两条**互相独立**的证据，各自回答不同的问题：

    A. **候选级：这条规则有多依赖这组字节排列？**
       同一条帧结构在原始窗口 vs 打乱窗口上的分数差（假设匹配置换检验）。
       它随候选而变，因此能在多个候选间做选择 —— 实测"匹配 gap 最大的候选"
       在全部正样本上都命中真解，包括真解排在第 2、第 3 名时
       （帧数评分饱和点不当、低熵载荷产生多帧伪解时会这样）。

    B. **群体级：这条流里到底有没有结构？**
       窗口最高分 vs 打乱后各次搜索的最高分（全局 max-vs-max 置换检验）。
       两侧都是"对全部假设取 max"，因此无偏。但它与候选无关，无法做选择。

    满足 A 或 B 之一即接受；选中的候选是匹配 gap 最大者。两条证据都失败才拒绝。
    实测标定见 ``bench/calibrate.py``：正样本 15/15 通过，负样本（真随机字节流）
    5/5 被拒。

    :return: ``(最佳帧结构, 候选列表, 最佳走查结果, 诊断信息)``
             未通过验证时帧结构为 ``None``，但候选列表仍会返回供人工复核。
    """
    diagnostics: Dict = {}
    if len(data) < 4:
        return None, [], None, diagnostics

    caught: Dict[str, Any] = {}

    def _accept(scored_, data_, cfg_) -> bool:
        """阶段 1 的短路判据：与最终决策用的是**同一条**候选级证据。"""
        dec = _matched_decision(scored_, data_, cfg_)
        if dec is None:
            return False
        caught["decision"] = dec
        return True

    scored, diagnostics = _search_staged(data, cfg, _accept)
    if not scored:
        return None, [], None, diagnostics

    candidates = []
    for sc, r, ag in scored[:cfg.top_candidates]:
        sp = r.to_spec()
        candidates.append(
            Candidate(offset=r.offset, format=r.format,
                      width=FORMATS[r.format].width, overhead=r.overhead,
                      semantics=sp.semantics, score=sc, scale=r.scale,
                      evidence={"frames": len(r.frames), "leftover": r.leftover,
                                "start": r.start, "agreement": ag,
                                "variable_overhead": r.count_width,
                                "scale": r.scale,
                                "values": r.values[:12],
                                "formula": sp.formula()}))

    # ---- 阶段 1 短路：核心子空间已经给出足够强的证据 ----
    dec = caught.get("decision")
    if diagnostics.get("staged") == "stage1" and dec is not None:
        chosen_rank, matched, window = dec
        top1 = scored[:max(1, cfg.verify_candidates)]
        gaps = [m["gap"] for m in matched]
        diagnostics["window_bytes"] = len(window)
        diagnostics["matched"] = [
            {"format": r.format, "offset": r.offset, "overhead": r.overhead,
             "scale": r.scale, "score": sc, "frames": len(r.frames),
             "agreement": ag, "gap": m["gap"], "p_value": m["p_value"]}
            for (sc, r, ag), m in zip(top1, matched)]
        diagnostics["max_matched_gap"] = round(max(gaps), 4)
        diagnostics["accepted_by"] = "matched"
        diagnostics["chosen_rank"] = chosen_rank
        return top1[chosen_rank][1].to_spec(), candidates, \
            top1[chosen_rank][1], diagnostics

    top = scored[:max(1, cfg.verify_candidates)]
    window = _perm_window(data, top[0][1], cfg)
    chosen_rank = 0

    # ---- 证据 A：候选级（便宜，K×trials 次走查）----
    matched = _perm_matched(window, [r for _, r, _ in top],
                            [ag for _, _, ag in top], cfg)
    diagnostics["window_bytes"] = len(window)
    if matched is not None:
        gaps = [m["gap"] for m in matched]
        chosen_rank = max(range(len(gaps)), key=lambda i: gaps[i])
        diagnostics["matched"] = [
            {"format": r.format, "offset": r.offset, "overhead": r.overhead,
             "scale": r.scale, "score": sc, "frames": len(r.frames),
             "agreement": ag, "gap": m["gap"], "p_value": m["p_value"]}
            for (sc, r, ag), m in zip(top, matched)]
        diagnostics["max_matched_gap"] = round(max(gaps), 4)
        if max(gaps) >= cfg.min_matched_gap:
            diagnostics["accepted_by"] = "matched"
            diagnostics["chosen_rank"] = chosen_rank
            return top[chosen_rank][1].to_spec(), candidates, \
                top[chosen_rank][1], diagnostics

    # ---- 证据 B：群体级（昂贵，只看必要时才算）----
    if matched is None:
        # 置换检验整体不可用（流过大 / 手动关闭）：退化为一致性 + 分数门槛
        passing = [v for v in top
                   if v[2] >= cfg.min_agreement or v[0] >= cfg.min_stream_score]
        if not passing:
            diagnostics["rejected_by"] = "agreement"
            return None, candidates, None, diagnostics
        item = max(passing, key=lambda v: v[0])
        diagnostics.update({"accepted_by": "score",
                            "best_score": item[0],
                            "agreement": item[2],
                            "frames": len(item[1].frames)})
        return item[1].to_spec(), candidates, item[1], diagnostics

    # 观测侧与打乱侧共用同一套精简配置（并入主搜索最佳假设），无偏性不变。
    pcfg = _perm_config(cfg, top[0][1])
    glob = _perm_global(window, pcfg)
    diagnostics["global"] = glob
    diagnostics["perm_config"] = {"scales": list(pcfg.scales),
                                  "formats": list(pcfg.formats),
                                  "max_offset": pcfg.max_offset}
    if glob is None or glob["gap"] < cfg.min_perm_gap:
        diagnostics["rejected_by"] = "permutation"
        return None, candidates, None, diagnostics

    diagnostics["accepted_by"] = "global"
    diagnostics["chosen_rank"] = chosen_rank
    return top[chosen_rank][1].to_spec(), candidates, top[chosen_rank][1], \
        diagnostics


def apply_spec(data: bytes, spec: LengthFieldSpec, cfg: AnalysisConfig,
               start: int = 0) -> Tuple[List[Frame], int, bool]:
    """用已知帧结构切分流，返回 ``(帧列表, 末尾剩余字节数, 是否截断)``。"""
    res = walk(data, spec.offset, spec.format, spec.overhead, cfg, start,
               count_width=spec.variable_overhead, scale=spec.scale)
    frames: List[Frame] = []
    for i, (pos, flen) in enumerate(res.frames):
        raw = data[pos:pos + flen]
        header = raw[:spec.header_len] if spec.header_len <= len(raw) else raw
        body = raw[spec.header_len:] if spec.header_len <= len(raw) else b""
        frames.append(Frame(index=i, offset=pos, length=flen,
                            declared_value=res.values[i] if i < len(res.values) else None,
                            header=header, body=body))
    if res.leftover > 0:
        tail_start = (res.frames[-1][0] + res.frames[-1][1]) if res.frames else start
        frames.append(Frame(index=len(frames), offset=tail_start,
                            length=res.leftover, declared_value=None,
                            header=data[tail_start:], body=b"", truncated=True))
    return frames, res.leftover, res.truncated
