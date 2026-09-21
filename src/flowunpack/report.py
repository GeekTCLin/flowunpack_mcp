"""人类可读的文本报告（MCP 之外，CLI / 日志场景使用）。"""

from __future__ import annotations

from typing import Sequence

from .models import AnalysisResult, ByteProfile, Frame

__all__ = ["render_report", "render_frames_table"]


def _bar(value: float, width: int = 20) -> str:
    filled = int(round(value * width))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def render_frames_table(frames: Sequence[Frame], limit: int = 10) -> str:
    lines = [f"{'#':>4}  {'offset':>8}  {'len':>5}  {'declared':>8}  body(hex, 前16字节)",
             "-" * 78]
    for f in frames[:limit]:
        body_hex = f.body[:16].hex()
        lines.append(f"{f.index:>4}  {f.offset:>8X}  {f.length:>5}  "
                     f"{'' if f.declared_value is None else f.declared_value:>8}  {body_hex}")
    if len(frames) > limit:
        lines.append(f"... 共 {len(frames)} 帧")
    return "\n".join(lines)


def render_report(result: AnalysisResult, frame_limit: int = 10,
                  profile_limit: int = 24) -> str:
    """把 :class:`AnalysisResult` 渲染成终端友好的文本。"""
    out: list = []
    out.append("=" * 78)
    out.append("TCP 流协议结构启发式分析报告")
    out.append("=" * 78)
    out.append(f"分析模式    : {result.mode}")
    out.append(f"输入字节数  : {result.input_bytes}")
    out.append(f"单元数量    : {result.unit_count}")
    out.append(f"长度分布    : {result.unique_lengths[:16]}")
    out.append(f"协议提示    : {result.protocol_hint}")
    out.append(f"结论        : {result.message}")

    if result.detected and result.framing is not None:
        fr = result.framing
        out.append("")
        out.append("[分帧结构]")
        out.append(f"  模板         : {fr.kind}（{fr.label()}）")
        if fr.kind == "length_prefixed" and fr.length_field is not None:
            spec = fr.length_field
            out.append(f"  长度字段偏移 : {spec.offset}")
            out.append(f"  编码格式     : {spec.format} ({spec.endian})")
            out.append(f"  帧长公式     : {spec.formula()}")
            out.append(f"  语义         : {spec.semantics}")
            out.append(f"  包头长度     : {spec.header_len}")
            out.append(f"  包体起始     : {spec.body_offset}")
        elif fr.kind == "delimited":
            ascii_repr = "".join(chr(b) if 32 <= b < 127 else "."
                                 for b in fr.delimiter)
            out.append(f"  分隔符       : {fr.delimiter.hex()}  \"{ascii_repr}\"")
        elif fr.kind == "ascii_length":
            out.append(f"  进制         : {fr.ascii_radix}")
            out.append(f"  终止符       : {fr.ascii_terminator.hex()}")
            out.append(f"  起始偏移     : {fr.ascii_offset}")
        elif fr.kind == "fixed_length":
            out.append(f"  帧长         : {fr.frame_len}")
        out.append(f"  置信度       : {result.confidence:.1%}  "
                   f"{_bar(result.confidence)}")
    else:
        out.append("")
        out.append("[分帧结构] 未检测到可靠结构")

    if result.candidates:
        out.append("")
        out.append("[长度前缀候选排行]")
        out.append(f"{'offset':>6} {'format':<10} {'scale':>5} {'overhead':>8} {'score':>7}  evidence")
        out.append("-" * 78)
        for c in result.candidates[:8]:
            ev = c.evidence or {}
            brief = " ".join(f"{k}={v}" for k, v in list(ev.items())[:4])
            out.append(f"{c.offset:>6} {c.format:<10} {c.scale:>5} "
                       f"{c.overhead:>8} {c.score:>7.3f}  {brief}")

    if result.fields:
        out.append("")
        out.append("[字段推断]（帧内相对偏移；offset 为负表示距帧尾）")
        out.append(f"{'offset':>6} {'len':>4} {'类型':<12} {'可信':>5} {'取值数':>5}  依据")
        out.append("-" * 78)
        for f in result.fields:
            ev = f.evidence or {}
            brief = " ".join(f"{k}={v}" for k, v in list(ev.items())[:2])
            out.append(f"{f.offset:>6} {f.length:>4} {f.label:<12} "
                       f"{f.confidence:>5.2f} {f.cardinality:>5}  {brief}")
        summary = result.statistics.get("field_summary") or {}
        if summary:
            payload = summary.get("payload_offset")
            out.append("  包头长度 %s / 载荷起点 %s / 尾部 %s 字节"
                       % (summary.get("inferred_header_len"),
                          payload if payload is not None else "未识别",
                          summary.get("trailer_len")))

    if result.message_types and len(result.message_types) > 1:
        out.append("")
        out.append("[消息类型]（按 keyword 字段分簇）")
        for t in result.message_types[:8]:
            out.append("  " + t.describe()
                       + f"  帧长 {t.unique_lengths[:5]}")
            if t.keyword_offset is not None:
                out.append(f"      keyword@%d+%d 取值 %s"
                           % (t.keyword_offset, t.keyword_length,
                              "/".join(t.keyword_values)))

    sm = result.state_machine
    if sm is not None:
        out.append("")
        out.append("[状态机]（由消息序列推断；PTA + k-Tail 状态合并）")
        out.append("  符号字段     : %s，%d 种取值（%s）"
                   % (sm.symbol_source or "?",
                      len(sm.alphabet), "/".join(sm.alphabet[:8])))
        out.append("  规模         : %d 状态 / %d 转移（k=%d）"
                   % (sm.states, len(sm.transitions), sm.k))
        out.append("  初始状态     : q%d" % sm.initial)
        out.append("  压缩率       : %.0f%%（状态数 %d / 符号数 %d，越高越有结构）"
                   % (100 * sm.compression, sm.states, sm.symbol_count))
        out.append("  结构强度     : %.1f%%  %s"
                   % (100 * sm.confidence, _bar(sm.confidence)))
        out.append("  转移表       :")
        for t in sm.transitions[:16]:
            out.append("      q%d --%s--> q%d   观测 %d 次"
                       % (t["src"], t["symbol"], t["dst"], t["count"]))
        if len(sm.transitions) > 16:
            out.append("      ... 共 %d 条转移" % len(sm.transitions))
        if sm.cycles:
            for c, n in zip(sm.cycles[:4], sm.cycle_traversals[:4]):
                out.append("  环（周期 %d，绕行 %d 次）: %s → %s"
                           % (len(c), n, " → ".join(c), c[0]))
        else:
            out.append("  环           : 未发现被反复执行的环")
        if sm.k_sensitivity:
            out.append("  k 敏感性     : %s —— 单条样本无法唯一确定 k"
                       % "，".join("k=%s→%d 态" % (k, v)
                                   for k, v in sorted(sm.k_sensitivity.items())))
        for n in sm.notes:
            out.append("  [!] " + n)
    elif result.statistics.get("state_machine_summary"):
        out.append("")
        out.append("[状态机] " + str(result.statistics["state_machine_summary"]))

    if result.framing_hypotheses:
        out.append("")
        out.append("[其它自洽分帧 / 低置信假设]")
        for h in result.framing_hypotheses[:6]:
            ev = h.get("evidence") or {}
            detail = ev.get("delimiter_hex") or (
                f"frame_len={ev.get('frame_len')}" if "frame_len" in ev
                else f"radix={ev.get('radix')}")
            out.append(f"  {h['kind']:<15} frames={h['frames']:<4} "
                       f"score={h['score']:<7} {detail}")
            if "constant_ratio" in ev:
                out.append(f"     恒定列比例 {ev['constant_ratio']} "
                           f"({ev.get('constant_columns')}/{ev.get('columns')})")

    if result.magic:
        out.append("")
        out.append("[魔数候选]")
        for m in result.magic[:6]:
            out.append(f"  offset {m['offset']:<3} len {m['length']:<3} "
                       f"hex={m['hex']:<20} ascii={m['ascii']}")

    profiles: Sequence[ByteProfile] = result.byte_profile[:profile_limit]
    if profiles:
        out.append("")
        out.append("[包头字节画像]")
        out.append(f"{'off':>4} {'hex':>6} {'dec':>4} {'chr':>4} {'freq':>7} {'ent':>6}  status")
        out.append("-" * 60)
        for p in profiles:
            out.append(f"{p.offset:>4} {p.likely_value:#04x} {p.likely_value:>4} "
                       f"{p.chr:>4} {p.frequency:>7.1%} {p.entropy:>6.2f}  "
                       f"{'FIXED' if p.is_fixed else 'VAR'}")

    if result.frames:
        out.append("")
        out.append("[分帧结果]")
        out.append(render_frames_table(result.frames, frame_limit))

    if result.stream_trailing:
        out.append("")
        out.append(f"[!] 流末尾有 {result.stream_trailing} 字节无法成帧")

    for w in result.warnings:
        out.append(f"[!] {w}")

    out.append("=" * 78)
    return "\n".join(out)
