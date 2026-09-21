"""MCP 检测服务：接收 Wireshark MCP 提取的单条流字节，返回协议结构与分帧结果。

链路：:

    Wireshark MCP --(单条流的 hex/base64)--> flowunpack MCP --(帧结构/分帧结果)--> 调用方

对外工具
--------
``analyze_stream``   流模式分析（推荐：Wireshark 重组流就是连续字节）
``analyze_packets``  逐包模式分析（当上游能给出每个 TCP 包的 payload 边界时）
``analyze_bidirectional``  双向流联合推断（请求/响应两条流互相解歧义）
``decode_stream``    用已知帧结构切分流（二次调用，避免重复检测）
``explain_spec``     把帧结构翻译成人类可读的说明
``list_formats``     列出支持的长度字段编码
``service_info``     服务自检 / 版本
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

_SRC = str(Path(__file__).resolve().parent)
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from flowunpack import __version__                      # noqa: E402
from flowunpack.bidir import analyze_bidirectional       # noqa: E402
from flowunpack.codecs import available_formats          # noqa: E402
from flowunpack.config import AnalysisConfig, DEFAULT_CONFIG  # noqa: E402
from flowunpack.engine import (                          # noqa: E402
    analyze_packets, analyze_stream, resolve_spec,
)
from flowunpack.io_utils import (                        # noqa: E402
    InputError, coerce_bytes, coerce_packet_list, hexdump,
)
from flowunpack.models import LengthFieldSpec            # noqa: E402
from flowunpack.report import render_report              # noqa: E402
from flowunpack.statemachine import (                    # noqa: E402
    infer_state_machine as _infer_state_machine,
)

# ---------------------------------------------------------------------------
# MCP SDK 兼容层：mcp>=2.0 叫 MCPServer，mcp<2.0 叫 FastMCP，接口一致。
# ---------------------------------------------------------------------------
try:                                                     # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _ServerImpl
except ImportError:                                      # mcp < 2.0
    try:
        from mcp.server.fastmcp import FastMCP as _ServerImpl
    except ImportError as _exc:                          # pragma: no cover
        raise SystemExit(
            "未安装 mcp 依赖。请执行: pip install 'mcp>=1.0'  "
            "(当前错误: %s)" % _exc
        )

__all__ = ["create_server", "main", "SERVER_NAME"]

SERVER_NAME = "flowunpack"

_INSTRUCTIONS = """TCP 流二进制协议结构启发式检测服务。

典型用法：先用 Wireshark MCP 导出某条 TCP 流（tcp.stream）的 payload，
拿到 hex 字符串后调用 analyze_stream，即可得到：
    - 分帧模板（framing.kind）：length_prefixed / delimited / ascii_length / fixed_length
    - 长度前缀模板下：长度字段的偏移 / 编码格式 / 端序 / 计数单位
      （帧长公式 frame_len = scale * value + overhead，scale 通常是 1）
    - 包头长度、包体起始偏移
    - 切分出的每一帧（hex + ascii）
    - 字段级推断（fields）：字段边界 + 语义类型（魔数/命令字/长度/校验和/
      文本/IPv4/时间戳/浮点/计数器/随机数…），以及 head/payload/trailer 划分
    - 消息类型分簇（message_types）：按 keyword 字段把帧分成若干类
    - 置信度与候选排行

分隔符分帧（\\r\\n、RESP 等）、HTTP chunked 的 ASCII 文本长度、以及带刚性包头的
定长帧同样支持；其中定长帧**无法自证**，只作为低置信结论并在 warnings 中提示。

若上游能给出逐包 payload 边界，改用 analyze_packets 精度更高。
**若能同时拿到一条双向连接的两个方向，优先用 analyze_bidirectional**：
请求与响应出自同一份格式定义，交叉验证可以解掉单方向无法分辨的歧义
（实测能纠正被"自信伪解"锁定的错误分帧），也能识别出两条流其实无关。
已确定长度前缀结构后，后续调用可直接使用 decode_stream 跳过检测。
"""


# ---------------------------------------------------------------------------
# 工具实现（纯函数，便于单测；MCP 只是薄薄一层包装）
# ---------------------------------------------------------------------------

def _cfg_from(**kwargs) -> AnalysisConfig:
    return DEFAULT_CONFIG.overridden(**kwargs)


def _slim(result_dict: Dict[str, Any], verbose: bool) -> Dict[str, Any]:
    """非 verbose 时裁剪体积大的字段，避免污染上下文。"""
    if verbose:
        return result_dict
    stats = dict(result_dict.get("statistics") or {})
    for key in ("entropy",):
        stats.pop(key, None)
    result_dict["statistics"] = stats
    result_dict["byte_profile"] = result_dict.get("byte_profile", [])[:16]
    result_dict["candidates"] = result_dict.get("candidates", [])[:5]
    types = result_dict.get("message_types") or []
    for t in types:
        if isinstance(t, dict) and len(t.get("lengths") or []) > 16:
            t["lengths"] = t["lengths"][:16]
    if len(types) > 8:
        result_dict["message_types"] = types[:8]
    sm = result_dict.get("state_machine")
    if isinstance(sm, dict):
        for key in ("sequence", "sequence_ascii", "state_sequence"):
            val = sm.get(key)
            if isinstance(val, list) and len(val) > 64:
                sm[key] = val[:64]
        trans = sm.get("transitions")
        if isinstance(trans, list) and len(trans) > 64:
            sm["transitions"] = trans[:64]
    return result_dict


def tool_analyze_stream(stream: str,
                        encoding: str = "auto",
                        max_offset: Optional[int] = None,
                        max_overhead: Optional[int] = None,
                        scan_start_offsets: bool = False,
                        verbose: bool = False,
                        include_text_report: bool = False) -> Dict[str, Any]:
    """分析一条连续流（Wireshark 重组流）的协议结构并分帧。"""
    try:
        data = coerce_bytes(stream, encoding=encoding)
    except InputError as exc:
        return {"ok": False, "error": str(exc)}
    if not data:
        return {"ok": False, "error": "输入为空"}

    cfg = _cfg_from(max_offset=max_offset, max_overhead=max_overhead,
                    scan_start_offsets=scan_start_offsets or None)
    result = analyze_stream(data, cfg)
    out = _slim(result.to_dict(), verbose)
    out["ok"] = True
    out["input_hex_prefix"] = data[:32].hex()
    if include_text_report:
        out["text_report"] = render_report(result)
    return out


def tool_analyze_packets(packets: Any,
                         encoding: str = "auto",
                         max_offset: Optional[int] = None,
                         verbose: bool = False,
                         include_text_report: bool = False) -> Dict[str, Any]:
    """分析逐包 payload（每个元素是一个包的 hex）。"""
    try:
        units = coerce_packet_list(packets, encoding=encoding)
    except InputError as exc:
        return {"ok": False, "error": str(exc)}
    units = [u for u in units if u]
    if not units:
        return {"ok": False, "error": "没有可用的非空包"}

    cfg = _cfg_from(max_offset=max_offset)
    result = analyze_packets(units, cfg)
    out = _slim(result.to_dict(), verbose)
    out["ok"] = True
    if include_text_report:
        out["text_report"] = render_report(result)
    return out


def tool_analyze_bidirectional(c2s: str, s2c: str,
                               encoding: str = "auto",
                               max_offset: Optional[int] = None,
                               max_overhead: Optional[int] = None,
                               verbose: bool = False) -> Dict[str, Any]:
    """双向流联合推断：把一条双向连接的两个方向一起分析。

    为什么要两条流：单条流可能同时自洽于多种切法（长度前缀分帧本身有歧义）。
    请求与响应出自同一份格式定义，因此一方的结构可以用**可证伪**的方式
    约束另一方 —— 用它去切对方，能完整走完才说明两边共用同一套帧长公式。

    返回的 ``coupling`` 给出三条独立证据（结构可迁移 / 类型双射 / 长度相关）
    与综合强度；``coupling.repaired`` 记录被跨方向迁移**改写**的结论（例如
    某一方向因恒定帧长被伪解锁定、由另一方向纠正回真解），
    ``coupling.conflicts`` 记录无法裁决的分歧。

    :param c2s: 客户端→服务端方向的 hex/base64
    :param s2c: 服务端→客户端方向的 hex/base64
    """
    try:
        a_bytes = coerce_bytes(c2s, encoding=encoding)
        b_bytes = coerce_bytes(s2c, encoding=encoding)
    except InputError as exc:
        return {"ok": False, "error": str(exc)}
    if not a_bytes or not b_bytes:
        return {"ok": False, "error": "两个方向都必须是非空流"}

    cfg = _cfg_from(max_offset=max_offset, max_overhead=max_overhead)
    r = analyze_bidirectional(a_bytes, b_bytes, cfg)
    out = r.to_dict()
    out["c2s"] = _slim(out["c2s"], verbose)
    out["s2c"] = _slim(out["s2c"], verbose)
    out["ok"] = True
    return out


def tool_infer_state_machine(stream: str,
                             encoding: str = "auto",
                             k: Optional[int] = None,
                             max_offset: Optional[int] = None,
                             verbose: bool = False) -> Dict[str, Any]:
    """推断一条流的协议状态机（消息序列 → 确定自动机）。

    流程：先分帧（analyze_stream）→ 字段与消息类型推断 → 把每条消息**按命令字
    符号化** → PTA + k-Tail 状态合并 → 输出状态转移表与检测到的环。

    状态机是**消息序列**（时间序）的性质，不是消息集合的性质：同样的若干帧，
    换个顺序就是另一台状态机。因此输入必须是原始流，不能是打乱后的帧列表。

    只在命令字**取值会重复**时才推断（取值互不重复的字段更像递增序号或随机数，
    没有可合并的状态）；无法符号化时 ``inferred=False`` 并给出 ``reason``，
    不会凭空给出一台状态机。

    :param k: k-Tail 的尾部深度（Nerode 等价的 k 阶近似）。省略时用配置默认值 2。
        k 越大状态越多越精确，k 越小越激进。**单条样本无法唯一确定 k**，
        返回里会带 ``k_sensitivity``（k=1..4 各自的状态数）供人工判断。
    """
    try:
        data = coerce_bytes(stream, encoding=encoding)
    except InputError as exc:
        return {"ok": False, "error": str(exc)}
    if not data:
        return {"ok": False, "error": "输入为空"}

    cfg = _cfg_from(max_offset=max_offset)
    result = analyze_stream(data, cfg)
    if not result.detected:
        return {"ok": False, "detected": False, "error": "未能确定分帧结构，"
                "无法推断状态机", "message": result.message}

    if result.state_machine is None:
        return {"ok": True, "detected": True, "inferred": False,
                "reason": result.statistics.get("state_machine_summary"),
                "frames": result.unit_count,
                "message_types": [t.describe() for t in result.message_types]}

    sm = result.state_machine
    if k is not None:
        units = [f.header + f.body for f in result.frames]
        recomputed = _infer_state_machine(units, result.message_types,
                                          result.fields, cfg, k=int(k))
        if recomputed is not None:
            sm = recomputed

    out = sm.to_dict()
    out.update({
        "ok": True, "detected": True, "inferred": True,
        "frames": result.unit_count,
        "framing": result.framing.describe() if result.framing else None,
        "summary": sm.describe(),
    })
    if not verbose:
        for key in ("sequence", "sequence_ascii", "state_sequence"):
            val = out.get(key)
            if isinstance(val, list) and len(val) > 64:
                out[key] = val[:64]
    return out


def tool_decode_stream(stream: str,
                       offset: int,
                       format: str,
                       overhead: int,
                       variable_overhead: bool = False,
                       header_len: Optional[int] = None,
                       encoding: str = "auto",
                       max_frames: int = 32,
                       scale: int = 1) -> Dict[str, Any]:
    """用给定的帧结构切分流：frame_len = scale*value + overhead (+ width 若变长)。"""
    try:
        data = coerce_bytes(stream, encoding=encoding)
    except InputError as exc:
        return {"ok": False, "error": str(exc)}

    try:
        spec = LengthFieldSpec(
            offset=int(offset), format=str(format), overhead=int(overhead),
            variable_overhead=bool(variable_overhead),
            semantics="body_length", width=None,
            header_len=int(header_len) if header_len is not None
            else int(offset) + int(overhead),
            body_offset=int(header_len) if header_len is not None
            else int(offset) + int(overhead),
            scale=max(1, int(scale)),
        )
    except (TypeError, ValueError) as exc:
        return {"ok": False, "error": "spec 参数非法: %s" % exc}

    if spec.format not in available_formats():
        return {"ok": False, "error": "未知格式: %s，可用: %s"
                % (spec.format, ", ".join(available_formats()))}

    cfg = DEFAULT_CONFIG.overridden(max_frames_output=max_frames)
    return resolve_spec(data, spec, cfg)


def tool_explain_spec(spec: Dict[str, Any]) -> Dict[str, Any]:
    """把帧结构翻译成人类可读说明（含解码示例）。"""
    try:
        s = LengthFieldSpec.from_dict(spec)
    except (TypeError, ValueError) as exc:
        return {"ok": False, "error": "spec 解析失败: %s" % exc}
    tail = " + width" if s.variable_overhead else ""
    unit = "字节" if s.scale == 1 else f"{s.scale} 字节"
    return {
        "ok": True,
        "spec": s.to_dict(),
        "description": s.describe(),
        "formula": s.formula(),
        "meaning": (
            f"第 {s.offset} 字节起的 {s.format} 字段给出长度值 v（以 {unit} 为单位计数）；"
            f"整帧长度 = {s.scale}*v + {s.overhead}{tail}；"
            f"包头 {s.header_len} 字节，包体从第 {s.body_offset} 字节开始。"
        ),
    }


def tool_hexdump(stream: str, encoding: str = "auto",
                 limit: int = 512) -> Dict[str, Any]:
    """把流转储为 offset|hex|ascii 文本，便于人工核对。"""
    try:
        data = coerce_bytes(stream, encoding=encoding)
    except InputError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "length": len(data), "hexdump": hexdump(data, limit=limit)}


def tool_list_formats() -> Dict[str, Any]:
    """列出支持的长度字段编码格式。"""
    return {"ok": True, "formats": available_formats()}


def tool_service_info() -> Dict[str, Any]:
    """服务自检：版本、配置默认值、依赖状态。"""
    info: Dict[str, Any] = {
        "ok": True,
        "service": SERVER_NAME,
        "version": __version__,
        "python": sys.version.split()[0],
        "formats": available_formats(),
        "framing_kinds": ["length_prefixed", "delimited", "ascii_length",
                          "fixed_length"],
        "defaults": {
            "max_offset": DEFAULT_CONFIG.max_offset,
            "max_overhead": DEFAULT_CONFIG.max_overhead,
            "min_frames": DEFAULT_CONFIG.min_frames,
            "scales": list(DEFAULT_CONFIG.scales),
            "perm_trials": DEFAULT_CONFIG.perm_trials,
            "min_perm_gap": DEFAULT_CONFIG.min_perm_gap,
            "min_matched_gap": DEFAULT_CONFIG.min_matched_gap,
            "verify_candidates": DEFAULT_CONFIG.verify_candidates,
            "detect_min_score": DEFAULT_CONFIG.detect_min_score,
            "delim_min_frames": DEFAULT_CONFIG.delim_min_frames,
            "delim_alpha": DEFAULT_CONFIG.delim_alpha,
            "delim_min_lift": DEFAULT_CONFIG.delim_min_lift,
            "fixed_min_constant_ratio": DEFAULT_CONFIG.fixed_min_constant_ratio,
            "coupling_corr_threshold": DEFAULT_CONFIG.coupling_corr_threshold,
            "sm_default_k": DEFAULT_CONFIG.sm_default_k,
            "sm_min_symbols": DEFAULT_CONFIG.sm_min_symbols,
            "sm_min_symbol_repeats": DEFAULT_CONFIG.sm_min_symbol_repeats,
        },
        "field_kinds": ["magic", "constant", "enum", "length", "checksum",
                        "text", "ipv4", "timestamp", "float", "counter",
                        "random", "integer", "binary"],
        "field_defaults": {
            "field_scan_bytes": DEFAULT_CONFIG.field_scan_bytes,
            "field_max_units": DEFAULT_CONFIG.field_max_units,
            "field_min_units": DEFAULT_CONFIG.field_min_units,
            "field_max_fields": DEFAULT_CONFIG.field_max_fields,
            "enum_max_cardinality": DEFAULT_CONFIG.enum_max_cardinality,
            "cluster_min_units": DEFAULT_CONFIG.cluster_min_units,
            "cluster_max_types": DEFAULT_CONFIG.cluster_max_types,
        },
    }
    try:
        import scapy  # noqa: F401
        info["scapy"] = "available"
    except ImportError:
        info["scapy"] = "not installed (仅读取本地 pcap 时需要)"
    return info


# ---------------------------------------------------------------------------
# MCP 服务器装配
# ---------------------------------------------------------------------------

def create_server(name: str = SERVER_NAME) -> Any:
    """创建并注册好所有工具的 MCP 服务器实例。"""
    server = _ServerImpl(name=name, instructions=_INSTRUCTIONS, version=__version__)

    @server.tool(name="analyze_stream",
                 description="分析一条连续 TCP 流的二进制协议结构。识别分帧模板"
                             "（长度前缀 / 分隔符 / ASCII 文本长度 / 定长），"
                             "长度前缀下给出长度字段偏移、编码、端序、计数单位与帧长公式"
                             " frame_len = scale*value + overhead，并切分出每一帧。"
                             "输入为 Wireshark 导出流的 hex 或 base64。")
    def _analyze_stream(stream: str, encoding: str = "auto",
                        max_offset: Optional[int] = None,
                        max_overhead: Optional[int] = None,
                        scan_start_offsets: bool = False,
                        verbose: bool = False,
                        include_text_report: bool = False) -> str:
        return json.dumps(tool_analyze_stream(
            stream, encoding=encoding, max_offset=max_offset,
            max_overhead=max_overhead, scan_start_offsets=scan_start_offsets,
            verbose=verbose, include_text_report=include_text_report),
            ensure_ascii=False)

    @server.tool(name="analyze_packets",
                 description="逐包模式分析：输入多个 TCP 包的 payload（hex 数组或多行 hex），"
                             "识别长度字段与包头结构。")
    def _analyze_packets(packets: Any, encoding: str = "auto",
                         max_offset: Optional[int] = None,
                         verbose: bool = False,
                         include_text_report: bool = False) -> str:
        return json.dumps(tool_analyze_packets(
            packets, encoding=encoding, max_offset=max_offset,
            verbose=verbose, include_text_report=include_text_report),
            ensure_ascii=False)

    @server.tool(name="analyze_bidirectional",
                 description="双向流联合推断：同时传入一条双向连接的 c2s 与 s2c 两个"
                             "方向（hex/base64），利用\"请求与响应共用同一套格式定义\""
                             "这一先验互相解歧义。会交叉验证帧结构是否可跨方向迁移、"
                             "请求/响应消息类型是否构成双射、两侧帧长是否相关，"
                             "并在某一方向被伪解锁定时按可迁移性裁定纠正。"
                             "两条互不相关的流会被识别出来并下调置信度。")
    def _analyze_bidirectional(c2s: str, s2c: str, encoding: str = "auto",
                               max_offset: Optional[int] = None,
                               max_overhead: Optional[int] = None,
                               verbose: bool = False) -> str:
        return json.dumps(tool_analyze_bidirectional(
            c2s, s2c, encoding=encoding, max_offset=max_offset,
            max_overhead=max_overhead, verbose=verbose), ensure_ascii=False)

    @server.tool(name="decode_stream",
                 description="用已确定的帧结构切分流（跳过检测）。"
                             "frame_len = scale*value + overhead，"
                             "scale 是长度字段的计数单位（默认 1，即字节）。")
    def _decode_stream(stream: str, offset: int, format: str, overhead: int,
                       variable_overhead: bool = False,
                       header_len: Optional[int] = None,
                       encoding: str = "auto", max_frames: int = 32,
                       scale: int = 1) -> str:
        return json.dumps(tool_decode_stream(
            stream, offset=offset, format=format, overhead=overhead,
            variable_overhead=variable_overhead, header_len=header_len,
            encoding=encoding, max_frames=max_frames, scale=scale),
            ensure_ascii=False)

    @server.tool(name="explain_spec",
                 description="把帧结构（offset/format/overhead 等）翻译成人类可读说明。")
    def _explain_spec(spec: Dict[str, Any]) -> str:
        return json.dumps(tool_explain_spec(spec), ensure_ascii=False)

    @server.tool(name="hexdump",
                 description="把流转储为 offset/hex/ascii 文本，便于人工核对输入是否正确。")
    def _hexdump(stream: str, encoding: str = "auto", limit: int = 512) -> str:
        return json.dumps(tool_hexdump(stream, encoding=encoding, limit=limit),
                          ensure_ascii=False)

    @server.tool(name="list_formats",
                 description="列出支持的长度字段编码格式（uint*/varint/uleb128 等）。")
    def _list_formats() -> str:
        return json.dumps(tool_list_formats(), ensure_ascii=False)

    @server.tool(name="service_info",
                 description="服务自检：版本、默认阈值、依赖状态。")
    def _service_info() -> str:
        return json.dumps(tool_service_info(), ensure_ascii=False)

    # 暴露底层函数，便于直接单测（不经过 JSON 序列化）
    server.fn = {                                        # type: ignore[attr-defined]
        "analyze_stream": tool_analyze_stream,
        "analyze_packets": tool_analyze_packets,
        "analyze_bidirectional": tool_analyze_bidirectional,
        "infer_state_machine": tool_infer_state_machine,
        "decode_stream": tool_decode_stream,
        "explain_spec": tool_explain_spec,
        "hexdump": tool_hexdump,
        "list_formats": tool_list_formats,
        "service_info": tool_service_info,
    }
    return server


def main(transport: str = "stdio") -> None:
    """启动 MCP 服务（默认 stdio）。"""
    create_server().run(transport=transport)


if __name__ == "__main__":
    main()
