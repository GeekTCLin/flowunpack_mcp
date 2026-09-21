"""
flowunpack —— TCP 流二进制协议结构启发式检测库（拆包/分帧）。

典型链路：Wireshark MCP 提取单条流的字节 -> 交给本库 -> 返回帧结构与分帧结果。

快速上手
--------
>>> from flowunpack import analyze_stream, io_utils
>>> result = analyze_stream(io_utils.coerce_bytes("000548454c4c4f0003576f"))
>>> result.detected
True

命令行::

    python -m flowunpack --hex 000548454c4c4f
    python -m flowunpack --pcap capture.pcap

MCP 服务::

    python -m mcp_server            # stdio 传输
"""

from .__version__ import __version__, __version_info__
from .analyzers import detect_length_field, evaluate_candidate, explain
from .config import AnalysisConfig, DEFAULT_CONFIG
from .detectors import (
    Detection,
    choose_framing,
    detect_ascii_length,
    detect_delimited,
    detect_fixed_length,
    detect_templates,
)
from .engine import analyze, analyze_packets, analyze_stream, resolve_spec
from .fields import (
    detect_trailer_checksum,
    field_boundaries,
    infer_fields,
    infer_message_types,
    split_header_payload,
)
from .io_utils import (
    InputError,
    coerce_bytes,
    coerce_packet_list,
    hexdump,
    join_packets,
    parse_base64,
    parse_hex,
    to_ascii,
    to_hex,
)
from .models import (
    AnalysisResult,
    Candidate,
    FieldSpec,
    Frame,
    FramingSpec,
    LengthFieldSpec,
    MessageType,
)
from .report import render_report
from .segmentation import apply_spec, segment_stream, walk

__all__ = [
    "__version__", "__version_info__",
    # 配置
    "AnalysisConfig", "DEFAULT_CONFIG",
    # 模型
    "AnalysisResult", "Candidate", "Frame", "FramingSpec", "LengthFieldSpec",
    "FieldSpec", "MessageType",
    # 输入
    "InputError", "coerce_bytes", "coerce_packet_list", "hexdump",
    "join_packets", "parse_base64", "parse_hex", "to_ascii", "to_hex",
    # 分析
    "analyze", "analyze_stream", "analyze_packets", "resolve_spec",
    "detect_length_field", "evaluate_candidate", "explain",
    # 分帧
    "segment_stream", "apply_spec", "walk",
    # 模板探测器（长度前缀之外）
    "Detection", "choose_framing", "detect_templates",
    "detect_delimited", "detect_ascii_length", "detect_fixed_length",
    # 字段级推断（P1）
    "infer_fields", "infer_message_types", "split_header_payload",
    "field_boundaries", "detect_trailer_checksum",
    # 输出
    "render_report",
]
