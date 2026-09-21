"""结构化数据模型：所有分析结果都是这些 dataclass 的实例，可直接 JSON 序列化。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence


def _jsonable(obj: Any) -> Any:
    """把 bytes / dataclass 递归转成 JSON 友好的类型。"""
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).hex()
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(v) for v in obj]
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "__dict__") and not isinstance(obj, type):
        return {k: _jsonable(v) for k, v in vars(obj).items()
                if not k.startswith("_")}
    return obj


@dataclass
class LengthFieldSpec:
    """识别出的长度字段及其分帧语义。

    核心不变量：``frame_len = scale * value + overhead``
    （变长编码时再加长度字段实际宽度 ``width``）。

    ``scale`` 是长度字段的**计数单位**：
      * ``scale=1`` —— 长度以字节计（绝大多数协议）
      * ``scale=4`` —— 长度以 4 字节字计（IPv4 的 IHL、部分工控/音视频协议）
    """

    offset: int                     # 长度字段在帧内的起始偏移
    format: str                     # 编码格式名，见 codecs.FORMATS
    width: Optional[int]            # 定长格式的字节宽度；变长格式为 None
    overhead: int                   # frame_len = scale*value + overhead (+ width)
    semantics: str                  # "body_length" | "total_length" | "unknown"
    header_len: int                 # 推断出的包头长度
    body_offset: int                # 包体起始偏移
    endian: str = "big"
    variable_overhead: bool = False # 变长编码：frame_len 需再加上长度字段实际宽度
    scale: int = 1                  # 长度字段的计数单位（字节数 / 长度值）

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LengthFieldSpec":
        """从外部（MCP / JSON）解析帧结构。

        允许只给核心字段：``width`` 可由 ``format`` 推出，
        ``header_len`` / ``body_offset`` 默认取 ``offset + overhead``。
        """
        from .codecs import FORMATS          # 局部导入避免循环依赖

        known = set(cls.__dataclass_fields__)
        d = {k: v for k, v in data.items() if k in known}

        d.setdefault("overhead", 0)
        d.setdefault("endian", "big")
        d.setdefault("variable_overhead", False)
        d.setdefault("semantics", "unknown")
        d.setdefault("scale", 1)
        if d.get("width") is None and d.get("format") in FORMATS:
            d["width"] = FORMATS[d["format"]].width
        d.setdefault("width", None)
        fallback = int(d.get("offset", 0)) + int(d["overhead"])
        d.setdefault("header_len", fallback)
        d.setdefault("body_offset", fallback)
        return cls(**d)

    def formula(self) -> str:
        """帧长公式的文本形式，例如 ``frame_len = 4*value + 2``。"""
        head = "value" if self.scale == 1 else f"{self.scale}*value"
        tail = " + width" if self.variable_overhead else ""
        return f"frame_len = {head} + {self.overhead}{tail}"

    def describe(self) -> str:
        return (f"长度字段 @offset={self.offset} ({self.format}, {self.endian}), "
                f"{self.formula()}, "
                f"包头 {self.header_len} 字节")


#: 分帧模板类型 -> 人类可读标签（用于 protocol_hint 与报告）。
KIND_LABELS: Dict[str, str] = {
    "length_prefixed": "长度前缀",
    "delimited": "分隔符",
    "ascii_length": "ASCII 文本长度",
    "fixed_length": "定长",
}

#: 证据强度优先级：覆盖率相同时，数字大者胜出。
#: 长度前缀经过完整置换检验（最强的显著性证据）；ASCII 长度可自校验
#: （声明的长度必须与后续字节吻合）；分隔符靠频率显著性；定长只有整除性。
KIND_PRIORITY: Dict[str, int] = {
    "length_prefixed": 4,
    "ascii_length": 3,
    "delimited": 2,
    "fixed_length": 1,
}


@dataclass
class FramingSpec:
    """通用分帧规格：四种模板的统一表示。

    与 :class:`LengthFieldSpec` 的关系：``length_prefixed`` 只是其中一种
    ``kind``，其细节放在 ``length_field`` 字段；这样既支持多模板，
    又保持向后兼容（``AnalysisResult.length_field`` 在长度前缀场景下仍会填充）。

    kind 取值：

    * ``length_prefixed`` —— ``frame_len = scale*value + overhead``（现有能力）
    * ``delimited``       —— 以固定字节序列结尾分帧（``\\r\\n``、RESP 等）
    * ``ascii_length``    —— 文本长度前缀（HTTP chunked 的十六进制长度）
    * ``fixed_length``    —— 所有帧等长（**仅整除性，无法自证**，永远低置信）
    """

    kind: str
    confidence: float = 0.0
    length_field: Optional[LengthFieldSpec] = None   # kind == length_prefixed
    delimiter: bytes = b""                            # kind == delimited
    ascii_offset: int = 0                             # kind == ascii_length
    ascii_radix: int = 16                             # 16=十六进制，10=十进制
    ascii_terminator: bytes = b"\r\n"
    frame_len: Optional[int] = None                   # kind == fixed_length
    start_offset: int = 0                             # 首个帧的起始位置

    def to_dict(self) -> Dict[str, Any]:
        return _jsonable(asdict(self))

    def describe(self) -> str:
        if self.kind == "length_prefixed" and self.length_field is not None:
            return "长度前缀分帧 —— " + self.length_field.describe()
        if self.kind == "delimited":
            return ("分隔符分帧 —— 每帧以 %s 结尾（%d 字节分隔符）"
                    % (self.delimiter.hex(), len(self.delimiter)))
        if self.kind == "ascii_length":
            return ("ASCII 长度分帧 —— %d 进制文本长度字段 @offset=%d，"
                    "终止符 %s" % (self.ascii_radix, self.ascii_offset,
                                   self.ascii_terminator.hex()))
        if self.kind == "fixed_length":
            return "定长分帧 —— 每帧 %s 字节" % (self.frame_len,)
        return "未知分帧类型 %s" % self.kind

    def label(self) -> str:
        return KIND_LABELS.get(self.kind, self.kind)


@dataclass
class Frame:
    """一个被切分出来的帧。"""

    index: int
    offset: int                     # 在流中的绝对偏移
    length: int
    declared_value: Optional[int]   # 长度字段原始值
    header: bytes = b""
    body: bytes = b""
    truncated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "offset": self.offset,
            "length": self.length,
            "declared_value": self.declared_value,
            "header_hex": self.header.hex(),
            "body_hex": self.body.hex(),
            "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in self.body),
            "truncated": self.truncated,
        }


@dataclass
class Candidate:
    """一个候选方案（含评分与证据），供人工复核。"""

    offset: int
    format: str
    width: Optional[int]
    overhead: int
    semantics: str
    score: float
    scale: int = 1                   # frame_len = scale*value + overhead
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass
class ByteProfile:
    """单个偏移位置的字节分布画像。"""

    offset: int
    likely_value: int
    frequency: float
    variety: int
    entropy: float
    is_fixed: bool
    chr: str = "."

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


#: 字段语义类型 -> 人类可读标签
FIELD_LABELS: Dict[str, str] = {
    "constant": "常量",
    "magic": "魔数",
    "enum": "枚举/命令字",
    "length": "长度字段",
    "checksum": "校验和",
    "text": "文本",
    "ipv4": "IPv4 地址",
    "timestamp": "时间戳",
    "float": "浮点数",
    "counter": "计数器/序号",
    "integer": "整数",
    "random": "随机数/会话 ID",
    "binary": "未知二进制",
}


@dataclass
class FieldSpec:
    """推断出的一个字段（帧内相对偏移）。

    ``kind`` 取值见 :data:`FIELD_LABELS`。所有类型判定都要求**跨全部样本一致**
    （例如"校验和"必须每条帧都验得上），因此 ``confidence`` 反映的是
    "该判据的强度"，而不是"猜得有多像"。
    """

    offset: int
    length: int
    kind: str = "binary"
    label: str = ""
    confidence: float = 0.0
    cardinality: int = 0          # 该字段跨样本的取值种类数
    entropy: float = 0.0          # 逐列平均熵（bits）
    samples: List[str] = field(default_factory=list)   # 取值样例（hex）
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.label:
            self.label = FIELD_LABELS.get(self.kind, self.kind)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def describe(self) -> str:
        return "@%d+%d %s" % (self.offset, self.length, self.label)


@dataclass
class MessageType:
    """一簇同类消息（按 keyword 字段取值分簇的结果）。

    keyword 缺失（``keyword_offset is None``）表示这条流只有一种消息类型，
    或者没能找到可靠的分簇依据 —— 此时 ``count`` 等于总帧数。
    """

    index: int
    count: int
    keyword_offset: Optional[int] = None
    keyword_length: int = 0
    keyword_values: List[str] = field(default_factory=list)
    lengths: List[int] = field(default_factory=list)
    unique_lengths: List[int] = field(default_factory=list)
    header_len: int = 0
    fields: List[FieldSpec] = field(default_factory=list)
    sample_index: int = 0
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return _jsonable(asdict(self))

    def describe(self) -> str:
        if self.keyword_offset is None:
            return "类型#%d：%d 帧" % (self.index, self.count)
        return ("类型#%d：keyword@%d = %s（%d 帧）"
                % (self.index, self.keyword_offset,
                   "/".join(self.keyword_values[:4]), self.count))


@dataclass
class AnalysisResult:
    """一次完整分析的输出。"""

    mode: str                                   # "stream" | "packets"
    ok: bool
    message: str
    input_bytes: int
    unit_count: int                             # 帧数或包数
    unit_lengths: List[int]
    unique_lengths: List[int]

    detected: bool = False
    confidence: float = 0.0
    protocol_hint: str = "unknown"
    length_field: Optional[LengthFieldSpec] = None
    framing: Optional[FramingSpec] = None        # 通用分帧规格（多模板）
    candidates: List[Candidate] = field(default_factory=list)
    frames: List[Frame] = field(default_factory=list)
    byte_profile: List[ByteProfile] = field(default_factory=list)
    magic: List[Dict[str, Any]] = field(default_factory=list)
    stream_trailing: int = 0                    # 流末尾无法成帧的字节数
    # 字段级推断（P1，见 fields.py）：帧内字段边界与语义类型
    fields: List[FieldSpec] = field(default_factory=list)
    message_types: List[MessageType] = field(default_factory=list)
    # 无法自证的假设（如定长帧）：永远不作为 detected 结论，只列出供人工复核
    framing_hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return _jsonable(asdict(self))

    # ---- 便捷访问 ----
    @property
    def best(self) -> Optional[LengthFieldSpec]:
        return self.length_field

    def summary(self) -> str:
        if not self.detected or self.framing is None:
            return f"未检测到可靠的分帧结构（{self.message}）"
        return (f"{self.protocol_hint}：{self.framing.describe()}"
                f"，置信度 {self.confidence:.0%}")
