"""输入归一化：把 Wireshark / tshark / 其它 MCP 交过来的各种字符串变成 bytes。

上游（wireshark mcp）常见的交付形态：

* ``"aabbcc"``                        —— 紧凑 hex
* ``"aa bb cc"`` / ``"aa:bb:cc"``     —— 带分隔符 hex
* ``"0xaa, 0xbb"``                    —— 带 0x 前缀
* ``"qrvM"``                          —— base64
* ``["aabb", "ccdd"]``                —— 逐包列表
* ``"aabb\\nccdd"``                   —— 多行，一行一包
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Iterable, List, Sequence, Union

__all__ = [
    "InputError",
    "parse_hex",
    "parse_base64",
    "coerce_bytes",
    "coerce_packet_list",
    "to_hex",
    "to_ascii",
    "hexdump",
]

BytesLike = Union[str, bytes, bytearray, memoryview]

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=\r\n]+$")


class InputError(ValueError):
    """输入无法解析为字节序列。"""


def _strip_noise(text: str) -> str:
    """去掉 hex 里常见的噪声：空白、冒号、逗号、0x 前缀、引号、反斜杠。"""
    text = text.strip()
    text = re.sub(r"(?i)0x", "", text)
    text = re.sub(r"[ \t\r\n:,;|\\'\"]+", "", text)
    return text


def parse_hex(text: str) -> bytes:
    """解析 hex 字符串，容忍空格 / 冒号 / 逗号 / ``0x`` 前缀 / 换行。"""
    cleaned = _strip_noise(text)
    if not cleaned:
        return b""
    if not _HEX_RE.match(cleaned):
        raise InputError("不是合法的 hex 字符串（清理后前 32 字符: %r）" % cleaned[:32])
    if len(cleaned) % 2:
        raise InputError("hex 长度为奇数 (%d)，可能数据被截断" % len(cleaned))
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:  # pragma: no cover - 正则已保证
        raise InputError(str(exc)) from exc


def parse_base64(text: str) -> bytes:
    """解析 base64 字符串（自动补 padding）。"""
    cleaned = re.sub(r"\s+", "", text)
    if not cleaned:
        return b""
    pad = (-len(cleaned)) % 4
    try:
        return base64.b64decode(cleaned + "=" * pad, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise InputError("base64 解析失败: %s" % exc) from exc


def coerce_bytes(value: Any, *, encoding: str = "auto") -> bytes:
    """把任意常见形态强制转换为 ``bytes``。

    :param encoding: ``auto`` 先按 hex 再按 base64 试探；也可强制 ``hex`` / ``base64``。
    """
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, (list, tuple)) and all(isinstance(x, int) for x in value):
        return bytes(value)
    if not isinstance(value, str):
        raise InputError("无法把 %s 转换为 bytes" % type(value).__name__)

    text = value.strip()
    if not text:
        return b""

    cleaned = _strip_noise(text)
    if encoding in ("auto", "hex"):
        if cleaned and _HEX_RE.match(cleaned) and len(cleaned) % 2 == 0:
            return bytes.fromhex(cleaned)
        if encoding == "hex":
            raise InputError("按 hex 解析失败: %r" % text[:64])
    if encoding in ("auto", "base64"):
        if _B64_RE.match(text):
            try:
                return parse_base64(text)
            except InputError:
                if encoding == "base64":
                    raise
    raise InputError("无法识别输入编码: %r" % text[:64])


def _split_multi(text: str) -> List[str]:
    """把「一行一包」的文本切成多段。"""
    parts = [p.strip() for p in re.split(r"[\r\n]+", text) if p.strip()]
    return parts if len(parts) > 1 else [text.strip()]


def coerce_packet_list(value: Any, *, encoding: str = "auto") -> List[bytes]:
    """把输入转换为「包列表」。

    支持：``bytes``（视为单包）、hex/base64 字符串（单包）、
    字符串列表、以及用换行分隔的多包文本。
    """
    if value is None:
        return []
    if isinstance(value, (bytes, bytearray, memoryview)):
        return [bytes(value)]
    if isinstance(value, str):
        parts = _split_multi(value)
        return [coerce_bytes(p, encoding=encoding) for p in parts]
    if isinstance(value, dict):
        # 允许 {"packets": [...]} / {"data": "..."} 这类包装
        for key in ("packets", "frames", "payloads", "data", "stream"):
            if key in value:
                return coerce_packet_list(value[key], encoding=encoding)
        raise InputError("字典输入缺少 packets/data 字段")
    if isinstance(value, Iterable):
        return [coerce_bytes(v, encoding=encoding) for v in value]
    raise InputError("无法把 %s 转换为包列表" % type(value).__name__)


def to_hex(data: BytesLike, sep: str = "") -> str:
    """bytes -> hex 字符串。"""
    raw = data if isinstance(data, (bytes, bytearray, memoryview)) else coerce_bytes(data)
    hx = bytes(raw).hex()
    if not sep:
        return hx
    return sep.join(hx[i:i + 2] for i in range(0, len(hx), 2))


def to_ascii(data: BytesLike, placeholder: str = ".") -> str:
    """bytes -> 可打印 ASCII（不可打印字符用 ``placeholder``）。"""
    raw = bytes(data) if isinstance(data, (bytes, bytearray, memoryview)) else coerce_bytes(data)
    return "".join(chr(b) if 32 <= b < 127 else placeholder for b in raw)


def hexdump(data: BytesLike, width: int = 16, limit: int = 256) -> str:
    """生成 ``offset | hex | ascii`` 形式的转储文本。"""
    raw = bytes(data) if isinstance(data, (bytes, bytearray, memoryview)) else coerce_bytes(data)
    raw = raw[:limit]
    lines = []
    for start in range(0, len(raw), width):
        chunk = raw[start:start + width]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        lines.append(f"{start:08X}  {hexpart:<{width * 3}}  {to_ascii(chunk)}")
    return "\n".join(lines)


def join_packets(packets: Sequence[bytes]) -> bytes:
    """把包列表按序拼接为一条流。"""
    return b"".join(packets)
