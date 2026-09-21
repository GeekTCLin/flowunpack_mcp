"""
统一的二进制整数 / 变长整数编解码器。

本模块是整个项目**唯一**的编解码实现，任何其它模块都必须复用它，
不允许再各自实现一份 varint（历史代码中曾存在三份互相矛盾的实现）。

术语约定
--------
varint / uleb128
    LEB128（Little-Endian Base 128），低 7 位组在前，MSB 为继续位。
    Protobuf、SQLite、DWARF 使用此编码。``uleb128`` 是 ``varint`` 的别名。
varint_be
    高 7 位组在前的变长编码（部分私有协议使用）。
sleb128
    有符号 LEB128，最后一字节的第 6 位为符号位。
zigzag
    有符号 varint：``(n << 1) ^ (n >> 31)`` 映射后再按 varint 编码。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

__all__ = [
    "MAX_VARINT_BYTES",
    "LengthFieldFormat",
    "FORMATS",
    "available_formats",
    "decode_varint",
    "encode_varint",
    "decode_varint_be",
    "decode_uleb128",
    "decode_sleb128",
    "decode_zigzag",
    "encode_zigzag",
    "decode_at",
    "value_at",
    "try_decode_all",
    "min_width",
]

MAX_VARINT_BYTES = 10


class DecodeError(ValueError):
    """解码失败：数据不足、越界或编码非法。"""


# --------------------------------------------------------------------------
# 变长整数
# --------------------------------------------------------------------------

def decode_varint(data: bytes, offset: int = 0,
                  max_bytes: int = MAX_VARINT_BYTES) -> Tuple[int, int]:
    """解码 LEB128 / Protobuf varint。

    每个字节低 7 位为数据，最高位为继续位；**低 7 位组排在前面**。

    :return: ``(解码值, 消耗的字节数)``
    :raise DecodeError: 数据不足或编码超过 ``max_bytes``
    """
    result = 0
    shift = 0
    pos = offset
    count = 0
    while pos < len(data):
        if count >= max_bytes:
            raise DecodeError("varint 超过最大字节数 %d" % max_bytes)
        byte = data[pos]
        pos += 1
        count += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, count
        shift += 7
    raise DecodeError("varint 数据不完整（未遇到结束字节）")


def encode_varint(value: int) -> bytes:
    """编码为 LEB128 / Protobuf varint。负数是先转成 64 位补码。"""
    if value < 0:
        value += 1 << 64
        if value < 0:
            raise ValueError("无法编码该负数: %d" % value)
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def decode_varint_be(data: bytes, offset: int = 0,
                     max_bytes: int = MAX_VARINT_BYTES) -> Tuple[int, int]:
    """解码高位组在前的变长整数（``result = result << 7 | group``）。"""
    result = 0
    pos = offset
    count = 0
    while pos < len(data):
        if count >= max_bytes:
            raise DecodeError("varint_be 超过最大字节数 %d" % max_bytes)
        byte = data[pos]
        pos += 1
        count += 1
        result = (result << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            return result, count
    raise DecodeError("varint_be 数据不完整")


def decode_uleb128(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """``uleb128`` —— 与 :func:`decode_varint` 完全等价的别名。"""
    return decode_varint(data, offset)


def decode_sleb128(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """解码有符号 LEB128：结束字节的 bit6 为符号位，需做符号扩展。"""
    result = 0
    shift = 0
    pos = offset
    byte = 0
    count = 0
    while pos < len(data):
        if count >= MAX_VARINT_BYTES:
            raise DecodeError("sleb128 超过最大字节数")
        byte = data[pos]
        pos += 1
        count += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            if byte & 0x40:
                result -= 1 << (shift + 7)
            return result, count
        shift += 7
    raise DecodeError("sleb128 数据不完整")


def decode_zigzag(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """解码 zigzag 编码的有符号 varint。"""
    raw, n = decode_varint(data, offset)
    return (raw >> 1) ^ -(raw & 1), n


def encode_zigzag(value: int) -> bytes:
    """zigzag 编码后按 varint 输出。"""
    return encode_varint((value << 1) ^ (value >> 63) if value < 0 else (value << 1))


# --------------------------------------------------------------------------
# 定长整数
# --------------------------------------------------------------------------

def _fixed(width: int, byteorder: str) -> Callable[[bytes, int], Tuple[int, int]]:
    def _decoder(data: bytes, offset: int) -> Tuple[int, int]:
        if offset < 0 or offset + width > len(data):
            raise DecodeError("需要 %d 字节，但仅剩 %d 字节" % (width, len(data) - offset))
        return int.from_bytes(data[offset:offset + width], byteorder), width

    return _decoder


@dataclass(frozen=True)
class LengthFieldFormat:
    """一种长度字段编码格式的描述。"""

    name: str
    width: Optional[int]          # None 表示变长
    endian: str                   # big / little / leb128 / varint_be ...
    decoder: Callable[[bytes, int], Tuple[int, int]]
    variable: bool = False

    def to_dict(self) -> dict:
        return {"name": self.name, "width": self.width,
                "endian": self.endian, "variable": self.variable}


FORMATS: Dict[str, LengthFieldFormat] = {
    f.name: f
    for f in (
        LengthFieldFormat("uint8", 1, "big", _fixed(1, "big")),
        LengthFieldFormat("uint16_be", 2, "big", _fixed(2, "big")),
        LengthFieldFormat("uint16_le", 2, "little", _fixed(2, "little")),
        LengthFieldFormat("uint24_be", 3, "big", _fixed(3, "big")),
        LengthFieldFormat("uint24_le", 3, "little", _fixed(3, "little")),
        LengthFieldFormat("uint32_be", 4, "big", _fixed(4, "big")),
        LengthFieldFormat("uint32_le", 4, "little", _fixed(4, "little")),
        LengthFieldFormat("uint64_be", 8, "big", _fixed(8, "big")),
        LengthFieldFormat("uint64_le", 8, "little", _fixed(8, "little")),
        LengthFieldFormat("varint", None, "leb128", decode_varint, variable=True),
        LengthFieldFormat("varint_be", None, "varint_be", decode_varint_be, variable=True),
        LengthFieldFormat("uleb128", None, "leb128", decode_varint, variable=True),
        LengthFieldFormat("sleb128", None, "leb128", decode_sleb128, variable=True),
        LengthFieldFormat("zigzag", None, "leb128", decode_zigzag, variable=True),
    )
}


def available_formats() -> List[str]:
    """返回所有受支持的格式名。"""
    return list(FORMATS)


def min_width(name: str) -> int:
    """该格式解码所需的最小字节数（变长格式为 1）。"""
    fmt = FORMATS.get(name)
    if fmt is None:
        raise KeyError("未知格式: %s" % name)
    return fmt.width or 1


def decode_at(data: bytes, offset: int, name: str) -> Optional[Tuple[int, int]]:
    """安全解码：成功返回 ``(值, 宽度)``，失败返回 ``None``。"""
    fmt = FORMATS.get(name)
    if fmt is None or offset < 0 or offset >= len(data):
        return None
    try:
        return fmt.decoder(data, offset)
    except (DecodeError, IndexError, ValueError, TypeError):
        return None


def value_at(data: bytes, offset: int, name: str) -> Optional[int]:
    """只取解码值，失败返回 ``None``。"""
    got = decode_at(data, offset, name)
    return None if got is None else got[0]


def try_decode_all(data: bytes, offset: int,
                   names: Optional[Sequence[str]] = None) -> List[dict]:
    """用所有（或指定）格式尝试解码同一偏移，用于诊断输出。"""
    out: List[dict] = []
    for name in (names or FORMATS):
        got = decode_at(data, offset, name)
        if got is None:
            continue
        value, width = got
        out.append({
            "format": name,
            "value": value,
            "width": width,
            "bytes": data[offset:offset + width].hex(),
        })
    return out
