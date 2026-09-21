"""逐字节结构统计：固定字节、魔数、熵值、包头模板、协议猜测。

输入是"同类单元"列表（逐包模式=包列表；流模式=切分出的帧列表），
输出统一为可 JSON 序列化的结构。
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, List, Optional, Sequence, Set, Tuple

from ..config import AnalysisConfig
from ..models import ByteProfile

__all__ = [
    "byte_profile",
    "fixed_bytes",
    "find_magic",
    "match_known_magic",
    "entropy_profile",
    "guess_protocol",
    "header_consistency",
]

# 常见魔数/协议指纹（仅用于给出提示，不参与评分）
KNOWN_MAGIC: Tuple[Tuple[bytes, str], ...] = (
    (b"\x16\x03", "TLS/SSL"),
    (b"GET ", "HTTP"),
    (b"POST", "HTTP"),
    (b"HTTP/", "HTTP"),
    (b"PK\x03\x04", "ZIP"),
    (b"\x1f\x8b", "GZIP"),
    (b"\x89PNG", "PNG"),
    (b"GIF8", "GIF"),
    (b"BM", "BMP"),
    (b"\x7fELF", "ELF"),
    (b"\xca\xfe\xba\xbe", "Java class"),
    (b"MQTT", "MQTT"),
    (b"\x00\x01\x00", "DNS"),
)


def _min_len(units: Sequence[bytes]) -> int:
    return min((len(u) for u in units), default=0)


def byte_profile(units: Sequence[bytes], cfg: AnalysisConfig) -> List[ByteProfile]:
    """对每个偏移统计众数、频率、取值种类数与熵。"""
    if not units:
        return []
    limit = min(_min_len(units), cfg.scan_bytes)
    total = len(units)
    profiles: List[ByteProfile] = []

    for offset in range(limit):
        counts: Counter = Counter()
        for unit in units:
            if len(unit) > offset:
                counts[unit[offset]] += 1
        if not counts:
            continue
        value, hits = counts.most_common(1)[0]
        freq = hits / total
        entropy = _entropy(counts, total)
        profiles.append(ByteProfile(
            offset=offset,
            likely_value=value,
            frequency=round(freq, 4),
            variety=len(counts),
            entropy=round(entropy, 3),
            is_fixed=freq >= cfg.fixed_byte_threshold,
            chr=chr(value) if 32 <= value < 127 else ".",
        ))
    return profiles


def _entropy(counts: Counter, total: int) -> float:
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts.values():
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def fixed_bytes(profiles: Sequence[ByteProfile]) -> Dict[int, dict]:
    """取出所有被判定为固定的偏移。"""
    return {
        p.offset: {
            "value": p.likely_value,
            "hex": f"0x{p.likely_value:02X}",
            "frequency": p.frequency,
        }
        for p in profiles if p.is_fixed
    }


def find_magic(profiles: Sequence[ByteProfile], cfg: AnalysisConfig) -> List[dict]:
    """把连续固定偏移合并为魔数候选。"""
    out: List[dict] = []
    fixed_offsets = [p.offset for p in profiles if p.is_fixed]
    if not fixed_offsets:
        return out

    start = fixed_offsets[0]
    values = [next(p for p in profiles if p.offset == start).likely_value]

    def flush(s: int, vals: List[int]) -> None:
        if len(vals) >= cfg.magic_min_len:
            raw = bytes(vals)
            out.append({
                "offset": s,
                "length": len(vals),
                "hex": raw.hex(),
                "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in raw),
            })

    for off in fixed_offsets[1:]:
        if off == start + len(values):
            values.append(next(p for p in profiles if p.offset == off).likely_value)
        else:
            flush(start, values)
            start, values = off, [next(p for p in profiles if p.offset == off).likely_value]
    flush(start, values)
    return out


def match_known_magic(sample: bytes) -> Optional[str]:
    """用前若干字节匹配已知协议指纹。"""
    for magic, name in KNOWN_MAGIC:
        if sample.startswith(magic):
            return name
    return None


def entropy_profile(units: Sequence[bytes], cfg: AnalysisConfig) -> List[dict]:
    """返回每个偏移的熵，附带区域解读（低熵=固定字段，高熵=数据/加密）。"""
    out = []
    for p in byte_profile(units, cfg):
        if p.entropy < 1.0:
            zone = "constant"
        elif p.entropy < 3.0:
            zone = "structured"
        elif p.entropy < 5.5:
            zone = "variable"
        else:
            zone = "random/payload"
        out.append({"offset": p.offset, "entropy": p.entropy, "zone": zone})
    return out


def header_consistency(units: Sequence[bytes], header_len: int) -> float:
    """包头区域内「跨单元取值恒定」的位置占比（0~1）。

    真实协议包头通常含魔数/版本等常量字段，该值越高越像真包头。
    """
    if header_len <= 0 or len(units) < 2:
        return 0.0
    limit = min(_min_len(units), header_len)
    if limit <= 0:
        return 0.0
    constant = 0
    for offset in range(limit):
        vals: Set[int] = set()
        for u in units:
            if len(u) > offset:
                vals.add(u[offset])
                if len(vals) > 1:
                    break
        if len(vals) <= 1:
            constant += 1
    return constant / limit


def guess_protocol(profiles: Sequence[ByteProfile], units: Sequence[bytes],
                   length_field: bool) -> str:
    """给一个人类可读的协议形态提示。"""
    sample = units[0] if units else b""
    known = match_known_magic(sample)
    if known:
        return known
    if length_field:
        if profiles and profiles[0].is_fixed:
            return "Magic + Length-Prefix"
        return "Length-Prefix"
    if not profiles:
        return "unknown"
    fixed_ratio = sum(1 for p in profiles if p.is_fixed) / len(profiles)
    if fixed_ratio > 0.6:
        return "Fixed-Header"
    if sample[:1] and 32 <= sample[0] < 127 and b"\r\n" in sample[:512]:
        return "Text/Delimiter-Based"
    return "Custom/Binary"
