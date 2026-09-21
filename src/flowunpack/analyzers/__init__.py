"""分析器子包：逐字节结构统计 + 长度字段启发式检测。"""

from .length_field import detect_length_field, evaluate_candidate, explain
from .structure import (
    byte_profile,
    entropy_profile,
    find_magic,
    fixed_bytes,
    guess_protocol,
    header_consistency,
    match_known_magic,
)

__all__ = [
    "detect_length_field", "evaluate_candidate", "explain",
    "byte_profile", "entropy_profile", "find_magic", "fixed_bytes",
    "guess_protocol", "header_consistency", "match_known_magic",
]
