"""字段级推断诊断：先看字段边界 / 语义标注 / 消息类型聚类在各合成协议上的表现。

用法：``python bench/diag_fields.py``
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from flowunpack.config import DEFAULT_CONFIG                     # noqa: E402
from flowunpack.fields import (infer_fields,                     # noqa: E402
                               infer_message_types,
                               split_header_payload)
from flowunpack.segmentation import apply_spec                   # noqa: E402
from flowunpack import synth                                     # noqa: E402


def show(name: str, data: bytes, spec=None) -> None:
    print()
    print("=== %s (%d 字节) ===" % (name, len(data)))
    if spec is None:
        units = [data]
    else:
        frames, leftover, _ = apply_spec(data, spec, DEFAULT_CONFIG)
        units = [f.header + f.body for f in frames if not f.truncated]
        print("  切帧 %d，剩余 %d" % (len(units), leftover))
    if not units:
        print("  (无帧)")
        return
    fields, stats = infer_fields(units, DEFAULT_CONFIG, spec)
    hl, po, tl = split_header_payload(stats, fields, DEFAULT_CONFIG)
    print("  header_len=%d payload_offset=%s trailer_len=%d" % (hl, po, tl))
    print("  %-6s %-5s %-12s %-5s %-5s %s"
          % ("offset", "len", "kind", "conf", "card", "evidence"))
    for f in fields:
        ev = " ".join("%s=%s" % (k, v) for k, v in list(f.evidence.items())[:3])
        print("  @%-5d %-5d %-12s %-5.2f %-5d %s"
              % (f.offset, f.length, f.kind, f.confidence, f.cardinality, ev))
    types = infer_message_types(units, fields, DEFAULT_CONFIG, hl)
    print("  消息类型 %d 簇：" % len(types))
    for t in types:
        print("    " + t.describe())


def main() -> None:
    show("crc32 尾部校验和", *synth.make_crc_length_stream())
    show("多类型包头（ts/ipv4/float）", *synth.make_typed_fields_stream())
    show("三类型混合流", *synth.make_multi_type_stream())
    show("魔数+长度", *synth.make_magic_length_stream())
    show("纯长度前缀", *synth.make_length_prefixed_stream())
    show("随机字节（负样本）", synth.random_stream(1024))


if __name__ == "__main__":
    main()
