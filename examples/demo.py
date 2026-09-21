"""端到端演示：模拟 Wireshark MCP 交付流字节 -> flowunpack 检测 -> 得到帧结构。

    python examples/demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from flowunpack import analyze_stream, render_report                 # noqa: E402
from flowunpack.io_utils import hexdump                               # noqa: E402
from flowunpack.synth import make_magic_length_stream                 # noqa: E402


def main() -> int:
    # 1) 假设这是 Wireshark MCP 从 tcp.stream == 3 提取出来的流（hex 字符串）
    stream, truth = make_magic_length_stream()
    wire_hex = stream.hex()

    print("=" * 70)
    print("1. Wireshark MCP 交付的流（前 64 字节）")
    print("=" * 70)
    print(hexdump(bytes.fromhex(wire_hex[:64])))

    # 2) 交给 flowunpack 检测
    result = analyze_stream(bytes.fromhex(wire_hex))

    # 3) 打印报告
    print()
    print(render_report(result, frame_limit=6, profile_limit=10))

    # 4) 结构化结论（这才是给 LLM / 下游程序用的部分）
    print()
    print("=" * 70)
    print("2. 结构化结论")
    print("=" * 70)
    spec = result.length_field
    print("detected   :", result.detected)
    print("confidence :", f"{result.confidence:.1%}")
    print("protocol   :", result.protocol_hint)
    if spec:
        print("length field offset :", spec.offset)
        print("encoding            :", spec.format, f"({spec.endian})")
        print("frame length formula: frame_len = value + %d%s"
              % (spec.overhead, " + width" if spec.variable_overhead else ""))
        print("header length       :", spec.header_len)
        print("body offset         :", spec.body_offset)
    print("frames     :", result.unit_count)
    for f in result.frames[:3]:
        print(f"  #{f.index} offset={f.offset:<4} len={f.length:<4} "
              f"declared={f.declared_value:<4} body={f.body[:16].hex()} "
              f"ascii={''.join(chr(b) if 32 <= b < 127 else '.' for b in f.body[:16])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
