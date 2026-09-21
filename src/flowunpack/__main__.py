"""``python -m flowunpack`` 命令行入口。

    python -m flowunpack --hex "0005 4845 4c4c 4f"        # 直接分析 hex 流
    python -m flowunpack --file stream.bin                # 分析二进制文件
    python -m flowunpack --pcap capture.pcap --flow 0     # 分析抓包（需 scapy）
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .__version__ import __version__
from .config import DEFAULT_CONFIG
from .engine import analyze_packets, analyze_stream
from .io_utils import coerce_bytes, coerce_packet_list
from .pcap import load_flows, load_stream
from .report import render_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="flowunpack",
        description="TCP 流二进制协议结构启发式检测（长度前缀 / 分帧）",
    )
    p.add_argument("--version", action="version", version=f"flowunpack {__version__}")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--hex", dest="hex", help="hex 字符串（可带空格/冒号/0x 前缀）")
    src.add_argument("--b64", dest="b64", help="base64 字符串")
    src.add_argument("--file", dest="file", help="二进制文件路径")
    src.add_argument("--pcap", dest="pcap", help="pcap/pcapng 文件路径（需 scapy）")
    src.add_argument("--stdin", action="store_true", help="从 stdin 读取 hex/base64")

    p.add_argument("--packets", action="store_true",
                   help="逐包模式：输入按行拆分为多个包")
    p.add_argument("--flow", type=int, default=None, help="pcap 中第 N 条流（默认第一条）")
    p.add_argument("--json", action="store_true", help="输出 JSON 而非文本报告")
    p.add_argument("--max-offset", type=int, default=None)
    p.add_argument("--max-overhead", type=int, default=None)
    p.add_argument("--scan-start-offsets", action="store_true",
                   help="尝试非 0 起始偏移（更慢）")
    return p


def _read_input(args) -> bytes | list:
    if args.stdin:
        return sys.stdin.read()
    if args.hex:
        return args.hex
    if args.b64:
        return args.b64
    if args.file:
        return Path(args.file).read_bytes()
    if args.pcap:
        if args.flow is None:
            return load_stream(args.pcap)
        flows = load_flows(args.pcap)
        keys = sorted(flows)
        if not keys:
            raise SystemExit("pcap 中未找到 TCP 载荷")
        idx = args.flow if 0 <= args.flow < len(keys) else 0
        return b"".join(flows[keys[idx]])
    raise SystemExit("缺少输入")


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = DEFAULT_CONFIG.overridden(
        max_offset=args.max_offset,
        max_overhead=args.max_overhead,
        scan_start_offsets=args.scan_start_offsets or None,
    )

    try:
        raw = _read_input(args)
        if args.packets or (isinstance(raw, str) and "\n" in raw.strip() and args.packets):
            units = coerce_packet_list(raw)
            result = analyze_packets(units, cfg)
        else:
            data = coerce_bytes(raw)
            result = analyze_stream(data, cfg)
    except Exception as exc:  # noqa: BLE001 - CLI 边界统一报错
        print(f"错误: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(render_report(result))
    return 0 if result.detected else 1


if __name__ == "__main__":
    raise SystemExit(main())
