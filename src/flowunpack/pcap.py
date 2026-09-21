"""pcap / pcapng 加载器（可选依赖 scapy）。

拆包分析本身**不需要** scapy：Wireshark MCP 交过来的已经是流字节。
只有在本地直接读抓包文件时才需要本模块，因此 scapy 是惰性导入的可选依赖。
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .io_utils import join_packets

__all__ = ["load_flows", "load_stream", "SCAPY_MISSING_MSG"]

SCAPY_MISSING_MSG = (
    "读取 pcap 需要 scapy（可选依赖）。安装：pip install -e '.[pcap]'  "
    "或 pip install scapy。若数据来自 Wireshark MCP，无需此依赖。"
)


def _require_scapy():
    try:
        from scapy.all import IP, IPv6, TCP, Raw, PcapReader  # noqa: F401
        return IP, IPv6, TCP, Raw, PcapReader
    except ImportError as exc:  # pragma: no cover - 取决于环境
        raise RuntimeError(SCAPY_MISSING_MSG) from exc


def _endpoints(pkt, IP, IPv6, TCP) -> Optional[Tuple[str, str, int, int]]:
    if TCP not in pkt:
        return None
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return None
    return src, dst, int(pkt[TCP].sport), int(pkt[TCP].dport)


def load_flows(path: str, *, include_empty: bool = False) -> Dict[Tuple, List[bytes]]:
    """按五元组把 pcap 中的 TCP 载荷分组。

    :return: ``{(sip, dip, sport, dport): [payload, ...]}``，按抓包顺序。
    """
    IP, IPv6, TCP, Raw, PcapReader = _require_scapy()
    flows: Dict[Tuple, List[bytes]] = {}
    with PcapReader(path) as reader:
        for pkt in reader:
            key = _endpoints(pkt, IP, IPv6, TCP)
            if key is None:
                continue
            payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            if not payload and not include_empty:
                continue
            flows.setdefault(key, []).append(payload)
    return flows


def load_stream(path: str, flow: Optional[Tuple] = None) -> bytes:
    """读取某条流（默认第一条）重组后的完整字节流。"""
    flows = load_flows(path)
    if not flows:
        return b""
    if flow is None:
        flow = next(iter(flows))
    elif flow not in flows:
        raise KeyError("pcap 中不存在该流: %r" % (flow,))
    return join_packets(flows[flow])
