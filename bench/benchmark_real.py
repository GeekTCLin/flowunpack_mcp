"""真实协议金标准基准：tshark PDML 字段边界 vs flowunpack 字段推断。

与 ``benchmark.py``（合成流、分帧金标准）互补：本脚本用**真实抓包**评估
字段级推断，回答"在真实协议上推断的字段边界有多准"。

    python bench/benchmark_real.py                 # 跑全部数据集
    python bench/benchmark_real.py --list          # 列出数据集
    python bench/benchmark_real.py --only mdns-q   # 只跑指定数据集
    python bench/benchmark_real.py --json          # 机器可读输出

依赖：``tshark``（PATH 上，或 --tshark 指定路径）。样本 pcap 在 ``bench/data/``，
来自 Wireshark 官方仓库的测试抓包（各 <100KB，随仓库分发以保证可复现）。

金标准构造
----------
``tshark -T pdml`` 导出每包应用层（如 ``dns``）的字段树。容器字段
（如 ``dns.queries``）内部含子字段，会把多个字段算成一个 —— 因此只保留
**原子字段**（不包含任何其它字段）的 ``(pos, size)``，其起点即金标准边界。
``size==0`` 的位域子字段（如 ``dns.flags.response``）不产生字节边界，跳过。

预测
----
数据集的显示过滤保证消息类型基本单一（如 mDNS 只取查询方向），
直接对全部载荷跑 ``infer_fields`` 取主模板；偏移为负的 trailer 字段
按"距帧尾"换算回绝对位置。边界集只含**字段起点**（0 除外）。

指标
----
* Precision / Recall / F1 —— BinaryInferno 式逐边界匹配，语料级累计；
* FMS（γ=2）—— NEMESYS 的格式匹配分，逐消息计算后取均值。

已知边界（诚实记录，不粉饰）：

* ``git-pktline`` 是一个**预期失败**的数据集：git pkt-line 的 ASCII 长度
  计的是"含自身"的总长且数据后**没有终止符**，不属于当前的
  ``<数字><term><数据><term>`` 模板 —— 用它度量当前能力的下限。
"""

from __future__ import annotations

import argparse
import json
import math
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from flowunpack import __version__, infer_fields  # noqa: E402
from flowunpack.config import DEFAULT_CONFIG      # noqa: E402
from flowunpack.io_utils import parse_hex         # noqa: E402

# ---------------------------------------------------------------------------
# 数据集定义
# ---------------------------------------------------------------------------

DATA_DIR = _ROOT / "bench" / "data"

#: 各数据集：pcap + 显示过滤（保证消息类型单一）+ 应用层协议名 + 载荷字段。
#: ``proto`` 是 tshark PDML 里的 proto 名（注意 Wireshark 4.x 的改名：
#: bootp → ``dhcp``；mDNS 的 dissector 名是 ``mdns`` 而非 ``dns``）。
DATASETS: List[Dict[str, str]] = [
    dict(name="mdns-q", pcap="dns-mdns.pcap",
         flt="mdns && udp && dns.flags.response == 0",
         proto="mdns", payload="udp.payload",
         note="mDNS 查询（UDP 5353，定长 90B 文本载荷）"),
    dict(name="dhcp", pcap="dhcp.pcap",
         flt="dhcp && udp",
         proto="dhcp", payload="udp.payload",
         note="DHCP/BOOTP（固定头部 + 变长 options 尾部，4 条样本）"),
    dict(name="dns-port", pcap="dns_port.pcap",
         flt="dns && udp",
         proto="dns", payload="udp.payload",
         note="非标准端口的 DNS（4 条消息，最小样本）"),
    dict(name="git-pktline", pcap="gitOverTCP.pcap",
         flt="tcp",
         proto="git", payload="tcp.payload",
         note="git pkt-line（预期失败：总长 ASCII 长度且无终止符）"),
]


def _run(cmd: List[str], timeout: int = 120) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"命令失败（exit {proc.returncode}）: "
                           f"{' '.join(cmd)}\n{proc.stderr.strip()[:500]}")
    return proc.stdout


# ---------------------------------------------------------------------------
# tshark 输入
# ---------------------------------------------------------------------------

def load_payloads(tshark: str, pcap: Path, flt: str, payload_field: str
                  ) -> Tuple[List[bytes], List[int]]:
    """返回 ``(载荷列表, 每包载荷在帧内的起始偏移)``。"""
    out = _run([tshark, "-r", str(pcap), "-Y", flt,
                "-T", "fields", "-e", payload_field])
    msgs: List[bytes] = []
    starts: List[int] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        hexstr = re.sub(r"[^0-9a-fA-F]", "", line.split("\t")[0])
        if not hexstr:
            continue
        msgs.append(parse_hex(hexstr))
        starts.append(0)                    # 由 PDML 的 pos 覆盖
    return msgs, starts


def load_gold(tshark: str, pcap: Path, flt: str, proto: str,
              payload_field: str) -> List[Dict[str, object]]:
    """从 PDML 提取每包的 ``(载荷起点, 金标准边界集合)``。

    边界 = 原子字段起点（相对载荷，> 0）。容器字段（范围覆盖了其它字段）
    与 ``size==0`` 的位域被剔除。
    """
    out = _run([tshark, "-r", str(pcap), "-Y", flt, "-T", "pdml"])
    root = ET.fromstring(out)
    packets: List[Dict[str, object]] = []
    for pkt in root.findall("packet"):
        app = pkt.find(f"./proto[@name='{proto}']")
        if app is None:
            continue
        pay = pkt.find(f"./proto/field[@name='{payload_field}']")
        if pay is None or pay.get("pos") is None:
            continue
        msg_start = int(pay.get("pos"))
        fields: List[Tuple[int, int]] = []
        for f in app.iter("field"):
            if f.get("pos") is None or f.get("size") is None:
                continue
            pos, size = int(f.get("pos")), int(f.get("size"))
            if size <= 0:
                continue
            fields.append((pos - msg_start, size))
        # 原子字段：区间不覆盖任何其它字段
        atomic = [a for a in fields
                  if not any(a[0] <= b[0] and b[0] + b[1] <= a[0] + a[1]
                             and b != a for b in fields)]
        bounds = {p for p, _ in atomic if p > 0}
        packets.append({"start": msg_start, "bounds": bounds})
    return packets


# ---------------------------------------------------------------------------
# 指标
# ---------------------------------------------------------------------------

def _predicted_boundaries(units: Sequence[bytes],
                          fields) -> List[set]:
    """把字段模板应用到每条消息，得到预测边界集合（起点 > 0）。"""
    out: List[set] = []
    for u in units:
        n = len(u)
        s = set()
        for f in fields:
            pos = f.offset if f.offset >= 0 else n + f.offset
            if 0 < pos < n:
                s.add(pos)
        out.append(s)
    return out


def _fms(gold: List[Tuple[int, int]], pred_bounds: set,
         gamma: float = 2.0) -> Optional[float]:
    """NEMESYS FMS：特异性惩罚 × 边界距离的高斯加权增益。"""
    ref = sorted({p for p, _ in gold if p > 0})
    if not ref:
        return None
    if not pred_bounds:
        return 0.0
    delta = [min(abs(r - p) for p in pred_bounds) for r in ref]
    gain = sum(math.exp(-(d / gamma) ** 2) for d in delta) / len(ref)
    spec = math.exp(-((len(ref) - len(pred_bounds)) / len(ref)) ** 2)
    return spec * gain


def evaluate(units: Sequence[bytes], fields, gold: List[Dict[str, object]]
             ) -> Dict[str, float]:
    tp = fp = fn = 0
    fms_sum, fms_n = 0.0, 0
    for i, (unit, g) in enumerate(zip(units, gold)):
        n = len(unit)
        gb = {p for p in g["bounds"] if p < n}                  # type: ignore[union-attr]
        pb = {p for p in _predicted_boundaries([unit], fields)[0] if p < n}
        tp += len(pb & gb)
        fp += len(pb - gb)
        fn += len(gb - pb)
        if gb or pb:
            v = _fms([(p, 1) for p in gb], pb)
            if v is not None:
                fms_sum += v
                fms_n += 1
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"precision": prec, "recall": rec, "f1": f1,
            "fms": fms_sum / fms_n if fms_n else 0.0,
            "messages": len(units)}


# ---------------------------------------------------------------------------
# 数据集运行
# ---------------------------------------------------------------------------

def run_dataset(tshark: str, ds: Dict[str, str], verbose: bool = False
                ) -> Dict[str, object]:
    pcap = DATA_DIR / ds["pcap"]
    units, _ = load_payloads(tshark, pcap, ds["flt"], ds["payload"])
    gold = load_gold(tshark, pcap, ds["flt"], ds["proto"], ds["payload"])
    if len(units) != len(gold):
        return {"name": ds["name"], "note": ds["note"], "error":
                f"载荷数 {len(units)} 与 PDML 包数 {len(gold)} 不一致"}
    if not units:
        return {"name": ds["name"], "note": ds["note"],
                "error": "没有匹配的载荷"}

    fields, _ = infer_fields(units, DEFAULT_CONFIG)
    if not fields:
        return {"name": ds["name"], "note": ds["note"], "error":
                f"字段推断拒绝（样本 {len(units)} 条，min_units="
                f"{DEFAULT_CONFIG.field_min_units}）"}
    metrics = evaluate(units, fields, gold)
    out: Dict[str, object] = {"name": ds["name"], "note": ds["note"],
                              "proto": ds["proto"], **metrics,
                              "field_count": len(fields)}
    if verbose:
        out["fields"] = [f.describe() for f in fields]
        out["gold_example"] = sorted(next(iter(
            g["bounds"] for g in gold if g["bounds"]), set()))       # type: ignore
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tshark", default=shutil.which("tshark"),
                    help="tshark 路径（默认取 PATH）")
    ap.add_argument("--only", action="append",
                    help="只跑指定数据集（可多次）")
    ap.add_argument("--list", action="store_true", help="列出数据集并退出")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="打印推断出的字段列表")
    args = ap.parse_args(argv)

    if args.list:
        for ds in DATASETS:
            print(f"{ds['name']:<12} {ds['pcap']:<16} {ds['note']}")
        return 0
    if not args.tshark:
        print("错误：找不到 tshark。请安装 Wireshark 或用 --tshark 指定路径。",
              file=sys.stderr)
        return 2

    todo = [d for d in DATASETS
            if not args.only or d["name"] in args.only]
    results = []
    for ds in todo:
        try:
            results.append(run_dataset(args.tshark, ds, args.verbose))
        except Exception as exc:                       # noqa: BLE001
            results.append({"name": ds["name"], "note": ds["note"],
                            "error": str(exc)[:300]})

    if args.json:
        print(json.dumps({"version": __version__, "results": results},
                         ensure_ascii=False, indent=2))
        return 0

    print("=" * 74)
    print("真实协议字段推断基准（金标准：tshark PDML 原子字段边界）")
    print("=" * 74)
    for r in results:
        if "error" in r:
            print(f"\n[{r['name']}] {r['note']}\n  跳过/失败：{r['error']}")
            continue
        print(f"\n[{r['name']}] {r['note']}  （{r['messages']} 条消息，"
              f"模板 {r['field_count']} 个字段）")
        print(f"  Precision {r['precision']:.3f}   Recall {r['recall']:.3f}"
              f"   F1 {r['f1']:.3f}   FMS {r['fms']:.3f}")
        if args.verbose and "fields" in r:
            for d in r["fields"]:                       # type: ignore
                print(f"    {d}")
    print("\n说明：合成基准（bench/benchmark.py）回答\"分帧边界是否精确\"，")
    print("本基准回答\"真实协议上字段边界有多准\"。git-pktline 为预期失败用例。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
