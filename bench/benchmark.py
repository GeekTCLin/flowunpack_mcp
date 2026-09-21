"""分帧评估基准：用金标准帧边界计算 precision / recall / F1 / FMS。

指标定义
--------

* ``precision`` / ``recall`` / ``F1`` —— 以**帧边界集合**为单位。
  预测边界 = 检出帧的起点集合；金标准边界 = 真实协议帧的起点集合。
  这样即使字段语义判断有偏差，只要帧切对了就算对。
* ``FMS``（NEMESYS, WOOT'18 的 Message Format Score 简化版）——
  逐帧比较 ``(offset, length)`` 是否与金标准一致，再对帧取平均。
  比单纯的边界集合更严格：位置对了但长度错了会被扣分。
* ``FPR`` —— 在真随机字节流上被"检出"的比例。宁可少报也不错报，
  因此这个值比 recall 更重要。

金标准来源
----------

``sync`` 模式：由 :mod:`flowunpack.synth` 生成，自带真实帧边界：
长度前缀用例用 ``apply_spec`` 走查得到；分隔符 / ASCII 长度 / 定长用例分别用
``split_by_delimiter`` / ``parse_ascii_length`` / 整除式构造得到。无需外部依赖。

``pcap`` 模式（需 tshark）：从真实抓包按协议字段切出消息边界。
本仓库当前未附带 pcap 语料，保留接口与说明，见 ``docs/ALGORITHM_ROADMAP.md``
第三节"建立 ground-truth 基准"。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from flowunpack import synth                                      # noqa: E402
from flowunpack.config import DEFAULT_CONFIG                      # noqa: E402
from flowunpack.detectors import (                                # noqa: E402
    parse_ascii_length, split_by_delimiter,
)
from flowunpack.engine import analyze_stream                      # noqa: E402
from flowunpack.segmentation import apply_spec                    # noqa: E402


# --------------------------------------------------------------------------
# 指标
# --------------------------------------------------------------------------

def boundary_sets(data: bytes, spec) -> set:
    """用给定 spec 走查，返回帧起点集合。"""
    _frames, _leftover, _trunc = apply_spec(data, spec, DEFAULT_CONFIG)
    return {f.offset for f in _frames if not getattr(f, "truncated", False)}


def gold_frames_of(data: bytes, spec) -> List[Tuple[int, int]]:
    frames, _leftover, _trunc = apply_spec(data, spec, DEFAULT_CONFIG)
    return [(f.offset, f.length)
            for f in frames if not getattr(f, "truncated", False)]


def prf(pred: set, gold: set) -> Tuple[float, float, float]:
    if not pred and not gold:
        return 1.0, 1.0, 1.0
    if not pred or not gold:
        return 0.0, 0.0, 0.0
    tp = len(pred & gold)
    p = tp / len(pred)
    r = tp / len(gold)
    f1 = 0.0 if p + r == 0 else 2 * p * r / (p + r)
    return p, r, f1


def fms(pred_frames, gold_frames) -> float:
    """逐帧比较 (offset, length)。帧数不同则按较长者归一化。"""
    if not pred_frames and not gold_frames:
        return 1.0
    n = max(len(pred_frames), len(gold_frames))
    if n == 0:
        return 1.0
    hit = sum(1 for i in range(min(len(pred_frames), len(gold_frames)))
              if pred_frames[i][:2] == gold_frames[i][:2])
    return hit / n


# --------------------------------------------------------------------------
# 用例集
# --------------------------------------------------------------------------

def positive_cases() -> List[Tuple[str, bytes, List[Tuple[int, int]], str, object]]:
    """``(名称, 数据, 金标准帧区间, 期望模板, 期望 LengthFieldSpec 或 None)``。"""
    def lp(name, pair):
        data, spec = pair
        return (name, data, gold_frames_of(data, spec), "length_prefixed", spec)

    out = [
        lp("uint8", synth.make_length_prefixed_stream("uint8")),
        lp("uint16_be", synth.make_length_prefixed_stream("uint16_be")),
        lp("uint16_le", synth.make_length_prefixed_stream("uint16_le")),
        lp("uint32_be", synth.make_length_prefixed_stream("uint32_be")),
        lp("uint32_le", synth.make_length_prefixed_stream("uint32_le")),
        lp("magic+len", synth.make_magic_length_stream()),
        lp("varint", synth.make_varint_stream()),
        lp("total-len", synth.make_total_length_stream()),
        lp("scale=2", synth.make_scaled_length_stream(2)),
        lp("scale=4", synth.make_scaled_length_stream(4)),
        lp("scale=8", synth.make_scaled_length_stream(8)),
        lp("ascii-20f", synth.make_length_prefixed_stream(
            "uint16_be", frames=20, payload="ascii")),
        lp("bin-20f", synth.make_length_prefixed_stream(
            "uint16_be", frames=20, payload="bytes")),
        lp("ascii-200f", synth.make_length_prefixed_stream(
            "uint16_be", frames=200, payload="ascii")),
        lp("bin-200f", synth.make_length_prefixed_stream(
            "uint16_be", frames=200, payload="bytes")),
        lp("uint16_be-f8", synth.make_length_prefixed_stream(
            "uint16_be", frames=8)),
        lp("uint32_be-f60", synth.make_length_prefixed_stream(
            "uint32_be", frames=60)),
        lp("scale=4-f60", synth.make_scaled_length_stream(4, frames=60)),
        # ---- P1：字段级推断的载体（带 CRC trailer / 多类型包头 / 多消息类型）----
        lp("crc32", synth.make_crc_length_stream()),
        lp("typed-hdr", synth.make_typed_fields_stream()),
        lp("multi-type", synth.make_multi_type_stream()),
        # ---- 包头/包体布局：包头定长，长度字段埋在包头中间（最常见的一类协议）----
        lp("hdr-len@0", synth.make_header_body_stream(
            header_len=6, len_offset=0, magic=b"")),
        lp("hdr-len@3", synth.make_header_body_stream(
            header_len=8, len_offset=3)),
        lp("hdr-len@12", synth.make_header_body_stream(
            header_len=16, len_offset=12)),
        lp("hdr-total", synth.make_header_body_stream(
            header_len=8, len_offset=3, semantics="total_length")),
        lp("hdr-crc", synth.make_header_body_stream(
            header_len=8, len_offset=3, trailer=4)),
        lp("hdr-varint", synth.make_header_varint_stream()),
    ]

    # ---- P0-2：长度前缀之外的模板 ----
    txt = synth.make_delimited_stream(b"\r\n")
    out.append(("delim-crlf", txt, split_by_delimiter(txt, b"\r\n")[0],
                "delimited", None))
    nul = synth.make_delimited_stream(b"\x00\x00", frames=16,
                                      min_len=16, max_len=60)
    out.append(("delim-nul2", nul, split_by_delimiter(nul, b"\x00\x00")[0],
                "delimited", None))
    plain = synth.make_text_stream()
    out.append(("text-crlf", plain, split_by_delimiter(plain, b"\r\n")[0],
                "delimited", None))

    chk = synth.make_chunked_stream()
    out.append(("chunked-hex", chk, parse_ascii_length(chk, 0, 16, b"\r\n")[0],
                "ascii_length", None))
    chd = synth.make_chunked_stream(radix=10)
    out.append(("chunked-dec", chd, parse_ascii_length(chd, 0, 10, b"\r\n")[0],
                "ascii_length", None))

    fx = synth.make_fixed_length_stream(frame_len=16, const_bytes=6)
    out.append(("fixed-16", fx, [(i, 16) for i in range(0, len(fx), 16)],
                "fixed_length", None))
    return out


def negative_cases() -> List[Tuple[str, bytes]]:
    out = [("no-delim-text", synth.make_no_delimiter_text())]
    out += [(f"random{n}", synth.random_stream(n))
            for n in (64, 128, 256, 512, 1024, 4096, 8192, 65536)]
    return out


# --------------------------------------------------------------------------
# 运行
# --------------------------------------------------------------------------

def run(verbose: bool = True, only_neg: bool = False,
        json_out: Optional[str] = None) -> Dict:
    rows = []
    if not only_neg:
        for name, data, gold_frames, expect_kind, gold_spec in positive_cases():
            t0 = time.time()
            res = analyze_stream(data)
            dt = time.time() - t0
            gold_b = {off for off, _ in gold_frames}
            if res.detected and res.framing is not None:
                pred_b = {f.offset for f in res.frames
                          if not getattr(f, "truncated", False)}
                pred_frames = [(f.offset, f.length) for f in res.frames
                               if not getattr(f, "truncated", False)]
            else:
                pred_b, pred_frames = set(), []
            p, r, f1 = prf(pred_b, gold_b)

            got_kind = res.framing.kind if res.framing else None
            kind_ok = bool(res.detected and got_kind == expect_kind)
            spec_ok = kind_ok
            if (gold_spec is not None and kind_ok
                    and expect_kind == "length_prefixed" and res.length_field):
                s = res.length_field
                spec_ok = (s.offset == gold_spec.offset
                           and s.format == gold_spec.format
                           and s.overhead == gold_spec.overhead
                           and s.scale == gold_spec.scale
                           and s.variable_overhead == gold_spec.variable_overhead)

            row = {"case": name, "kind": "pos", "detected": bool(res.detected),
                   "framing_kind": got_kind, "expect_kind": expect_kind,
                   "kind_ok": kind_ok,
                   "precision": round(p, 3), "recall": round(r, 3),
                   "f1": round(f1, 3),
                   "fms": round(fms(pred_frames, gold_frames), 3),
                   "seconds": round(dt, 2), "spec_ok": spec_ok,
                   "got": (res.length_field.formula() if res.length_field
                           else (got_kind or None)),
                   "want": (gold_spec.formula() if gold_spec is not None
                            else expect_kind),
                   "accepted_by": (res.statistics.get("diagnostics", {}) or {})
                                  .get("accepted_by")}
            rows.append(row)
            if verbose:
                mark = "OK " if spec_ok else ("~  " if row["detected"] else "MISS")
                print(f"{mark} {name:<14} det={str(row['detected']):<5} "
                      f"kind={(got_kind or '-'):<15} "
                      f"P={p:.2f} R={r:.2f} F1={f1:.2f} FMS={row['fms']:.2f} "
                      f"{dt:5.2f}s")
                if not spec_ok:
                    print(f"      got  {row['got']}")
                    print(f"      want {row['want']}")

    neg_rows = []
    for name, data in negative_cases():
        t0 = time.time()
        res = analyze_stream(data)
        dt = time.time() - t0
        neg_rows.append({"case": name, "kind": "neg",
                         "detected": bool(res.detected),
                         "seconds": round(dt, 2)})
        if verbose:
            print(f"{'FP ' if res.detected else 'ok '} {name:<14} "
                  f"det={res.detected} {dt:5.2f}s")

    pos = [r for r in rows]
    neg = neg_rows
    summary = {
        "positives": len(pos),
        "spec_correct": sum(1 for r in pos if r["spec_ok"]),
        "kind_correct": sum(1 for r in pos if r["kind_ok"]),
        "detected": sum(1 for r in pos if r["detected"]),
        "mean_precision": round(sum(r["precision"] for r in pos) / len(pos), 4)
        if pos else 0.0,
        "mean_recall": round(sum(r["recall"] for r in pos) / len(pos), 4)
        if pos else 0.0,
        "mean_f1": round(sum(r["f1"] for r in pos) / len(pos), 4) if pos else 0.0,
        "mean_fms": round(sum(r["fms"] for r in pos) / len(pos), 4) if pos else 0.0,
        "negatives": len(neg),
        "false_positives": sum(1 for r in neg if r["detected"]),
        "max_seconds": max([r["seconds"] for r in pos + neg], default=0.0),
    }

    print()
    print("=== 汇总 ===")
    print(f"  正样本          {summary['spec_correct']}/{summary['positives']} "
          f"规格完全正确（模板正确 {summary['kind_correct']}，"
          f"detected {summary['detected']}）")
    print(f"  边界 P/R/F1/FMS  {summary['mean_precision']:.3f} / "
          f"{summary['mean_recall']:.3f} / {summary['mean_f1']:.3f} / "
          f"{summary['mean_fms']:.3f}")
    print(f"  负样本误报      {summary['false_positives']}/{summary['negatives']}")
    print(f"  单例最长耗时    {summary['max_seconds']:.2f}s")

    if json_out:
        Path(json_out).write_text(
            json.dumps({"summary": summary, "rows": rows, "negatives": neg_rows},
                       ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  明细已写入      {json_out}")
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description="分帧评估基准")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--only-neg", action="store_true")
    ap.add_argument("--json", default=None, help="把明细写入该 JSON 文件")
    a = ap.parse_args()
    run(verbose=not a.quiet, only_neg=a.only_neg, json_out=a.json)


if __name__ == "__main__":
    main()
