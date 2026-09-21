"""定位 _payload_alias 为何不生效，并打印候选的评分项拆解。"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from flowunpack import synth                                       # noqa: E402
from flowunpack.codecs import FORMATS, min_width                   # noqa: E402
from flowunpack.config import DEFAULT_CONFIG                       # noqa: E402
from flowunpack.segmentation import (_payload_alias, _search,      # noqa: E402
                                    _tightness, _truncated_field, walk)

CFG = DEFAULT_CONFIG


def breakdown(data, res):
    n = len(res.frames)
    w = FORMATS[res.format].width or min_width(res.format)
    fs = min(1.0, __import__("math").log2(1.0 + n) / __import__("math").log2(1.0 + CFG.frames_saturation))
    header_len = min(res.prefix_len(w), min(fl for _, fl in res.frames))
    cons = 0.0
    if header_len > 0 and n >= 2:
        const = sum(1 for i in range(header_len)
                    if len({data[p + i] for p, _ in res.frames if p + i < len(data)}) <= 1)
        cons = const / header_len
    var = min(1.0, len(set(res.values)) / n * 2)
    st, sem = _tightness(res, w)
    alias = _payload_alias(data, res)
    in_byte = sum(1 for v in res.values if 0 <= v <= 255)
    return dict(n=n, frame_score=fs, cons=cons, var=var, struct=st,
                alias=alias, in_byte_ratio=in_byte / n if n else 0,
                values_head=res.values[:8], sem=sem,
                trunc_field=_truncated_field(data, res, w))


def show(name, data, exp=None):
    print(f"===== {name}  len={len(data)} =====")
    scored, _ = _search(data, CFG)
    if not scored:
        print("  无候选")
        return
    for i, (sc, r, ag) in enumerate(scored[:4]):
        b = breakdown(data, r)
        print(f"  rank{i} score={sc:.4f} {r.format}@{r.offset}+{r.overhead} "
              f"scale={r.scale} var={int(r.count_width)} ag={ag}")
        print(f"        {b}")
    if exp is not None:
        r = walk(data, exp.offset, exp.format, exp.overhead, CFG, 0,
                 count_width=exp.variable_overhead, scale=exp.scale)
        if r.complete:
            b = breakdown(data, r)
            print(f"  TRUE  {exp.format}@{exp.offset}+{exp.overhead} "
                  f"scale={exp.scale} var={int(exp.variable_overhead)}")
            print(f"        {b}")
        else:
            print(f"  TRUE 走不通: complete={r.complete} frames={len(r.frames)}"
                  f" leftover={r.leftover}")
    print()


if __name__ == "__main__":
    data, exp = synth.make_varint_stream()
    show("varint(ascii)", data, exp)
    data, exp = synth.make_length_prefixed_stream("uint16_be", frames=20, payload="ascii")
    show("uint16_be ascii 20f", data, exp)
    data, exp = synth.make_length_prefixed_stream("uint16_be", frames=20, payload="bytes")
    show("uint16_be bytes 20f", data, exp)
