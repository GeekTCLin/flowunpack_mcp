"""诊断：多分帧模板（delimiter / ascii_length / fixed_length）的行为。

打印每个用例的胜出模板、置信度、帧数与覆盖率，用于人工核对集成裁决是否符合预期。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from flowunpack import analyze_stream                    # noqa: E402
from flowunpack.synth import (                            # noqa: E402
    make_chunked_stream,
    make_delimited_stream,
    make_fixed_length_stream,
    make_length_prefixed_stream,
    make_no_delimiter_text,
    make_scaled_length_stream,
    make_text_stream,
    make_varint_stream,
    random_stream,
)


def show(name: str, data: bytes) -> None:
    r = analyze_stream(data)
    kind = r.framing.kind if r.framing else "-"
    n = len(data)
    covered = sum(f.length for f in r.frames if not f.truncated)
    cov = covered / n if n else 0.0
    print(f"{name:<22} n={n:<7} det={str(r.detected):<5} kind={kind:<15} "
          f"frames={r.unit_count:<4} cov={cov:.3f} conf={r.confidence:.3f}")
    if r.detected:
        for w in r.warnings:
            print(f"    ! {w}")
        for h in r.framing_hypotheses[:3]:
            print(f"    alt: kind={h['kind']} frames={h['frames']} "
                  f"score={h['score']}")
    else:
        print(f"    msg: {r.message[:110]}")
        for h in r.framing_hypotheses[:3]:
            ev = h["evidence"]
            print(f"    hypo fixed_len={ev.get('frame_len')} "
                  f"frames={ev.get('frames')} const_ratio={ev.get('constant_ratio')}")


def main() -> None:
    print("=== 新模板正样本 ===")
    show("delim CRLF", make_delimited_stream())
    show("delim NULx2", make_delimited_stream(b"\x00\x00", frames=16,
                                              min_len=16, max_len=60))
    show("delim CRLFCRLF", make_delimited_stream(b"\r\n\r\n", frames=8))
    show("chunked hex", make_chunked_stream())
    show("chunked dec", make_chunked_stream(radix=10))
    show("chunked no-final", make_chunked_stream(final=False))
    show("fixed 16B rigid", make_fixed_length_stream())
    show("fixed 32B rigid", make_fixed_length_stream(frame_len=32, const_bytes=14))

    print("\n=== 长度前缀正样本（应保持 length_prefixed）===")
    for nm, maker in (("uint16_be", lambda: make_length_prefixed_stream("uint16_be")),
                      ("varint", lambda: make_varint_stream()),
                      ("scale4", lambda: make_scaled_length_stream(4))):
        data, _ = maker()
        show(nm, data)

    print("\n=== 负样本 ===")
    for n in (512, 1024, 4096, 8192, 65536):
        show(f"random{n}", random_stream(n))
    show("no-delim text", make_no_delimiter_text())
    show("text (CRLF lines)", make_text_stream())


if __name__ == "__main__":
    main()
