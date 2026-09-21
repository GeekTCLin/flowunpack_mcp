"""校验：新分帧模板经 MCP 工具层端到端可用，且文本报告能正确渲染。

不启动真实 MCP 进程（那由 tests/smoke_mcp_stdio.py 负责），
直接调用 server 暴露的纯函数，验证工具契约（入参 / 出参字段）没有遗漏。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from flowunpack.engine import analyze_stream                # noqa: E402
from flowunpack.report import render_report                  # noqa: E402
from flowunpack.synth import (                               # noqa: E402
    make_chunked_stream, make_crc_length_stream,
    make_delimited_stream, make_fixed_length_stream,
    make_length_prefixed_stream, make_multi_type_stream,
    make_typed_fields_stream,
)
from flowunpack_mcp.server import create_server              # noqa: E402


def main() -> int:
    server = create_server()
    fn = server.fn

    cases = [
        ("length_prefixed", make_length_prefixed_stream("uint16_be")[0]),
        ("delimited", make_delimited_stream(b"\r\n")),
        ("ascii_length", make_chunked_stream()),
        ("fixed_length", make_fixed_length_stream(frame_len=16, const_bytes=6)),
    ]

    ok = True
    for expect, data in cases:
        out = fn["analyze_stream"](data.hex(), include_text_report=True)
        got_kind = (out.get("framing") or {}).get("kind")
        status = "OK " if got_kind == expect else "BAD"
        if got_kind != expect:
            ok = False
        print(f"{status} {expect:<16} -> framing.kind={got_kind} "
              f"detected={out.get('detected')} frames={out.get('unit_count')}")
        assert "text_report" in out and out["text_report"], "文本报告缺失"
        # 报告必须走对应模板分支且不出现占位文本
        rep = out["text_report"]
        assert expect in rep, f"{expect}: 报告未给出模板名"
        assert "[分帧结构]" in rep, f"{expect}: 报告缺少分帧结构段"
        assert "None" not in rep.split("[其它自洽分帧")[0], \
            f"{expect}: 报告出现 None 占位"
        print(f"    报告 {len(rep)} 字符，含 [分帧结构]")

    # 报告渲染冒烟（含新模板分支 + 并列假设分支）
    rep = render_report(analyze_stream(make_chunked_stream()))
    assert "[分帧结构]" in rep and "ascii_length" in rep
    assert "其它自洽分帧" in rep, "并列自洽分帧未在报告中呈现"
    print("OK  文本报告渲染（含并列假设）")

    # ---- P1：字段级推断必须经 MCP 层暴露，且文本报告能渲染 ----
    p1 = [
        ("crc32", make_crc_length_stream()[0], "checksum"),
        ("typed-hdr", make_typed_fields_stream()[0], "ipv4"),
    ]
    for name, data, want_kind in p1:
        out = fn["analyze_stream"](data.hex(), include_text_report=True)
        kinds = [f["kind"] for f in out.get("fields") or []]
        status = "OK " if want_kind in kinds else "BAD"
        if want_kind not in kinds:
            ok = False
        print(f"{status} {name:<16} -> fields={kinds} "
              f"types={len(out.get('message_types') or [])}")
        rep = out["text_report"]
        assert "[字段推断]" in rep, f"{name}: 报告缺少字段推断段"
        assert "None" not in rep.split("[字段推断]")[1].split("[消息类型]")[0], \
            f"{name}: 字段推断段出现 None 占位"

    multi = fn["analyze_stream"](make_multi_type_stream()[0].hex(),
                                 include_text_report=True)
    assert len(multi.get("message_types") or []) == 3, "多消息类型未分簇"
    assert "[消息类型]" in multi["text_report"]
    print("OK  multi-type        -> message_types=3，报告含 [消息类型]")

    info = fn["service_info"]()
    assert "fixed_length" in info["framing_kinds"]
    assert info["defaults"]["delim_alpha"] > 0
    assert "checksum" in info["field_kinds"]
    assert info["field_defaults"]["field_min_units"] >= 4
    print("OK  service_info 暴露 framing_kinds / field_kinds 与新阈值")

    # 未知格式仍应被拒绝（回归保护）
    bad = fn["decode_stream"]("00010203", offset=0, format="uint7_be", overhead=0)
    assert bad.get("ok") is False and "未知格式" in bad["error"]
    print("OK  decode_stream 仍拒绝未知格式")

    print()
    print("=== JSON 摘要（chunked）===")
    sample = fn["analyze_stream"](make_chunked_stream().hex(), verbose=False)
    print(json.dumps({"framing": sample["framing"],
                      "warnings": sample.get("warnings"),
                      "hypotheses": [h["kind"] for h in
                                     sample.get("framing_hypotheses", [])]},
                     ensure_ascii=False, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
