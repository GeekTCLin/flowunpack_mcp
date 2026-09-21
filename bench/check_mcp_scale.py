"""验证 MCP 工具层对 scale 与决策诊断的端到端支持。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from flowunpack import synth                                        # noqa: E402
from flowunpack_mcp import server as S                             # noqa: E402


def main() -> None:
    data, exp = synth.make_scaled_length_stream(4)
    hx = data.hex()

    print("=== analyze_stream（scale=4）===")
    r = S.tool_analyze_stream(hx)
    print("detected  :", r["detected"])
    print("spec      :", json.dumps(r["length_field"], ensure_ascii=False))
    print("expected  :", exp.formula())
    print("frames    :", r["unit_count"])
    print("confidence:", r["confidence"])
    print("accepted  :", (r.get("statistics", {}).get("diagnostics", {}) or {})
          .get("accepted_by"))
    print("explain   :", json.dumps(S.tool_explain_spec(r["length_field"]),
                                    ensure_ascii=False)[:240])
    print()

    # 用返回的 spec 直接解码（含 scale）
    sp = r["length_field"]
    d2 = S.tool_decode_stream(hx, sp["offset"], sp["format"], sp["overhead"],
                              sp["variable_overhead"], sp["header_len"],
                              scale=sp["scale"])
    print("=== decode_stream（沿用 spec）===")
    print("ok       :", d2["ok"], "frames:", d2["frame_count"],
          "leftover:", d2["leftover"])
    print("frame0   :", json.dumps(d2["frames"][0], ensure_ascii=False)[:200])
    print()

    print("=== 负样本 ===")
    neg = S.tool_analyze_stream(synth.random_stream(2048).hex())
    print("detected :", neg["detected"])
    print("message  :", neg["message"])
    print()

    print("=== service_info ===")
    info = S.tool_service_info()
    print(json.dumps({k: info[k] for k in list(info)[:8]}, ensure_ascii=False)[:400])


if __name__ == "__main__":
    main()
