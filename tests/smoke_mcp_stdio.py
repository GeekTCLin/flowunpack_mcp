"""MCP stdio 冒烟测试：真实启动服务进程，完成 initialize / tools/list / tools/call。"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp import ClientSession, StdioServerParameters  # type: ignore
from mcp.client.stdio import stdio_client  # type: ignore


async def main() -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(ROOT / "mcp_server.py")],
        env=None,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            # mcp 1.x 用 serverInfo（协议字段原名），mcp 2.x 提供 server_info 别名
            info = getattr(init, "server_info", None) or init.serverInfo
            print("server:", info.name, info.version)

            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            print("tools:", names)
            # 工具清单断言：实现与注册必须一致（防止"有实现没注册"的缺口）
            expected_tools = {"analyze_stream", "analyze_packets",
                              "analyze_bidirectional", "infer_state_machine",
                              "export_template", "decode_stream", "explain_spec",
                              "hexdump", "list_formats", "service_info"}
            assert set(names) == expected_tools, \
                f"工具注册不一致: 多={set(names) - expected_tools} " \
                f"少={expected_tools - set(names)}"

            # 构造一条 magic + uint16_be 长度前缀的流
            from flowunpack.synth import make_magic_length_stream
            data, expected = make_magic_length_stream()
            print("expected:", expected.format, "offset", expected.offset,
                  "overhead", expected.overhead)

            res = await session.call_tool("analyze_stream", {"stream": data.hex()})
            payload = json.loads(res.content[0].text)
            spec = payload["length_field"]
            print("detected:", payload["detected"], "confidence:", payload["confidence"])
            print("spec:", json.dumps(spec, ensure_ascii=False))
            print("frames:", payload["unit_count"], "protocol:", payload["protocol_hint"])

            ok = (payload["detected"]
                  and spec["format"] == expected.format
                  and spec["offset"] == expected.offset
                  and spec["overhead"] == expected.overhead)
            print("RESULT:", "PASS" if ok else "FAIL")
            return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
