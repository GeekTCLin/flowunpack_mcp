#!/usr/bin/env python
"""MCP 服务启动入口（无需安装包，直接把 src 加入模块搜索路径）。

    python mcp_server.py                 # stdio 传输（默认）
    python mcp_server.py --transport sse
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from flowunpack_mcp.server import main  # noqa: E402

if __name__ == "__main__":
    transport = "stdio"
    if "--transport" in sys.argv:
        idx = sys.argv.index("--transport")
        if idx + 1 < len(sys.argv):
            transport = sys.argv[idx + 1]
    main(transport=transport)
