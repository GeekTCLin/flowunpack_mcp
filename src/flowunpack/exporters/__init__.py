"""结构导出器：把分析结果转成下游可直接使用的资产。

目前提供三种导出（kind）：

* ``boofuzz`` —— boofuzz 模板脚本（``s_size`` / ``s_checksum``）。
  仅支持 ``length_prefixed`` 定宽编码；变长编码与其它模板会抛出
  :class:`UnsupportedTemplateError`。
* ``aflnet``  —— 独立的消息切分脚本，供 AFLNet / ProFuzzBench 使用
  （AFLNet 复盘指出消息边界识别是其唯一强制人工输入）。四种模板全支持。
* ``lua``     —— Wireshark Lua dissector，四种模板全支持。

所有产物都是**文本**，写入文件即用；boofuzz/lua 产物为独立脚本，
不依赖本库。导出的是"推断结果"，不保证正确 —— 产物头部都带推断元
信息，供人工核对。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:                        # pragma: no cover
    from ..models import AnalysisResult

__all__ = ["export_template", "SUPPORTED_KINDS", "UnsupportedTemplateError",
           "to_boofuzz", "to_aflnet_splitter", "to_lua_dissector"]


class UnsupportedTemplateError(ValueError):
    """当前模板/编码无法用指定导出后端表达。"""


SUPPORTED_KINDS = ("boofuzz", "aflnet", "lua")

# 子模块在异常类定义之后导入（它们会 from . import UnsupportedTemplateError）
from .aflnet import to_aflnet_splitter                   # noqa: E402
from .boofuzz import to_boofuzz                          # noqa: E402
from .lua import to_lua_dissector                        # noqa: E402


def export_template(result: "AnalysisResult", kind: str, **kwargs: Any) -> str:
    """把 :class:`AnalysisResult` 导出为指定后端的脚本文本。

    多余的 kwargs（各后端不接受的）会被忽略，调用方可以统一传参。

    :param kind: ``boofuzz`` / ``aflnet`` / ``lua``
    :raises UnsupportedTemplateError: 模板或编码无法被该后端表达
    :raises ValueError: 未知 kind
    """
    if kind == "boofuzz":
        kw = {k: kwargs[k] for k in ("host", "port") if k in kwargs}
        return to_boofuzz(result, **kw)
    if kind == "aflnet":
        return to_aflnet_splitter(result)
    if kind == "lua":
        kw = {k: kwargs[k] for k in ("proto_name",) if k in kwargs}
        return to_lua_dissector(result, **kw)
    raise ValueError(f"未知导出类型 {kind!r}，支持: {', '.join(SUPPORTED_KINDS)}")
