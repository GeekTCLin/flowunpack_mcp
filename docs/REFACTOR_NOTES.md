# 重构说明（legacy → flowunpack）

本文记录本仓库从 `legacy/` 旧脚本重构为 `flowunpack` 包时的改动，属于开发历史，
不属于使用文档（使用说明见 [`README.md`](../README.md)）。

## 一、修复的硬性缺陷

| 问题 | 原状 | 现在 |
|------|------|------|
| `varint_utils.py` 无法导入 | 用了 `Tuple/List/Dict` 却没 import，直接 `NameError` | 统一到 `codecs.py`，零缺失 import |
| `parallel_unpack.py` 无法编译 | 623 行 f-string 语法错误 | 已废弃，能力并入 `segmentation.py` |
| varint 解码错误 | `shift` 从未递增，`[0x80,0x01]` 解成 1 而非 128 | 修正为 LEB128，并补 `varint_be`/`sleb128`/`zigzag` |
| 三份重复的 varint 实现 | `heuristic_unpack.py`、`varint_utils.py`、`parallel_unpack.py` 各一份且行为矛盾 | 唯一实现 `codecs.py`，全项目复用 |
| 正反向流串味 | 每个包同时写进正向流和反向流，统计被污染 | 按五元组单向分组（`pcap.py`） |
| 误报严重 | 只靠"能走完"判定 | 增加置换检验等三重门槛，随机数据 0 误报 |
| 硬依赖 scapy | 导入即崩 | 核心库**零依赖**；scapy 降为可选（仅读本地 pcap 用） |

## 二、结构变化

旧脚本是若干彼此复制的单文件，没有包边界、没有测试、阈值散落在函数体内。
现在按职责分层：

```
codecs / io_utils      基础层：编解码与输入归一化
models / config        数据模型与全部可调阈值
segmentation / detectors / fields   算法层：分帧 → 多模板 → 字段解释
analyzers              统计层：长度字段评分、结构画像
engine / report        编排与输出
flowunpack_mcp         服务层：MCP 工具
```

## 三、遗留说明

`legacy/` 目录仅作对照保留，不参与构建、不被测试覆盖、不再维护。
需要旧行为时请自行移植，不要直接 import。
