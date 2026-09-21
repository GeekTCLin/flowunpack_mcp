---
name: flowunpack-verify
description: flowunpack 仓库的回归验证流程（单测 / 分帧基准 / 四模板诊断 / MCP 端到端），含本机 shell 绕行方法。改动分帧算法、新增模板探测器、调整 config 阈值、或提交前回归时使用。
agent_created: true
---

# flowunpack 回归验证流程

## 环境前提（先看这条，否则会白折腾）

本机 Bash 工具的 PATH 是坏的：`dirname`、`ls`、`tail`、`head`、`rm` 都不可用，
**任何管道都会失败**（`... 2>&1 | tail` 会报 `tail: command not found`，退出码 127）。
`rm` 走的是安全 shim，同样报错。删除文件请用 Python 的 `os.remove`。

固定使用托管 venv 的绝对路径，**不要用**裸 `python`：

```
PY="C:/Users/Xi/.workbuddy/binaries/python/envs/default/Scripts/python.exe"
```

每次运行都 `> 输出文件 2>&1`，再用 Read 工具读该文件。

## 一键回归（7 项，全部应 exit 0）

不要用 `&&` 串联后只看尾部——分开跑并逐个记录退出码：

```bash
PY="C:/Users/Xi/.workbuddy/binaries/python/envs/default/Scripts/python.exe"
"$PY" -m pytest tests -q -rxX        > _pytest.txt 2>&1; echo "pytest=$?"
"$PY" bench/benchmark.py -q         > _bench.txt  2>&1; echo "bench=$?"
"$PY" bench/diag_fields.py          > _diagf.txt  2>&1; echo "diagf=$?"
"$PY" bench/diag_templates.py       > _diag.txt   2>&1; echo "diag=$?"
"$PY" bench/diag_header_body.py     > _hb.txt     2>&1; echo "hb=$?"
"$PY" bench/check_mcp_templates.py  > _check.txt  2>&1; echo "check=$?"
"$PY" tests/smoke_mcp_stdio.py      > _smoke.txt  2>&1; echo "smoke=$?"
```

### 期望基线（2026-09 起，P1 与包头布局用例之后）

| 检查 | 期望 |
|---|---|
| pytest | `165 passed, 3 xfailed` |
| benchmark 汇总 | 正样本 33/33，模板正确 33，P/R/F1/FMS = 1.000，负样本误报 0/9 |
| diag_fields | crc32 尾部 `checksum@-4`、typed-hdr 的 `timestamp/ipv4`、multi-type 分 3 簇 |
| diag_templates | 4 个模板正样本 `det=True`；random512~65536 与 no-delim-text 全部 `det=False` |
| diag_header_body | 前 6 个"支持"用例全对；变长包头/BCD 应显示"不支持" |
| check_mcp_templates | 四模板 `framing.kind` 各自正确，报告含 `[分帧结构]` / `[字段推断]` |
| smoke_mcp_stdio | `RESULT: PASS`，7 个工具注册 |

**3 项 xfail 是已知失败，不是噪声**：零填充包头、变长包头、BCD 长度。
它们用 `strict=False`，一旦被修好会报 XPASS——那时应当把 `xfail` 标记删掉并
同步更新 README §9/§11。**不要为了让 CI 全绿而删掉这些用例。**

**数字变化时先判断是回归还是有意改进**：pytest 用例数、正样本数、`max_seconds`
都会随功能改动而变；但 `P/R/F1/FMS < 1.000` 或负样本误报 > 0 一定是回归。

## 改动算法时的注意点

- 阈值全部集中在 `src/flowunpack/config.py` 的 `AnalysisConfig`，带 `#` 注释说明标定依据；
  改阈值务必回填实测数字。
- `delim_alpha` 方向与其它门槛**相反**：越小越严格。
- 分帧模板的优先级在 `models.KIND_PRIORITY`；集成裁决在 `detectors.choose_framing`
  （覆盖率 → 证据类型 → 帧数 → 分数，顺序有实测依据，别随意调换）。
- 新增/修模板后，同步更新四处：`bench/benchmark.py` 的用例、`tests/test_detection.py`、
  `README.md` 的 §5 工作原理 / §9 评估 / §11 已知限制，以及 `docs/ALGORITHM_ROADMAP.md`。
- README 已于 2026-09-21 重写为正式文档（16 节 + 目录），节号为：
  1 概述 / 2 特性 / 3 安装 / 4 快速开始 / 5 工作原理 / 6 MCP 服务 / 7 Python API /
  8 命令行 / 9 评估 / 10 调参 / 11 已知限制 / 12 项目结构 / 13 开发与测试 /
  14 路线图 / 15 参考 / 16 许可。改文档时保持这个骨架，别把开发日志塞回 README
  （历史记录放 `docs/REFACTOR_NOTES.md`）。
- `fields.py` 的字段推断在**分帧之后**跑，样本上限 `field_max_units`、只扫前
  `field_scan_bytes` 列；改这里不会动分帧结论，但会动 `fields` / `message_types`。
- 改 `refine_by_type` 的目标函数前先想清楚：目标必须**乘字段长度**，否则
  "切得越碎总分越高"，永远选碎分割。
- 任何"熵阈值"类判据都要随样本量自适应（n 个样本单列熵上限 log2(min(n,256))），
  固定阈值在十几帧的流上永远触发不了。

## 清理

跑完删掉临时文件（用 Python，别用 `rm`）：

```python
import os
root = r'E:\opencode_workspace\unpacket'
for n in ('_pytest.txt','_bench.txt','_diagf.txt','_diag.txt','_hb.txt',
          '_check.txt','_smoke.txt','_hb2.txt'):
    p = os.path.join(root, n)
    if os.path.exists(p): os.remove(p)
```
