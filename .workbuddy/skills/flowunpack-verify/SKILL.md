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

## 一键回归（10 项，全部应 exit 0）

不要用 `&&` 串联后只看尾部——分开跑并逐个记录退出码：

```bash
PY="C:/Users/Xi/.workbuddy/binaries/python/envs/default/Scripts/python.exe"
"$PY" -m pytest tests -q -rxX        > _pytest.txt 2>&1; echo "pytest=$?"
"$PY" bench/benchmark.py -q         > _bench.txt  2>&1; echo "bench=$?"
"$PY" bench/diag_fields.py          > _diagf.txt  2>&1; echo "diagf=$?"
"$PY" bench/diag_templates.py       > _diag.txt   2>&1; echo "diag=$?"
"$PY" bench/diag_header_body.py     > _hb.txt     2>&1; echo "hb=$?"
"$PY" bench/diag_header_body2.py    > _hb2.txt    2>&1; echo "hb2=$?"
"$PY" bench/diag_zero_fill.py       > _zf.txt     2>&1; echo "zf=$?"
"$PY" bench/diag_bidir.py           > _bidir.txt  2>&1; echo "bidir=$?"
"$PY" bench/check_mcp_templates.py  > _check.txt  2>&1; echo "check=$?"
"$PY" tests/smoke_mcp_stdio.py      > _smoke.txt  2>&1; echo "smoke=$?"
```

### 期望基线（2026-09-21 起，零填充修复之后）

| 检查 | 期望 |
|---|---|
| pytest | `210 passed, 3 skipped, 2 xfailed` |
| benchmark 汇总 | 正样本 33/33，模板正确 33，P/R/F1/FMS = 1.000，负样本误报 0/9 |
| diag_fields | crc32 尾部 `checksum@-4`、typed-hdr 的 `timestamp/ipv4`、multi-type 分 3 簇 |
| diag_templates | 4 个模板正样本 `det=True`；random512~65536 与 no-delim-text 全部 `det=False` |
| diag_header_body | 前 6 个用例全标"支持"（`len@12` 走 `equiv` 判据，见下）；变长包头/BCD 应"不符" |
| diag_header_body2 | 追查一三行"正确"；追查二只有 `max_offset=64` 的两行"正确"（默认配置那行是参数不足，预期"错误"） |
| diag_zero_fill | 一：旧判据复现 30 帧（含 10 个零载荷帧）；二：A/B 均 **10 帧且帧边界一致**；三：等价族含 `uint32_be@10`；四：四种填充全部 10 帧 |
| diag_bidir | 用例 1~4 的耦合证据开关符合期望；用例 7 两组必须出现 `[修复]`（s2c → 10 帧） |
| check_mcp_templates | 四模板 `framing.kind` 各自正确，报告含 `[分帧结构]` / `[字段推断]` |
| smoke_mcp_stdio | `RESULT: PASS`，**8** 个工具注册（含 `analyze_bidirectional`） |

**2 项 xfail 是已知失败，不是噪声**：变长包头、BCD 长度。
它们用 `strict=False`，一旦被修好会报 XPASS——那时应当把 `xfail` 标记删掉并
同步更新 README §9/§11。**不要为了让 CI 全绿而删掉这些用例。**
（零填充包头曾在此列，2026-09-21 已修复并转成正向断言 `test_zero_filled_header`。）

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

### 两条 P2 期间踩过的坑（改对应模块前先读）

**改 `segmentation.py` 的分阶段搜索（P2-9）**：短路判据必须与最终决策用**同一条**
候选级证据（`matched_gap ≥ min_matched_gap`），否则就是"悄悄换结论换来的加速"。
`tests/test_staged_search.py` 里有一条**不等于**：8 帧 varint 上全量搜索拒绝、
分阶段接受（全量的 top-K 被冷子空间伪解挤占）。断言写成"分阶段 ≥ 全量"，
别改成严格相等，那不是 bug。

**改 `bidir.py`（P2-8）**：判断"两侧结论矛盾"只能比较**长度字段身份**
`(offset, format, scale, variable_overhead)`，**不能包含 `overhead`** ——
请求与响应的包头长度不同是常态（响应多带状态码/时间戳），把它当冲突会
无端下调正常协议的置信度（实测 0.870→0.783）。`overhead` 差异只意味着
"结构不可迁移"，不意味着"冲突"。

另注：`bidir` 的"补全"路径（一侧完全未检出、靠另一侧迁移补上）在随机搜索
400 组样本里命中 0 次 —— 因为 hint 与自身搜索都要求走查完整且 ≥ `min_frames`。
真正的价值在**冲突裁决**（`synth.make_constant_length_pair`，默认 `response_body=12`
即触发）。不要为了"演示补全"去构造不自然的样本。

**改 `walk` 的帧长下限（零填充修复，2026-09-21）**：帧必须容纳**整个帧头**
（`overhead + 长度字段宽度`）再加 1 字节载荷，等价于"长度值不得为 0"。
旧判据 `frame_len < offset + width + 1` 在长度字段埋于帧头中间
（`offset + width < overhead`）时允许 `frame_len == overhead` 的零载荷帧，
于是包头零填充会被切成 30 段（真解 10 段）。守它的是
`test_frame_must_hold_whole_header` 与 `test_zero_filled_header`。

注意：零填充下长度字段的 `(offset, width)` 是**等价族** —— `uint16_be@12` /
`uint8@13` / `uint32_be@10` 数值与帧边界完全相同（零填充让高位字节恒为 0），
实测报 `uint32_be@10`。**试过**把"字段覆盖的恒定字节数"插到 `_dedup_key`
的 width 之前来纠正它，结果 20 项断言从 `uint16_be@N` 翻成 `uint8@N+1`、
个别样本反而退化，已回退。**别重复这个尝试**；等价族要断言就断言"字段覆盖了
真实长度字节 + 帧头长度正确"，不要断言具体 offset。

## 清理

跑完删掉临时文件（用 Python，别用 `rm`）：

```python
import os
root = r'E:\opencode_workspace\unpacket'
for n in ('_pytest.txt','_bench.txt','_diagf.txt','_diag.txt','_hb.txt',
          '_check.txt','_smoke.txt','_hb2.txt','_bidir.txt','_zf.txt'):
    p = os.path.join(root, n)
    if os.path.exists(p): os.remove(p)
```
