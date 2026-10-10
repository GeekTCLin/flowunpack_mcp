# 参与贡献

感谢关注 flowunpack！欢迎通过 Issue 报告问题、提交 Pull Request 改进代码或文档。

## 开发环境

```bash
git clone <仓库地址>
cd flowunpack
pip install -e ".[dev]"      # pytest + mcp + scapy
python -m pytest tests -q    # 应全部通过（含少量 xfail = 已知失败）
```

要求 Python ≥ 3.9。核心库（`src/flowunpack`）**零第三方依赖**，贡献时不要给核心库引入新依赖。

## 提交前必做

改动算法后，以下检查应全部通过且基准指标不回退：

```bash
python -m pytest tests -q              # 单测
python bench/benchmark.py              # 分帧基准（P/R/F1/FMS = 1.000，负样本误报 0/9）
python bench/diag_fields.py            # 字段推断诊断
python bench/diag_templates.py         # 四模板集成裁决诊断
python bench/diag_bidir.py             # 双向耦合诊断
python bench/diag_statemachine.py      # 状态机诊断
python tests/smoke_mcp_stdio.py        # MCP 端到端（需安装 mcp）
```

## 约定

### 测试

- 新功能必须带 pytest 用例；修 bug 先写复现用例再修。
- 仓库里少量 `xfail` 用例是**有意保留的已知失败**（变长包头、BCD 长度），
  修复后会报 XPASS——届时请删除 xfail 标记并同步 README。
  **不要为了让 CI 全绿而删除这些用例。**

### 阈值与判据

- 所有阈值集中在 `src/flowunpack/config.py` 的 `AnalysisConfig`，每项带标定依据注释；
  改阈值必须在注释里回填实测数字，并说明对正/负样本的影响。
- 引入新判据时优先考虑**可证伪性**（例如"对打乱数据是否同样成立"），
  而不是往评分函数里加权重。
- `delim_alpha` 方向与其它门槛相反（越小越严格），改动时注意。

### 文档

- 算法行为变化需同步 `README.md` 对应章节（§5 工作原理 / §9 评估 / §11 已知限制）。
- 开发历史与诊断过程写入 `docs/REFACTOR_NOTES.md`，不要塞进 README。
- 新增诊断脚本放 `bench/diag_*.py`，命名与现有风格一致。

### 提交信息

遵循 Conventional Commits：`feat: ...` / `fix: ...` / `docs: ...` / `bench: ...` / `refactor: ...`。

## 报告 Issue

请附上：输入流的 hex（或可复现的最小构造样本）、期望行为、实际行为、
`analyze_stream` 的完整 JSON 输出。涉及真实流量的请先脱敏。
