# 更新日志

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。
（开源发布时把版本条目链接到实际远程仓库的 Release 页。）

## [1.0.0] - 2026-09

首个公开发布版本。

### 新增

- **四种分帧模板**：长度前缀（`frame_len = scale·value + overhead`）、ASCII 文本长度
  （HTTP chunked）、分隔符（泊松尾概率 × Bonferroni 校正）、定长（整除性 + 刚性包头佐证），
  统一集成裁决（覆盖率 → 证据类型优先级 → 帧数 → 分数）。
- **两级置换检验**压误报：匹配置换检验选真解 + 全局 max-vs-max 定采纳，随机数据 0 误报。
- **字段级语义标注**：13 种字段类型（magic/length/checksum/ipv4/timestamp/float 等），
  判据要求对全部样本成立；校验和用 CRC32 反算验证；帧尾 trailer 按帧尾对齐单独推断。
- **消息类型聚类**：包头 keyword 字段识别与分簇，每簇单独出模板。
- **双向流联合推断**（`analyze_bidirectional`）：结构可迁移 / 类型双射 / 字段位置一致 /
  长度相关四条耦合证据，能纠正在单方向上被伪解锁定的结论。
- **协议状态机推断**（`infer_state_machine`）：消息符号化 → PTA → k-Tail 状态合并 →
  SCC + 绕行次数门槛的环检测；暴露 `k_sensitivity` 与 `compression`，符号不可得时拒绝。
- **分阶段搜索**：核心子空间证据足够强时短路，最坏情况与全量搜索同价
  （varint 3.98s→1.17s，全套测试 55.6s→10.5s）。
- **MCP 服务**：10 个工具（`analyze_stream` / `analyze_packets` / `analyze_bidirectional` /
  `infer_state_machine` / `export_template` / `decode_stream` / `explain_spec` /
  `hexdump` / `list_formats` / `service_info`），stdio 与 SSE 传输。
- 命令行入口 `python -m flowunpack`（hex / 文件 / pcap）与 `--export`
  （boofuzz / aflnet / lua）。
- 金标准基准 `bench/benchmark.py`（33 正样本 P/R/F1/FMS = 1.000，9 负样本 0 误报）。
- **导出器** `flowunpack.exporters`：boofuzz fuzzing 模板（`s_size`/`s_checksum`，
  仅长度前缀定宽编码）、AFLNet/ProFuzzBench 消息切分脚本（四种模板全支持）、
  Wireshark Lua dissector（四种模板，varint 除外）；CLI `--export` /
  Python `export_template()` / MCP `export_template` 工具三入口。
- **真实协议基准** `bench/benchmark_real.py`：tshark PDML 原子字段边界作金标准，
  样本抓包（Wireshark 官方测试抓包）在 `bench/data/` 随仓库分发；首次基线见
  README §9.1。
- MCP `infer_state_machine` 工具补注册（此前有实现未注册）。

### 修复

- 包头零填充导致的超量伪解：帧长必须容纳整个帧头（等价于长度值不得为 0），
  30 帧伪解全部消失。
- 帧数 > 96 时检测失效（probe 阶段误杀真实假设）。
- 置换检验采样窗口切断帧、试验次数随流长衰减两个问题。
- 低熵载荷"必然伪解"压过真解：长度值分布与载荷分布总变差距离（TVD）判据。

### 兼容性

- MCP 服务器适配 mcp 1.x / 2.x 两代 API（按构造函数签名自适应传参）。
