# flowunpack

**TCP 流二进制协议结构启发式检测库 —— 拆包、自动分帧、字段级语义标注，可作为 MCP 服务供 Wireshark MCP 调用。**

| | |
|---|---|
| 版本 | `1.0.0` |
| 许可 | MIT |
| 依赖 | 核心库**零第三方依赖**；Python ≥ 3.9（实测 3.13） |
| 可选依赖 | `mcp`（MCP 服务）、`scapy`（读本地 pcap） |
| 测试 | 165 项 pytest 用例（含 3 项标记 xfail 的已知失败） |
| 文档 | 算法路线与论文/开源参考见 [`docs/ALGORITHM_ROADMAP.md`](docs/ALGORITHM_ROADMAP.md) |

---

## 目录

- [1. 概述](#1-概述)
- [2. 特性](#2-特性)
- [3. 安装](#3-安装)
- [4. 快速开始](#4-快速开始)
- [5. 工作原理](#5-工作原理)
- [6. MCP 服务](#6-mcp-服务)
- [7. Python API](#7-python-api)
- [8. 命令行](#8-命令行)
- [9. 评估](#9-评估)
- [10. 调参指引](#10-调参指引)
- [11. 已知限制](#11-已知限制)
- [12. 项目结构](#12-项目结构)
- [13. 开发与测试](#13-开发与测试)
- [14. 路线图](#14-路线图)
- [15. 参考](#15-参考)
- [16. 许可](#16-许可)

---

## 1. 概述

### 1.1 它解决什么

给你一条**连续的 TCP 流字节**（没有包边界、没有协议描述），它回答三个问题：

1. **帧在哪切断？** —— 识别分帧模板，把连续字节流切成一帧一帧；
2. **长度字段在哪、怎么解？** —— 长度前缀协议下给出偏移、编码、端序、计数单位；
3. **帧里面是什么？** —— 推断字段边界并标注语义类型（魔数、长度、校验和、时间戳、IPv4……）。

### 1.2 它不解决什么

- **加密 / 压缩流**：字节层面没有可利用的结构，应当先用熵判据显式拒绝。
- **TLV / ASN.1 BER 嵌套结构**：需要递归嵌套推断，当前未实现。
- **有服务端可交互的场景**：本工具是**纯离线**的，不做主动探测
  （DynPRE 那条路线依赖能与服务器交互，不适用）。

### 1.3 典型链路

```
Wireshark MCP --(单条流 hex/base64)--> flowunpack MCP --(帧结构 + 分帧结果)--> 调用方
```

上游负责"把某条 `tcp.stream` 的 payload 掏出来"，本工具负责"读懂它"。
两者分工明确：本工具**不做**抓包、解析 pcap、重组 TCP 会话。

> 与 Netzob / NetPlier / NEMESYS / BinaryInferno 的关系：它们的输入是
> **一个个独立的消息**，解决"格式推断"；本项目解决的是它们的**前置步骤**
> ——从连续字节流里切出消息边界。详见 [§15 参考](#15-参考)。

---

## 2. 特性

- **四种分帧模板**：长度前缀、ASCII 文本长度（HTTP chunked）、分隔符、定长。
- **显著性检验压误报**：不靠"能走完"判定，用两级置换检验
  （匹配置换选真解 + 全局 max-vs-max 定采纳），随机数据 0 误报。
- **支持非字节计数单位**：帧长公式推广为 `frame_len = scale·value + overhead`，
  `scale=4` 表示长度字段以 4 字节字计（IPv4 的 IHL、部分工控协议）。
- **字段级语义标注**：13 种字段类型，全部判据要求"对全部样本成立"；
  校验和用 CRC32 反算验证。
- **消息类型聚类**：识别包头 keyword 字段并分簇，每簇单独出模板。
- **歧义显式暴露**：一条流同时自洽于多个模板时，给出胜出者并**并列**其余方案，
  不做无依据的取舍。
- **零依赖核心库**：只有读本地 pcap 才需要 scapy；MCP 服务独立可选。

---

## 3. 安装

```bash
pip install -e .            # 核心库（零依赖）
pip install -e ".[mcp]"     # + MCP 服务
pip install -e ".[pcap]"    # + 读本地 pcap（scapy）
pip install -e ".[dev]"     # + 开发（pytest）
```

> 只是把 Wireshark MCP 的流交给本服务检测的话，**不需要 scapy**。

---

## 4. 快速开始

### 4.1 三十秒例子

```python
from flowunpack import analyze_stream

# 一条魔数 + uint16_be 长度前缀的流
data = bytes.fromhex("504b544d" "0005" "48454c4c4f" "0005" "576f726c64")
result = analyze_stream(data)

print(result.detected)                  # True
print(result.length_field.describe())   # 长度字段偏移/编码/端序/公式
print(result.framing.kind)              # 'length_prefixed'
print(result.confidence)                # 0.96
for f in result.frames:
    print(f.offset, f.length, f.body)
```

文本报告：

```python
from flowunpack import render_report
print(render_report(result))
```

### 4.2 接进 MCP 客户端

把 `mcp-config-example.json` 的内容并入客户端的 MCP 配置（如 `~/.workbuddy/mcp.json`），
把 `<PYTHON>` 与 `<PROJECT>` 换成绝对路径：

```json
{
  "mcpServers": {
    "flowunpack": {
      "command": "C:/path/to/python.exe",
      "args": ["E:/opencode_workspace/unpacket/mcp_server.py"]
    }
  }
}
```

> 添加后需在连接管理页对新服务点「信任」才会真正启用。

---

## 5. 工作原理

调用链固定为三段，**后一段不修改前一段的结论**：

```
segmentation   切帧      →  detectors  多模板集成裁决  →  fields  字段解释
```

### 5.1 四种分帧模板

`analyze_stream` 并行跑四个探测器，再按统一规则集成（`detectors.choose_framing`）：

| 模板 `framing.kind` | 帧形态 | 能否自证 | 判据 |
|---|---|---|---|
| `length_prefixed` | `frame_len = scale·value + overhead` | ✓ | 完整走查 + **两级置换检验** |
| `ascii_length` | `<十六进制长度><CRLF><数据><CRLF>`（HTTP chunked） | ✓ | 声明长度必须与后续字节**精确吻合** |
| `delimited` | 每帧以固定字节序列结尾（`\r\n`、RESP…） | ✓（仅**多字节**） | 泊松尾概率 × **Bonferroni 多重比较校正** |
| `fixed_length` | 所有帧等长 | ✗ | 整除性 **+ 跨帧刚性包头**（恒定列）佐证 |

集成规则：**覆盖率 → 证据类型优先级 → 帧数 → 分数**。

两类证据强度不可等同，因此不能只靠打分：

- **能自证的三个模板**里，长度前缀要过完整置换检验；ASCII 长度要求"声明的长度
  与后续字节恰好吻合再跟终止符"，几乎是强约束；分隔符靠频率显著性。
- **单字节分隔符不可自证** —— 它的"随机期望出现次数"就是它自己的出现次数
  （lift 恒为 1），因此只进低置信假设表，不会成为结论。
- **定长帧不可自证** —— 流长的任意因子都构成一个合法定长分帧
  （`random_stream(4096)` 对 1/2/4/8/…/4096 全部成立）。只有存在**刚性包头**
  才提升为结论，且始终低置信。

### 5.2 长度前缀模板

核心假设：协议帧满足

```
frame_len = scale * value + overhead      （变长编码时再 + 字段自身宽度）
```

`scale` 是长度字段的计数单位：`scale=1` 以字节计（绝大多数协议），`scale=4` 以 4 字节字计。
算法枚举 `(offset, format, scale, overhead)`，逐帧走查整条流。

#### 包头 / 包体布局：什么能表达，什么不能

`overhead` 就是"除包体之外的一切实长开销"，所以**包头定长**时，长度字段在包头里的
哪个位置都无所谓——偏移由 `offset` 表达，包头长度折进 `overhead`：

| 布局 | `offset` | `overhead` | 支持 |
|---|---|---|---|
| `[len2][magic2][cmd1][rsv1][body]` | 0 | 6 | ✓ |
| `[magic2][cmd1][len2][seq2][rsv1][body]` | 3 | 8 | ✓ |
| `[magic2][cmd1][rsv1×9][len2][seq2][body]` | 12 | 16 | ✓ |
| 同上但 `value` 含包头（total_length） | 3 | **0** | ✓ |
| `[magic2][cmd1][len2][seq2][rsv1][body][crc4]` | 3 | **12** | ✓ |
| `[magic2][cmd1][varint_len][rsv1][body]` | 3 | 4，`variable_overhead=True` | ✓ |
| **包头长度随命令字变**（6B / 10B 混用） | — | 无单一取值 | **✗** |
| **长度字段偏移随命令字变** | 不固定 | — | **✗** |

前六行都实测通过（见 `bench/diag_header_body.py`）。后两行不是参数没调对，而是
`frame_len = a·v + b` 这个模型**表达不了**——`b` 是常量。穷举全部 `(offset, overhead)`
组合，能走完 12 帧的方案数为 0。

> 长度字段偏移超过 32 时需手动放宽：`max_offset=64`。实测一个 48 字节包头、
> 长度字段在 offset 40 的协议，放宽后能正确切出 10 帧（可能以同族的等价编码给出，
> 如 `uint32_le@41`，但**帧边界完全一致**）。

#### 为什么"走完且无剩余"不够

实测：对 512~4096 字节的随机流，枚举全部假设后能找到数十个"恰好走完"的方案，
`random_stream(65536)` 上甚至能搜出 369 帧的完整走查。

原因是走查的约束**不对称**：只有末帧"恰好落在流尾"需要运气，中间帧只要不越界即可。
所以"能完整走通"在长流上是常态而非异常，判断真伪必须靠显著性检验。

#### 结构证据（用于排序与选择）

1. **假设一致性（agreement）** —— 真实协议会被一族假设同时命中
   （`uint32_le@0` 与 `uint8@0` 在 body<256 时给出**完全相同**的帧边界），
   按帧边界签名分组，组内假设数即一致性证据。
2. **紧致拟合（tight fit）** —— 同一族假设中优先取长度字段紧贴包体的那个，
   这能把"把 uint32 当 uint8 读"的误判纠正回真实宽度。
3. **帧数**（对数曲线，12 帧饱和）—— 帧数的边际证据递减，不能无限加分。
4. 惩罚项：常量字段、只读宽字段低位字节（高位恒为 0）、低熵载荷的"必然伪解"。

#### 接受证据（用于定案，两条并列，满足其一即接受）

| | 统计量 | 回答的问题 | 实测标定 |
|---|---|---|---|
| A | **匹配置换检验**：同一帧结构在原始窗口 vs 打乱窗口上的分数差 | 这条规则有多依赖这组字节排列 → **选谁** | 正样本最小 +0.2817，负样本最大 +0.2180 |
| B | **全局 max-vs-max**：窗口最高分 vs 打乱后各次搜索的最高分 | 这条流里到底有没有结构 → **采纳否** | 正样本最小 +0.0142，负样本最大 −0.0225 |

两条证据的有效域不同，必须并列使用：A 随候选而变（能选出真解，实测含真解排在第 2、3 名时），
但**随机数据上也为正**（巧合分帧同样"打乱就走不通"）；B 是 max 对 max 因此无偏，
但**与候选无关**（无法用于选择）。接受时取匹配 gap 最大的候选；A 优先命中时
不需要计算昂贵的 B（B 要跑 10 次完整搜索）。

#### 并列自洽

一条流常常同时自洽于多个模板（例如 HTTP chunked 也能被 `\r\n` 切成更细的帧）。
程序不做无依据的取舍，而是取出胜出者、把其它自洽方案并列放进
`framing_hypotheses` 并在 `warnings` 里点明。

### 5.3 字段级语义推断

切出帧之后再做一层：`fields.py` 在一组**同类消息**上推断字段边界并标注语义类型。
这一步不改变分帧结论，只在其上叠加解释。

**字段边界**用两条判据取并集（NEMESYS 的 ∆BC 单独用会在短流上退化）：

1. **∆BC**：相邻列的 bit-congruence 跨消息取均值 → 差分 → 高斯平滑 → 局部极大；
2. **列熵突变**：相邻列熵差 ≥ `field_entropy_jump`（1.5 bits）。

得到候选边界后，在边界子集上跑**动态规划**选全局最优分割，目标函数是
`Σ (类型具体程度 + 置信度) × 字段长度 − 字段数 × penalty`。乘字段长度是关键：
它让"用 IPv4 解释 4 字节"胜过"2 字节常量 + 2 字节整数"（26 > 13.4）——
按字段数计分的话切得越碎分越高。

**语义类型**（`fields[].kind`）：
`magic / constant / enum / length / checksum / text / ipv4 / timestamp / float / counter / random / integer / binary`。
所有判据都要求**对全部样本成立**——例如"校验和"必须每条消息都验得上
（CRC32 / 反算 CRC32 / 求和 / 异或，BE 与 LE 各试一遍），这是防误标的主要手段。

**尾部 trailer 必须单独按帧尾对齐去找**：trailer 的位置随帧长变化，在"帧首对齐"
的坐标系里根本看不到（实测一个 `[magic][cmd][len][body][crc32]` 的协议，
帧首对齐最多只能看到最短帧的前 17 列）。结果里 `offset` 为负表示距帧尾。

**消息类型聚类**：在包头区找 keyword 字段（取值会重复、种类少、与帧长耦合），
按取值把帧分簇，每簇给出自己的长度分布与字段模板。找不到可靠 keyword 时返回单一类型。

---

## 6. MCP 服务

### 6.1 启动

```bash
python mcp_server.py                    # stdio（默认）
python mcp_server.py --transport sse
```

### 6.2 工具列表

| 工具 | 用途 |
|------|------|
| `analyze_stream` | **主入口**：输入一条连续流（hex/base64），返回帧结构 + 分帧结果 |
| `analyze_packets` | 逐包模式：输入多个 TCP 包的 payload（hex 数组或多行 hex） |
| `decode_stream` | 用已确定的帧结构切分流，跳过检测（适合二次调用） |
| `explain_spec` | 把帧结构翻译成人类可读说明 |
| `hexdump` | 转储为 offset/hex/ascii，核对输入是否正确 |
| `list_formats` | 列出支持的编码格式 |
| `service_info` | 服务自检（版本、支持的模板、当前阈值） |

### 6.3 典型调用链

```
1) Wireshark MCP  : 导出 tcp.stream == N 的 payload  ->  "504b544d0007..."
2) flowunpack MCP : analyze_stream(stream="504b544d0007...")
                    -> { detected: true,
                         length_field: { offset: 4, format: "uint16_be", overhead: 6,
                                         header_len: 6, body_offset: 6 },
                         confidence: 0.965,
                         frames: [ {offset:0, length:13, body_hex:"464658..." }, ... ] }
3) 后续同协议流    : decode_stream(stream=..., offset=4, format="uint16_be", overhead=6)
```

### 6.4 返回字段说明

```jsonc
{
  "ok": true,
  "detected": true,
  "confidence": 0.965,              // 0~1
  "protocol_hint": "Magic + Length-Prefix",
  "framing": {                      // 通用分帧规格（四种模板统一表示）
    "kind": "length_prefixed",      // length_prefixed | delimited | ascii_length | fixed_length
    "confidence": 0.965,
    "length_field": { ... },        // 仅 length_prefixed
    "delimiter": "",                // 仅 delimited（hex）
    "ascii_radix": 16,              // 仅 ascii_length
    "ascii_terminator": "",         // 仅 ascii_length（hex）
    "frame_len": null,              // 仅 fixed_length
    "start_offset": 0
  },
  "length_field": {                 // length_prefixed 时的便捷镜像（向后兼容）
    "offset": 4,                    // 长度字段起始偏移
    "format": "uint16_be",          // 编码
    "endian": "big",
    "overhead": 6,                  // frame_len = scale*value + overhead
    "variable_overhead": false,     // varint 时为 true，公式再加字段实际宽度
    "semantics": "body_length",     // body_length | total_length
    "header_len": 6,                // 包头长度
    "body_offset": 6,               // 包体起始偏移
    "scale": 1                      // 计数单位：1=字节，4=4 字节字
  },
  "candidates": [ ... ],            // 长度前缀候选排行，含 evidence（agreement / perm gap 等）
  "framing_hypotheses": [ ... ],    // 其它自洽分帧（并列解释）与定长等低置信假设
  "frames": [ { "offset", "length", "declared_value", "header_hex", "body_hex", "ascii" } ],
  "magic": [ { "offset": 0, "hex": "504b544d", "ascii": "PKTM" } ],
  // 字段级推断：帧内相对偏移；offset 为负表示距帧尾
  "fields": [ { "offset": 0, "length": 4, "kind": "magic", "confidence": 1.0,
                "cardinality": 1, "samples": ["504b544d"], "evidence": {...} },
              { "offset": 5, "length": 2, "kind": "length", ... },
              { "offset": -4, "length": 4, "kind": "checksum",
                "evidence": { "algorithm": "crc32(trailer)", "from_end": true } } ],
  "message_types": [ { "index": 0, "count": 6, "keyword_offset": 4,
                       "keyword_values": ["03"], "lengths": [...], "fields": [...] } ],
  "statistics": { "diagnostics": { "permutation": { "gap_max": 0.15 } },
                  "framing": { ... },
                  "field_summary": { "inferred_header_len": 7,
                                     "payload_offset": 6, "trailer_len": 4 } },
  "warnings": []
}
```

`frames[*]` 满足 `header + body == 原始帧字节`，可无损拼回原流（分隔符模板下
`body` 含结尾分隔符——分隔符是帧的终止标记，拆出去就无法复原）。

`detected=false` 时 `candidates` 仍会返回，`statistics.diagnostics.rejected_by`
说明被哪道门槛拒绝（`permutation` / `agreement`），便于人工复核。

---

## 7. Python API

```python
from flowunpack import analyze_stream, analyze_packets, resolve_spec
from flowunpack.io_utils import coerce_bytes

# 流模式（推荐）
result = analyze_stream(coerce_bytes("000548454c4c4f"))
print(result.detected, result.confidence, result.length_field.describe())

# 逐包模式：上游能给出包边界时精度更高
result = analyze_packets([b"\x00\x05HELLO", b"\x00\x05World"])

# 已知结构直接分帧，跳过检测
out = resolve_spec(data, result.length_field)
```

覆写阈值：

```python
from flowunpack import analyze_stream
from flowunpack.config import DEFAULT_CONFIG

cfg = DEFAULT_CONFIG.overridden(max_offset=64, max_overhead=128, scan_start_offsets=True)
analyze_stream(data, cfg)
```

主要导出：`analyze_stream` / `analyze_packets` / `resolve_spec` /
`segment_stream` / `apply_spec` / `walk` / `analyze` /
`detect_delimited` / `detect_ascii_length` / `detect_fixed_length` / `choose_framing` /
`infer_fields` / `infer_message_types` / `render_report`。

---

## 8. 命令行

```bash
python -m flowunpack --hex "0005 4845 4c4c 4f 0005 576f 726c 64"
python -m flowunpack --file stream.bin --json
python -m flowunpack --pcap capture.pcap --flow 0     # 需 scapy
```

---

## 9. 评估

`bench/benchmark.py` 用**金标准帧边界**评测（合成流自带真实 spec，`apply_spec`
走查即得真实边界，无需外部依赖）。

```bash
python bench/benchmark.py
```

**当前结果**（33 个正样本覆盖四种模板 + 9 个负样本）：

| 指标 | 值 |
|---|---|
| 正样本规格与模板完全正确 | **33/33** |
| 帧边界 Precision | **1.000** |
| 帧边界 Recall | **1.000** |
| 帧边界 F1 | **1.000** |
| FMS（NEMESYS 的格式匹配分） | **1.000** |
| 负样本误报（随机流 64B~64KB + 无分隔符文本） | **0/9** |
| 单例最长耗时 | 3.3s（本次运行；视机器负载在 3~6s 间波动） |

33 个正样本的分布：5 种定长编码 + 魔数 + varint + total_length + scale(2/4/8)
+ 20/200 帧 + CRC trailer + 多字段包头 + 混合消息类型
+ **6 个包头/包体布局**（`hdr-len@0/@3/@12`、`hdr-total`、`hdr-crc`、`hdr-varint`）
+ 3 个分隔符 / 2 个 ASCII 长度 / 1 个定长。

> **读这份数字时要注意**：金标准来自合成流，不是真实抓包。
> 合成负样本（纯随机字节）比真实流量"干净"，真实场景的误报率会更高。
> 字节级 FPR 的第三方佐证参见 BinaryInferno 论文：当前 SOTA 的
> Precision 天花板约 0.69、FPR 约 0.04（见 [§15 参考](#15-参考)）。
>
> **不在基准里的失败**：基准只收"应当成功"的用例。三个已知失败模式以
> `pytest.mark.xfail` 固定在 `tests/test_detection.py::TestHeaderBodyLayout`
> 里（`test_zero_filled_header` / `test_variable_header_should_be_rejected` /
> `test_bcd_length_should_be_rejected`），修好后会自动报 XPASS。

---

## 10. 调参指引

所有阈值集中在 `flowunpack/config.py` 的 `AnalysisConfig`。

| 场景 | 建议 |
|------|------|
| 流首部有握手/非协议字节 | `scan_start_offsets=True` |
| 长度字段位置靠后 | 调大 `max_offset` |
| 包头很长 | 调大 `max_overhead` |
| 长度以字/双字计（非字节） | 默认已枚举 `scales=(1,2,4,8)`；只在确定不用时可收窄以提速 |
| 只有 2~3 帧就想出结果 | 调小 `min_frames`（会降低抗误报能力） |
| 误报偏多 | 调高 `min_matched_gap` / `min_perm_gap`；或调小 `delim_alpha`（更严） |
| 漏报偏多 | 调低 `min_matched_gap`；或调大 `verify_candidates` 让更多候选参与验证 |
| 分隔符太短（如 `\x00\x00`）漏检 | 调低 `delim_min_frames` 或调大 `delim_alpha`（会放松多重比较校正） |
| 定长帧未被识别 | 检查是否有刚性包头；`fixed_min_constant_ratio` 调低可放宽（但会增加误报） |
| 超大流（>256KB）嫌慢 | 调小 `perm_trials`；超过 `perm_max_bytes` 会自动关闭置换检验 |
| 字段被切得太碎 | 调大 `field_segment_penalty`（每多一个字段的扣分）；或调小 `field_entropy_jump` |
| 帧首魔数被并进相邻字段 | 调大 `field_segment_penalty`（默认 2.0）；帧首常量被并成 enum/random 是显式禁止的 |
| 样本多、字段推断太慢 | 调小 `field_max_units`（默认 128）或 `field_scan_bytes`（默认只推断前 64 列） |
| 消息类型没分出来 | 需要 ≥ `cluster_min_units`（6）帧，且包头区存在"取值会重复、种类 ≤16"的字段 |

> `delim_alpha` 是**显著性门槛**，方向与其它"门槛"相反：取值越小越严格。
> 分隔符检测用"泊松尾概率 × Bonferroni 校正"，短流上朴素 lift 会被随机尖峰
> 击穿（实测 `random_stream(8192)` 必然存在某个 2-gram 出现 4~5 次、朴素 lift 高达 32），
> 因此校正这一环不能省。

---

## 11. 已知限制

**能力边界**

- **TLV / ASN.1 BER 嵌套、加密/压缩流**不在能力范围内：前者需要递归嵌套结构推断，
  后者应先用熵判据显式拒绝。
- **单字节分隔符**（`\n`、`\x00`）不可自证——它的随机期望出现次数就是它自己的出现次数
  （lift 恒为 1），因此只作低置信假设列出，不会成为结论。
- **无刚性包头的定长帧**不可自证（流长的任意因子都构成合法分帧），无法从字节自身识别；
  需要上游给出包边界，此时应改用 `analyze_packets`。
- ASCII 长度模板只覆盖 `<数字><终止符>` 形态（HTTP chunked / 十进制文本长度）。
  允许前导字节时的起始位置扫描范围是 `ascii_scan_start`（默认 64）；
  真实 HTTP 报文头更长时需自行截取 body。
- 变长编码仅支持 `varint`/`varint_be`/`uleb128` 等常见形态，不含 QUIC 的 2-bit 前缀 varint。

**歧义不消除（有意的设计）**

- 一条流常常同时自洽于多个模板，程序**不做自动消除**：给出胜出者作为结论，
  其余并列放进 `framing_hypotheses` 并在 `warnings` 里点明。
  实测：一个 12 条刚性定长记录的流也能被一条 4 帧的长度前缀规则完整铺满，
  此时报告的是长度前缀并同时列出定长。
- **IPv4 / 时间戳 / 浮点三者存在歧义**（都是 4 字节），判据只能要求"对全部样本成立"
  并按信息量排序，不能消除歧义；`evidence` 里会写明。

**精度上限**

- 样本需 ≥ 4 帧（`min_frames`），否则无法排除巧合。
- **低熵载荷（HTTP/SMTP/SIP 等文本 body）是最难的情形**：任意偏移读出的字节都落在窄区间，
  会产生大量"必然伪解"。当前靠帧数评分、紧致拟合与置换检验缓解，但未根治。
- **包头里的零填充保留字段同样危险，且比低熵载荷更常见**。实测：一个 16 字节包头、
  长度字段在 offset 12 的协议，包头中间 9 字节填 `0x00` 时给出 30 帧的伪解且置信度
  高达 0.83；同样的布局填 `0xAA` 则完全正确（见 `bench/diag_header_body.py`）。
  **遇到"包头定长但被判出异常多的帧"时，先怀疑包头里的常量/零填充区。**
- **包头里含逐帧随机字段（序列号、会话 ID、随机数）时结论不稳定**：真解通常仍在
  候选列表里，但可能排在伪解之后；跑法不同的数据可能翻车。
- **变长包头（包头长度随命令字变化）在模型上就无解** —— `frame_len = a·v + b` 里的
  `b` 是常量，无法同时表达两种包头长度。实测穷举全部 `(offset, overhead)` 组合，
  能走完 12 帧的方案数为 **0**。这类协议只能先按消息类型分簇、再逐簇单独建模（P1 的
  `message_types` 是这条路的起点，但尚未接回分帧）。
- **字段边界的分辨率有上限**：字段后面紧邻高熵载荷时，两者在熵上无法区分，
  边界会被并进载荷（实测：包头末尾的 IEEE 754 浮点字段与随后的随机载荷之间
  提不出边界）。NEMESYS 同样有此现象（其后续工作用 PCA 细化边界）。
- **消息类型聚类只认包头区**、且要求 keyword 取值重复（≥2 帧同类）并与帧长耦合。
  随机数字段、计数器都无法当 keyword。

**性能**

- 长度前缀：35 185 个假设 × 完整走查，54KB 流约 3~6s（视机器负载）。
- 字段推断：只在切出的帧上做（样本上限 128、只扫前 64 列），实测增量 < 0.2s。
- 定长枚举：仅 ≤ 1MB 且长度前缀未定案时执行，约 0.3s。
- 大流建议先截取前若干 KB 试跑。

---

## 12. 项目结构

```
src/
├── flowunpack/              核心库（零第三方依赖）
│   ├── codecs.py            变长/定长整数编解码（唯一实现）
│   ├── io_utils.py          hex / base64 / 多形态输入归一化
│   ├── models.py            LengthFieldSpec / FramingSpec / Frame / AnalysisResult / FieldSpec
│   ├── config.py            全部阈值与权重（可调，集中一处）
│   ├── segmentation.py      长度前缀模板：流级自动分帧 + 两级置换检验（核心算法）
│   ├── detectors.py         分隔符 / ASCII 长度 / 定长 三个模板探测器 + 集成裁决
│   ├── fields.py            字段级推断：边界 + 语义类型 + 消息类型聚类
│   ├── analyzers/
│   │   ├── length_field.py  逐包模式长度字段检测与评分
│   │   └── structure.py     固定字节 / 魔数 / 熵值 / 包头模板
│   ├── engine.py            编排层：analyze_stream / analyze_packets / resolve_spec
│   ├── report.py            文本报告
│   ├── pcap.py              可选：读 pcap（惰性 import scapy）
│   └── synth.py             合成测试数据（可指定高熵/低熵载荷、四种模板）
├── flowunpack_mcp/          MCP 服务实现
├── tests/                   pytest 用例（165 项，其中 3 项 xfail 标记已知失败）
├── bench/                   评估与剖析脚本
│   ├── benchmark.py         金标准帧边界 → P/R/F1/FMS/FPR（覆盖四种模板）
│   ├── calibrate.py         正负样本上的置换统计量标定
│   ├── diag_scale.py        scale 假设为何被伪解压过
│   ├── diag_alias.py        低熵载荷"必然伪解"的诊断
│   ├── diag_templates.py    四种模板的集成裁决行为诊断
│   ├── diag_fields.py       字段边界 / 语义类型 / 消息分簇的诊断
│   ├── profile_search.py    搜索耗时构成剖析
│   └── check_mcp_templates.py  MCP 工具层 + 报告渲染的模板与字段覆盖校验
├── examples/demo.py         端到端演示
└── docs/
    ├── ALGORITHM_ROADMAP.md 算法改进路线与学术/开源参考
    └── REFACTOR_NOTES.md    legacy → flowunpack 的重构说明
legacy/                      旧脚本（已归档，不参与构建，仅作参考）
```

---

## 13. 开发与测试

```bash
python -m pytest tests -q              # 165 项（3 项 xfail = 已知失败，见 README §11）
python -m pytest tests -q -rxX         # 打印 xfail 原因
python tests/smoke_mcp_stdio.py        # 真实启动 MCP 进程做端到端验证
python bench/benchmark.py              # 分帧准确率基准（四模板 P/R/F1/FMS + 误报率）
python bench/diag_fields.py            # 字段边界 / 语义类型 / 消息分簇诊断
python bench/diag_templates.py         # 四种模板的集成裁决行为诊断
python bench/check_mcp_templates.py    # MCP 工具层 + 报告渲染的模板覆盖校验
python bench/calibrate.py              # 置换统计量在正负样本上的标定
```

改动算法后，上述五项应全部通过且基准指标不回退。

## 14. 路线图

已完成：P0-1（帧长公式推广为 `a·v + b`）、P0-2（多模板探测器集成）、
P0-3（金标准基准）、P1（字段级语义标注 + 消息类型聚类）。

**P2 —— 能力拓展**（`docs/ALGORITHM_ROADMAP.md` 第 8~10 项）：

| # | 方向 | 要点 |
|---|---|---|
| 8 | **双向流联合推断**（remote coupling） | 请求与响应语义强耦合。新增接受 c2s / s2c 两条流的工具，用双向证据互相验证。参考 NetPlier。 |
| 9 | **性能优化** | 8KB 流上置换检验占总耗时 91%。手段：numpy 向量化走查、置换检验只对 top-K 做、跨调用缓存 spec（同一五元组结构不变）。 |
| 10 | **状态机推断** | 在消息类型聚类之后，按消息序列推断协议状态机。参考 Netzob 的 PTA / 主状态机推断。 |

另有两项延后：评分改为因子图后验概率（需先有标注数据集）、
真实 pcap 语料上的 FPR 评测（需先有语料）。

---

## 15. 参考

| 项目 | 适用点 |
|---|---|
| [Netzob](https://github.com/netzob/netzob) | 最完整的 PRE 框架：MSA 推断、分隔符、关键字聚类、状态机 |
| [NetPlier](https://github.com/netplier-tool/NetPlier) | 多序列比对 + 概率因子图推断 keyword（NDSS'21） |
| [nemesys](https://github.com/vs-uulm/nemesys) | 单消息内在结构、bit 级边界、FMS 指标、PCA 细化边界 |
| [fieldhunter](https://github.com/vs-uulm/fieldhunter) | 语义类型推断（长度/校验和/主机名/命令字） |
| BinaryInferno (NDSS'23) | 探测器集成 + 熵变边界检测 + 序列化模式搜索 |

BinaryInferno 论文给出的 SOTA 对比（值得作为精度天花板的参照）：

| 工具 | Precision | Recall | FPR |
|---|---|---|---|
| BinaryInferno | 0.69 | 0.73 | 0.04 |
| FieldHunter | 0.68 | 0.37 | 0.01 |
| Netzob | 0.57 | 0.42 | 0.03 |
| NEMESYS | 0.31 | 0.44 | 0.11 |
| NetPlier | 0.29 | 0.75 | 0.22 |

完整论文清单（含 Discoverer、NEMESYS、NEMETYL、NetPlier、DynPRE 等 12 篇）
见 [`docs/ALGORITHM_ROADMAP.md`](docs/ALGORITHM_ROADMAP.md) 第五节。

---

## 16. 许可

MIT。详见 [`pyproject.toml`](pyproject.toml)。

`legacy/` 目录下的旧脚本仅作历史对照保留，不参与构建、不被测试覆盖、不再维护。
重构改了什么见 [`docs/REFACTOR_NOTES.md`](docs/REFACTOR_NOTES.md)。
