# flowunpack

**TCP 流二进制协议结构启发式检测库 —— 拆包、自动分帧、字段级语义标注、协议状态机推断，可作为 MCP 服务供 LLM 客户端调用。**

| | |
|---|---|
| 版本 | `1.0.0` |
| 许可 | MIT（[LICENSE](LICENSE)） |
| 依赖 | 核心库**零第三方依赖**；Python ≥ 3.9（实测 3.10 / 3.13） |
| 可选依赖 | `mcp`（MCP 服务，兼容 mcp 1.x / 2.x）、`scapy`（读本地 pcap） |
| 测试 | 254 项 pytest 用例通过（3 项跳过；另 2 项 xfail 标记已知失败） |
| 文档 | 算法路线与论文/开源参考见 [`docs/ALGORITHM_ROADMAP.md`](docs/ALGORITHM_ROADMAP.md)；贡献流程见 [`CONTRIBUTING.md`](CONTRIBUTING.md)；变更历史见 [`CHANGELOG.md`](CHANGELOG.md) |

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

各节内部的小节编号（如 §5.5 协议状态机推断、§6.2 工具列表）不在目录里单独列出。

---

## 1. 概述

### 1.1 它解决什么

给你一条**连续的 TCP 流字节**（没有包边界、没有协议描述），它回答三个问题：

1. **帧在哪切断？** —— 识别分帧模板，把连续字节流切成一帧一帧；
2. **长度字段在哪、怎么解？** —— 长度前缀协议下给出偏移、编码、端序、计数单位；
3. **帧里面是什么？** —— 推断字段边界并标注语义类型（魔数、长度、校验和、时间戳、IPv4……）；
4. **消息按什么顺序出现？** —— 把消息序列抽象成符号序列，推断协议状态机与状态环
   （握手 → 轮询循环这类阶段结构）。

### 1.2 它不解决什么

- **加密 / 压缩流**：字节层面没有可利用的结构，应当先用熵判据显式拒绝。
- **TLV / ASN.1 BER 嵌套结构**：需要递归嵌套推断，当前未实现。
- **有服务端可交互的场景**：本工具是**纯离线**的，不做主动探测
  （DynPRE 那条路线依赖能与服务器交互，不适用）。
- **状态机只有正样本**：推断出的是**过近似**自动机，能说明"观测到的序列长这样"，
  不能判定"别的序列非法"；且单条 trace 无法唯一确定 k（见 §5.5 与 §11）。

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
- **导出下游可执行资产**：boofuzz fuzzing 模板（`s_size`/`s_checksum`）、
  AFLNet/ProFuzzBench 消息切分脚本（消除协议 fuzzing 唯一强制人工输入——消息边界识别）、
  Wireshark Lua dissector，命令行 / Python API / MCP 三种入口。

---

## 3. 安装

```bash
git clone https://github.com/GeekTCLin/flowunpack_mcp
cd flowunpack_mcp                        # 或发布后: pip install flowunpack
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

已 `pip install flowunpack[mcp]` 时，在客户端的 MCP 配置（如 `~/.workbuddy/mcp.json`、
Claude Desktop 的 `claude_desktop_config.json` 等）里加入：

```json
{
  "mcpServers": {
    "flowunpack": {
      "command": "flowunpack-mcp",
      "args": []
    }
  }
}
```

未安装包时，`command` 填 Python 绝对路径、`args` 填 `["<仓库路径>/mcp_server.py"]`
（该入口会自动把 `src` 加入模块搜索路径）。完整示例见 [`mcp-config-example.json`](mcp-config-example.json)。

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
>
> 上表第 3 行的 `rsv1×9` 若填 `0x00`（真实协议的常态），帧边界与帧头长度仍然正确，
> 但长度字段的 `(offset, width)` 会落入**等价族**（实测报 `uint32_be@10`）——
> 这是信息论歧义，不是缺陷。见 §11。

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

### 5.4 双向流联合推断

单条流是**信息不足**的：一条短流常常同时自洽于多种切法，只能靠置换检验这类
弱证据取舍。但真实协议的两个方向**语义耦合**（NetPlier 称之为 remote coupling）——
请求与响应出自同一份格式定义，一方的信息可以用来解除另一方的歧义。
`bidir.py` 提供三条**可验证**的耦合证据：

| 证据 | 判据 | 权重 |
|---|---|---|
| **结构可迁移** | 用 A 的帧长公式去切 B，能完整走完且无剩余 | 0.45 |
| **类型双射** | 第 i 个请求的消息类型与第 i 个响应的类型构成稳定双射 | 0.25 |
| **字段位置一致** | 两侧长度字段的 offset / format / scale 完全相同 | 0.20 |
| **长度相关** | 请求帧长序列与响应帧长序列显著相关（r ≥ 0.7） | 0.10 |

**可迁移性是唯一被当作硬证据的一条**，因为它可证伪：换一条无关的流去切必然走不通。
其余三条是软证据，只用于加权。

迁移有两种用途（`analyze_stream(hint=...)` 保证只增不减，失败即退回正常搜索）：

- **补全** —— 一侧没有可信长度字段（完全未检出，或只被定长/分隔符这类弱模板解释），
  而另一侧的结构能把它完整切开 → 采纳迁移结果。
- **裁决** —— 两侧都有长度字段但**身份不同**且各自自洽。单看一侧无法分辨真假，
  但"共同结构"必须对两边都成立：若 A 的结构能解释 B、反向不成立，则共同结构是 A 的。

裁决不是纸上谈兵。响应侧帧长恒定时，长度字段取值跨帧恒定，而块置换检验**不会改变**
这些字节，于是伪解与真解在置换检验下无法区分；stage-1 短路（见 §5.1 性能）一旦先撞上
伪解就直接收工，得到一个**自信的错误结论**（实测切出 5 帧、匹配 gap 0.74，而真解是 10 帧）。
跨方向的可证伪性是唯一能纠正它的手段：

```python
from flowunpack import analyze_bidirectional, synth

c2s, s2c, spec = synth.make_constant_length_pair(response_body=12)
r = analyze_bidirectional(c2s, s2c)
assert r.s2c.unit_count == 10                    # 单方向只能得到 5 帧
print(r.coupling.repaired)
# ['s2c：5 帧·frame_len = value + 20 → 10 帧·frame_len = value + 4
#   （c2s 的结构可解释 s2c，反向不成立）']
```

三条证据全不成立时，双向给出的是**反面**信息：两侧各自成立却互不呼应，
联合置信度被下调，并在 `message` 里提示"两条流可能不属于同一协议"。
无法裁决的分歧（两侧互相都能解释）记入 `coupling.conflicts` 并再打九折，
不做无依据的改写。

### 5.5 协议状态机推断

上一步得到"有哪几种消息"，这一步回答"它们按什么顺序出现"。`statemachine.py`
把每条消息**符号化**（取命令字），整条流于是变成一个符号序列，再用
**PTA + k-Tail 状态合并**（Biermann & Feldman 1972；Netzob 用的同一族方法）
推断生成它的确定自动机：

1. **符号化** —— 用 keyword 字段（消息类型聚类选出的那个）在每帧上的取值。
   分簇判据不成立时（例如握手的命令字只出现一次，凑不满"每簇 ≥2 条"）自动回退到
   包头里 cardinality 最小的枚举字段。两级都拿不到 → **不做推断并说明原因**。
2. **PTA** —— 把符号序列展开成前缀树接受器。单条流只是一条链，这一步不含压缩。
3. **k-Tail 合并** —— 两个位置若"后 k 步的符号串"相同则视为同一状态，这是 Nerode
   等价关系的 k 阶近似。**末尾不足 k 个符号的位置按最长可用前缀并入已有等价类** ——
   否则链尾会凭空多出一个状态，并让它的前驱出现**假的非确定性**（实测 3 周期序列
   k=2 时冲突数从 0 变成 1）。
4. **环检测** —— SCC 与"绕行次数 ≥ `sm_min_cycle_traversals`"双重门槛。绕行次数
   取环上各转移观测次数的最小值。这道门槛不可省：24 个随机命令字能凑出一个 3 状态环，
   但环上三条转移各只观测到 1 次（只走过一遍），那是巧合 —— 加门槛后该样本环列表清空、
   结构强度从 0.12 降到 0.05。

```python
from flowunpack import analyze_stream, synth

data, spec, cmds = synth.make_interaction_stream()   # 握手 0 + 循环 (1,2,3)×5
r = analyze_stream(data)
sm = r.state_machine
print(sm.describe())
# 4 状态 / 4 转移（k=2，符号 field@2+1 共 16 个）；检测到 1 个环，最长周期 3（最少绕行 3 次）
print(sm.initial_transitions())
# [{'src': 0, 'symbol': '00', 'dst': 1, 'count': 1}]     ← 握手只从初始状态出去
print(sm.cycles, sm.cycle_traversals)
# [['03', '01', '02']] [3]
```

**三条必须与结论一起读的边界**：

- **只从正样本学习**，所有状态都是接受态，得到的是**过近似**自动机：它接受所有观测过的
  序列，对未观测序列不做保证，**不能用来判定"某个序列非法"**。
- **单条 trace 无法唯一确定 k**。"完整走通且确定"的自动机有无穷多个，因此结果里始终带
  `k_sensitivity`（k=1..4 各自的状态数），而不是假装存在唯一答案。实测带单点噪声的样本
  给出 `{1:4, 2:5, 3:6, 4:7}` —— 这个不确定性本身就是要交付的信息。
- **压缩率是"有没有结构"的客观度量**。`compression = 1 − 状态数/符号数`；接近 0 意味着
  状态数 ≈ 符号数，即什么都没推断出来。此时只给低置信度，并在 `notes` 里写明
  "推断结果不具解释力"，不粉饰。

无法符号化（整条流只有一种消息、样本不足、或符号取值互不重复）时 `state_machine`
保持 `None`，原因写在 `statistics["state_machine_summary"]`：**不给结论比给错结论好**。
诊断见 `bench/diag_statemachine.py`。

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
| `analyze_bidirectional` | **双向联合推断**：同时输入 c2s 与 s2c 两条流，交叉验证并互相解歧义 |
| `infer_state_machine` | **状态机推断**：把消息序列按命令字符号化，PTA + k-Tail 推断 DFA 与状态环 |
| `export_template` | **导出下游模板**：kind=boofuzz（fuzzing 脚本）/ aflnet（消息切分脚本）/ lua（Wireshark dissector） |
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

# 状态机：从消息序列推断 DFA（仅在消息可符号化时有值）
if result.state_machine:
    print(result.state_machine.describe())
    print(result.state_machine.cycles)
else:
    print(result.statistics["state_machine_summary"])   # 为什么没推断
```

导出下游模板（boofuzz fuzzing 脚本 / AFLNet 消息切分脚本 / Lua dissector）：

```python
from flowunpack import analyze_stream, export_template

result = analyze_stream(data)
lua_text = export_template(result, "lua", proto_name="myproto")       # Wireshark dissector
splitter_text = export_template(result, "aflnet")                     # AFLNet/ProFuzzBench 切分脚本
fuzz_text = export_template(result, "boofuzz", host="10.0.0.1", port=9999)
# 无法表达的模板（如变长编码 vs 定宽 s_size）会抛 UnsupportedTemplateError
```

覆写阈值：

```python
from flowunpack import analyze_stream
from flowunpack.config import DEFAULT_CONFIG

cfg = DEFAULT_CONFIG.overridden(max_offset=64, max_overhead=128, scan_start_offsets=True)
analyze_stream(data, cfg)

# 状态机相关：k-Tail 深度、最小符号数、符号重复次数门槛
sm_cfg = DEFAULT_CONFIG.overridden(sm_default_k=3, sm_min_symbols=16)
```

主要导出：`analyze_stream` / `analyze_packets` / `resolve_spec` /
`segment_stream` / `apply_spec` / `walk` / `analyze` /
`detect_delimited` / `detect_ascii_length` / `detect_fixed_length` / `choose_framing` /
`infer_fields` / `infer_message_types` / `analyze_bidirectional` /
`infer_state_machine` / `ktail_states` / `render_report`。

---

## 8. 命令行

```bash
python -m flowunpack --hex "0005 4845 4c4c 4f 0005 576f 726c 64"
python -m flowunpack --file stream.bin --json
python -m flowunpack --pcap capture.pcap --flow 0     # 需 scapy
```

导出下游模板（产物为独立脚本，`--out` 写文件、缺省打印）：

```bash
python -m flowunpack --file stream.bin --export boofuzz --out fuzz_proto.py
python -m flowunpack --file stream.bin --export aflnet --out split_messages.py
python -m flowunpack --file stream.bin --export lua --proto-name myproto --out dissector.lua
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
| 单例最长耗时 | 2.5s（本次运行；视机器负载在 2.5~6s 间波动） |

33 个正样本的分布：5 种定长编码 + 魔数 + varint + total_length + scale(2/4/8)
+ 20/200 帧 + CRC trailer + 多字段包头 + 混合消息类型
+ **6 个包头/包体布局**（`hdr-len@0/@3/@12`、`hdr-total`、`hdr-crc`、`hdr-varint`）
+ 3 个分隔符 / 2 个 ASCII 长度 / 1 个定长。

> **读这份数字时要注意**：金标准来自合成流，不是真实抓包。
> 合成负样本（纯随机字节）比真实流量"干净"，真实场景的误报率会更高。
> 字节级 FPR 的第三方佐证参见 BinaryInferno 论文：当前 SOTA 的
> Precision 天花板约 0.69、FPR 约 0.04（见 [§15 参考](#15-参考)）。
>
> **不在基准里的失败**：基准只收"应当成功"的用例。两个已知失败模式以
> `pytest.mark.xfail` 固定在 `tests/test_detection.py::TestHeaderBodyLayout`
> 里（`test_variable_header_should_be_rejected` /
> `test_bcd_length_should_be_rejected`），修好后会自动报 XPASS。
> （**包头零填充**曾在此列，2026-09 已修复并转成正向断言 `test_zero_filled_header`。）

### 9.1 真实协议字段推断基准

`bench/benchmark_real.py` 用**真实抓包**评估字段级推断：金标准来自
`tshark -T pdml` 的原子字段边界（Wireshark 官方测试抓包，样本在 `bench/data/`
随仓库分发），指标为逐边界 Precision/Recall/F1 与 NEMESYS FMS(γ=2)。

```bash
python bench/benchmark_real.py        # 需要 tshark
```

**首次基线**（2026-10，诚实记录）：

| 数据集 | 消息数 | Precision | Recall | F1 | FMS |
|---|---|---|---|---|---|
| mDNS 查询（定长 90B 文本载荷） | 126 | 1.000 | 0.125 | 0.222 | 0.081 |
| DHCP（固定头 + 变长 options） | 4 | 0.500 | 0.034 | 0.063 | 0.027 |
| DNS（非标准端口，最小样本） | 4 | 0.000 | 0.000 | 0.000 | 0.089 |
| git pkt-line（**预期失败**用例） | 4 | 0.000 | 0.000 | 0.000 | 0.000 |

**读这份数字时要注意**：

- 真实协议的字段密度远高于合成流（DNS 头部 6 个 2 字节字段 + 变长域名），
  Recall 低的主要原因是字段推断在真实数据上**过度合并**（边界候选存在但
  DP 合成一个字段）——这与 README §11 的"字段边界分辨率上限"一致，
  是后续 P1（PCA 细化、类型驱动分裂）要解决的问题。
- Precision 仍保持高位（mDNS 1.000）——"几乎总是对的，宁可少报"的设计
  在真实数据上同样成立。
- git pkt-line 是**能力缺口**的真实样本：其 ASCII 长度计"含自身"的总长且
  数据后无终止符，不属于当前 `<数字><term><数据><term>` 模板。
- 4 条消息的数据集低于可靠推断的样本量（`field_min_units` 附近），数字仅作
  退化行为记录。

> 合成基准（§9 上表）回答"分帧边界是否精确"，本基准回答"真实协议上字段
> 边界有多准"；前者是回归门槛，后者是能力地图。

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
- **包头里的零填充保留字段是最常见也最难的形态**（真实协议的保留字段几乎都填 0）。
  零区让"任意偏移读出的长度值"都落在极窄区间，制造出大量等价假设。实测：一个 16
  字节包头、长度字段在 offset 12 的协议，包头中间 9 字节填 `0x00` 时曾被判成
  `offset=2 uint16_le overhead=5` 的 **30 帧伪解**（置信度 0.83），而真解（10 帧）
  **根本不在候选列表里**。根因是走查只要求帧容纳"长度字段 + 1 字节"，长度值为 0 时
  帧长退化成帧头长度，一条"帧长 = 帧头长"的假链恰好把流等分成 30 段。现在走查要求
  帧必须容纳**整个帧头**再加 1 字节载荷（等价于长度值不得为 0），超量伪解全部消失。
  诊断见 `bench/diag_zero_fill.py`。
  **遇到"包头定长但被判出异常多的帧"时，先怀疑包头里的常量/零填充区** —— 这条经验
  对任何长度前缀检测器都适用。
- **零填充下"长度字段的宽度"是不可判的**（信息论层面，非缺陷）：帧边界（10 帧）与
  帧头长度（`overhead=16`）都已正确，但字段的 `(offset, width)` 落入**等价族** ——
  零填充让 b12/b14/b15 恒为 0，`uint8@13` / `uint16_be@12` / `uint32_be@10` 读出
  同一数值、给出同一套帧边界，任何判据都只能在其中挑一个。实测报 `uint32_be@10`
  （比真值多覆盖两个恒零字节）。复核时看"字段是否覆盖了真正的长度字节"即可，
  不必纠结宽度。曾尝试把"字段覆盖的恒定字节数"提到 `_dedup_key` 的宽度之前来修
  这一点，结果 20 项既有断言从 `uint16_be@N` 翻成 `uint8@N+1`、个别样本反而退化
  —— 收益不抵风险，已回退（见 `segmentation._dedup_key` 的说明）。
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

- **双向裁决只在"单向可迁移"时有效**。若两侧的帧长公式不同却**互相都能解释**
  对方（各自都能完整走完对方那条流），信息不足以取舍，此时不做改写、只记录
  `coupling.conflicts` 并把联合置信度打九折。这是有意的保守处理：宁可报告不确定，
  也不做无依据的改写。
- **双向推断要求两个方向共用帧长公式或长度字段位置**。像"请求用长度前缀、
  响应用分隔符"这类异构协议，耦合证据全部不成立，工具会明确提示（这是正确行为，
  不是缺陷）。

**状态机推断的边界**（方法论层面，不是待修的缺陷）

- **只从正样本学习 → 得到过近似自动机**。所有状态都是接受态，它接受所有观测过的
  序列，对未观测序列不做保证，**不能用来判定"某个序列非法"**（拒绝负样本需要负样本
  或主动学习，不在当前范围）。
- **单条 trace 无法唯一确定 k，也无法唯一确定状态机**。任何"完整走通且确定"的自动机
  都是合法假设，因此结果始终携带 `k_sensitivity`（k=1..4 各自的状态数）。看到
  "k=1 给 4 态、k=4 给 7 态"不是 bug，是这个问题的固有不确定性。
- **符号不可得时拒绝，不硬造**：整条流只有一种消息、消息数 < `sm_min_symbols`（12）、
  或符号平均重复次数 < `sm_min_symbol_repeats`（2.0，过滤递增序号/随机数）时，
  `state_machine` 保持 `None` 并在 `statistics["state_machine_summary"]` 写明原因。
- **"环"必带绕行次数门槛**。SCC 只能说明"存在回路"，加上"环上各转移至少观测到
  `sm_min_cycle_traversals`（2）次"才等于"被反复执行的结构"。少于这个门槛的环是
  巧合 —— 实测 24 个随机命令字能凑出 3 状态环但只走过一遍，加门槛后被正确剔除。
- **状态数 ≈ 符号数时不要读结论**。`compression` 接近 0 意味着没有可合并状态，
  推断结果不具解释力；`notes` 会直接这么写。

**性能**

- 长度前缀：核心子空间短路命中时约 1/7 的假设枚举量；未命中则补搜剩余子空间，
  最坏情况与全量同价。54KB 流约 2.5s（视机器负载）。
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
│   ├── bidir.py             双向流联合推断：三条耦合证据 + 跨方向迁移裁决
│   ├── statemachine.py      状态机推断：符号化 + PTA + k-Tail 合并 + 环检测
│   ├── exporters/           导出器（产物为独立脚本，不依赖本库）
│   │   ├── boofuzz.py       boofuzz fuzzing 模板（s_size / s_checksum，仅长度前缀定宽编码）
│   │   ├── aflnet.py        AFLNet/ProFuzzBench 消息切分脚本（四种模板全支持）
│   │   └── lua.py           Wireshark Lua dissector（四种模板全支持，varint 除外）
│   ├── analyzers/
│   │   ├── length_field.py  逐包模式长度字段检测与评分
│   │   └── structure.py     固定字节 / 魔数 / 熵值 / 包头模板
│   ├── engine.py            编排层：analyze_stream / analyze_packets / resolve_spec
│   ├── report.py            文本报告
│   ├── pcap.py              可选：读 pcap（惰性 import scapy）
│   └── synth.py             合成测试数据（可指定高熵/低熵载荷、四种模板）
├── flowunpack_mcp/          MCP 服务实现
├── tests/                   pytest 用例（274 项通过，另 2 项 xfail 标记已知失败）
├── bench/                   评估与剖析脚本
│   ├── benchmark.py         金标准帧边界 → P/R/F1/FMS/FPR（覆盖四种模板）
│   ├── benchmark_real.py    真实协议字段推断基准（tshark PDML 金标准，需 tshark）
│   ├── data/                真实协议样本抓包（Wireshark 官方测试抓包，<100KB 随仓库分发）
│   ├── calibrate.py         正负样本上的置换统计量标定
│   ├── calibrate_staged.py  分阶段搜索短路阈值（min_matched_gap）的标定
│   ├── diag_scale.py        scale 假设为何被伪解压过
│   ├── diag_alias.py        低熵载荷"必然伪解"的诊断
│   ├── diag_templates.py    四种模板的集成裁决行为诊断
│   ├── diag_fields.py       字段边界 / 语义类型 / 消息分簇的诊断
│   ├── diag_header_body.py  包头/包体布局的支持边界与三类失败模式
│   ├── diag_zero_fill.py    零填充伪解的成因拆解（帧长/帧头关系、等价族、修复前后）
│   ├── diag_bidir.py        双向耦合三条证据开关 + 冲突裁决诊断
│   ├── diag_statemachine.py 状态机推断：周期/握手/噪声/拒绝/环绕行门槛诊断
│   ├── profile_search.py    搜索耗时构成剖析
│   ├── profile_p2.py        P2 性能剖析
│   └── check_mcp_templates.py  MCP 工具层 + 报告渲染的模板与字段覆盖校验
├── examples/demo.py         端到端演示
└── docs/
    ├── ALGORITHM_ROADMAP.md 算法改进路线与学术/开源参考
    └── REFACTOR_NOTES.md    重构与开发过程记录

.github/workflows/ci.yml     CI（3.9 / 3.11 / 3.13 矩阵：单测 + 基准 + 诊断 + MCP 端到端）
mcp_server.py                MCP 服务启动入口（免安装直跑）
```

---

## 13. 开发与测试

```bash
python -m pytest tests -q              # 280 项通过（2 项 xfail = 已知失败，见 README §11）
python -m pytest tests -q -rxX         # 打印 xfail 原因
python tests/smoke_mcp_stdio.py        # 真实启动 MCP 进程做端到端验证（含工具清单断言）
python bench/benchmark.py              # 分帧准确率基准（四模板 P/R/F1/FMS + 误报率）
python bench/benchmark_real.py         # 真实协议字段推断基准（需 tshark，基线见 §9.1）
python bench/diag_fields.py            # 字段边界 / 语义类型 / 消息分簇诊断
python bench/diag_templates.py         # 四种模板的集成裁决行为诊断
python bench/diag_bidir.py             # 双向耦合三条证据的开关 + 冲突裁决诊断
python bench/diag_statemachine.py      # 状态机诊断
python bench/check_mcp_templates.py    # MCP 工具层 + 报告渲染的模板覆盖校验
python bench/calibrate.py              # 置换统计量在正负样本上的标定
```

改动算法后，上述检查应全部通过且基准指标不回退（提交前清单见 [`CONTRIBUTING.md`](CONTRIBUTING.md)）。
CI 在 Python 3.9 / 3.11 / 3.13 上跑同一套检查（`.github/workflows/ci.yml`）。

## 14. 路线图

已完成：P0-1（帧长公式推广为 `a·v + b`）、P0-2（多模板探测器集成）、
P0-3（金标准基准）、P1（字段级语义标注 + 消息类型聚类）、
**P2-9（分阶段搜索）**、**P2-8（双向流联合推断）**、**P2-10（状态机推断）**。

**P2 —— 能力拓展**（`docs/ALGORITHM_ROADMAP.md` 第 8~10 项）：

| # | 方向 | 状态与要点 |
|---|---|---|
| 8 | **双向流联合推断**（remote coupling） | ✅ 已完成。`bidir.py` + `analyze_bidirectional` 工具；三条可验证的耦合证据（结构可迁移 / 类型双射 / 字段身份一致 / 长度相关），能**纠正在单方向上被伪解锁定的结论**，也能识别出两条无关的流。见 §5.4。 |
| 9 | **性能优化** | ✅ 已完成。`_search` 拆成"枚举 + 排序"，核心子空间证据足够强时短路（`matched_gap ≥ 0.25`），否则只补搜剩余子空间（不重复枚举，最坏情况与全量同价）。varint 3.98s→1.17s、random-8192 4.51s→0.62s；全套测试 55.6s→10.5s。 |
| 10 | **状态机推断** | ✅ 已完成。`statemachine.py` + `infer_state_machine` 工具：消息符号化（keyword → 枚举字段回退）→ PTA → **k-Tail 状态合并**（末尾短窗口按最长前缀归组，否则产生假非确定性）→ SCC + 绕行次数门槛的环检测。暴露 `k_sensitivity` 与 `compression`，符号不可得时**拒绝而非硬造**。见 §5.5。 |

另有两项延后：评分改为因子图后验概率（需先有标注数据集）、
真实 pcap 语料上的 FPR 评测（需先有语料）。

**P3 —— 开源后的候选方向**（依据 2026-10 的第六轮调研，
`docs/ALGORITHM_ROADMAP.md` 第十一节）：

| # | 方向 | 状态与要点 |
|---|---|---|
| 11 | **fuzzing 桥接** | ✅ 已完成。`exporters/boofuzz.py`（`s_size` + `s_checksum`，仅长度前缀定宽编码，变长编码显式拒绝）+ `exporters/aflnet.py`（独立消息切分脚本，四种模板全支持）。见 §8。 |
| 12 | **Wireshark dissector 导出** | ✅ 已完成。`exporters/lua.py`：四种模板全支持（varint 除外），字段语义 → `ProtoField` 映射，trailer 按帧尾对齐；已用 tshark 实际加载并析出全部帧验证。见 §8。 |
| 13 | **真实协议金标准基准** | ✅ 首轮完成。`bench/benchmark_real.py` + `bench/data/` 样本（Wireshark 官方抓包），基线见 §9.1；后续扩协议语料并随字段推断改进重跑。 |
| 14 | **高熵字段标签** | 未做。给随机/加密区打显式标签，并与长度/CRC 假设做互斥验证（`fields.py` 已有 `random` kind，属于字段推断小修）。 |
| 15 | **LLM 交叉证伪** | 未做。让 LLM 对照猜测的 RFC 证伪 k-Tail 状态机（规范文档路线的反向借鉴）；属编排层，给出示例/文档即可，不做成库内功能。 |

包头零填充导致的超量伪解（30 伪帧 vs 10 真帧）已于 2026-09-21 修复。根因是走查
缺少"帧长必须容纳整个帧头"这条必要条件 —— 在 `frame_len = scale*value + overhead`
里，长度值为 0 时帧长退化成帧头长度。修复见 `segmentation.walk`；回归用例
`tests/test_detection.py::TestHeaderBodyLayout::test_zero_filled_header` 与
`test_frame_must_hold_whole_header`；诊断见 `bench/diag_zero_fill.py`。

残留一项**信息论层面的歧义**（非缺陷）：零填充让长度字段的高/低位字节变成常量，
`(offset, width)` 不可判（实测报 `uint32_be@10`）。见 §11。

---

## 15. 参考

| 项目 | 适用点 |
|---|---|
| [Netzob](https://github.com/netzob/netzob) | 最完整的 PRE 框架：MSA 推断、分隔符、关键字聚类、状态机（PTA / 状态融合） |
| Biermann & Feldman, *On SYNTHESIS of finite-state machines from samples of their behavior* (IEEE TC, 1972) | k-Tail 状态合并的原始方法 —— 本项目 `statemachine.py` 的算法基础 |
| [NetPlier](https://github.com/netplier-tool/NetPlier) | 多序列比对 + 概率因子图推断 keyword（NDSS'21）；双向 remote coupling 的思路来源 |
| [nemesys](https://github.com/vs-uulm/nemesys) | 单消息内在结构、bit 级边界、FMS 指标、PCA 细化边界 |
| [fieldhunter](https://github.com/vs-uulm/fieldhunter) | 语义类型推断（长度/校验和/主机名/命令字） |
| BinaryInferno (NDSS'23) | 探测器集成 + 熵变边界检测 + 序列化模式搜索 |
| [ChatAFL](https://github.com/ChatAFLndss/ChatAFL) (NDSS'24) | LLM 引导的协议 fuzzing：本项目走"确定性结构 + LLM 语义"分层架构的直接参照 |
| AFLNet Five Years Later (IEEE TSE 2025) | 复盘指出消息边界识别是 fuzzing 唯一强制人工输入 —— 本项目分帧输出的核心下游价值 |
| [protodissect](https://github.com/dilates/protodissect) (BSD-3) | 确定性 PRE → Wireshark dissector 导出（P3-12 的路线参照） |
| [ProtoForge](https://github.com/topics/protocol-reverse-engineering) (2026) | 定位最接近的新项目：推断 + 活体回放验证 + 确定性 fuzz |

BinaryInferno 论文给出的 SOTA 对比（值得作为精度天花板的参照）：

| 工具 | Precision | Recall | FPR |
|---|---|---|---|
| BinaryInferno | 0.69 | 0.73 | 0.04 |
| FieldHunter | 0.68 | 0.37 | 0.01 |
| Netzob | 0.57 | 0.42 | 0.03 |
| NEMESYS | 0.31 | 0.44 | 0.11 |
| NetPlier | 0.29 | 0.75 | 0.22 |

完整论文清单（含 Discoverer、NEMESYS、NEMETYL、NetPlier、DynPRE、ROSE/LOTUS、FLINT
等 16 篇，以及 2024-2026 LLM 路线的新工作）见
[`docs/ALGORITHM_ROADMAP.md`](docs/ALGORITHM_ROADMAP.md) 第五、十一节。

---

## 16. 许可

MIT，详见 [LICENSE](LICENSE)。

重构与开发过程记录见 [`docs/REFACTOR_NOTES.md`](docs/REFACTOR_NOTES.md)。
