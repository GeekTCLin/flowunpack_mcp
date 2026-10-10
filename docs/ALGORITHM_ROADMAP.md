# 分帧检测算法：改进空间与学术/开源参考

本文基于对 `src/flowunpack/segmentation.py` 的逐条实测（非推演），记录当前算法的能力边界、
已修复的缺陷、按 ROI 排序的改进清单，以及可参照的开源实现与论文。

---

## 一、本轮实测发现并已修复的缺陷

### 1. 帧数 > 96 时检测彻底失效（最严重）

`_search` 先用 `probe=max_probe_frames`（默认 96）做快速走查，并**要求 probe 阶段就
`complete=True`**。而 `walk()` 一旦走满 96 帧就提前返回 `complete=False`，于是真实假设
在探测阶段就被整轮误杀：

```
修复前（uint16_be 长度前缀流）
  真实帧数=  96  det=True   报告帧数=  96
  真实帧数= 100  det=False  报告帧数=   0     ← 断崖
  真实帧数= 400  det=False  报告帧数=   0
  真实帧数=1000  det=False  报告帧数=   0
```

Wireshark 导出的一条流动辄几百上千帧，这个缺陷在真实场景里是致命的。

**修复**：给 `WalkResult` 增加 `probe_limited` 状态——探测走满上限且全程未出错，是"提前收工"
而非"失败"；终判交给完整走查的 `leftover == 0`。

```
修复后
  真实帧数= 100  det=True   报告帧数= 100
  真实帧数= 400  det=True   报告帧数= 400
  真实帧数=2000  det=True   报告帧数=2000   t=3.53s
```

### 2. 置换检验的采样窗口切断了帧，导致大流上观察值恒为 0

置换检验原本在 `data[:8192]` 上重跑搜索。但窗口边界几乎必然落在某一帧的中间，
窗口内任何假设都无法"走完且无剩余" → 观察分数恒为 0、打乱后的分数也是 0 → `gap = 0` →
把真实协议全部误杀。

**修复**：窗口按**已检出假设的帧边界**对齐后再采样。

### 3. 置换检验次数随流长衰减到 2，放行荒谬解

原实现对流 >64KB 把 `perm_trials` 降到 2。方差过大，实测一条 78 KB 流被切成 **4 帧**
的巧合解，却以 `gap_max=0.54` 通过检验。

**修复**：试验次数恒定，代价改为由**固定采样窗口**（默认 8 KB）控制；观察值必须在
同一窗口上计算，保证分数尺度一致。

### 4. 低熵载荷产生"必然解"，压过真实解（根本性难点）

这是本轮最有价值的发现。合成载荷是 ASCII 文本（字节值集中在 0x30–0x5A），
于是**任意偏移读出的字节都落在窄区间内**，一个"长度字段 + 合适的 overhead"很容易把整条流走完。
这不是巧合，是载荷分布的必然结果：

```
54 KB 的 varint 流，真解只有 14 帧；搜索却给出：
  uint8@0+36  → 515 帧，leftover=0，score 0.712   ← 胜出
  uint8@3+11  → 661 帧，leftover=0，score 0.704
  uint8@6+20  → 605 帧，leftover=0，score 0.695
  varint@0+0  →  14 帧（真解），score 0.653       ← 被压过
```

**修复**：新增 `_payload_alias()` 判据——比较**长度值的经验分布**与**载荷字节分布**的
总变差距离（TVD）。真长度字段的取值来自独立语义，分布必然偏离载荷分布或干脆超出单字节值域；
而"必然解"的长度值就是载荷字节本身，两者分布几乎重合。重合则按
`penalty_payload_alias=0.60` 重罚。

修复后：8/8 正样本全部正确，0 误报，102 项测试通过。

> 这条判据对真实协议同样重要：HTTP、SMTP、SIP、Redis 等文本载荷协议的 body 都是低熵的，
> 这个问题不是测试数据的瑕疵，而是真实场景的主要风险来源。

---

## 二、仍然存在的边界（实测）

| 协议形态 | 实测结果 | 说明 |
|---|---|---|
| 定长帧（如 NTP 48 字节） | `detected=False` | 完全没有长度字段，当前只搜索"长度前缀"这一种模板 |
| 分隔符分帧（`\r\n`、Redis RESP） | `detected=False` | 未实现 delimiter 假设 |
| HTTP chunked（长度是 **ASCII 十六进制**） | `detected=False` | 未实现文本编码的长度字段 |
| 长度字段 + CRC32 尾部 | 检测成功，但 CRC 被算进 body | 能定帧，但无法识别 trailer，语义不完整 |
| 高熵随机 4 KB | 正确拒绝 | 置换检验有效 |
| 长度字段以字/双字为单位（`frame_len = 4·v`） | `detected=False` | 当前 `frame_len = value + overhead` 只能表达斜率 a=1，见第七节 |
| TLV / ASN.1 BER 嵌套 | 未覆盖 | 需要递归/嵌套结构推断 |

---

## 三、改进清单（按 ROI 排序）

### P0 — 投入小、收益确定

**1. 补齐分帧模板（定长 / 分隔符 / ASCII 长度）**
当前只有 `frame_len = value + overhead` 一种模板。建议扩展为四个并行假设族：
`length_prefixed`（现有）、`fixed_length`（所有帧等长，用 gcd 或众数判定）、
`delimited`（扫描重复出现的分隔字节序列）、`ascii_length`（hex/dec 文本长度 + 分隔符）。
Netzob 明确把协议分为 text / delimiter-based / fixed-fields / variable-length 四类。

**2. 加密与压缩流量的显式拒绝**
整体字节熵 > ~7.9 bits/byte 时直接返回"疑似加密或压缩，无法分析"，而不是给出一堆低置信候选。
零成本，显著减少误用。（所有主流工具都把加密流量排除在适用范围外。）

**3. 建立 ground-truth 基准**
目前只有自造的合成样本，说服力有限。建议用 `tshark -T json` 导出真实协议
（DNS / DHCP / NTP / SMB / Modbus / DNP3 / MAVLink）的字段边界作为金标准，
再套用学界通用指标（见第五节）。**这是判断"能不能信"的唯一途径。**

### P1 — 结构性升级

**4. 用列变化分布定位候选偏移（取代全枚举）**
当前对 offset 0..32 × 11 种格式 × overhead 全枚举，代价高且候选多。
NEMESYS 的思路是：先看**单条消息内部的字节值变化分布**在哪些位置出现拐点，
把候选偏移从 32 个降到 2–3 个。这既解决性能，也减少伪解。

**5. 把手工加权评分换成概率推断**
`config.py` 里 `s_frames=0.22 / s_agreement=0.25 …` 是拍脑袋定的权重，且实测显示
agreement 权重过高（低熵载荷上的伪解能凑出 agreement=3 而胜出）。
NetPlier 的做法值得照搬：把"哪个字段是长度字段"建模为**随机变量**，把"跨帧恒定度"
"值与帧长的相关性""请求-响应耦合"作为观测因子，用因子图 + sum-product 求后验概率。
这样权重由数据和模型结构决定，而不是手工调参。

**6. 消息类型聚类（keyword 识别）**
当前一条流只输出一个 spec。真实流里混杂请求/响应和多种命令字，
应当在分帧后识别 header 中"取值少且分簇明显"的 keyword 字段，按它分簇、每簇单独出模板。
这是 NetPlier / NEMETYL 的核心步骤，也是下游写 dissector 或做 fuzzing 的前提。

**7. 字段语义标注**
分帧之后给每个字段打类型标签：ASCII/UTF-8 文本、IPv4/IPv6、Unix 时间戳、IEEE 754 浮点、
CRC/校验和（可用 CRC32 反算验证）、枚举（低基数）、随机数/会话 ID（高熵）。
BinaryInferno 用"探测器集成 + 图搜索取最大覆盖"来合并冲突结论，架构可直接借鉴。
其中 **checksum 检测**对本项目特别有用：能反过来确认 header_len 并识别 trailer。

### P2 — 能力拓展

**8. 双向流联合推断（remote coupling）**
NetPlier 的关键洞察：请求与响应在语义上强耦合，联合建模能大幅提升准确率。
当前 MCP 只接受单条流，建议增加接受 c2s / s2c 两条流的工具，用双向证据互相验证。

**9. 性能优化**
实测 8 KB 流上置换检验占总耗时的 **91%**（search 0.11s vs perm 1.10s）。
可选手段：用 numpy 向量化走查；置换检验只对 top-K 候选做；跨调用缓存 spec
（同一五元组的协议结构不会变）。

**10. 状态机推断**
在消息类型聚类之后，按消息序列推断协议状态机。Netzob 内置 PTA / 主状态机推断，可直接参考。

---

## 四、开源实现参考

| 项目 | 语言/许可 | 适用点 | 备注 |
|---|---|---|---|
| [Netzob](https://github.com/netzob/netzob) | Python / GPLv3 | 最完整的 PRE 框架：MSA 推断、分隔符、关键字聚类、状态机、流量生成与 fuzzing | 仓库最后更新 2024-04，依赖较重（含 C 扩展）；nemesys 要求其 `fix-layer-build` 分支而非官方版 |
| [NetPlier](https://github.com/netplier-tool/NetPlier) | Python | 多序列比对 + 概率因子图推断 keyword | NDSS'21，代码与数据集均公开 |
| [nemesys](https://github.com/vs-uulm/nemesys) | Python | 单消息内在结构、bit 级边界、消息类型聚类(NEMETYL)、字段类型分类、PCA 细化边界、FMS 指标 | 同一仓库含 4 篇后续工作，是最贴近"改进清单"的一手实现 |
| [fieldhunter](https://github.com/vs-uulm/fieldhunter) | Python | 语义类型推断（长度/校验和/主机名/命令字等） | FieldHunter 论文的公开复现版 |
| BinaryInferno | Python | 探测器集成 + 熵变边界检测 + 序列化模式搜索 | NDSS'23，论文声明开源（官方站点 BinaryInferno.net），提供 Colab notebook |

> 注意：这些工具的输入都是**一个个独立的消息**（每行一条 hex），而不是一条连续的 TCP 流。
> 它们解决的是"格式推断"，**不做**"从连续字节流里切出帧边界"。本项目做的分帧
> （segmentation）恰好是它们的前置步骤——这也是本项目相对它们的独特价值所在。
> 反过来，它们的字段级能力正是本项目 P1 阶段要补的。

---

## 五、论文参考

### 奠基与序列比对路线

1. **Beddoe, "Network Protocol Analysis using Bioinformatics Algorithms"**, McAfee Inc. 技术报告, 2004.
   把生物信息学的序列比对引入协议逆向（Protocol Informatics 项目）。非同行评审，但是该路线起点。
2. **Cui, Kannan, Wang, "Discoverer: Automatic Protocol Reverse Engineering from Network Traces"**,
   *USENIX Security 2007*.
   开山之作。tokenization → 递归聚类 → 类型化序列比对合并。在 HTTP/RPC/CIFS 上 >90% 推断格式
   对应到唯一真实格式。**本项目"跨字段依赖（长度字段后跟对应长度的数据）"的思想直接源于此。**
3. **Bossert, Guihéry, Hiet, "Towards Automated Protocol Reverse Engineering Using Semantic Information"**,
   *ASIACCS 2014*. Netzob 的方法论基础。

### 语义类型推断

4. **Bermudez et al., "Towards Automatic Protocol Field Inference"**, *Computer Communications 84*, 2016.
   FieldHunter：按语义类型（长度、校验和、主机名、命令字…）定位字段。
5. **Chandler, Wick, Fisher, "BinaryInferno: A Semantic-Driven Approach to Field Inference for
   Binary Message Formats"**, *NDSS 2023*.
   探测器集成 + 图搜索合并冲突。**其对比数据很值得记住——当前 SOTA 的精度天花板并不高**：

   | 工具 | Precision | Recall | FPR |
   |---|---|---|---|
   | BinaryInferno | 0.69 | 0.73 | 0.04 |
   | FieldHunter | 0.68 | 0.37 | 0.01 |
   | Netzob | 0.57 | 0.42 | 0.03 |
   | NEMESYS | 0.31 | 0.44 | 0.11 |
   | NetPlier | 0.29 | 0.75 | 0.22 |
   | AWRE | 0.18 | 0.03 | 0.04 |

   作者的设计目标值得认同：**"几乎总是对的"，宁可少报也不要带人走错路**——这正是本项目
   用置换检验压低误报的思路。

### 单消息内在结构

6. **Kleber, Kopp, Kargl, "NEMESYS: Network Message Syntax Reverse Engineering by Analysis of
   the Intrinsic Structure of Individual Messages"**, *WOOT 2018*.
   不看多条消息的共性，只看单条消息内部的字节变化分布；线性复杂度（Netzob 为指数）。
   同时提出 **FMS（Format Match Score）**——第一个格式推断质量的量化指标。
7. **Kleber, van der Heijden, Kargl, "Message Type Identification of Binary Network Protocols
   using Continuous Segment Similarity" (NEMETYL)**, *INFOCOM 2020*. 消息类型聚类。
8. **Kleber, Stute, Hollick, Kargl, "Network Message Field Type Classification and Recognition
   for Unknown Binary Protocols"**, *DSN DCDS 2022*. 字段数据类型分类。
9. **Kleber, Kargl, "Refining Network Message Segmentation with Principal Component Analysis"**,
   *CNS 2022*. 用 PCA 把粗分割的边界修正到真实字段边界。

### 概率推断与动态推断

10. **Ye, Zhang, Wang, Zhang, Xu, "NETPLIER: Probabilistic Network Protocol Reverse Engineering
    from Message Traces"**, *NDSS 2021*.
    多序列比对 + 因子图概率推断 keyword + **remote coupling（请求-响应耦合）**。
    10 个协议上 100% homogeneity / 97.9% completeness。**P1 第 5、6、8 项的主要参考。**
11. **Luo et al., "DynPRE: Protocol Reverse Engineering via Dynamic Inference"**, *NDSS 2024*.
    主动与服务器交互、改写报文探测语义。perfection 0.50 / V-measure 0.94，
    对比 Netzob (0.15, 0.72)、NetPlier (0.16, 0.73)、FieldHunter (0.15, 0.83)。
    **注意其路线依赖"能与服务器交互"，纯离线抓包场景不适用**——本项目属于离线场景。
12. **Zhao et al., "Protocol syntax recovery via knowledge transfer" (SynRe)**,
    *Computer Networks 258*, 2025. 利用协议演化积累的先验知识做语法恢复。

### 另一条路线（需要程序二进制，不适用于纯流量）

13. **Caballero et al., "Polyglot: Automatic Extraction of Protocol Message Format using Dynamic
    Binary Analysis"**, *CCS 2007*.
14. **Cui et al., "Tupni: Automatic Reverse Engineering of Input Formats"**, *CCS 2008*.
15. **Lin, Zhang, "Deriving Input Syntactic Structure from Execution" (AutoFormat)**, *FSE 2008*.
16. **Comparetti et al., "Prospex: Protocol Specification Extraction"**, *S&P 2009*. 消息格式 + 状态机。

    这几项靠动态污点分析从二进制程序里提取格式，精度远高于纯流量方法，但前提是拿得到程序。
    本项目场景（只有 Wireshark 抓的流量）用不上，仅作方法参考。

---

## 六、建议的评估基准

学界常用指标，可直接套用为本项目的回归基准：

| 指标 | 来源 | 含义 |
|---|---|---|
| FMS | NEMESYS | 推断边界与真实边界的加权距离，同时惩罚过度切分 |
| Precision / Recall / FPR | BinaryInferno | 逐字节边界的二分类；**FPR 必须单独看**（SOTA 也只做到 0.01–0.22） |
| Perfection | DynPRE | 字段两端边界**完全**命中才算对，比 F1 严格得多 |
| Homogeneity / Completeness | NetPlier | 消息类型聚类的纯度与完整性 |
| V-measure | DynPRE | 消息类型推断的综合指标 |

落地建议：写一个 `bench/benchmark.py`，用 `tshark -T json` 从真实 pcap 导出字段边界作金标准，
对 DNS / DHCP / NTP / SMB / Modbus / DNP3 / MAVLink 各取 100 / 500 / 1000 条消息三档，
输出上述指标 + 随机数据上的 FPR。有了它，本文第三节的每一项改进都能被客观验证，
而不是靠"看着对"。

---

## 七、第二轮调研：明确优于当前实现的具体方案

第一轮清单偏"工具与论文索引"。这一轮深入各方案的实现机制，筛出**三项机制上确实更优**、
且可落到本项目的方案，并实测确认了一个此前未发现的能力缺口。

### 7.1 缺口实测：当前只能表达 `frame_len = 1·v + b`

`models.LengthFieldSpec` 的核心不变量写死为 `frame_len = value + overhead`（+width），
即斜率 `a` 恒为 1、`b` 为整数枚举。实测（40 帧，长度字段以 `scale` 字节为单位计数）：

```
scale=1  (frame_len = 1*v)  det=True   fr=40
scale=2  (frame_len = 2*v)  det=False  fr=  0
scale=4  (frame_len = 4*v)  det=False  fr=  0
scale=8  (frame_len = 8*v)  det=False  fr=  0
```

这不是边缘场景：IPv4 的 IHL 以 4 字节字为单位、部分工控与音视频协议以字/双字计数。
**Netzob 的 RelationFinder 同样只支持 1/2/4 字节 BE/LE 的 size field，也有这个限制**——
所以这不是"我们没实现某个已知功能"，而是这一整类方法共享的建模局限。

### 7.2 方案 A（收益最大）：ROSE / LOTUS 的线性回归判据

- **ROSE**, *IEEE TrustCom 2023*：*"Extracting Length Field of Unknown Binary Network Protocol
  from Static Trace"*。首个针对静态流量长度字段提取的工作。
- **LOTUS**, *J. Network and Computer Applications 249*, 2026：ROSE 的扩展版，
  doi `10.1016/j.jnca.2026.104452`。

机制（与我们最直接相关）：

1. 按字母字符比例做**二值化判定**：二进制协议 vs 文本协议（文本协议走 ASCII 十六进制/十进制
   长度分支——正好覆盖本项目缺失的 HTTP chunked 场景）；
2. 用 **k-means 对相似字段聚类**，识别出一批"完整消息"及其真实长度；
3. 用 **n-gram 生成候选长度字段**；
4. 对 `(候选字段值, 真实消息长度)` 建**多维线性方程组，最小二乘求解** → 得到 `(a, b)` 及残差；
5. 残差足够小则接受，否则判定"该协议无长度字段"。

关键优势：

- **斜率自由**：`frame_len = a·v + b` 一次回归就覆盖 body_length（a=1,b=overhead）、
  total_length（a=1,b=0）、字计数（a=2/4/8）以及它们的任意组合。7.1 的缺口自动消失。
- **天然给出"无长度字段"的结论**（残差大），这正好是我们负样本判定的另一种、且与置换检验
  正交的实现路径。LOTUS 论文明确宣称能识别无长度字段的协议。
- 实测指标：18 条真实协议 trace（12 二进制 + 6 文本）上 **Precision 0.75 / Recall 0.73 /
  F1 0.73**，而 BinaryInferno 在同样任务上约 **0.32**。

**落地的硬前提**：ROSE/LOTUS 的输入是**一个个独立报文**（报文长度即消息长度），
而我们拿到的是重组后的 TCP 流，没有"消息长度"这个真值。所以不能直接照搬，
需要先用本项目的分帧（或 LOTUS 作者另一项工作里的"水平熵分布定位消息头"）拿到候选帧长，
再回归。**建议作为 P1 第 4 项（候选偏移定位）的替代/增强方案评估。**

### 7.3 方案 B（架构最优）：BinaryInferno 的探测器集成 + 冲突消解

*NDSS 2023*，代码已公开（Python，依赖仅 sklearn/scipy + GNU parallel；输入为 stdin 每行一条
hex；可按 `--detectors` 单独启用某个探测器；另有 Colab notebook）。

机制细节：

- **每个探测器只看消息的一个"垂直切片"**（跨所有消息的同一偏移列），
  返回该切片的**部分描述**（一种数据描述语言），而不是全局结论；
- 探测器族包括：原子类型（IEEE 754 float、timestamp、**length field**）、
  **基于 Shannon 熵变化的字段边界探测器**、
  **序列化模式搜索**（对常见序列化习语做**迭代加深 DFS**，
  约束是"所有消息的字节必须被恰好读完"），各探测器可并行；
- **集成阶段解冲突的原则是：最大化被描述的字节总量**，而不是投票或打分。

对我们的价值：

1. "每个探测器独立出部分描述 + 最大化覆盖来合并" **正是 P0 第 1 项（多分帧模板）
   应该采用的架构**——定长、分隔符、长度前缀、ASCII 长度各自成为一个探测器，
   冲突由一个统一的覆盖度目标裁决，避免现在这种"单一评分函数里塞所有证据"的僵化。
2. 它的**序列化模式迭代加深 DFS** 是本项目 `walk()` 的直接推广：
   `walk` 只走一层 `value+overhead`，而它能表达 TLV、嵌套、变长序列，
   且"必须恰好读完"这个约束和我们 `leftover == 0` 的判据是同一个思想。
3. 熵变边界探测器可直接复用为 P0 第 2 项之外的"字段边界"证据。

注意其适用前提是**同格式的一组消息**，不做消息分簇；且论文自述依赖输入聚类质量。

### 7.4 方案 C（评分区）：NetPlier 的因子图概率推断

*NDSS 2021*，代码与数据集公开。机制：

1. 用生物信息学的**多序列比对（MSA）** 一次对齐全部消息（避免 NetPlier 之前的
   两两比对的组合爆炸）；
2. 区分静态/动态字节，生成"unit field"→ 组合成 keyword 候选；
3. 对每个候选字段引入**随机布尔变量**"它是不是 keyword"，并引入观测变量：
   - `M(f,c)` 消息相似性、`R(f,c)` **remote coupling（请求-响应远程耦合）**、
     `S(f,c)` 结构一致性、`D(f)` 维度约束；
4. 构成**因子图**，用 **sum-product 求后验边缘概率**，取最大者；
5. 用选出的 keyword 聚类，再迭代重对齐、重推断。

对我们的价值：把 `config.py` 里手工拍的权重（实测已暴露 agreement 权重过高的问题）
换成**后验概率**。新增证据（如置换检验 gap、回归残差）只是加一个因子，
不再需要重新调阈值。10 协议上 100% homogeneity / 97.9% completeness。

### 7.5 补充：NEMESYS 的机制细节与 FMS

- 计算相邻字节的 **Bit Congruence**（Sokal & Michener 定义的按位相似度），
  得到逐位置的 ∆BC 序列 → **高斯平滑 `g_σ(∆BC)`** → 取**拐点**作为字段边界 → 细化。
- 只看单条消息的内在结构，不看跨消息共性；复杂度线性。
  实测 10 000 条消息：DNS 0.1s / DHCP 0.9s / NTP 0.9s（Netzob 为 246s / — / 312s）。
- **FMS**（本项目做基准时建议直接采用，γ 默认 2）：

  ```
  FMS = exp( -((|R|-|I|)/|R|)^2 )  ·  (1/|R|) Σ_{r∈R} exp( -(δ_r/γ)^2 )
        └── 特异性惩罚（字段数偏差）┘   └── 匹配增益（边界距离高斯加权）┘
  ```

  实测 FMS（best / avg，10 000 条消息）：DNS 0.71/0.45、DHCP 0.73/0.54、NTP 0.67/0.45；
  Netzob 同期为 0.56/0.47、0.66/0.52、0.61/0.47。
- 仓库要求 Netzob 的 `fix-layer-build` 分支（官方 PyPI 版缺修复），这是落地时的实际阻力。

### 7.6 补充：FLINT（2025，变长字段）

*Computer Networks 2025*，*"Similarity-based Field Inference for Unknown Binary Network
Protocols"*。先用结构相似度聚类消息、用**信息熵分离包头与载荷**，再做**位置感知的关联分析**
定位变长字段候选，用序列对齐细化边界，最后**零填充归一化 + 位级相似度 + 指数衰减拟合**
取曲线特征点定剩余边界。16 个协议上优于 SOTA。

价值：其"用熵分离 head/payload"与"位置感知关联"正是本项目 `header_len` 推断
（当前只能取 `offset + overhead` 这个粗糙近似）的改进方向。

### 7.7 修订后的优先级

| 优先级 | 动作 | 参考 | 收益 |
|---|---|---|---|
| **P0** | 多分帧模板改为**探测器集成 + 最大化覆盖度合并**架构 | BinaryInferno | 覆盖定长/分隔符/ASCII 长度，且不再靠单一评分函数硬塞 |
| **P0** | 帧长公式从 `v + b` 推广为 `a·v + b` | ROSE / LOTUS | 一次解决字计数协议（7.1 实测缺口），改动在 `models` + `walk` |
| **P0** | tshark ground-truth 基准 + FMS/Precision/Recall/FPR | NEMESYS + BinaryInferno | 让后续每项改进可客观验证 |
| P1 | 评分改因子图后验概率 | NetPlier | 消除手工权重，新增证据无需重调阈值 |
| P1 | 候选偏移用 ∆BC 高斯平滑 + 拐点定位 | NEMESYS | 32×11 全枚举 → 2–3 个候选，兼解性能 |
| P1 | 熵分离 head/payload、变长字段位置关联 | FLINT | `header_len` 从近似值变为推断值 |
| P2 | TLV/嵌套：序列化模式迭代加深 DFS | BinaryInferno | 覆盖 TLV、ASN.1 BER |
| P2 | 双向流 remote coupling | NetPlier | 请求-响应互证 |

> 保留第一轮的判断：**这些工具都不做"从连续字节流切帧"**，分帧仍是本项目相对它们的独特价值；
> 但 7.2/7.3/7.4 三项机制确实比当前实现更优，值得直接吸收。

## 八、第三轮：P0-1 落地与由此暴露的更根本问题

本轮实现了 P0 第一项（帧长公式推广为 `a·v + b`）与第二项的一部分（决策规则重构），
并建立了 P0 第三项的评估基准。**过程比预期重要**：加上 `scale` 维度后，搜索空间
多出 3 倍假设，把之前被掩盖的一个更根本的问题顶了出来。

### 8.1 已落地

| 改动 | 位置 | 实测效果 |
|---|---|---|
| 帧长公式 `frame_len = scale·value + overhead` | `models.LengthFieldSpec.scale`、`walk`、`analyzers/length_field`、`report`、MCP | `scale=2/4/8` 从**完全检测不到**变为 100% 正确 |
| 走查用**字节预算 + 帧数上限**双限筛查 | `walk(probe_bytes=...)`、`config.probe_stage1_bytes` | 删除冗余的"二级 96 帧探测"（实测占 95% 步数），varint 流 7.3s → 5.6s |
| `overhead` 枚举加**第 2 帧存在性**解析上界 | `_overhead_range` | 候选 overhead 数大幅下降（必要条件，不会误杀） |
| 帧数评分饱和点 32 → 12 | `config.frames_saturation` | 修复"91 帧伪解压过 14 帧真解" |
| 基准脚本 + 指标 | `bench/benchmark.py`、`bench/calibrate.py` | 18/18 正样本规格正确，P/R/F1/FMS = 1.000，0/9 误报 |

`scale` 的语义与边界在 `synth.make_scaled_length_stream` 的 docstring 里写明了两个
设计取舍，因为第一版合成器把"scale 难点"和"低熵载荷难点"混在一起，导致无法归因：

* 对齐填充用**随机字节**而非零字节（零填充会造出"某偏移恒为 0"的强结构伪影）；
* 默认载荷用**高熵** `"bytes"`（低熵场景由 `payload="ascii"` 单独覆盖）。

### 8.2 本轮最重要的发现：置换统计量的两种构造各有各的有效域

早期实现只有一个统计量：**全局 max-vs-max**
（窗口最高分 − 打乱后各次搜索的最高分）。它在 rank-1 上是对的，但加上 `scale`
维度后，低熵载荷产生的伪解会把真解挤到 rank 15~48 名，真解就**没有任何被检验的机会**。

自然的修法是"逐候选验证"，于是试了**假设匹配**统计量（同一假设在原始/打乱窗口上的
分数差）。它有代价优势（每轮一次走查，替代每轮一次完整搜索，实测降两个数量级），
也确实能选出真解，但**单独用它做门槛会失效**：

| 统计量 | 候选级（能选谁） | 群体级（有无结构） |
|---|---|---|
| 全局 max-vs-max | ✗ 与候选无关 | ✓ max 对 max，无偏，随机数据 gap ≤ −0.0225 |
| 假设匹配 | ✓ 实测全部命中真解（含真解排名 2、3 时） | ✗ 随机数据的巧合分帧"打乱也走不通"，gap 恒为正（+0.087~+0.218） |

最终采用**两条证据并列**（`segment_stream`）：满足其一即接受，选中的是匹配 gap 最大者。

* 分支 A（候选级，便宜）：某候选的匹配 gap ≥ `min_matched_gap`（0.25）
* 分支 B（群体级，昂贵，仅在 A 失败时才算）：rank-0 的全局 gap ≥ `min_perm_gap`（0.0）

标定数据（`bench/calibrate.py`）：

```
分支A  max gapB  正样本最小 +0.2817   负样本最大 +0.2180
分支B  gapA      正样本最小 +0.0142   负样本最大 -0.0225
```

副产品：分支 A 优先让**昂贵的全局 null 在大多数情况下根本不用算**。

### 8.3 一个必须记住的理论结论：帧数的边际证据是递减的

我一开始把"帧数"当成最硬的证据（每多一帧多满足一次约束），把饱和点设到 32。
实测被推翻：`varint` 流上出现了一个 **91 帧的伪解**压过 14 帧的真解。

原因是走查的约束结构不对称：**只有末帧"恰好落在流尾"是需要运气的**，
中间帧只要不越界即可。因此帧数的边际证据递减，饱和点取 12 反而让两组用例同时正确。
这条结论直接写进了 `config.frames_saturation` 的注释。

更一般地：一次 n 帧的完整走查，其巧合概率大致由"末帧精确落点"决定（≈ 1/可达长度数），
所以**长流上"能完整走通"的假设非常多是常态**，不是异常。这也解释了为什么
`random65536` 上能搜出 369 帧的完整走查。判断真伪必须靠显著性，不能靠帧数。

### 8.4 仍未解决 / 下一步

* **P0-2 探测器集成** —— **已在第九节落地**。定长帧、分隔符、HTTP chunked 的
  ASCII 十六进制长度原先全部漏检（根因见第二节：只搜索 `a·v + b` 这一种模板）。
  设计即 7.3 的"最大化被描述字节数"合并规则；落地过程中发现"定长帧无法从字节自身验证"
  这个难点需要一个**独立于整除性的统计依据**（跨帧恒定列），详见 9.2 第 4 条。
  原先的结论保留如下，可作为设计动机的存档：
  定长必须作为**低置信假设**报告而非无依据地 `detected=True`，这需要改输出模型；
  分隔符与 ASCII 长度则可自验证（后者校验 hex 长度与后续字节是否吻合），优先做。
* **低熵载荷的"必然伪解"仍未根治。** `_payload_alias` 想做的判据在 n 小时不成立：
  TVD/KS 这类需要分布估计的统计量在 n=14~24 时噪声主导，实测对伪解恒返回 0（不惩罚）。
  这属于 P1"字段语义标注"的范畴 —— 需要用"长度值是否与载荷字节可交换"这类
  **无需分布估计**的小样本判据（例如秩统计量），或直接上 NetPlier 的因子图。
* **性能仍是 P2。** 最长单例 5.6s（54803 字节 / 14 帧的 varint 流），瓶颈在
  35 185 个假设 × 完整走查。可行的方向：把 `decode_at` 内联进走查循环、
  用 NEMESYS 的 ∆BC 把偏移候选从 33 个降到 2–3 个。

---

## 九、第四轮：P0-2 探测器集成落地（多分帧模板）

本轮把 7.3 的"探测器集成"架构真正落地：新增 `detectors.py`，在长度前缀之外
补上 **分隔符 / ASCII 文本长度 / 定长** 三个模板。同时新增 `models.FramingSpec`
作为四种模板的统一表示（`length_prefixed` 只是其中一种 kind，`LengthFieldSpec`
被嵌在其 `length_field` 字段里，因此对既有 API / MCP 输出完全向后兼容）。

### 9.1 已落地

| 改动 | 位置 | 实测效果 |
|---|---|---|
| 通用分帧规格 `FramingSpec`（kind + 各模板字段） | `models.py` | MCP 输出新增 `framing`，`length_field` 保留为便捷镜像 |
| 分隔符探测器（多字节，频率显著性） | `detectors.detect_delimited` | `\r\n`、`\x00\x00`、RESP 类全部识别 |
| ASCII 长度探测器（`<数字><终止符>`，自校验） | `detectors.detect_ascii_length` | HTTP chunked（hex）与十进制文本长度均识别 |
| 定长探测器（整除性 + 刚性包头） | `detectors.detect_fixed_length` | 带刚性包头的定长帧识别；无包头只列假设 |
| 集成裁决（覆盖率 → 证据类型 → 帧数 → 分数） | `detectors.choose_framing` | 四模板正样本 24/24 规格与模板正确 |
| 并列自洽方案并列暴露 | `engine.analyze_stream` → `framing_hypotheses` | 不再做无依据的取舍 |
| 基准扩到四模板 24 正样本 / 9 负样本 | `bench/benchmark.py` | P/R/F1/FMS = 1.000，0/9 误报 |
| 新增 26 项用例（122 → 148） | `tests/test_detection.py` | 全绿 |

### 9.2 本轮最有价值的四条实证结论

**1. 朴素 lift 不能当分隔符的判据 —— 它对"重复同一字节"的分隔符有系统性偏差。**

设分隔符为 ``b"\x00\x00"``、帧内容平均长 `c`、帧数 `F`。因为这两个 0x00 只来自分隔符本身，
`freq(0x00) ≈ 2/(c+2)`，于是

```
lift = 观测次数 / (按字节频率的期望次数) ≈ (c + 2) / 4
```

**lift 与帧数无关，只取决于帧内容长度**。也就是说：帧越多证据越强，但 lift 纹丝不动，
一个 16 帧的 `\x00\x00` 分隔符 lift 只有 ~7，直接被"lift ≥ 10"的护栏误杀。
反之，ASCII 载荷里偶然高频的 2-gram 反而能拿到 lift 4.9。

正解是把判据换成**泊松尾概率 + Bonferroni 多重比较校正**：

```
lam  = (#位置) · Π freq(byte)          # 各字节独立零假设下的期望出现次数
p    = P(X >= count),  X ~ Poisson(lam)
接受  iff  p · M <= delim_alpha 且 count >= delim_min_frames
```

**2. Bonferroni 的 `M` 必须是"全部被检验过的候选数"，不能截断。**

早期实现用 `counts.most_common(96)` 的长度当 `M`，等于把校正量算小、显著性算大。
改成 `len(counts)`（该流上所有 2..4-gram 的**不同**取值）后，短流不再被随机尖峰击穿。
实测 `random_stream(8192)` 上必然存在某个 2-gram 出现 4~5 次（朴素 lift 高达 32），
校正后的 p 值把它拦住了。

**3. 集成裁决里"帧数优先"是错的 —— 更细的分帧常常是更弱模板的副产品。**

一开始按"覆盖率相同则取帧数更多者"排序，结果 HTTP chunked 被判成分隔符：
``\r\n`` 把每个块的"长度头"和"数据体"各切一刀得到 **18 帧**，而真正的 ASCII 长度
模板只有 **9 帧**。反过来，一个 12 条刚性定长记录的流，也能被一条 **4 帧**的长度前缀规则
完整铺满，此时又希望取帧数更多的定长。

两个方向完全相反，说明帧数不是可靠的裁决维度，**证据类型才是**：

```
覆盖率 → 证据类型优先级 → 帧数 → 分数
```

**4. 定长帧的"可自证"需要一个独立的统计依据，而不是靠整除性。**

整除性毫无信息量（`random_stream(4096)` 对 1/2/4/8/…/4096 全部成立）。
本轮改用**跨帧恒定列**（刚性包头）：`M` 帧下某列恰好全部相同的概率 ≈ `256^-(M-1)`，
`M ≥ 4` 时已低至 1.5e-5，因此"恒定列"几乎不可能是巧合。要求
`constant_columns >= 4` 且占比 `>= 25%` 才提升为结论，且始终标注低置信。

### 9.3 一个必须记住的边界：歧义不做自动消除

一条流常常**同时自洽于多个模板**，且互不构成简单的前后包含关系。当前的取舍是：

* 取 `choose_framing` 的胜出者作为结论；
* 其余并列自洽方案（覆盖率达到胜出者的）全量放进 `framing_hypotheses`，
  并在 `warnings` 里用一句话点明。

这比"猜一个"更诚实。实测例子：12 条 32 字节刚性定长记录（384 字节）上，
`uint8@0+26` 形成一条完美的 4 帧长度前缀规则，并通过了置换检验。
程序报告长度前缀（4 帧）并同时列出"定长（12 帧，恒定列 16/32）"。

### 9.4 仍未解决

* **P1 字段级推断** —— **已在第十节落地**（字段边界 + 语义类型 + 消息类型聚类）。
* **单字节分隔符**（`\n`、`\x00`）不可自证：lift 恒为 1（期望频次就是自身频次），
  与定长同属"只能列假设"的一类。若要提升为结论，需要引入**跨帧结构一致性**这类
  独立证据（本质上是把定长/分隔符统一到"跨帧恒定列"框架下）。
* **真实 pcap 语料的 FPR 仍未测**：`bench/benchmark.py` 的 `pcap` 通道是占位，
  仓库无 pcap 语料，字节级 FPR 只有合成数据的结论。
* **无刚性包头的定长帧**依然无法识别（信息论上确实无法从单条流自证）。
* **TLV / ASN.1 BER 嵌套**：需要 7.3 提到的"序列化模式迭代加深 DFS"，本轮未做。
* **低熵载荷的必然伪解**仍未根治（见 8.4）。

---

## 十、第五轮：P1 落地（字段级语义推断 + 消息类型聚类）

本轮新增 `fields.py`，把 P1 里**能离线验证**的三项落地：字段边界推断（NEMESYS
∆BC）、字段语义标注（含 CRC 反算）、消息类型聚类（keyword）。P1 剩下的
"评分改因子图后验概率"（7.4）需要带标注的数据集才能标定，本轮没做。

### 10.1 已落地

| 改动 | 位置 | 实测效果 |
|---|---|---|
| 字段边界：∆BC 高斯平滑 + 列熵突变（取并集） | `fields.field_boundaries` | 单独用 ∆BC 在短流上退化（列熵本来就低，∆BC 几乎平坦），叠加熵突变后稳定 |
| 边界子集上的**动态规划**最优分割 | `fields.refine_by_type` | 修复"IPv4 的 192.168 恒定、末两字节变化"被切成两段 |
| 13 类语义标注（判据须对所有样本成立） | `fields.classify_field` | 魔数/命令字/长度/CRC/文本/IPv4/时间戳/计数器 全部识别 |
| **帧尾对齐**的 trailer 校验和检测 | `fields.detect_trailer_checksum` | CRC32 trailer 从"完全看不到"到 100% 识别 |
| head / payload 熵分离（FLINT 思路） | `fields.split_header_payload` | `header_len` 不再是 `offset+overhead` 的粗糙近似 |
| keyword 分簇（纯度评分） | `fields.infer_message_types` | 三类型混合流分成 3 簇，每簇 5 帧，keyword 命中命令字 |
| 基准扩到 27 正样本 | `bench/benchmark.py` | 27/27 规格与模板正确，P/R/F1/FMS = 1.000，0/9 误报 |
| 新增 10 项用例（148 → 158） | `tests/test_detection.py` | 全绿 |

### 10.2 本轮最有价值的四条实证结论

**1. trailer 在"帧首对齐"的坐标系里根本不存在。**

字段边界推断默认按帧首对齐（第 i 列 = 各帧的第 i 字节）。但 trailer 的位置
**随帧长变化**。实测一个 `[magic][cmd][len][body][crc32]` 的协议：最短帧 17 字节，
帧首对齐最多只能看到前 17 列，而 CRC 位于 `7+v .. 11+v` —— 除最短帧外全在视野之外。
必须**单独按帧尾对齐**再找一遍。结果里用 `offset < 0` 表示"距帧尾"。

**2. 最优分割的目标函数必须乘字段长度。**

一开始按"字段数"最小化 + 类型具体程度最大化来合并，结果**切得越碎总分越高**
（两个 1 字节字段的类型分之和 > 合并后一个 2 字节字段的分），永远选碎分割。
改成 `Σ (类型具体程度 + 置信度) × 字段长度 − 字段数 × penalty` 后才对：
"用 IPv4 解释 4 字节"（6.5×4 = 26）胜过"2 字节常量 + 2 字节整数"（4.5×2 + 2.2×2 = 13.4）。
这就是 BinaryInferno "最大化被描述的字节数"，只不过目标换成"被**有语义地**描述的字节数"。

**3. 两条硬性禁止——否则最优分割会吞掉帧首魔数。**

* 起点为 0、且第 0 列恒定的字段，不允许被并成 `enum` / `random` / `binary` / `integer`。
  实测："2 字节魔数 + 1 字节命令字"被一个"3 值 enum"整体吞掉，最强的特征没了。
* **任何段都不允许跨过已定案的长度字段区间**。实测：`[magic(2)][cmd(1)][len(1)]`
  这 4 个字节被一个"IPv4"（首字节 0xab = 171 ≤ 223）整体吞掉。

**4. 所有"信息量阈值"都必须随样本量自适应。**

n 个样本的单列熵上限是 `log2(min(n,256))`。用固定的 6.5 bits 当"随机数"判据、
5.0 bits 当"载荷区"判据，在 12 条消息的流上（熵上限仅 3.58）**永远触发不了**。
改为 `min(阈值, 0.9·log2(n))` 后两个判据才开始工作。

### 10.3 仍未解决

* **字段后面紧邻高熵载荷时提不出边界。** 实测包头末尾的 IEEE 754 浮点字段与
  随后的随机载荷在熵上不可区分，边界并进了载荷。NEMESYS 同样有此现象
  （其后续工作用 PCA 细化边界）。这需要**类型驱动的分裂**（而不只是合并），
  即"在某个偏移上切开能得到更好的类型解释" —— 本轮只做了合并。
* **IPv4 / 时间戳 / 浮点三者不可消除地歧义**（都是 4 字节）。目前靠"对所有样本成立"
  + 按信息量排序来降低误标，但 `192.168.x.y` 与 `1.7e9` 完全可能互相误判。
* **评分改因子图后验概率（7.4 / NetPlier）未做。** 它要引入 MSA + sum-product，
  且"权重由数据决定"这个好处只有在有标注数据集时才能验证 —— 而仓库没有
  真实 pcap 语料。这是当前最大的"能力未被验证"缺口。
* **消息类型聚类只看了包头区**，且要求 keyword 取值重复。若真实协议的命令字
  位于变长区或与 session-id 混在一起，当前实现会漏。


---

## 十一、第六轮调研（2026-10 开源前）：LLM 时代的协议逆向与下游应用

开源前的最后一轮调研，聚焦 2024-2026 年的新工作：LLM 参与的协议逆向、
状态机推断新方法、以及"格式推断成果被下游利用"的方式。结论先行：
**纯轨迹驱动 + 显著性检验压误报这条路线在当前文献里依然稀缺，是本项目的差异化卖点**；
最大的可借鉴点来自下游（fuzzing 对消息边界自动化的刚需）与分层架构（确定性结构 + LLM 语义）。

### 11.1 LLM 用于协议逆向：分层借鉴，不要让 LLM 碰结构

| 工作 | 来源 | 有代码 | 机制 | 可借鉴点 |
|---|---|---|---|---|
| ChatAFL | NDSS'24 | ✅ [ChatAFLndss/ChatAFL](https://github.com/ChatAFLndss/ChatAFL) | LLM 为每类报文构建语法并预测消息序列，接入 AFLNet | 把 flowunpack 的分帧 + 字段标注作为**确定性骨架**，LLM 只做语义命名与消息类型扩写——结构推断绝不交给 LLM（幻觉会破坏帧边界） |
| protodissect | GitHub, BSD-3 | ✅ [dilates/protodissect](https://github.com/dilates/protodissect) | 确定性 PRE，从 PCAP 直接生成 Wireshark dissector，可选本地 LLM 命名字段 | 加一个 **"模板 → Lua dissector 导出"** 工具作为下游验证闭环：能被 Wireshark 加载且解析成功的模板就是可用的模板 |
| Moosa-Salehi PRE 管道 | GitHub | ✅ [Moosa-Salehi/protocol_reverse_engineering](https://github.com/Moosa-Salehi/protocol_reverse_engineering) | PCAP→规范化→聚类→分帧/字段/关系→HTML 报告 | "结构推断（确定性）+ 语义（LLM）"分层与报告化输出；我们的差异化在零依赖与置换检验 |
| ProtocolGPT | arXiv 2405.00393 | ✗ | RAG + 提示工程从协议实现源码推断状态机 | 源码路线，与流量路线互补，不适用本项目 |
| ICProFuzz | IEEE 2024 | ✗ | LLM 理解私有工控协议后做格式保持变异 | 印证"结构必须先确定、变异才格式保持"的分工 |

### 11.2 状态机推断：规范文档路线兴起，反向借用作交叉证伪

FlowFSM（arXiv 2507.11222）、SpecGPT（arXiv 2510.14348）、RAG-ReAct FSM 评测
（arXiv 2502.15727）均仅论文，共同趋势是 2024 后从"轨迹→FSM"转向
"RFC/3GPP 规范文档→FSM"。对本项目的启发：

- 本项目 `statemachine.py` 的 k-Tail 输出可以让 LLM 对照猜测的 RFC 做**交叉证伪**
  ——这是与"双向流耦合"同级的第三类硬证据来源（规范里写了状态机，观测序列若与
  高置信规范矛盾，说明符号化或分帧有误）。
- 纯轨迹驱动 + 置换检验压误报在当前文献里仍是稀缺组合，README 应把这一点写足。

### 11.3 下游应用：fuzzing 是格式推断成果的最大消费方

**最重要的发现**：AFLNet Five Years Later（IEEE TSE 2025，arXiv 2412.20324）复盘指出，
AFLNet 唯一强制的人工输入就是**消息边界识别**。这正好是 flowunpack 的核心输出。

可落地的下游桥接（建议作为路线图新条目）：

1. **AFLNet / ProFuzzBench 边界脚本生成**：把 `frames[]` 输出转成 AFLNet 的
   消息边界描述，消除其唯一人工环节——这是最有说服力的应用叙事。
2. **boofuzz 模板映射**：`frame_len = scale·value + overhead` 直接映射为 boofuzz 的
   `size` block 定义；CRC32 反算字段输出为"需重算区"提示。
3. **ProtoForge**（Python，2026-08 活跃，✅ 有代码）：当前定位最接近的项目
   （录流量→推断分帧/字段/校验和→活体回放验证→确定性 fuzz）。其"活体验证"环节
   是本项目（纯离线）可补的差异点——不联网也能做"回放一致性"校验。

### 11.4 结构感知的加密流量分析：一个可复用的先验

Language of Network（arXiv 2505.19482）、Pcap-Encoder（arXiv 2507.16438）、
Lens（arXiv 2402.03646）均为表征学习路线，与规则式推断距离较远。唯一可落地的是
**"报头/加密区分离"先验**：给高熵字段打"加密/随机区"标签，并与 CRC/长度假设做
互斥验证（一个字段若被判定为随机数，就不应同时被解释为长度字段）。

### 11.5 竞品格局小结

Netzob/BinaryInferno 之后无老牌工具复兴；2024 后同定位新项目（protodissect、
ProtoForge、Moosa-Salehi 管道、CNNPRE）均走"确定性推断 + 可选 LLM 命名"路线且体量小。
本项目的四模板分帧 + 全样本成立的字段约束 + 两级置换检验仍是差异化点；
短板是**没有真实 pcap 语料上的第三方评测**（§6 的 ground-truth 基准仍是 P0）。

### 11.6 落地注记（2026-10 开源整理期间）

本节调研的 11.3（fuzzing 桥接）、11.1 的 dissector 导出、11.5 的评测短板
已在开源前落地：

| 项 | 落点 | 说明 |
|---|---|---|
| P3-11 fuzzing 桥接 | `src/flowunpack/exporters/boofuzz.py`、`aflnet.py` | boofuzz：`s_size` + `math` 回调表达 `frame_len = scale*value + overhead`，CRC32 trailer 转 `s_checksum`；变长编码/非长度前缀显式拒绝（不产出错误模板）。AFLNet：独立零依赖切分脚本，四种模板全支持，varint 内联 LEB128 |
| P3-12 dissector 导出 | `src/flowunpack/exporters/lua.py` | 四种模板全支持（varint 除外）；`FieldSpec.kind` → `ProtoField` 映射；负 offset trailer 按帧尾解析；`bind_port` 可直接绑定端口。已用 tshark 实际加载 + text2pcap 构造流量验证析出全部帧 |
| 真实协议基准 | `bench/benchmark_real.py` + `bench/data/` | tshark PDML 原子字段边界作金标准（容器字段/位域剔除），P/R/F1 + FMS；样本取 Wireshark 官方测试抓包随仓库分发。**首次基线暴露：字段推断在真实数据上过度合并（mDNS Recall 0.125 / Precision 1.000），与 §10 的字段边界分辨率上限一致**；git pkt-line 确认为模板缺口（总长 ASCII 长度且无终止符） |

实施中发现的一个额外缺口：`infer_state_machine` 此前**有实现但未注册**为
MCP 工具（README 却已记载）——已补注册，并给 `smoke_mcp_stdio.py` 加了
工具清单断言防止复发。
