"""可配置的启发式阈值与权重（所有魔法数字集中在此处）。"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class AnalysisConfig:
    """启发式分析配置。

    所有阈值集中一处，便于按协议场景调优；运行时可用 :meth:`overridden`
    生成带覆写的副本，而不修改全局默认值。
    """

    # ---- 搜索空间 ----
    max_offset: int = 32            # 枚举的长度字段起始偏移上限 [0, max_offset)
    max_overhead: int = 64          # frame_len = scale*value + overhead，overhead 枚举上限
    max_start_offset: int = 16      # 流起始未对齐时允许跳过的开头字节数
    # 帧长公式的斜率候选：frame_len = scale * value + overhead。
    # scale=1 覆盖绝大多数协议（长度以字节计）；scale>1 覆盖"长度以字/双字为单位计数"
    # 的协议（IPv4 的 IHL 以 4 字节字为单位、部分工控与音视频协议）。
    # 实测：只支持 scale=1 时，frame_len=2v/4v/8v 的协议全部检测不到。
    scales: Tuple[int, ...] = (1, 2, 4, 8)
    formats: Tuple[str, ...] = (
        "uint8", "uint16_be", "uint16_le", "uint24_be", "uint24_le",
        "uint32_be", "uint32_le", "uint64_be", "uint64_le",
        "varint", "varint_be",
    )

    # ---- 样本要求 ----
    min_packets: int = 2            # 逐包模式最少包数
    min_frames: int = 4             # 流模式最少帧数（<4 帧时随机数据也能轻易"走完"）

    # ---- 结构统计 ----
    scan_bytes: int = 48            # 统计固定字节 / 熵值时扫描的前 N 字节
    fixed_byte_threshold: float = 0.9
    magic_min_len: int = 2

    # ---- 评分权重（逐包模式，各项 0~1，加权和 0~1）----
    w_exact: float = 0.40           # 帧长公式精确命中的样本比例
    w_consistent: float = 0.22      # 等长包 -> 长度字段值一致
    w_discriminative: float = 0.14  # 值随包长变化（否则是常量字段）
    w_coverage: float = 0.10        # 值落在合法区间
    w_structural: float = 0.12      # overhead >= offset+width（body 语义）

    # ---- 评分权重（流模式，各项 0~1，加权和为 1）----
    s_frames: float = 0.28                  # 帧数越多，巧合走完的概率越低
    s_header_consistency: float = 0.16      # 包头跨帧恒定（魔数/命令字）
    s_value_variety: float = 0.10           # 长度值有变化
    s_structural: float = 0.15              # 长度字段紧贴包体
    s_offset_prior: float = 0.06            # 偏移越小越像协议头
    s_agreement: float = 0.25               # 同族假设命中数（最强判据）

    # 帧数的饱和点：frame_score = log2(1+n)/log2(1+frames_saturation)。
    # 早期实现用 min(1, n/6)，6 帧即饱和 —— 实测会把"24 帧的真解"和"8 帧的伪解"
    # 打平，进而被伪解压过。但也不能让帧数无限加分：一次完整走查里，真正"需要运气"
    # 的是**末帧恰好落在流尾**，中间帧只要不越界即可，因此帧数的边际证据递减。
    # 实测：饱和点取 32 时，低熵载荷会产生 91 帧的伪解压过 14 帧的真解；
    # 取 12 时两组用例同时正确（真解帧数 ≥12 时不再靠帧数区分，交给置换检验）。
    frames_saturation: int = 12

    # ---- 流模式接受门槛（两条独立证据，满足其一即接受）----
    # 详见 segmentation.segment_stream 的决策说明。实测标定（见 bench/calibrate.py）：
    #   分支A（强候选证据）正样本最小 +0.2817，负样本最大 +0.2180
    #   分支B（群体证据）  正样本最小 +0.0142，负样本最大 -0.0225
    min_agreement: int = 2                  # 置换检验不可用时的一致性门槛
    min_stream_score: float = 0.75          # 置换检验不可用时的分数门槛
    min_matched_gap: float = 0.25           # 分支A：某候选与打乱的分数差
    min_perm_gap: float = 0.0               # 分支B：rank-0 分数 − 打乱最高分

    # ---- 置换检验：把流按小块打乱后比较分数 ----
    # 真实协议的结构是"这个字节排列"特有的，打乱后分数会明显下降；
    # 随机数据的巧合解只是字节分布的性质，打乱后分数几乎不变。
    perm_trials: int = 10
    perm_max_bytes: int = 262144            # 超过该长度自动关闭置换检验（保性能）
    perm_sample_bytes: int = 8192           # 置换检验的采样窗口：代价与流长解耦
    perm_min_bytes: int = 64                # 窗口太小时不做置换检验

    # ---- 惩罚系数 ----
    penalty_constant_value: float = 0.15   # 包长不同但长度字段不变
    penalty_zero_padding: float = 0.20     # 落在前导 0 填充区且值恒为 0
    penalty_partial_tail: float = 0.85
    penalty_truncated_field: float = 0.70  # 只读了宽字段的低位字节（高位恒为 0）
    penalty_payload_alias: float = 0.60    # 长度值分布 == 载荷字节分布（低熵载荷的必然解）

    # ---- 分帧模板探测（长度前缀之外的模板，见 detectors.py）----
    # 覆盖率相同时的优先级见 models.KIND_PRIORITY：
    # 长度前缀（经置换检验）> ASCII 长度（可自校验）> 分隔符（频率显著性）> 定长（仅整除性）。
    detect_min_score: float = 0.35       # 非长度前缀模板的最低接受分数

    # 分隔符分帧。关键结论：**单字节**分隔符无法自证 —— 它的"随机期望出现次数"
    # 就是它自己的出现次数（lift 恒为 1），因此只有**多字节**分隔符能进入结论，
    # 单字节候选只进低置信假设表。
    delim_min_frames: int = 4
    delim_min_lift: float = 3.0          # 出现次数 / 随机期望次数（仅作下限护栏）
    delim_alpha: float = 0.01            # 泊松尾概率 × Bonferroni 校正后的门槛
    delim_min_coverage: float = 0.5      # 分帧至少要覆盖流的一半
    delim_scan_bytes: int = 65536        # 只在前 N 字节上统计候选（控制代价）
    delim_max_len: int = 4               # 候选分隔符的最大字节数
    delim_max_candidates: int = 96
    delim_extra: Tuple[bytes, ...] = (b"\r\n", b"\r\n\r\n", b"\n\n",
                                      b"\x00\x00", b"\xff\xff")

    # ASCII 文本长度（HTTP chunked 形态：<hex>\r\n<data>\r\n）
    ascii_radices: Tuple[int, ...] = (16, 10)
    ascii_terminators: Tuple[bytes, ...] = (b"\r\n", b"\n")
    ascii_scan_start: int = 64           # 允许前导字节时的起始位置扫描范围
    ascii_min_coverage: float = 0.6      # 分块必须覆盖流的大部分

    # 定长帧：整除性无法自证（流的任意因子都构成一个"定长分帧"）。
    # 提升为结论需要**独立于整除性的证据**：跨帧存在刚性包头。
    #
    # 统计依据：M 帧下，某一列"恰好全部相同"的概率 ≈ 256^-(M-1)。M>=4 时
    # 已低至 1.5e-5，因此"恒定列"几乎不可能是巧合。但为了不把偶发的单列
    # 巧合当成包头，仍要求恒定列达到一定数量与比例。
    fixed_min_frames: int = 4
    fixed_min_constant_ratio: float = 0.25
    fixed_min_constant_columns: int = 4
    fixed_max_columns: int = 32          # 只统计每帧前 N 列（包头区域），控代价
    fixed_scan_max_bytes: int = 65536    # 超过该长度不做定长枚举（代价 ~O(n·d(n))）

    # ---- 字段级推断（P1，见 fields.py）----
    # 输入是**分帧后的一组同类消息**（NEMESYS / NetPlier 的设定），
    # 代价上限由"扫描列数 × 样本数"控制，与流长解耦。
    field_scan_bytes: int = 64          # 只推断每帧前 N 列
    field_max_units: int = 128          # 参与统计的最大样本数（超出则等距抽样）
    field_min_units: int = 4            # 少于该样本数不做字段推断（统计量不可靠）
    # 字段边界：NEMESYS 的 ∆BC 判据（相邻列 bit-congruence 的差分 → 高斯平滑 → 局部极大）。
    # 单靠 ∆BC 在短流上会退化，因此叠加"列熵突变"作为第二判据，两者取并集。
    field_sigma: float = 1.0            # 高斯平滑尺度
    field_dbc_floor: float = 0.06       # 边界分数绝对下限
    field_dbc_k: float = 0.5            # 边界分数 ≥ mean + k·std
    field_entropy_jump: float = 1.5     # 相邻列熵差 ≥ 该值（bits）即为边界
    field_min_len: int = 1              # 过短的字段会与相邻字段合并
    field_max_fields: int = 12          # 字段数上限（边界过多时按分数截断）
    field_segment_penalty: float = 2.0  # 最优分割里"每多一个字段"的扣分

    # 语义类型判定阈值
    enum_max_cardinality: int = 16      # 取值种类 ≤ 该值且 >1 → 枚举/命令字
    random_entropy: float = 6.5         # 列熵 ≥ 该值 → 随机数/会话 ID
    text_printable_ratio: float = 0.9   # 可打印字节占比 ≥ 该值 → 文本
    timestamp_min: int = 1_000_000_000  # 2001-09-09（秒级 Unix 时间下限）
    timestamp_max: int = 2_500_000_000  # 2049 年
    checksum_min_units: int = 3         # 校验和判据所需的最少样本

    # head / payload 分离（FLINT 的"熵分离"思路）
    payload_entropy: float = 5.0        # 连续若干列熵 ≥ 该值 → 进入载荷区
    payload_run: int = 3                # 需要连续多少列

    # ---- 消息类型聚类（keyword）----
    cluster_min_units: int = 6          # 样本太少不做聚类
    cluster_max_types: int = 16         # 超过该簇数说明选错了 keyword
    cluster_min_group: int = 2          # 每簇至少几帧

    # ---- 输出控制 ----
    top_candidates: int = 8
    max_frames_output: int = 32
    max_probe_frames: int = 96      # 枚举阶段的帧数筛查上限
    probe_stage1_frames: int = 4    # 筛查：帧数上限（帧小的时候起作用）
    probe_stage1_bytes: int = 8192  # 筛查：字节预算上限（帧大的时候起作用）

    # ---- 双向流联合推断（P2-8，见 bidir.py）----
    # 请求/响应帧长序列的相关系数门槛：达到即为"长度呼应"证据。
    # 只作为**辅助**证据（权重 0.10），因为长度相关也可能由"载荷大小相近"造成。
    coupling_corr_threshold: float = 0.7

    # ---- 分阶段搜索（P2-9，见 segmentation._search_staged）----
    # 全量假设空间是 scales × formats × offsets × overhead，其中 scale>1 与冷门
    # 编码占了约 6/7，而绝大多数协议落在 scale=1 + 常见编码里。因此先只搜这个
    # 核心子空间；只有它没能给出强证据时，才**补搜剩余子空间**（不重复已搜的
    # 部分），合并后再决策 —— 因此最坏情况与全量同价，命中时省约 70%。
    #
    # 标定（bench/calibrate_staged.py）：负样本在阶段 1 的候选级 gap 最高 0.119，
    # 长度前缀正样本普遍 ≥0.4 —— 沿用 min_matched_gap=0.25 作短路门槛即可，
    # 安全余量充足。真解是 scale>1 的样本阶段 1 gap 仅 0.12 左右，会自动落到
    # 补搜分支（这是设计意图：它们本来就必须在完整空间里找）。
    staged_search: bool = True
    stage1_scales: Tuple[int, ...] = (1,)
    stage1_formats: Tuple[str, ...] = (
        "uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le", "varint",
    )

    # ---- 置换检验用的搜索配置（P2-9）----
    # 全局 max-vs-max 要在采样窗口上跑 trials+1 次完整搜索，这是负样本的主要成本。
    # 观测侧与打乱侧**用同一套配置**，因此无偏性不变；缩小假设空间只是降低
    # "打乱后偶然撞出高分伪解"的机会。
    #
    # 标定：精简后负样本 gap 仍全为负（max -0.009），正样本反而更高
    # （varint -0.016 → +0.098）—— 分离度变好而非变差。
    # 为避免"真解是冷门编码"时观测侧搜不到它，运行时会把主搜索的最佳假设
    # 动态并入该集合（见 segmentation._perm_config）。
    perm_scales: Tuple[int, ...] = (1,)
    perm_formats: Tuple[str, ...] = (
        "uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le", "varint",
    )
    perm_max_offset: int = 16

    # ---- 候选验证 ----
    # 启发式分数只能排序，不能定案：实测真解可能排在第 15~48 名
    # （伪解帧数少但其它维度占优）。因此对分数最高的前 K 个**不同帧边界**候选
    # 逐一做置换检验，在通过显著性门槛的候选中取分数最高者。
    # 只验证 rank-1（早期实现）会让真解没有任何被检验的机会。
    verify_candidates: int = 5

    # ---- 行为开关 ----
    allow_trailing_partial: bool = True   # 允许最后一帧被截断（抓包常见）
    scan_start_offsets: bool = False      # 是否尝试非 0 起始偏移（更慢）

    def overridden(self, **kwargs) -> "AnalysisConfig":
        """返回覆写了若干字段的副本（忽略值为 ``None`` 的项）。"""
        data = {k: v for k, v in kwargs.items()
                if v is not None and k in self.__dataclass_fields__}
        if not data:
            return self
        return dataclasses.replace(self, **data)


DEFAULT_CONFIG = AnalysisConfig()
