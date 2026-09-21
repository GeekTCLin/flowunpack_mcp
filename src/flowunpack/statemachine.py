"""协议状态机推断（P2-10）。

在 :mod:`.fields` 的消息类型聚类**之后**运行：把每条消息抽象成一个**符号**，
于是一整条流变成一个符号序列，再从这条序列推断生成它的确定自动机（DFA）。

方法沿用 **PTA + k-Tail 状态合并**（Biermann & Feldman 1972；Netzob 的状态机
推断用的就是这一族）：

1. **符号化** —— 用 keyword 字段（消息类型聚类选出的那个）在每帧上的取值当符号。
   找不到可靠 keyword 时回退到包头里 cardinality 最小的枚举字段（且落在包头区）。
   两者都没有、整条流只有一种符号时**不做推断**并说明原因：单符号序列在信息上
   等价于"一直重复同一种消息"，任何状态机结论都是凭空捏造。
2. **PTA** —— 把符号序列展开成前缀树接受器（prefix tree acceptor）。单条流只是
   一条链，因此这一步本身不含任何压缩，价值全在下一步。
3. **k-Tail 合并** —— 两个位置若"后 k 步的符号串"相同则视为同一状态。这是
   Nerode 等价关系的 k 阶近似：k 大则精确（状态多），k 小则激进（状态少、可能
   过度泛化）。**末尾不足 k 个符号的位置按"最长可用前缀"并入已有的等价类** ——
   否则截断会在链尾造出假的非确定性（实测：3 周期序列 k=2 时，末位置自成一类，
   导致"倒数第二位置该指向谁"出现两个候选）。
4. **确定性检查** —— 合并后若同一状态同一符号出现两个后继，保留多数并记入
   ``conflicts``。这是 k-Tail 的已知代价，不隐藏。
5. **环检测** —— 在合并后的转移图上跑 SCC（Tarjan），找出**被反复执行**的状态环
   （环上每条转移的观测次数最小值 ≥ ``sm_min_cycle_traversals``）。这是协议状态机
   里最有价值的结构（轮询 / 心跳 / 请求-应答循环）；没有环就说明状态数 ≈ 符号数，
   等于什么都没推断出来。绕行次数门槛不可省：实测 24 个随机命令字能凑出一个
   3 状态环，但三条转移各只观测到 1 次（只走过一遍），那是巧合而非协议结构。

**诚实边界**（务必与结论一起读）：

* 只从**正样本**学习，因此所有状态都是接受态，得到的是**过近似**（over-
  approximation）自动机：它接受所有观测到的序列，对未观测序列不做任何保证。
  它不能用来判定"某个序列非法"。
* 单条 trace 上，"完整走通且确定"的自动机有无穷多个，**无法唯一确定**。因此
  本模块默认 ``k=2``，并把 ``k=1..4`` 的状态数一并暴露（``k_sensitivity``）供人工
  判断 —— 不假装存在唯一正确答案。
* ``confidence`` 是**结构强度启发式**（压缩率 × 样本量 × 是否有环 × 确定性），
  不是概率。压缩率接近 0 意味着"状态数 ≈ 符号数"，即没有可利用的重复结构。
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .config import AnalysisConfig, DEFAULT_CONFIG
from .models import FieldSpec, MessageType, _jsonable

__all__ = ["StateMachine", "infer_state_machine", "ktail_states"]


# ---------------------------------------------------------------------------
# 结果模型
# ---------------------------------------------------------------------------

@dataclass
class StateMachine:
    """推断出的协议状态机。

    ``transitions`` 每项是 ``{"src": int, "symbol": hex, "dst": int, "count": int}``。
    ``cycles`` 是检测到的环（每个环用符号序列表示），``cycle_lengths`` 是其长度。
    ``state_sequence`` 是原始符号序列上每个位置被归入的状态。
    """

    states: int
    initial: int
    accepting: List[int]
    transitions: List[Dict[str, Any]]
    alphabet: List[str]                       # 符号表（hex），按首次出现排序
    sequence: List[str]                       # 原始符号序列
    sequence_ascii: List[str] = field(default_factory=list)
    state_sequence: List[int] = field(default_factory=list)
    symbol_offset: int = 0
    symbol_length: int = 0
    symbol_source: str = ""                   # "keyword@2+1" / "field@4+1"
    k: int = 2
    cycles: List[List[str]] = field(default_factory=list)
    cycle_lengths: List[int] = field(default_factory=list)
    cycle_traversals: List[int] = field(default_factory=list)  # 每个环绕行的次数
    conflicts: int = 0
    compression: float = 0.0
    k_sensitivity: Dict[str, int] = field(default_factory=dict)
    confidence: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return _jsonable(asdict(self))

    # ---- 便捷访问 ----
    @property
    def symbol_count(self) -> int:
        return len(self.sequence)

    def initial_transitions(self) -> List[Dict[str, Any]]:
        return [t for t in self.transitions if t["src"] == self.initial]

    def transitions_of(self, state: int) -> List[Dict[str, Any]]:
        return [t for t in self.transitions if t["src"] == state]

    def describe(self) -> str:
        head = ("%d 状态 / %d 转移（k=%d，符号 %s 共 %d 个）"
                % (self.states, len(self.transitions), self.k,
                   self.symbol_source or "?", len(self.sequence)))
        if self.cycles:
            head += ("；检测到 %d 个环，最长周期 %d（最少绕行 %d 次）"
                     % (len(self.cycles), max(self.cycle_lengths),
                        min(self.cycle_traversals or [0])))
        else:
            head += "；未发现被反复执行的环（状态数≈符号数，无可用结构）"
        return head


# ---------------------------------------------------------------------------
# 符号化
# ---------------------------------------------------------------------------

def _choose_symbol_field(message_types: Sequence[MessageType],
                         fields: Sequence[FieldSpec],
                         cfg: AnalysisConfig) -> Optional[Tuple[int, int, str]]:
    """选出承载符号的字段：keyword 优先，回退到包头里基数最小的枚举字段。

    keyword 是消息类型聚类的结果，本身已经过"取值会重复 + 与帧长耦合"的筛选，
    因此优先。回退路径的存在意义是：有些流只分出一簇（keyword 判据没过关），
    但包头里仍有一个明显的命令字可用来区分消息。
    """
    for t in message_types:
        if t.keyword_offset is not None and t.keyword_length > 0:
            return t.keyword_offset, t.keyword_length, (
                "keyword@%d+%d" % (t.keyword_offset, t.keyword_length))
    cands = [f for f in fields
             if f.offset >= 0 and f.length > 0
             and f.kind in ("enum", "integer")
             and 2 <= f.cardinality <= cfg.enum_max_cardinality]
    if not cands:
        return None
    cands.sort(key=lambda f: (f.cardinality, f.offset))
    f = cands[0]
    return f.offset, f.length, "field@%d+%d" % (f.offset, f.length)


def _symbolize(units: Sequence[bytes], message_types: Sequence[MessageType],
               fields: Sequence[FieldSpec], cfg: AnalysisConfig
               ) -> Tuple[List[str], Optional[Tuple[int, int, str]], str]:
    """把每帧映射成符号（hex 字符串）。

    :return: ``(symbols, field, reason)``；``field`` 为 ``None`` 时 ``reason``
        说明为什么无法符号化（调用方据此给出"拒绝"而不是空结论）。
    """
    chosen = _choose_symbol_field(message_types, fields, cfg)
    if chosen is None:
        return [], None, ("包头区没有可分簇的字段（keyword 与枚举字段都不成立），"
                          "整条流只有一种消息 —— 单符号序列无法推断状态机")
    off, width, src = chosen
    out: List[str] = []
    for u in units:
        if len(u) < off + width:
            continue
        out.append(u[off:off + width].hex())
    return out, chosen, ""


# ---------------------------------------------------------------------------
# k-Tail 状态合并
# ---------------------------------------------------------------------------

def _tail_class(gram: Tuple[str, ...], full_keys: Sequence[Tuple[str, ...]],
                classes: Dict[Any, int]) -> int:
    """把末尾不足 k 个符号的窗口并入已有等价类。

    规则：找**以该短串为前缀**的完整 k-gram 中最早出现的那个类。找不到（该短串
    从未在任何完整窗口的开头出现过）时才另立新类。

    不这么做的话，链尾会因"tail 被截断"而与任何位置都不等价，凭空多出一个状态，
    并且它的**前驱**会同时指向两个不同状态 —— 制造假的非确定性。
    """
    best: Optional[int] = None
    for gram_full in full_keys:
        if gram_full[:len(gram)] != gram:
            continue
        c = classes[("g", gram_full)]
        if best is None or c < best:
            best = c
    if best is None:
        key = ("<tail>", gram)
        if key not in classes:
            classes[key] = len(classes)
        return classes[key]
    return best


def ktail_states(traces: Sequence[Sequence[str]], k: int
                 ) -> Tuple[int, List[List[int]], List[Dict[str, Any]], int]:
    """对若干条符号序列做 k-Tail 合并。

    :return: ``(状态数, 每条 trace 的状态序列, 转移列表, 冲突数)``。

    实现要点：先注册**全部完整 k-gram**（按首次出现顺序编号），再逐位置分类 ——
    末尾不足 k 的位置走 :func:`_tail_class`。这个两遍结构是必需的：末尾位置需要
    引用"后面才出现"的 gram。
    """
    if k < 1:
        k = 1
    classes: Dict[Any, int] = {}
    full_keys: List[Tuple[str, ...]] = []
    for tr in traces:
        n = len(tr)
        for i in range(n - k + 1):
            g = tuple(tr[i:i + k])
            key = ("g", g)
            if key not in classes:
                classes[key] = len(classes)
                full_keys.append(g)

    state_rows: List[List[int]] = []
    for tr in traces:
        row: List[int] = []
        for i, sym in enumerate(tr):
            g = tuple(tr[i:i + k])
            if len(g) == k:
                row.append(classes[("g", g)])
            else:
                row.append(_tail_class(g, full_keys, classes))
        state_rows.append(row)

    edge: Dict[Tuple[int, str], Counter] = {}
    for tr, row in zip(traces, state_rows):
        for i in range(len(tr) - 1):
            edge.setdefault((row[i], tr[i]), Counter())[row[i + 1]] += 1

    transitions: List[Dict[str, Any]] = []
    conflicts = 0
    for (src, sym), cnt in sorted(edge.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        if len(cnt) > 1:
            conflicts += 1
        dst = cnt.most_common(1)[0][0]                 # 冲突时取多数
        transitions.append({"src": src, "symbol": sym, "dst": dst,
                            "count": sum(cnt.values())})
    return len(classes), state_rows, transitions, conflicts


# ---------------------------------------------------------------------------
# 环检测（Tarjan SCC，迭代实现）
# ---------------------------------------------------------------------------

def _sccs(n: int, adj: Dict[int, List[Tuple[str, int]]]) -> List[List[int]]:
    """返回强连通分量列表（迭代版 Tarjan，避免深流触发递归上限）。"""
    index = [0] * n
    low = [0] * n
    on_stack = [False] * n
    stack: List[int] = []
    counter = [0]
    out: List[List[int]] = []

    for root in range(n):
        if index[root]:
            continue
        work: List[List[int]] = [[root, 0]]
        while work:
            v, i = work[-1]
            if i == 0:
                counter[0] += 1
                index[v] = low[v] = counter[0]
                stack.append(v)
                on_stack[v] = True
            recursed = False
            succ = adj.get(v, [])
            j = i
            while j < len(succ):
                w = succ[j][1]
                if not index[w]:
                    work[-1][1] = j + 1
                    work.append([w, 0])
                    recursed = True
                    break
                if on_stack[w]:
                    low[v] = min(low[v], index[w])
                j += 1
            if recursed:
                continue
            if low[v] == index[v]:
                comp: List[int] = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    comp.append(w)
                    if w == v:
                        break
                out.append(comp)
            work.pop()
            if work:
                p = work[-1][0]
                low[p] = min(low[p], low[v])
    return out


def _shortest_cycle(start: int, members: set,
                    adj: Dict[int, List[Tuple[str, int]]]
                    ) -> Tuple[List[str], List[int]]:
    """在 ``members`` 内部找一条 ``start`` 出发回到 ``start`` 的最短回路。

    :return: ``(符号序列, 节点序列)``；节点序列长度为 ``len(符号)+1``，
        首尾都是 ``start``。取最短回路是为了让报告里的"环"可读（长回路的
        起点往往是任意的）。无回路时返回 ``([], [])``。
    """
    best: Optional[Tuple[List[str], List[int]]] = None
    for sym, nxt in adj.get(start, []):
        if nxt not in members:
            continue
        if nxt == start:                              # 自环
            cand = ([sym], [start, start])
            if best is None or len(cand[0]) < len(best[0]):
                best = cand
            continue
        # 在分量内 BFS 找 nxt -> start 的最短路径
        prev: Dict[int, Tuple[int, str]] = {}
        queue = [nxt]
        seen = {nxt}
        found = False
        while queue and not found:
            cur = queue.pop(0)
            for s2, w in adj.get(cur, []):
                if w not in members or w in seen:
                    continue
                seen.add(w)
                prev[w] = (cur, s2)
                if w == start:
                    found = True
                    break
                queue.append(w)
        if not found:
            continue
        chain_syms: List[str] = []
        chain_nodes: List[int] = [start]
        node = start
        guard = 0
        while node != nxt and guard < len(members) + 2:
            p, s_ = prev[node]
            chain_syms.append(s_)
            node = p
            chain_nodes.append(node)
            guard += 1
        if node != nxt:
            continue
        syms = [sym] + list(reversed(chain_syms))
        nodes = [start] + list(reversed(chain_nodes))
        if best is None or len(syms) < len(best[0]):
            best = (syms, nodes)
    return best if best is not None else ([], [])


def _find_cycles(states: int, transitions: Sequence[Dict[str, Any]],
                 min_traversals: int) -> Tuple[List[List[str]], List[int]]:
    """找出**被反复执行**的状态环。

    SCC 找出候选后还要过一道门槛：环上每条转移的观测次数最小值就是"绕行次数"，
    必须 ≥ ``min_traversals``。这条判据不可省 —— 实测一条 24 个随机命令字的
    序列会凑出一个 3 状态环，但它的三条转移各只观测到 1 次，也就是只走过一遍，
    那是巧合而非协议结构。加门槛后这类噪声环被正确剔除。

    :return: ``(环列表, 每个环的绕行次数)``，按环长降序排列。
    """
    adj: Dict[int, List[Tuple[str, int]]] = {}
    counts: Dict[Tuple[int, str, int], int] = {}
    for t in transitions:
        adj.setdefault(t["src"], []).append((t["symbol"], t["dst"]))
        counts[(t["src"], t["symbol"], t["dst"])] = int(t["count"])
    if not adj:
        return [], []

    cycles: List[List[str]] = []
    traversals: List[int] = []
    seen: set = set()
    for comp in _sccs(states, adj):
        members = set(comp)
        trivial = len(comp) == 1 and not any(
            t["src"] == comp[0] and t["dst"] == comp[0] for t in transitions)
        if trivial:
            continue
        syms, nodes = _shortest_cycle(comp[0], members, adj)
        if not syms:
            continue
        key = tuple(syms)
        if key in seen:
            continue
        rounds = min(counts.get((nodes[i], syms[i], nodes[i + 1]), 0)
                     for i in range(len(syms)))
        if rounds < min_traversals:
            continue
        seen.add(key)
        cycles.append(syms)
        traversals.append(rounds)
    order = sorted(range(len(cycles)),
                   key=lambda i: (-len(cycles[i]), cycles[i]))
    return ([cycles[i] for i in order], [traversals[i] for i in order])


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def _looks_ascii(sym_hex: str) -> str:
    if len(sym_hex) % 2:
        return ""
    try:
        raw = bytes.fromhex(sym_hex)
    except ValueError:
        return ""
    if all(32 <= b < 127 for b in raw):
        return "".join(chr(b) for b in raw)
    return ""


def infer_state_machine(units: Sequence[bytes],
                        message_types: Sequence[MessageType] = (),
                        fields: Sequence[FieldSpec] = (),
                        cfg: AnalysisConfig = DEFAULT_CONFIG,
                        k: Optional[int] = None
                        ) -> Optional[StateMachine]:
    """从已切分的消息序列推断协议状态机。

    :param units: 分帧后的消息（``frame.header + frame.body``）。**顺序即时间序**，
        这是本函数最重要的输入 —— 状态机是"消息序列"的性质，不是"消息集合"的。
    :param message_types: :func:`flowunpack.fields.infer_message_types` 的结果，
        用来定位 keyword 字段。
    :param fields: :func:`flowunpack.fields.infer_fields` 的结果，作为符号化回退。
    :param k: k-Tail 的尾部深度；``None`` 时取 ``cfg.sm_default_k``。
    :return: :class:`StateMachine`；无法符号化或样本不足时返回 ``None``
        （原因写在调用方的 ``notes`` 里，见 :func:`explain_skip`）。
    """
    units = [u for u in units if u]
    if len(units) < cfg.sm_min_symbols:
        return None

    symbols, chosen, _reason = _symbolize(units, message_types, fields, cfg)
    if chosen is None or len(symbols) < cfg.sm_min_symbols:
        return None

    alphabet: List[str] = []
    for s in symbols:
        if s not in alphabet:
            alphabet.append(s)
    if len(alphabet) < 2:
        # 只有一种符号：状态机在信息上不可判 —— 不猜。
        return None
    if len(alphabet) > cfg.sm_max_alphabet:
        return None
    if len(symbols) / float(len(alphabet)) < cfg.sm_min_symbol_repeats:
        # 符号互不重复（递增序号 / 随机数）→ 无可合并状态，推不出结构。
        return None

    kk = int(k if k is not None else cfg.sm_default_k)
    kk = max(1, min(kk, cfg.sm_max_k))

    def build(kv: int):
        return ktail_states([symbols], kv)

    states, rows, transitions, conflicts = build(kk)

    # k 的敏感性：单条 trace 上不存在唯一正确的 k，暴露曲线让人工判断。
    sens: Dict[str, int] = {}
    for kx in cfg.sm_k_sensitivity:
        kx = max(1, int(kx))
        if kx > len(symbols):
            continue
        try:
            sens[str(kx)] = build(kx)[0]
        except Exception:                            # pragma: no cover - 防御
            continue

    cycles, cycle_traversals = _find_cycles(
        states, transitions, cfg.sm_min_cycle_traversals)
    cycle_lengths = [len(c) for c in cycles]

    n = len(symbols)
    compression = max(0.0, 1.0 - states / max(1, n))
    length_factor = min(1.0, n / float(max(1, cfg.sm_min_symbols)))
    loop_factor = 1.0 if cycles else 0.45
    det_factor = 1.0 - 0.5 * conflicts / float(max(1, len(transitions)))
    confidence = round(min(1.0, compression * length_factor
                           * loop_factor * max(0.0, det_factor)), 4)

    notes: List[str] = []
    if not cycles:
        notes.append("未发现被反复执行的状态环：状态数与符号数同阶（%d/%d），"
                     "说明这段序列没有可利用的重复结构，推断结果不具解释力"
                     % (states, n))
    if conflicts:
        notes.append("k-Tail 合并产生 %d 处非确定性（同一状态同一符号有多个后继），"
                     "已按多数保留 —— 这是 k 偏小的典型代价，可用更大的 k 复核"
                     % conflicts)
    if len(sens) > 1 and len(set(sens.values())) > 1:
        notes.append("k 敏感性：不同 k 给出不同状态数 %s —— 单条样本无法唯一确定 k，"
                     "默认取 k=%d" % (sens, kk))
    if len(alphabet) > cfg.cluster_max_types:
        notes.append("符号种类 %d 偏多，可能存在噪声字段被当成命令字" % len(alphabet))

    return StateMachine(
        states=states,
        initial=rows[0][0] if rows and rows[0] else 0,
        accepting=list(range(states)),
        transitions=transitions,
        alphabet=alphabet,
        sequence=list(symbols),
        sequence_ascii=[_looks_ascii(s) for s in symbols],
        state_sequence=list(rows[0]) if rows else [],
        symbol_offset=chosen[0] if chosen else 0,
        symbol_length=chosen[1] if chosen else 0,
        symbol_source=chosen[2] if chosen else "",
        k=kk,
        cycles=cycles,
        cycle_lengths=cycle_lengths,
        cycle_traversals=cycle_traversals,
        conflicts=conflicts,
        compression=round(compression, 4),
        k_sensitivity=sens,
        confidence=confidence,
        evidence={
            "symbol_count": n,
            "alphabet_size": len(alphabet),
            "transition_count": len(transitions),
            "length_factor": round(length_factor, 4),
            "loop_factor": loop_factor,
            "determinism_factor": round(det_factor, 4),
            "method": "PTA + k-Tail merging (Nerode 等价的 k 阶近似)",
        },
        notes=notes,
    )


def explain_skip(units: Sequence[bytes],
                 message_types: Sequence[MessageType] = (),
                 fields: Sequence[FieldSpec] = (),
                 cfg: AnalysisConfig = DEFAULT_CONFIG) -> str:
    """说明为什么没有推断出状态机（供报告渲染，避免"静默为空"）。"""
    units = [u for u in units if u]
    if len(units) < cfg.sm_min_symbols:
        return ("消息数 %d < sm_min_symbols=%d，样本太少，不做状态机推断"
                % (len(units), cfg.sm_min_symbols))
    symbols, chosen, reason = _symbolize(units, message_types, fields, cfg)
    if chosen is None:
        return reason
    if len(symbols) < cfg.sm_min_symbols:
        return ("可符号化的消息只有 %d 条（字段宽度超出部分帧长），样本不足"
                % len(symbols))
    alpha = set(symbols)
    if len(alpha) < 2:
        return ("符号字段 %s 在这条流上取值恒定（只有 %s）—— 单符号序列"
                "无法推断状态机：任何结论都等价于假设「一直重复同一种消息」"
                % (chosen[2], next(iter(alpha))))
    if len(alpha) > cfg.sm_max_alphabet:
        return ("符号种类 %d > sm_max_alphabet=%d，字段取值几乎不重复，"
                "不像命令字" % (len(alpha), cfg.sm_max_alphabet))
    reps = len(symbols) / float(len(alpha))
    if reps < cfg.sm_min_symbol_repeats:
        return ("符号平均只重复 %.1f 次（%d 条消息 / %d 种取值，门槛 %.1f）——"
                "符号取值几乎互不重复，更像递增序号或随机数，没有可合并的状态"
                % (reps, len(symbols), len(alpha), cfg.sm_min_symbol_repeats))
    return "未知原因"
