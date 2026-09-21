"""
高级启发式TCP数据包拆包工具
===========================

增强功能：
1. 多维度启发式规则分析
2. 模式匹配与相似度计算
3. 自动协议识别
4. 增量式包头学习
5. 可视化输出
"""

from scapy.all import rdpcap, TCP, IP, Raw
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional, Set, Callable
from dataclasses import dataclass, field
import struct
import json


@dataclass
class HeaderPattern:
    """包头模式"""
    fixed_bytes: Dict[int, int] = field(default_factory=dict)  # offset -> value
    length_field_offset: Optional[int] = None
    length_field_width: int = 2
    length_endian: str = 'big'
    magic: Optional[bytes] = None
    confidence: float = 0.0
    sample_count: int = 0


@dataclass  
class FlowStats:
    """流统计信息"""
    flow_id: Tuple
    packet_count: int = 0
    total_bytes: int = 0
    packet_lengths: List[int] = field(default_factory=list)
    unique_lengths: Set[int] = field(default_factory=set)
    first_packet_time: float = 0.0
    last_packet_time: float = 0.0


class AdvancedHeuristicUnpacker:
    """高级启发式拆包器"""
    
    def __init__(self):
        self.flows: Dict[Tuple, List[Tuple[bytes, int, float]]] = {}  # flow_id -> [(data, seq, time)]
        self.flow_stats: Dict[Tuple, FlowStats] = {}
        self.header_patterns: Dict[Tuple, HeaderPattern] = {}
        
        # 启发式规则权重
        self.weights = {
            'fixed_byte': 2.0,
            'magic_sequence': 5.0,
            'length_correlation': 3.0,
            'pattern_repetition': 2.5,
            'entropy_low': 1.0,  # 低熵区域可能是固定格式
        }
    
    def load_pcap(self, pcap_file: str) -> int:
        """加载pcap文件"""
        print(f"[*] Loading: {pcap_file}")
        packets = rdpcap(pcap_file)
        
        for pkt in packets:
            if TCP in pkt and IP in pkt and Raw in pkt:
                self._process_packet(pkt)
        
        print(f"[*] Loaded {len(self.flows)} TCP flows")
        return len(self.flows)
    
    def _process_packet(self, pkt):
        """处理单个TCP包"""
        sip = pkt[IP].src
        dip = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        seq = pkt[TCP].seq
        timestamp = float(pkt.time)
        data = bytes(pkt[Raw].load)
        
        flow_id = (sip, dip, sport, dport)
        
        if flow_id not in self.flows:
            self.flows[flow_id] = []
            self.flow_stats[flow_id] = FlowStats(
                flow_id=flow_id,
                first_packet_time=timestamp
            )
        
        self.flows[flow_id].append((data, seq, timestamp))
        self.flow_stats[flow_id].packet_count += 1
        self.flow_stats[flow_id].total_bytes += len(data)
        self.flow_stats[flow_id].packet_lengths.append(len(data))
        self.flow_stats[flow_id].unique_lengths.add(len(data))
        self.flow_stats[flow_id].last_packet_time = timestamp
    
    def analyze_flow(self, flow_id: Tuple) -> HeaderPattern:
        """分析单个流的包头模式"""
        packets = self.flows.get(flow_id, [])
        if len(packets) < 2:
            return HeaderPattern()
        
        pattern = HeaderPattern(sample_count=len(packets))
        
        # 规则1: 固定字节检测
        self._detect_fixed_bytes(packets, pattern)
        
        # 规则2: 魔数序列检测
        self._detect_magic_sequences(packets, pattern)
        
        # 规则3: 长度字段检测
        self._detect_length_field(packets, pattern)
        
        # 规则4: 重复模式检测
        self._detect_repetition(packets, pattern)
        
        # 计算置信度
        pattern.confidence = self._calculate_confidence(pattern)
        
        self.header_patterns[flow_id] = pattern
        return pattern
    
    def _detect_fixed_bytes(self, packets: List, pattern: HeaderPattern):
        """检测固定字节位置"""
        if not packets:
            return
        
        min_len = min(len(p[0]) for p in packets)
        max_check = min(min_len, 32)  # 最多检查32字节
        
        for offset in range(max_check):
            byte_counter = Counter()
            for data, _, _ in packets:
                if len(data) > offset:
                    byte_counter[data[offset]] += 1
            
            most_common = byte_counter.most_common(1)[0]
            frequency = most_common[1] / len(packets)
            
            # 90%以上相同认为是固定字节
            if frequency >= 0.9:
                pattern.fixed_bytes[offset] = most_common[0]
    
    def _detect_magic_sequences(self, packets: List, pattern: HeaderPattern):
        """检测魔数序列"""
        if not packets:
            return
        
        min_len = min(len(p[0]) for p in packets)
        if min_len < 4:
            return
        
        # 检查从0开始的连续固定字节序列
        fixed_start = 0
        while fixed_start < min_len - 1:
            first_val = packets[0][0][fixed_start]
            is_fixed = all(p[0][fixed_start] == first_val for p in packets if len(p[0]) > fixed_start)
            
            if not is_fixed:
                break
            fixed_start += 1
        
        if fixed_start >= 4:  # 至少4字节的魔数
            pattern.magic = packets[0][0][:fixed_start]
    
    def _detect_length_field(self, packets: List, pattern: HeaderPattern):
        """检测长度字段"""
        if not packets:
            return
        
        # 按长度分组
        length_groups: Dict[int, List[bytes]] = defaultdict(list)
        for data, _, _ in packets:
            length_groups[len(data)].append(data)
        
        # 检查2字节和4字节长度字段
        for width in [2, 4]:
            for endian in ['big', 'little']:
                for offset in range(min(16, min(len(p[0]) for p in packets) - width)):
                    # 相同长度包的该字段应相同
                    valid = True
                    for length, group in length_groups.items():
                        if len(group) > 1:
                            values = set()
                            for pkt in group:
                                if len(pkt) >= offset + width:
                                    try:
                                        val = int.from_bytes(pkt[offset:offset+width], endian)
                                        values.add(val)
                                    except:
                                        valid = False
                                        break
                            if len(values) > 1:
                                valid = False
                                break
                    
                    if valid:
                        pattern.length_field_offset = offset
                        pattern.length_field_width = width
                        pattern.length_endian = endian
                        return
    
    def _detect_repetition(self, packets: List, pattern: HeaderPattern):
        """检测重复模式"""
        # 对于相同长度的包，检查是否有重复的包头结构
        pass  # 扩展实现
    
    def _calculate_confidence(self, pattern: HeaderPattern) -> float:
        """计算置信度"""
        score = 0
        
        # 固定字节贡献
        score += len(pattern.fixed_bytes) * self.weights['fixed_byte']
        
        # 魔数贡献
        if pattern.magic:
            score += len(pattern.magic) * self.weights['magic_sequence']
        
        # 长度字段贡献
        if pattern.length_field_offset is not None:
            score += self.weights['length_correlation']
        
        # 归一化到0-1
        return min(1.0, score / 20.0)
    
    def extract_messages(self, flow_id: Tuple, pattern: HeaderPattern = None) -> List[dict]:
        """从流中提取消息"""
        packets = self.flows.get(flow_id, [])
        
        if pattern is None:
            pattern = self.header_patterns.get(flow_id, HeaderPattern())
        
        messages = []
        
        for i, (data, seq, time) in enumerate(packets):
            if pattern.length_field_offset is not None:
                # 使用长度字段提取
                body = self._extract_by_length_field(data, pattern)
            elif pattern.magic and data.startswith(pattern.magic):
                # 使用魔数提取
                body = data[len(pattern.magic):]
            else:
                body = data
            
            messages.append({
                'index': i,
                'seq': seq,
                'time': time,
                'data': data,
                'header': data[:len(pattern.magic) if pattern.magic else 0],
                'body': body,
                'hex': data.hex()
            })
        
        return messages
    
    def _extract_by_length_field(self, data: bytes, pattern: HeaderPattern) -> bytes:
        """根据长度字段提取包体"""
        offset = pattern.length_field_offset
        width = pattern.length_field_width
        endian = pattern.length_endian
        
        if len(data) <= offset + width:
            return b''
        
        try:
            length = int.from_bytes(data[offset:offset+width], endian)
            body_start = offset + width
            body_end = min(body_start + length, len(data))
            return data[body_start:body_end]
        except:
            return b''
    
    def generate_report(self, flow_id: Tuple) -> str:
        """生成流的分析报告"""
        stats = self.flow_stats.get(flow_id)
        pattern = self.header_patterns.get(flow_id, HeaderPattern())
        
        if not stats:
            return "Flow not found"
        
        report = []
        report.append("=" * 60)
        report.append(f"Flow: {stats.flow_id[0]}:{stats.flow_id[2]} -> {stats.flow_id[1]}:{stats.flow_id[3]}")
        report.append("=" * 60)
        report.append(f"Packets: {stats.packet_count}")
        report.append(f"Total bytes: {stats.total_bytes}")
        report.append(f"Unique lengths: {sorted(stats.unique_lengths)}")
        report.append(f"Confidence: {pattern.confidence:.1%}")
        
        if pattern.fixed_bytes:
            report.append("\n[Fixed Bytes]")
            for off, val in sorted(pattern.fixed_bytes.items()):
                report.append(f"  Offset {off:2d}: 0x{val:02X} ({val:3d})")
        
        if pattern.magic:
            report.append(f"\n[Magic]: {pattern.magic.hex()}")
        
        if pattern.length_field_offset is not None:
            report.append(f"\n[Length Field]: offset={pattern.length_field_offset}, width={pattern.length_field_width}, endian={pattern.endian}")
        
        return "\n".join(report)


class ProtocolLearner:
    """协议学习器 - 从分析结果中学习协议规则"""
    
    def __init__(self):
        self.learned_patterns: List[dict] = []
    
    def learn_from_flow(self, flow_id: Tuple, pattern: HeaderPattern, packets: List) -> dict:
        """从流中学习协议规则"""
        learned = {
            'flow_id': flow_id,
            'fixed_bytes': dict(pattern.fixed_bytes),
            'has_length_field': pattern.length_field_offset is not None,
            'length_field': None,
            'magic': None,
            'sample_packets': []
        }
        
        if pattern.length_field_offset is not None:
            learned['length_field'] = {
                'offset': pattern.length_field_offset,
                'width': pattern.length_field_width,
                'endian': pattern.length_endian
            }
        
        if pattern.magic:
            learned['magic'] = pattern.magic.hex()
        
        # 保存样例包
        for i, (data, seq, time) in enumerate(packets[:5]):
            learned['sample_packets'].append({
                'seq': seq,
                'hex': data[:64].hex() + ('...' if len(data) > 64 else ''),
                'length': len(data)
            })
        
        self.learned_patterns.append(learned)
        return learned
    
    def save_rules(self, filename: str):
        """保存学习到的规则"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.learned_patterns, f, indent=2)
    
    def load_rules(self, filename: str) -> List[dict]:
        """加载规则"""
        with open(filename, 'r', encoding='utf-8') as f:
            self.learned_patterns = json.load(f)
        return self.learned_patterns


# ==================== 启发式规则定义 ====================

class HeuristicRules:
    """启发式规则集合"""
    
    @staticmethod
    def rule_length_prefix_protocol() -> Dict:
        """长度前缀协议规则"""
        return {
            'name': 'Length-Prefix Binary Protocol',
            'rules': [
                {
                    'type': 'length_field',
                    'offset': 0,
                    'width': 2,
                    'description': 'First 2 bytes are length (big-endian)'
                },
                {
                    'type': 'length_field', 
                    'offset': 2,
                    'width': 4,
                    'description': 'First 4 bytes are length (big-endian)'
                }
            ],
            'patterns': [
                {'byte': [0x00, 0x00], 'offset': 0},  # 常见长度前缀特征
            ]
        }
    
    @staticmethod
    def rule_fixed_header_protocol() -> Dict:
        """固定包头协议规则"""
        return {
            'name': 'Fixed Header Protocol',
            'rules': [
                {
                    'type': 'fixed_header',
                    'min_header_len': 4,
                    'max_header_len': 32,
                    'description': 'Header has fixed structure, body is remainder'
                }
            ]
        }
    
    @staticmethod
    def rule_magic_prefix_protocol() -> Dict:
        """魔数前缀协议规则"""
        return {
            'name': 'Magic Prefix Protocol',
            'rules': [
                {
                    'type': 'magic',
                    'min_magic_len': 4,
                    'description': 'First N bytes are magic/protocol identifier'
                }
            ],
            'common_magic': [
                b'\x00\x00\x00\x00',
                b'\xFF\xFF\xFF\xFF',
                b'\x01\x00\x00\x00',
                b'ABCD',
                b'PK\x03\x04',  # ZIP
            ]
        }
    
    @staticmethod
    def rule_incremental_length() -> Dict:
        """增量长度协议规则"""
        return {
            'name': 'Incremental Length Protocol',
            'rules': [
                {
                    'type': 'incremental_length',
                    'description': 'Length field increases incrementally between packets'
                }
            ]
        }


def apply_heuristic_rules(packets: List[bytes], rules: Dict) -> Dict:
    """应用启发式规则到数据包"""
    results = {
        'matched_rules': [],
        'header_offset': None,
        'body_offset': None,
        'confidence': 0.0
    }
    
    if not packets:
        return results
    
    # 检测长度字段
    length_candidates = _find_length_fields(packets)
    if length_candidates:
        results['matched_rules'].append('length_prefix')
        results['header_offset'] = max(c['offset'] for c in length_candidates)
    
    # 检测魔数
    magic = _find_common_magic(packets)
    if magic:
        results['matched_rules'].append('magic_prefix')
        results['body_offset'] = len(magic)
    
    return results


def _find_length_fields(packets: List[bytes]) -> List[dict]:
    """查找可能的长度字段"""
    candidates = []
    
    if len(packets) < 2:
        return candidates
    
    min_len = min(len(p) for p in packets)
    
    for width in [1, 2, 4]:
        for endian in ['big', 'little']:
            for offset in range(min(16, min_len - width)):
                valid = True
                for pkt in packets:
                    if len(pkt) <= offset + width:
                        valid = False
                        break
                
                if valid:
                    candidates.append({
                        'offset': offset,
                        'width': width,
                        'endian': endian,
                        'score': _score_length_field(packets, offset, width, endian)
                    })
    
    return [c for c in candidates if c['score'] > 0]


def _score_length_field(packets: List[bytes], offset: int, width: int, endian: str) -> float:
    """评分长度字段候选"""
    if not packets:
        return 0.0
    
    # 检查相同长度包的长度字段是否相同
    length_groups: Dict[int, List[int]] = defaultdict(list)
    
    for pkt in packets:
        if len(pkt) > offset + width:
            try:
                val = int.from_bytes(pkt[offset:offset+width], endian)
                length_groups[len(pkt)].append(val)
            except:
                return 0.0
    
    score = 0.0
    
    # 同长度包应有一致的字段值
    for length, values in length_groups.items():
        if len(values) > 1 and len(set(values)) == 1:
            score += 2.0
    
    # 差异包长度与字段值差异的相关性
    lengths = sorted(length_groups.keys())
    for i in range(len(lengths) - 1):
        len_diff = lengths[i+1] - lengths[i]
        val_diff = abs(length_groups[lengths[i+1]][0] - length_groups[lengths[i]][0])
        
        if len_diff > 0 and val_diff > 0:
            ratio = max(len_diff, val_diff) / min(len_diff, val_diff)
            if ratio < 3:  # 差异相近
                score += 1.0
    
    return score


def _find_common_magic(packets: List[bytes]) -> Optional[bytes]:
    """查找共同的魔数前缀"""
    if not packets:
        return None
    
    min_len = min(len(p) for p in packets)
    if min_len < 4:
        return None
    
    magic_len = 0
    for offset in range(min_len):
        first_val = packets[0][offset]
        all_same = all(p[offset] == first_val for p in packets if len(p) > offset)
        
        if all_same:
            magic_len = offset + 1
        else:
            break
    
    if magic_len >= 4:
        return packets[0][:magic_len]
    
    return None


def visualize_packet(data: bytes, highlight_offset: int = None):
    """可视化数据包"""
    lines = []
    lines.append("Hex Dump:")
    lines.append("-" * 79)
    
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        
        # 地址
        addr = f"{i:08X}  "
        
        # 十六进制
        hex_part = ' '.join(f"{b:02X}" for b in chunk)
        hex_part = hex_part.ljust(47)
        
        # 特殊标记
        if highlight_offset is not None:
            if highlight_offset >= i and highlight_offset < i + 16:
                marker = ' ' * ((highlight_offset - i) * 3)
                marker += '^'
            else:
                marker = ' ' * 16
        else:
            marker = ''
        
        # ASCII
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        
        lines.append(f"{addr}{hex_part}  {ascii_part}")
    
    lines.append("-" * 79)
    return '\n'.join(lines)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
        
        # 创建分析器
        unpacker = AdvancedHeuristicUnpacker()
        learner = ProtocolLearner()
        
        # 加载并分析
        unpacker.load_pcap(pcap_file)
        
        print(f"\n[*] Analyzing {len(unpacker.flows)} flows...\n")
        
        # 分析每个流
        for flow_id in list(unpacker.flows.keys())[:10]:  # 限制输出数量
            pattern = unpacker.analyze_flow(flow_id)
            
            if pattern.confidence > 0.1:
                print(unpacker.generate_report(flow_id))
                print()
                
                # 学习协议
                packets = unpacker.flows[flow_id]
                learned = learner.learn_from_flow(flow_id, pattern, packets)
                
                # 显示样例
                if learned['sample_packets']:
                    print("[Sample Packets]")
                    for sample in learned['sample_packets'][:3]:
                        print(f"  Seq {sample['seq']}: len={sample['length']}, hex={sample['hex']}")
                    print()
        
        # 保存学习到的规则
        if learner.learned_patterns:
            learner.save_rules('learned_rules.json')
            print("[*] Learned rules saved to learned_rules.json")
    
    else:
        print("""
Advanced Heuristic TCP Unpacker
===============================

Usage: python advanced_unpack.py <pcap_file>

Features:
- Multi-dimensional heuristic analysis
- Automatic protocol pattern detection
- Length field detection
- Magic number identification
- Protocol learning and rule export
""")
