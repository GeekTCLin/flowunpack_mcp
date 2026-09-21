"""
启发式TCP数据包拆包工具
=======================
功能：
1. 读取pcap文件，按五元组划分TCP流
2. 启发式分析TCP数据，识别包头包体格式
3. 包头中某字节表示包体长度
4. 支持自定义协议格式识别
"""

from scapy.all import rdpcap, TCP, IP, Raw
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional, Set
import struct
from itertools import combinations


# ==================== 配置参数 ====================

# 默认暴力枚举的前N个包头字节
DEFAULT_BRUTE_FORCE_N = 40


# ==================== 暴力数学关系分析器 ====================

class BruteForceMathAnalyzer:
    """
    暴力枚举包头中的数学关系
    
    分析以下可能的数学关系：
    1. length_field = packet_length - overhead (长度 = 总长 - 固定开销)
    2. length_field = body_length (长度字段表示包体长度)
    3. length_field = header_length (长度字段表示包头长度)
    4. length_field = body_offset (长度字段表示包体偏移)
    5. length_field = packet_length - body_offset (长度 = 总长 - 包体偏移)
    6. length_field = packet_length - header_length (长度 = 总长 - 包头长度)
    7. length_field = header_length + body_offset (复合关系)
    """

    def __init__(self, header_scan_n: int = DEFAULT_BRUTE_FORCE_N):
        self.header_scan_n = header_scan_n
        self.results = {}

    def analyze(self, flow: TCPFlow) -> dict:
        """分析流的数学关系"""
        if len(flow.packets) < 2:
            return {'status': 'insufficient_data', 'reason': '需要至少2个包'}

        packets = flow.packets
        unique_lengths = sorted(set(len(p) for p in packets))
        
        result = {
            'status': 'analyzed',
            'packet_count': len(packets),
            'unique_lengths': unique_lengths,
            'math_relations': [],
            'best_candidates': []
        }

        # 收集统计信息
        packet_stats = self._collect_packet_stats(packets)
        result['packet_stats'] = packet_stats

        # 枚举所有可能的数学关系
        relations = self._enumerate_math_relations(packets, packet_stats)
        result['math_relations'] = relations

        # 对每个候选进行评分
        scored_candidates = self._score_candidates(relations, packet_stats)
        result['best_candidates'] = scored_candidates[:10]

        return result

    def _collect_packet_stats(self, packets: List[bytes]) -> dict:
        """收集包的统计信息"""
        lengths = [len(p) for p in packets]
        stats = {
            'lengths': lengths,
            'min_length': min(lengths),
            'max_length': max(lengths),
            'unique_lengths': sorted(set(lengths)),
            'length_to_packets': defaultdict(list)
        }

        for i, pkt in enumerate(packets):
            stats['length_to_packets'][len(pkt)].append((i, pkt))

        return stats

    def _enumerate_math_relations(self, packets: List[bytes], stats: dict) -> List[dict]:
        """枚举所有可能的数学关系"""
        relations = []
        n = min(self.header_scan_n, max(len(p) for p in packets))

        for offset in range(n):
            for format_name, format_info in LENGTH_FIELD_FORMATS.items():
                decoder = format_info['decoder']
                
                # 尝试在该偏移解码
                decoded_values = []
                valid = True

                for pkt in packets:
                    if len(pkt) > offset:
                        try:
                            val, consumed = decoder(pkt, offset)
                            decoded_values.append(val)
                        except:
                            valid = False
                            break
                    else:
                        valid = False
                        break

                if not valid or not decoded_values:
                    continue

                # 分析解码值的特征
                relation = self._analyze_decoded_values(
                    offset, format_name, consumed, 
                    decoded_values, stats
                )
                if relation:
                    relations.append(relation)

        return relations

    def _analyze_decoded_values(self, offset: int, format_name: str, 
                                 width: int, decoded_values: List[int],
                                 stats: dict) -> Optional[dict]:
        """分析解码值的数学关系"""
        unique_decoded = sorted(set(decoded_values))
        packet_lengths = stats['lengths']

        relation = {
            'offset': offset,
            'format': format_name,
            'width': width,
            'unique_values': unique_decoded,
            'unique_count': len(unique_decoded),
            'possible_relations': []
        }

        # 按包长度分组
        length_groups = defaultdict(list)
        for i, pkt_len in enumerate(packet_lengths):
            length_groups[pkt_len].append(decoded_values[i])

        # 获取每个长度的代表值（如果同长度包的值相同）
        representative_values = {}
        for pkt_len, values in length_groups.items():
            if len(set(values)) == 1:
                representative_values[pkt_len] = values[0]

        if not representative_values:
            return None

        relation['representative_values'] = representative_values

        # 检查是否是零填充区域（该偏移前面全是0）
        is_zero_padding = self._is_zero_padding_area(offset, stats)
        relation['is_zero_padding'] = is_zero_padding

        # 尝试多种数学关系
        # 关系1: length_field = packet_length - overhead
        self._test_overhead_relation(relation, representative_values, is_zero_padding)
        
        # 关系2: length_field = body_offset (包体相对于包头的偏移)
        self._test_body_offset_relation(relation, representative_values, stats, is_zero_padding)
        
        # 关系3: length_field = header_length (包头长度)
        self._test_header_length_relation(relation, representative_values, stats, is_zero_padding)
        
        # 关系4: length_field = body_length (包体长度)
        self._test_body_length_relation(relation, representative_values, stats, is_zero_padding)
        
        # 关系5: length_field = packet_length - header_length - body_offset
        self._test_compound_relation(relation, representative_values, stats, is_zero_padding)

        # 关系6: 检查是否是固定偏移关系
        self._test_fixed_offset_relation(relation, representative_values, stats, is_zero_padding)

        return relation if relation['possible_relations'] else None

    def _is_zero_padding_area(self, offset: int, stats: dict) -> bool:
        """检查该偏移是否在零填充区域（前面连续字节都是0）"""
        if not stats.get('length_to_packets'):
            return False
        
        # 获取第一个包的数据
        first_len = list(stats['length_to_packets'].keys())[0]
        first_pkt = stats['length_to_packets'][first_len][0][1]
        
        if not isinstance(first_pkt, bytes) or len(first_pkt) < offset:
            return False
        
        # 检查[offset-1]到[0]是否都是0
        for i in range(offset):
            if first_pkt[i] != 0:
                return False
        return True

    def _test_overhead_relation(self, relation: dict, rep_values: dict, is_zero_padding: bool = False):
        """测试: length_field = packet_length - overhead"""
        for overhead in range(0, 50):
            matches = 0
            errors = []
            all_zero_values = True  # 检查是否所有解码值都是0

            for pkt_len, val in rep_values.items():
                if val != 0:
                    all_zero_values = False
                expected = pkt_len - overhead
                if expected >= 0:
                    diff = abs(val - expected)
                    if diff <= 3:  # 允许3字节误差
                        matches += 1
                        errors.append(diff)
                    else:
                        break
                else:
                    break

            if matches >= len(rep_values) * 0.8:  # 80%匹配
                # 如果值都是0，且在零填充区域，则降低置信度
                if all_zero_values and is_zero_padding:
                    confidence = (matches / len(rep_values)) * 0.2  # 大幅降低
                else:
                    confidence = matches / len(rep_values)
                
                relation['possible_relations'].append({
                    'type': 'packet_length_minus_overhead',
                    'formula': f'length_field = packet_length - {overhead}',
                    'overhead': overhead,
                    'matches': matches,
                    'avg_error': sum(errors) / len(errors) if errors else 0,
                    'confidence': confidence,
                    'is_zero_padding': all_zero_values and is_zero_padding
                })

    def _test_body_offset_relation(self, relation: dict, rep_values: dict, stats: dict, is_zero_padding: bool = False):
        """测试: length_field = body_offset (包体开始的偏移)"""
        n = min(self.header_scan_n, stats['max_length'])

        for body_offset in range(0, n):
            matches = 0
            errors = []

            for pkt_len, val in rep_values.items():
                if pkt_len > body_offset:
                    expected = body_offset
                    diff = abs(val - expected)
                    if diff <= 2:
                        matches += 1
                        errors.append(diff)

            if matches >= len(rep_values) * 0.7:
                # 如果值都是0且在零填充区域，降低置信度
                if is_zero_padding and list(rep_values.values())[0] == 0:
                    confidence = (matches / len(rep_values)) * 0.3
                else:
                    confidence = matches / len(rep_values)
                
                relation['possible_relations'].append({
                    'type': 'body_offset',
                    'formula': f'length_field = body_offset ({body_offset})',
                    'body_offset': body_offset,
                    'matches': matches,
                    'avg_error': sum(errors) / len(errors) if errors else 0,
                    'confidence': confidence,
                    'is_zero_padding': is_zero_padding and list(rep_values.values())[0] == 0
                })

    def _test_header_length_relation(self, relation: dict, rep_values: dict, stats: dict, is_zero_padding: bool = False):
        """测试: length_field = header_length"""
        n = min(self.header_scan_n, stats['max_length'])

        for header_len in range(2, n):
            matches = 0
            errors = []

            for pkt_len, val in rep_values.items():
                if pkt_len > header_len:
                    expected = header_len
                    diff = abs(val - expected)
                    if diff <= 2:
                        matches += 1
                        errors.append(diff)

            if matches >= len(rep_values) * 0.7:
                relation['possible_relations'].append({
                    'type': 'header_length',
                    'formula': f'length_field = header_length ({header_len})',
                    'header_length': header_len,
                    'matches': matches,
                    'avg_error': sum(errors) / len(errors) if errors else 0,
                    'confidence': matches / len(rep_values)
                })

    def _test_body_length_relation(self, relation: dict, rep_values: dict, stats: dict, is_zero_padding: bool = False):
        """测试: length_field = body_length (不包含包头)"""
        n = min(self.header_scan_n, stats['max_length'])

        for header_len in range(0, n):
            matches = 0
            errors = []

            for pkt_len, val in rep_values.items():
                if pkt_len > header_len:
                    expected = pkt_len - header_len
                    diff = abs(val - expected)
                    if diff <= 3:
                        matches += 1
                        errors.append(diff)

            if matches >= len(rep_values) * 0.7:
                relation['possible_relations'].append({
                    'type': 'body_length',
                    'formula': f'length_field = packet_length - {header_len}',
                    'header_len': header_len,
                    'matches': matches,
                    'avg_error': sum(errors) / len(errors) if errors else 0,
                    'confidence': matches / len(rep_values)
                })

    def _test_compound_relation(self, relation: dict, rep_values: dict, stats: dict, is_zero_padding: bool = False):
        """测试: length_field = packet_length - header_len - body_offset"""
        n = min(self.header_scan_n, stats['max_length'])

        for header_len in range(0, min(n, 20)):
            for body_offset in range(0, min(n, 20)):
                if header_len + body_offset >= n:
                    continue

                matches = 0
                errors = []

                for pkt_len, val in rep_values.items():
                    expected = pkt_len - header_len - body_offset
                    if expected >= 0:
                        diff = abs(val - expected)
                        if diff <= 3:
                            matches += 1
                            errors.append(diff)

                if matches >= len(rep_values) * 0.7:
                    relation['possible_relations'].append({
                        'type': 'compound',
                        'formula': f'length_field = packet_length - {header_len} - {body_offset}',
                        'header_len': header_len,
                        'body_offset': body_offset,
                        'matches': matches,
                        'avg_error': sum(errors) / len(errors) if errors else 0,
                        'confidence': matches / len(rep_values)
                    })

    def _test_fixed_offset_relation(self, relation: dict, rep_values: dict, stats: dict, is_zero_padding: bool = False):
        """测试: length_field 与包长度的差值是否恒定"""
        if len(rep_values) < 2:
            return
            return

        diffs = []
        for pkt_len, val in rep_values.items():
            diffs.append(pkt_len - val)

        # 检查差值是否大致相同
        if diffs:
            avg_diff = sum(diffs) / len(diffs)
            variance = sum((d - avg_diff) ** 2 for d in diffs) / len(diffs)
            
            if variance < 10:  # 方差小于10
                relation['possible_relations'].append({
                    'type': 'fixed_overhead',
                    'formula': f'length_field + overhead = packet_length (overhead ≈ {avg_diff:.1f})',
                    'avg_overhead': avg_diff,
                    'variance': variance,
                    'confidence': 0.9 if variance < 5 else 0.7
                })

    def _score_candidates(self, relations: List[dict], stats: dict) -> List[dict]:
        """对候选方案进行评分"""
        candidates = []

        for rel in relations:
            for possible in rel.get('possible_relations', []):
                cand = {
                    'offset': rel['offset'],
                    'format': rel['format'],
                    'width': rel['width'],
                    'relation_type': possible['type'],
                    'formula': possible['formula'],
                    'confidence': possible.get('confidence', 0),
                    'matches': possible.get('matches', 0),
                    'avg_error': possible.get('avg_error', 0),
                    'representative_values': rel.get('representative_values', {}),
                    'is_zero_padding': possible.get('is_zero_padding', False)
                }

                # 综合评分
                base_score = possible.get('confidence', 0) * 100
                
                avg_error = possible.get('avg_error', 0)
                
                # 偏移量评分策略调整：
                # 1. 如果误差为0（完美匹配），偏移量越小越好
                # 2. 如果误差>0，应该更看重误差而不是偏移量
                # 3. 偏移0如果有误差，可能是因为有魔数前缀，应该惩罚
                if avg_error == 0:
                    # 完美匹配：偏移越小越好
                    if rel['offset'] == 0:
                        offset_bonus = 15
                    elif rel['offset'] <= 4:
                        offset_bonus = 10
                    elif rel['offset'] <= 10:
                        offset_bonus = 8
                    else:
                        offset_bonus = 5
                else:
                    # 有误差：主要看误差大小，偏移量影响较小
                    # 但偏移0如果有误差，可能是魔数前缀，应该大幅惩罚
                    if rel['offset'] == 0:
                        offset_bonus = -20  # 偏移0有误差，很可能不是真正的长度字段
                    elif rel['offset'] <= 4:
                        offset_bonus = 3
                    elif rel['offset'] <= 10:
                        offset_bonus = 5
                    else:
                        offset_bonus = 2

                # 误差惩罚：误差越大惩罚越重
                error_penalty = min(avg_error * 5, 40)

                # 格式惩罚：优先固定宽度格式
                format_bonus = 5 if rel['format'].startswith('uint') else 0

                # 完美匹配额外加分
                if avg_error == 0 and possible.get('matches', 0) >= len(stats['unique_lengths']) * 0.8:
                    perfect_bonus = 10
                else:
                    perfect_bonus = 0

                cand['score'] = base_score + offset_bonus + format_bonus - error_penalty + perfect_bonus
                
                # 额外检查：如果该偏移在零填充区域，且解码值与某个非零填充区域偏移的解码值相同
                # 则大幅降低该候选的分数（因为它可能是padding+real_value的组合）
                if possible.get('is_zero_padding', False):
                    cand['score'] *= 0.1
                
                candidates.append(cand)

        # 再次处理：排除零填充区域+实际值组合的误判
        # 如果多个偏移解码出相同的值，选择非零填充的那个
        self._deduplicate_padding_false_positives(candidates)

        # 按分数排序
        return sorted(candidates, key=lambda x: x['score'], reverse=True)

    def _deduplicate_padding_false_positives(self, candidates: List[dict]):
        """排除零填充区域的误判
        
        如果offset 0-1是0x00填充，而offset 2解码出的值与offset 0 uint32_be相同
        说明offset 0的解码包含了padding，应该选择offset 2作为真正的长度字段位置
        """
        if len(candidates) < 2:
            return
        
        # 按解码值分组（如果有多种关系类型，先收集每个偏移+值组合）
        offset_value_pairs = []
        for cand in candidates:
            rep_values = cand.get('representative_values', {})
            if rep_values:
                # 取第一个代表值作为标识
                first_val = list(rep_values.values())[0]
                offset_value_pairs.append((cand['offset'], first_val, cand))
        
        # 找出有相同值的偏移对
        for i, (off1, val1, cand1) in enumerate(offset_value_pairs):
            for off2, val2, cand2 in offset_value_pairs[i+1:]:
                if val1 == val2 and off1 < off2:
                    # 同一个值出现在两个偏移，检查是否一个是padding
                    # 如果off1是0且off2>0，且两者的解码值相同
                    # 说明off1的解码可能包含了off2所在的区域
                    if off1 == 0 and off2 > 0:
                        # 检查off1是否是padding（off1<off2，且off1的宽度覆盖了off2）
                        width1 = cand1.get('width', 1)
                        if off1 + width1 > off2:
                            # off1的解码区域覆盖了off2，大幅降低off1的分数
                            cand1['score'] *= 0.1


# ==================== Varint 编解码支持 ====================


# ==================== Varint 编解码支持 ====================

def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    解码标准Varint (MSB为继续位)
    返回: (解码值, 消耗的字节数)
    """
    result = 0
    shift = 0
    pos = offset
    max_bytes = 10
    
    while pos < len(data) and pos - offset < max_bytes:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, pos - offset
    return result, pos - offset


def decode_uleb128(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    解码ULEB128 (Little-Endian Base 128)
    """
    result = 0
    shift = 0
    pos = offset
    
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, pos - offset
        shift += 7
    return result, pos - offset


# ==================== 长度字段格式定义 ====================

LENGTH_FIELD_FORMATS = {
    'uint8': {'width': 1, 'endian': 'fixed', 'decoder': lambda d, o: (d[o], 1)},
    'uint16_be': {'width': 2, 'endian': 'big', 'decoder': lambda d, o: (int.from_bytes(d[o:o+2], 'big'), 2)},
    'uint16_le': {'width': 2, 'endian': 'little', 'decoder': lambda d, o: (int.from_bytes(d[o:o+2], 'little'), 2)},
    'uint32_be': {'width': 4, 'endian': 'big', 'decoder': lambda d, o: (int.from_bytes(d[o:o+4], 'big'), 4)},
    'uint32_le': {'width': 4, 'endian': 'little', 'decoder': lambda d, o: (int.from_bytes(d[o:o+4], 'little'), 4)},
    'uint64_be': {'width': 8, 'endian': 'big', 'decoder': lambda d, o: (int.from_bytes(d[o:o+8], 'big'), 8)},
    'uint64_le': {'width': 8, 'endian': 'little', 'decoder': lambda d, o: (int.from_bytes(d[o:o+8], 'little'), 8)},
    'varint': {'width': None, 'endian': 'varint', 'decoder': decode_varint},
    'uleb128': {'width': None, 'endian': 'leb128', 'decoder': decode_uleb128},
}


class TCPFlow:
    """TCP流，表示一个五元组连接"""
    def __init__(self, sip, dip, sport, dport):
        self.sip = sip
        self.dip = dip
        self.sport = sport
        self.dport = dport
        self.packets: List[bytes] = []  # 按时间顺序的原始数据
        self.packet_info: List[dict] = []  # 包含包序号、时间等信息
    
    @property
    def flow_id(self):
        return (self.sip, self.dip, self.sport, self.dport)
    
    @property
    def reverse_flow_id(self):
        return (self.dip, self.sip, self.dport, self.sport)
    
    def add_packet(self, pkt_data: bytes, seq: int, timestamp: float, pkt_index: int):
        self.packets.append(pkt_data)
        self.packet_info.append({
            'seq': seq,
            'timestamp': timestamp,
            'index': pkt_index,
            'length': len(pkt_data)
        })
    
    def get_all_data(self, direction: str = 'forward') -> bytes:
        """获取流中所有数据"""
        data = b''
        for i, pkt_data in enumerate(self.packets):
            data += pkt_data
        return data


class HeuristicUnpacker:
    """启发式拆包器"""
    
    def __init__(self, min_header_len: int = 4, max_header_len: int = 64, 
                 brute_force_n: int = DEFAULT_BRUTE_FORCE_N):
        self.min_header_len = min_header_len
        self.max_header_len = max_header_len
        self.brute_force_n = brute_force_n
        self.flows: Dict[Tuple, TCPFlow] = {}
        self.analysis_results: Dict[str, dict] = {}
        
        # 初始化暴力数学关系分析器
        self.math_analyzer = BruteForceMathAnalyzer(header_scan_n=brute_force_n)
        
    def load_pcap(self, pcap_file: str):
        """加载pcap文件并按五元组划分流"""
        print(f"[*] Loading pcap file: {pcap_file}")
        packets = rdpcap(pcap_file)
        print(f"[*] Total packets: {len(packets)}")
        
        for idx, pkt in enumerate(packets):
            if TCP in pkt and IP in pkt:
                self._process_packet(pkt, idx)
        
        print(f"[*] Total TCP flows: {len(self.flows)}")
        return self.flows
    
    def _process_packet(self, pkt, pkt_index: int):
        """处理单个TCP包"""
        sip = pkt[IP].src
        dip = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        seq = pkt[TCP].seq
        timestamp = float(pkt.time)
        
        flow_key = (sip, dip, sport, dport)
        
        # 获取TCP负载数据
        if Raw in pkt:
            pkt_data = bytes(pkt[Raw].load)
        else:
            pkt_data = b''
        
        if pkt_data:
            if flow_key not in self.flows:
                self.flows[flow_key] = TCPFlow(sip, dip, sport, dport)
            self.flows[flow_key].add_packet(pkt_data, seq, timestamp, pkt_index)
            
            # 同时添加到反向流
            reverse_key = (dip, sip, dport, sport)
            if reverse_key not in self.flows:
                self.flows[reverse_key] = TCPFlow(dip, sip, dport, sport)
            self.flows[reverse_key].add_packet(pkt_data, seq, timestamp, pkt_index)
    
    def analyze_flow(self, flow: TCPFlow) -> dict:
        """分析单个流，启发式识别包头包体格式"""
        if len(flow.packets) < 2:
            return {'status': 'insufficient_data', 'packets': len(flow.packets)}
        
        result = {
            'flow_id': flow.flow_id,
            'total_packets': len(flow.packets),
            'total_bytes': sum(len(p) for p in flow.packets),
            'packet_lengths': [len(p) for p in flow.packets],
            'status': 'analyzed'
        }
        
        # 启发式分析1: 分析长度字段在包头中的位置
        header_analysis = self._analyze_header_length_field(flow)
        result['header_analysis'] = header_analysis
        
        # 启发式分析2: 分析包头中的固定字段
        fixed_field_analysis = self._analyze_fixed_fields(flow)
        result['fixed_fields'] = fixed_field_analysis
        
        # 启发式分析3: 分析相同长度包的特征
        length_pattern = self._analyze_length_pattern(flow)
        result['length_pattern'] = length_pattern
        
        # 启发式分析4: 分析包头模板
        header_template = self._analyze_header_template(flow)
        result['header_template'] = header_template
        
        # 暴力数学关系分析 (新增!)
        math_analysis = self.math_analyzer.analyze(flow)
        result['math_relations'] = math_analysis
        
        # 综合结论
        result['conclusion'] = self._generate_conclusion(result)
        
        return result
    
    def _generate_conclusion(self, result: dict) -> dict:
        """生成综合分析结论"""
        conclusion = {
            'detected': False,
            'header_length': None,
            'body_offset': None,
            'length_field_offset': None,
            'length_field_format': None,
            'confidence': 0.0,
            'reasoning': []
        }
        
        # 从数学关系分析中获取最佳候选
        math = result.get('math_relations', {})
        best_candidates = math.get('best_candidates', [])
        
        if best_candidates and best_candidates[0]['score'] > 50:
            best = best_candidates[0]
            conclusion['detected'] = True
            conclusion['length_field_offset'] = best['offset']
            conclusion['length_field_format'] = best['format']
            conclusion['confidence'] = best['score'] / 100
            
            # 解析公式
            if best['relation_type'] == 'body_length':
                conclusion['header_length'] = best.get('header_len', best['offset'])
                conclusion['reasoning'].append(
                    f"长度字段在偏移{best['offset']}，表示包体长度 (packet_length - {best.get('header_len', 0)})"
                )
            elif best['relation_type'] == 'packet_length_minus_overhead':
                overhead = best.get('overhead', 0)
                conclusion['header_length'] = overhead
                conclusion['reasoning'].append(
                    f"长度字段在偏移{best['offset']}，值为 packet_length - {overhead}"
                )
            elif best['relation_type'] == 'fixed_overhead':
                conclusion['header_length'] = int(best.get('avg_overhead', 0))
                conclusion['reasoning'].append(
                    f"长度字段在偏移{best['offset']}，与包长度有固定差值关系"
                )
            else:
                conclusion['reasoning'].append(
                    f"长度字段在偏移{best['offset']}，类型: {best['relation_type']}"
                )
        
        # 从传统分析中获取补充信息
        header = result.get('header_analysis', {})
        if header.get('candidate_offsets') and not conclusion['detected']:
            cand = header['candidate_offsets'][0]
            if cand['score'] > 5:
                conclusion['detected'] = True
                conclusion['length_field_offset'] = cand['offset']
                conclusion['length_field_format'] = cand['best_format']
                conclusion['confidence'] = cand['score'] / 20
                conclusion['reasoning'].append(
                    f"备用方案：偏移{cand['offset']}的{cand['best_format']}格式，分数={cand['score']:.2f}"
                )
        
        return conclusion
    
    def _analyze_header_length_field(self, flow: TCPFlow) -> dict:
        """
        分析包头中表示包体长度的字段位置
        
        策略：
        1. 相同长度的包，包头中长度相关字节应相同
        2. 不同长度的包，长度字段应不同
        3. 支持多种长度格式: uint8/16/32/64, varint, uleb128
        4. 长度字段的值应该随包长度变化而变化
        """
        analysis = {
            'candidate_offsets': [],
            'candidate_formats': {},
            'method': 'length_field_detection'
        }
        
        # 按长度分组
        length_groups: Dict[int, List[Tuple[int, bytes]]] = defaultdict(list)
        for i, pkt_data in enumerate(flow.packets):
            if len(pkt_data) >= self.min_header_len:
                length_groups[len(pkt_data)].append((i, pkt_data))
        
        if not length_groups:
            return analysis
        
        unique_lengths = list(length_groups.keys())
        has_multiple_lengths = len(unique_lengths) >= 2
        
        # 检查所有支持的格式
        for format_name, format_info in LENGTH_FIELD_FORMATS.items():
            decoder = format_info['decoder']
            
            for offset in range(self.max_header_len):
                score = 0
                format_details = {
                    'offset': offset,
                    'format': format_name,
                    'width': format_info['width'],
                    'endian': format_info['endian'],
                    'samples': []
                }
                
                # 收集该格式解码的所有值
                decoded_values = {}  # packet_length -> list of decoded values
                all_valid = True
                
                for pkt_len, pkts in length_groups.items():
                    decoded_values[pkt_len] = []
                    for _, pkt_data in pkts:
                        try:
                            val, consumed = decoder(pkt_data, offset)
                            decoded_values[pkt_len].append(val)
                            format_details['samples'].append({
                                'pkt_len': pkt_len,
                                'decoded': val,
                                'bytes': pkt_data[offset:offset+consumed].hex()
                            })
                        except:
                            all_valid = False
                            break
                    if not all_valid:
                        break
                
                if not all_valid:
                    continue
                
                # 规则1: 相同长度的包，解码值应该相同
                same_length_consistent = True
                for pkt_len, values in decoded_values.items():
                    if len(values) > 1 and len(set(values)) > 1:
                        same_length_consistent = False
                        break
                
                if same_length_consistent:
                    score += 3.0
                
                # 规则2: 解码值与包长度应该有相关性
                if same_length_consistent:
                    for pkt_len, values in decoded_values.items():
                        if values:
                            avg_val = sum(values) / len(values)
                            if format_name.startswith('uint'):
                                # 固定宽度格式
                                overhead = offset + (format_info['width'] or 4)
                                diff = abs(pkt_len - avg_val - overhead)
                                if diff <= 5:  # 允许5字节误差
                                    score += 2.0
                                elif avg_val == pkt_len - overhead:
                                    score += 5.0  # 完美匹配
                
                # 规则1.5: 检查解码值是否随包长度变化（关键改进！）
                # 如果所有不同长度包的解码值都相同，这可能是固定前缀而非长度字段
                # 注意：这个惩罚要在所有其他规则之后执行
                is_fixed_value = False
                if has_multiple_lengths and same_length_consistent:
                    all_values = []
                    for pkt_len, values in decoded_values.items():
                        all_values.extend(values)
                    
                    unique_decoded = set(all_values)
                    # 如果只有1个唯一值，高度怀疑是固定前缀
                    if len(unique_decoded) == 1:
                        is_fixed_value = True
                        score *= 0.1  # 大幅降低固定值的分数
                    elif len(unique_decoded) == 2 and len(all_values) > 4:
                        is_fixed_value = True
                        score *= 0.3  # 少数唯一值，也降低分数
                
                # 规则3: 如果格式是varint/uleb128，检查是否符合编码特征
                if format_name in ['varint', 'uleb128']:
                    unique_lengths_count = len(decoded_values)
                    if unique_lengths_count > 3:
                        one_byte_count = sum(1 for s in format_details['samples'] 
                                            if s['decoded'] < 128 and len(bytes.fromhex(s['bytes'])) == 1)
                        if one_byte_count > len(format_details['samples']) * 0.8:
                            score *= 0.5
                
                if score > 0:
                    if offset not in analysis['candidate_formats']:
                        analysis['candidate_formats'][offset] = []
                    analysis['candidate_formats'][offset].append({
                        'format': format_name,
                        'score': score,
                        'samples': format_details['samples'][:5]
                    })
                    
                    # 计算值与长度的相关性得分
                    value_length_correlation = 0
                    if same_length_consistent and has_multiple_lengths:
                        # 计算解码值与包长度的相关性
                        correlation_score = 0
                        for pkt_len, values in decoded_values.items():
                            if values:
                                val = values[0]
                                # 如果解码值 + offset + width ≈ pkt_len，则相关性高
                                overhead = offset + (format_info['width'] or 4)
                                if format_name.startswith('uint'):
                                    expected_body_len = val
                                    actual_body_len = pkt_len - overhead
                                    if actual_body_len > 0 and abs(expected_body_len - actual_body_len) <= 5:
                                        correlation_score += 1
                                elif format_name in ['varint', 'uleb128']:
                                    # varint可能有不同的编码方式
                                    if val > 0 and val < pkt_len:
                                        correlation_score += 0.5
                        value_length_correlation = correlation_score
                    
                    # 更新总分数
                    existing = next((c for c in analysis['candidate_offsets'] if c['offset'] == offset), None)
                    if existing:
                        if score > existing['score']:
                            existing['score'] = score
                            existing['best_format'] = format_name
                            existing['value_length_correlation'] = value_length_correlation
                    else:
                        analysis['candidate_offsets'].append({
                            'offset': offset,
                            'score': score,
                            'best_format': format_name,
                            'value_length_correlation': value_length_correlation
                        })
        
        # 排序并返回top候选
        # 按分数降序排序
        analysis['candidate_offsets'] = sorted(
            analysis['candidate_offsets'], 
            key=lambda x: x['score'], 
            reverse=True
        )[:10]
        
        return analysis
    
    def _analyze_fixed_fields(self, flow: TCPFlow) -> dict:
        """
        分析包头中的固定字段（不随包变化的字节）
        
        策略：
        1. 某些协议在包头特定位置有固定的魔数或标识
        2. 同一流中这些位置应该保持不变
        """
        analysis = {
            'fixed_bytes': {},  # offset -> (value, count)
            'magic_candidates': []
        }
        
        if not flow.packets:
            return analysis
        
        min_len = min(len(p) for p in flow.packets)
        
        for offset in range(min(min_len, self.max_header_len)):
            byte_counts: Dict[int, int] = defaultdict(int)
            for pkt in flow.packets:
                if len(pkt) > offset:
                    byte_counts[pkt[offset]] += 1
            
            # 找到出现频率最高的字节
            if byte_counts:
                most_common_byte, most_common_count = max(byte_counts.items(), key=lambda x: x[1])
                frequency = most_common_count / len(flow.packets)
                
                if frequency > 0.8:  # 80%以上相同
                    analysis['fixed_bytes'][offset] = {
                        'value': most_common_byte,
                        'hex': f"0x{most_common_byte:02X}",
                        'frequency': frequency
                    }
        
        # 寻找可能的魔数（连续固定字节序列）
        fixed_sequences = self._find_magic_sequences(analysis['fixed_bytes'])
        analysis['magic_candidates'] = fixed_sequences
        
        return analysis
    
    def _find_magic_sequences(self, fixed_bytes: dict) -> List[dict]:
        """寻找连续的固定字节序列（可能的魔数）"""
        sequences = []
        
        if not fixed_bytes:
            return sequences
        
        offsets = sorted(fixed_bytes.keys())
        
        current_seq_start = offsets[0]
        current_seq_bytes = [fixed_bytes[offsets[0]]['value']]
        
        for i in range(1, len(offsets)):
            if offsets[i] == offsets[i-1] + 1:
                current_seq_bytes.append(fixed_bytes[offsets[i]]['value'])
            else:
                if len(current_seq_bytes) >= 2:
                    sequences.append({
                        'offset': current_seq_start,
                        'length': len(current_seq_bytes),
                        'hex': ''.join(f"{b:02X}" for b in current_seq_bytes),
                        'bytes': bytes(current_seq_bytes)
                    })
                current_seq_start = offsets[i]
                current_seq_bytes = [fixed_bytes[offsets[i]]['value']]
        
        # 处理最后一个序列
        if len(current_seq_bytes) >= 2:
            sequences.append({
                'offset': current_seq_start,
                'length': len(current_seq_bytes),
                'hex': ''.join(f"{b:02X}" for b in current_seq_bytes),
                'bytes': bytes(current_seq_bytes)
            })
        
        return sequences
    
    def _analyze_length_pattern(self, flow: TCPFlow) -> dict:
        """
        分析包长度模式
        
        策略：
        1. 识别相同长度的包
        2. 分析不同长度包之间的差异
        3. 检测是否有固定偏移表示的长度
        """
        analysis = {
            'unique_lengths': [],
            'length_distribution': {},
            'potential_body_offsets': []
        }
        
        lengths = [len(p) for p in flow.packets]
        unique_lengths = sorted(set(lengths))
        
        analysis['unique_lengths'] = unique_lengths
        analysis['length_distribution'] = {
            length: lengths.count(length) for length in unique_lengths
        }
        
        # 检测可能表示包体的偏移位置
        for offset in range(self.max_header_len):
            # 假设offset是包体开始，计算包体长度
            body_lengths = []
            valid = True
            
            for pkt in flow.packets:
                if len(pkt) > offset:
                    body_len = len(pkt) - offset
                    body_lengths.append(body_len)
                else:
                    valid = False
                    break
            
            if valid and len(set(body_lengths)) < len(lengths):
                # 包体长度种类少于总长度种类，可能有固定包头
                analysis['potential_body_offsets'].append({
                    'offset': offset,
                    'body_lengths': sorted(set(body_lengths)),
                    'header_len': offset
                })
        
        return analysis
    
    def _analyze_header_template(self, flow: TCPFlow) -> dict:
        """
        生成包头模板
        
        策略：
        1. 找出每个偏移位置最可能的字节值
        2. 标记固定值和可变值
        3. 尝试识别协议类型
        """
        analysis = {
            'template': [],
            'confidence': 0.0,
            'likely_protocol': None
        }
        
        if not flow.packets:
            return analysis
        
        min_len = min(len(p) for p in flow.packets)
        template = []
        fixed_count = 0
        
        for offset in range(min(min_len, self.max_header_len)):
            byte_counts: Dict[int, int] = defaultdict(int)
            for pkt in flow.packets:
                if len(pkt) > offset:
                    byte_counts[pkt[offset]] += 1
            
            most_common_byte, most_common_count = max(byte_counts.items(), key=lambda x: x[1])
            frequency = most_common_count / len(flow.packets)
            
            template.append({
                'offset': offset,
                'likely_value': most_common_byte,
                'hex': f"0x{most_common_byte:02X}",
                'chr': chr(most_common_byte) if 32 <= most_common_byte < 127 else '.',
                'frequency': frequency,
                'variety_count': len(byte_counts),
                'is_fixed': frequency > 0.9
            })
            
            if frequency > 0.9:
                fixed_count += 1
        
        analysis['template'] = template
        analysis['fixed_bytes_count'] = fixed_count
        analysis['confidence'] = fixed_count / len(template) if template else 0
        
        # 尝试识别协议
        analysis['likely_protocol'] = self._identify_protocol(template, flow)
        
        return analysis
    
    def _identify_protocol(self, template: List[dict], flow: TCPFlow) -> Optional[str]:
        """基于包头特征识别协议类型"""
        if len(template) < 4:
            return None
        
        # 常见协议特征检测
        known_patterns = {
            'HTTP': [(b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS'), 
                     (b'HTTP/1.0', b'HTTP/1.1')],
            'Length-Prefix': [],  # 自定义：前2或4字节表示长度
            'Fixed-Header': [],     # 固定长度包头
            'Delimiter-Based': [], # 使用分隔符
        }
        
        # 检查是否像Length-Prefix协议
        if len(template) >= 2:
            # 检查前两个字节是否相对固定
            if template[0]['frequency'] > 0.7 and template[1]['frequency'] > 0.7:
                return "Length-Prefix (2-byte length field)"
        
        # 检查固定包头
        fixed_ratio = sum(1 for t in template if t['is_fixed']) / len(template)
        if fixed_ratio > 0.6:
            return "Fixed-Header Protocol"
        
        return "Custom/Binary Protocol"
    
    def analyze_all_flows(self) -> Dict[str, dict]:
        """分析所有流"""
        results = {}
        
        for flow_id, flow in self.flows.items():
            flow_key = f"{flow_id[0]}:{flow_id[2]} -> {flow_id[1]}:{flow_id[3]}"
            results[flow_key] = self.analyze_flow(flow)
        
        self.analysis_results = results
        return results
    
    def extract_messages(self, flow: TCPFlow, header_len: int = None, length_offset: int = None) -> List[dict]:
        """
        从流中提取消息
        
        参数:
            header_len: 已知包头长度
            length_offset: 长度字段在包头中的偏移
        """
        messages = []
        
        for i, pkt_data in enumerate(flow.packets):
            if header_len is not None:
                if len(pkt_data) >= header_len:
                    messages.append({
                        'index': i,
                        'header': pkt_data[:header_len],
                        'body': pkt_data[header_len:],
                        'header_hex': pkt_data[:header_len].hex(),
                        'body_hex': pkt_data[header_len:].hex() if len(pkt_data) > header_len else '',
                        'total_len': len(pkt_data)
                    })
            elif length_offset is not None:
                # 尝试从指定偏移读取长度
                if len(pkt_data) > length_offset + 4:
                    try:
                        body_len = int.from_bytes(pkt_data[length_offset:length_offset+4], 'big')
                        if body_len <= len(pkt_data) - length_offset - 4:
                            body = pkt_data[length_offset+4:length_offset+4+body_len]
                            messages.append({
                                'index': i,
                                'header': pkt_data[:length_offset],
                                'body': body,
                                'declared_length': body_len,
                                'actual_length': len(body),
                                'match': body_len == len(body)
                            })
                    except:
                        pass
            else:
                # 自动检测
                messages.append({
                    'index': i,
                    'data': pkt_data,
                    'hex': pkt_data.hex()
                })
        
        return messages
    
    def print_analysis_report(self, results: Dict[str, dict]):
        """打印分析报告"""
        print("\n" + "="*80)
        print("TCP流启发式分析报告 (增强版 - 暴力数学关系分析)")
        print("="*80)
        
        for flow_key, result in results.items():
            print(f"\n{'='*60}")
            print(f"Flow: {flow_key}")
            print(f"{'='*60}")
            print(f"  Total packets: {result.get('total_packets', 0)}")
            print(f"  Total bytes: {result.get('total_bytes', 0)}")
            print(f"  Packet lengths: {result.get('packet_lengths', [])}")
            
            # ========== 暴力数学关系分析 (新增!) ==========
            math = result.get('math_relations', {})
            if math.get('best_candidates'):
                print(f"\n  [暴力数学关系分析 - Top候选]")
                print(f"  {'偏移':<6} {'格式':<10} {'关系类型':<25} {'分数':<8} {'置信度':<8} {'公式'}")
                print(f"  {'-'*6} {'-'*10} {'-'*25} {'-'*8} {'-'*8} {'-'*30}")
                for cand in math['best_candidates'][:5]:
                    print(f"  {cand['offset']:<6} {cand['format']:<10} {cand['relation_type']:<25} "
                          f"{cand['score']:<8.2f} {cand['confidence']:<8.2f} {cand['formula']}")
                
                # 显示分析统计
                stats = math.get('packet_stats', {})
                if stats.get('unique_lengths'):
                    print(f"\n  [数据包统计]")
                    print(f"    唯一长度数: {len(stats['unique_lengths'])}")
                    print(f"    长度分布: {stats['unique_lengths']}")
            
            # 综合结论
            conclusion = result.get('conclusion', {})
            if conclusion.get('detected'):
                print(f"\n  [综合结论]")
                print(f"    [OK] 检测到协议格式!")
                print(f"    长度字段偏移: {conclusion.get('length_field_offset')}")
                print(f"    长度字段格式: {conclusion.get('length_field_format')}")
                print(f"    置信度: {conclusion.get('confidence', 0):.1%}")
                print(f"    包头长度: {conclusion.get('header_length')}")
                for reason in conclusion.get('reasoning', []):
                    print(f"      → {reason}")
            # ========== 结束新增 ==========
            
            # 包头分析
            header = result.get('header_analysis', {})
            if header.get('candidate_offsets'):
                print(f"\n  [Header Length Candidates]")
                for candidate in header['candidate_offsets'][:5]:
                    print(f"    Offset {candidate['offset']}: score={candidate['score']:.2f}")
            
            # 固定字段
            fixed = result.get('fixed_fields', {})
            if fixed.get('fixed_bytes'):
                print(f"\n  [Fixed Bytes in Header]")
                for off, info in sorted(fixed['fixed_bytes'].items()):
                    print(f"    Offset {off}: {info['hex']} (freq={info['frequency']:.1%})")
            
            # 魔数
            magic = fixed.get('magic_candidates', [])
            if magic:
                print(f"\n  [Magic Number Candidates]")
                for m in magic:
                    print(f"    Offset {m['offset']}, length {m['length']}: {m['hex']}")
            
            # 包头模板
            tmpl = result.get('header_template', {})
            if tmpl.get('template'):
                print(f"\n  [Header Template]")
                print(f"    Protocol: {tmpl.get('likely_protocol', 'Unknown')}")
                print(f"    Confidence: {tmpl.get('confidence', 0):.1%}")
                print(f"    Fixed bytes: {tmpl.get('fixed_bytes_count', 0)}/{len(tmpl['template'])}")
                
                # 打印前16字节的模板
                print(f"\n    Offset | Hex      | Dec  | Chr  | Freq  | Status")
                print(f"    -------|----------|------|------|-------|--------")
                for t in tmpl['template'][:16]:
                    status = "FIXED" if t['is_fixed'] else "VAR"
                    print(f"    {t['offset']:7d} | {t['hex']:8s} | {t['likely_value']:4d} | {t['chr']:4s} | {t['frequency']:5.1%} | {status}")
            
            # 长度模式
            length_pat = result.get('length_pattern', {})
            if length_pat.get('unique_lengths'):
                print(f"\n  [Length Pattern]")
                print(f"    Unique lengths: {length_pat['unique_lengths']}")
                print(f"    Distribution: {length_pat['length_distribution']}")
            
            print()


def interactive_analysis(pcap_file: str, brute_force_n: int = DEFAULT_BRUTE_FORCE_N):
    """交互式分析
    
    参数:
        pcap_file: pcap文件路径
        brute_force_n: 暴力枚举的包头字节数 (默认40)
    """
    unpacker = HeuristicUnpacker(brute_force_n=brute_force_n)
    unpacker.load_pcap(pcap_file)
    
    results = unpacker.analyze_all_flows()
    unpacker.print_analysis_report(results)
    
    return unpacker, results


def batch_analysis(pcap_file: str, output_file: str = None, brute_force_n: int = DEFAULT_BRUTE_FORCE_N):
    """批量分析并输出JSON
    
    参数:
        pcap_file: pcap文件路径
        output_file: 输出JSON文件路径
        brute_force_n: 暴力枚举的包头字节数 (默认40)
    """
    import json
    
    unpacker = HeuristicUnpacker(brute_force_n=brute_force_n)
    unpacker.load_pcap(pcap_file)
    results = unpacker.analyze_all_flows()
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"[*] Analysis saved to: {output_file}")
    
    return unpacker, results


# 扩展规则系统
class ExtendedRules:
    """扩展规则系统，支持自定义启发式规则"""
    
    @staticmethod
    def common_protocol_rules() -> Dict[str, dict]:
        """常见协议规则"""
        return {
            # 长度前缀协议 (如大部分二进制协议)
            'length_prefix_2byte': {
                'name': '2字节长度前缀',
                'header_len': 4,  # 假设包头4字节
                'length_offset': 2,
                'length_endian': 'big',
                'length_width': 2
            },
            'length_prefix_4byte': {
                'name': '4字节长度前缀',
                'header_len': 8,  # 假设包头8字节
                'length_offset': 4,
                'length_endian': 'big',
                'length_width': 4
            },
            
            # 固定包头协议
            'fixed_8byte_header': {
                'name': '8字节固定包头',
                'header_len': 8,
                'description': '包头前8字节固定格式，后面的都是包体'
            },
            'fixed_16byte_header': {
                'name': '16字节固定包头',
                'header_len': 16,
                'description': '包头前16字节固定格式'
            },
            
            # 特殊协议
            'http_like': {
                'name': '类HTTP协议',
                'detect_pattern': lambda data: data.startswith((b'GET', b'POST', b'PUT', b'DELETE', b'HTTP'))
            }
        }
    
    @staticmethod
    def create_custom_rule(name: str, header_len: int = None, 
                           length_offset: int = None,
                           magic_bytes: bytes = None,
                           detect_fn: callable = None) -> dict:
        """创建自定义规则"""
        return {
            'name': name,
            'header_len': header_len,
            'length_offset': length_offset,
            'magic_bytes': magic_bytes,
            'detect_fn': detect_fn
        }


def apply_rules_to_flow(flow: TCPFlow, rules: Dict[str, dict]) -> List[dict]:
    """将规则应用到流上，尝试识别协议"""
    matches = []
    
    for rule_name, rule in rules.items():
        score = 0
        details = {'rule': rule_name, 'rule_name': rule['name'], 'score': 0}
        
        # 检测魔数
        if 'magic_bytes' in rule and rule['magic_bytes']:
            magic = rule['magic_bytes']
            if len(flow.packets) > 0:
                match_count = sum(1 for p in flow.packets if p.startswith(magic))
                if match_count > 0:
                    score += match_count / len(flow.packets) * 10
                    details['magic_matches'] = match_count
        
        # 检测自定义函数
        if 'detect_fn' in rule and rule['detect_fn']:
            try:
                if rule['detect_fn'](flow.packets[0] if flow.packets else b''):
                    score += 5
                    details['custom_match'] = True
            except:
                pass
        
        if score > 0:
            details['score'] = score
            matches.append(details)
    
    return sorted(matches, key=lambda x: x['score'], reverse=True)


if __name__ == '__main__':
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description='启发式TCP数据包拆包工具 (暴力数学关系分析版)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python heuristic_unpack.py capture.pcap                    # 默认分析
  python heuristic_unpack.py capture.pcap -n 60            # 枚举前60字节
  python heuristic_unpack.py capture.pcap -n 20 -o out.json  # 枚举20字节并输出JSON
        """
    )
    parser.add_argument('pcap_file', nargs='?', help='pcap文件路径')
    parser.add_argument('-n', '--header-bytes', type=int, default=DEFAULT_BRUTE_FORCE_N,
                        help=f'暴力枚举的包头字节数 (默认: {DEFAULT_BRUTE_FORCE_N})')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help='输出JSON文件路径')
    
    args = parser.parse_args()
    
    if args.pcap_file:
        print(f"[*] Analyzing: {args.pcap_file}")
        print(f"[*] Brute-force header bytes: {args.header_bytes}")
        
        if args.output:
            unpacker, results = batch_analysis(args.pcap_file, args.output, 
                                               brute_force_n=args.header_bytes)
        else:
            unpacker, results = interactive_analysis(args.pcap_file, 
                                                    brute_force_n=args.header_bytes)
        
        # 显示所有流的基本信息
        print("\n[*] Summary:")
        for flow_id, flow in unpacker.flows.items():
            if flow_id[2] < flow_id[3]:  # 只显示正向流
                total_data = sum(len(p) for p in flow.packets)
                print(f"  {flow_id[0]}:{flow_id[2]} -> {flow_id[1]}:{flow_id[3]}: {len(flow.packets)} packets, {total_data} bytes")
    else:
        print("""
启发式TCP数据包拆包工具
========================

用法: python heuristic_unpack.py <pcap_file> [选项]

功能:
1. 读取pcap文件，按五元组划分TCP流
2. 暴力枚举包头中的数学关系 (长度字段与包长的关系)
3. 检测包头中的长度字段位置
4. 识别固定字节和魔数
5. 生成包头模板
6. 综合分析结论

支持的数学关系:
- length_field = packet_length - overhead (固定开销)
- length_field = body_length (包体长度)
- length_field = header_length (包头长度)
- length_field = body_offset (包体偏移)
- 复合关系测试

示例:
  python heuristic_unpack.py capture.pcap
  python heuristic_unpack.py capture.pcap -n 60
  python heuristic_unpack.py capture.pcap -o out.json

选项:
  -n, --header-bytes  暴力枚举的包头字节数 (默认: 40)
  -o, --output        输出JSON文件路径
""")
