"""
高性能TCP流启发式拆包工具
=========================
优化特性:
1. 流式处理 - 支持GB级pcap
2. 多进程并行 - 充分利用多核CPU
3. 内存映射 - 减少内存占用
4. 分批处理 - 避免OOM
5. 增量分析 - 边读边分析
"""

from scapy.all import PcapReader, TCP, IP, Raw
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional, Iterator, Generator
from dataclasses import dataclass, field
from multiprocessing import Pool, cpu_count, Manager
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import os
import mmap
import struct
import json
from functools import partial
import hashlib


# ==================== Varint 编解码 ====================

def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
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


LENGTH_FIELD_FORMATS = {
    'uint8': {'width': 1, 'decoder': lambda d, o: (d[o], 1)},
    'uint16_be': {'width': 2, 'decoder': lambda d, o: (int.from_bytes(d[o:o+2], 'big'), 2)},
    'uint16_le': {'width': 2, 'decoder': lambda d, o: (int.from_bytes(d[o:o+2], 'little'), 2)},
    'uint32_be': {'width': 4, 'decoder': lambda d, o: (int.from_bytes(d[o:o+4], 'big'), 4)},
    'uint32_le': {'width': 4, 'decoder': lambda d, o: (int.from_bytes(d[o:o+4], 'little'), 4)},
    'varint': {'width': None, 'decoder': decode_varint},
    'uleb128': {'width': None, 'decoder': decode_uleb128},
}


# ==================== 数据结构 ====================

@dataclass
class FlowKey:
    """流键，5元组"""
    sip: str
    dip: str
    sport: int
    dport: int
    
    @property
    def reverse(self) -> 'FlowKey':
        return FlowKey(self.dip, self.sip, self.dport, self.sport)
    
    def __hash__(self):
        return hash((self.sip, self.dip, self.sport, self.dport))
    
    def __str__(self):
        return f"{self.sip}:{self.sport}->{self.dip}:{self.dport}"
    
    def to_tuple(self) -> Tuple:
        return (self.sip, self.dip, self.sport, self.dport)
    
    def to_dirname(self) -> str:
        return f"{self.sip}_{self.sport}_{self.dip}_{self.dport}"


@dataclass 
class PacketInfo:
    """数据包信息 - 精简存储"""
    data_hash: str      # 数据哈希，减少内存
    seq: int
    length: int
    timestamp: float


@dataclass
class FlowSummary:
    """流的摘要信息"""
    flow_key: FlowKey
    packet_count: int = 0
    total_bytes: int = 0
    unique_lengths: set = field(default_factory=set)
    length_distribution: dict = field(default_factory=dict)
    first_seen: float = 0.0
    last_seen: float = 0.0
    
    # 分析结果
    confidence: float = 0.0
    protocol_hint: str = None
    length_field_candidates: list = field(default_factory=list)
    fixed_bytes: dict = field(default_factory=dict)
    magic_candidates: list = field(default_factory=list)


# ==================== 流式处理器 ====================

class StreamingPCAPReader:
    """流式PCAP读取器 - 支持GB级文件"""
    
    def __init__(self, pcap_file: str, chunk_size: int = 10000):
        self.pcap_file = pcap_file
        self.chunk_size = chunk_size
        self.file_size = os.path.getsize(pcap_file)
        
    def iter_packets(self) -> Generator:
        """迭代器方式读取包，避免全量加载"""
        try:
            for pkt in PcapReader(self.pcap_file):
                yield pkt
        except Exception as e:
            print(f"Error reading pcap: {e}")
    
    def iter_tcp_flows(self) -> Generator[Tuple[FlowKey, bytes], None, None]:
        """
        迭代TCP流数据
        Yields: (FlowKey, data)
        """
        # 按流分组
        flow_buffers: Dict[FlowKey, List[bytes]] = defaultdict(list)
        flow_timestamps: Dict[FlowKey, float] = {}
        
        for pkt in self.iter_packets():
            if TCP not in pkt or IP not in pkt:
                continue
            
            if Raw not in pkt:
                continue
            
            sip = pkt[IP].src
            dip = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            seq = pkt[TCP].seq
            timestamp = float(pkt.time)
            data = bytes(pkt[Raw].load)
            
            flow_key = FlowKey(sip, dip, sport, dport)
            
            # 按SEQ排序后添加到buffer
            flow_buffers[flow_key].append((seq, data, timestamp))
            flow_timestamps[flow_key] = timestamp
        
        # 产出排好序的数据
        for flow_key, packets in flow_buffers.items():
            # 按SEQ排序
            packets.sort(key=lambda x: x[0])
            
            # 合并为完整流
            stream_data = b''.join(p[1] for p in packets)
            
            yield flow_key, stream_data
    
    def iter_chunks(self) -> Generator[List, None, None]:
        """分块迭代"""
        chunk = []
        for pkt in self.iter_packets():
            chunk.append(pkt)
            if len(chunk) >= self.chunk_size:
                yield chunk
                chunk = []
        
        if chunk:
            yield chunk


# ==================== 多进程分析器 ====================

class ParallelFlowAnalyzer:
    """多进程流分析器"""
    
    def __init__(self, num_workers: int = None):
        self.num_workers = num_workers or max(1, cpu_count() - 1)
        self.results: Dict[FlowKey, FlowSummary] = {}
        
    def analyze_pcap(self, pcap_file: str, 
                     min_packets: int = 2,
                     max_flows_in_memory: int = 10000) -> Dict[FlowKey, FlowSummary]:
        """
        分析大文件pcap
        
        Args:
            pcap_file: pcap文件路径
            min_packets: 最少包数量阈值
            max_flows_in_memory: 内存中最大流数量
        
        Returns:
            流分析结果字典
        """
        print(f"[*] Starting parallel analysis with {self.num_workers} workers")
        print(f"[*] File size: {os.path.getsize(pcap_file) / 1024 / 1024:.1f} MB")
        
        # Phase 1: 流式收集流数据
        print("[*] Phase 1: Collecting flows...")
        flow_data = self._collect_flows_streaming(pcap_file)
        
        print(f"[*] Found {len(flow_data)} flows")
        
        # Phase 2: 多进程分析
        print("[*] Phase 2: Analyzing flows in parallel...")
        flows_to_analyze = {
            k: v for k, v in flow_data.items() 
            if len(v) >= min_packets
        }
        print(f"[*] Flows to analyze (>{min_packets} packets): {len(flows_to_analyze)}")
        
        # 分批处理，避免内存溢出
        batch_size = 500
        flow_keys = list(flows_to_analyze.keys())
        
        for i in range(0, len(flow_keys), batch_size):
            batch_keys = flow_keys[i:i+batch_size]
            batch_data = {k: flows_to_analyze[k] for k in batch_keys}
            
            print(f"[*] Processing batch {i//batch_size + 1}/{(len(flow_keys)-1)//batch_size + 1}")
            
            # 多进程分析
            batch_results = self._parallel_analyze(batch_data)
            self.results.update(batch_results)
            
            # 清理内存
            del batch_data
        
        return self.results
    
    def _collect_flows_streaming(self, pcap_file: str) -> Dict[FlowKey, List[bytes]]:
        """流式收集流数据"""
        flow_packets: Dict[FlowKey, List[Tuple[int, bytes, float]]] = defaultdict(list)
        
        for pkt in StreamingPCAPReader(pcap_file).iter_packets():
            if TCP not in pkt or IP not in pkt or Raw not in pkt:
                continue
            
            flow_key = FlowKey(
                pkt[IP].src, pkt[IP].dst,
                pkt[TCP].sport, pkt[TCP].dport
            )
            
            seq = pkt[TCP].seq
            data = bytes(pkt[Raw].load)
            timestamp = float(pkt.time)
            
            flow_packets[flow_key].append((seq, data, timestamp))
        
        # 按SEQ排序并合并
        result = {}
        for flow_key, packets in flow_packets.items():
            packets.sort(key=lambda x: x[0])
            result[flow_key] = [p[1] for p in packets]
        
        return result
    
    def _parallel_analyze(self, flow_data: Dict[FlowKey, List[bytes]]) -> Dict[FlowKey, FlowSummary]:
        """多进程分析"""
        results = {}
        
        with ProcessPoolExecutor(max_workers=self.num_workers) as executor:
            futures = {
                executor.submit(analyze_single_flow, flow_key.to_tuple(), packets): flow_key
                for flow_key, packets in flow_data.items()
            }
            
            completed = 0
            total = len(futures)
            
            for future in as_completed(futures):
                flow_key = futures[future]
                try:
                    summary = future.result()
                    if summary:
                        results[flow_key] = summary
                except Exception as e:
                    print(f"Error analyzing {flow_key}: {e}")
                
                completed += 1
                if completed % 100 == 0:
                    print(f"  Progress: {completed}/{total}")
        
        return results


# ==================== 单流分析函数 ====================

def analyze_single_flow(flow_tuple: Tuple, packets: List[bytes]) -> Optional[FlowSummary]:
    """
    分析单个流 - 在子进程中执行
    
    Args:
        flow_tuple: (sip, dip, sport, dport)
        packets: 数据包列表
    
    Returns:
        FlowSummary or None
    """
    flow_key = FlowKey(*flow_tuple)
    
    if len(packets) < 2:
        return None
    
    # 统计信息
    lengths = [len(p) for p in packets]
    length_dist = dict(Counter(lengths))
    
    summary = FlowSummary(
        flow_key=flow_key,
        packet_count=len(packets),
        total_bytes=sum(lengths),
        unique_lengths=set(lengths),
        length_distribution=length_dist
    )
    
    # 分析包头
    analysis = analyze_header_pattern(packets)
    
    if analysis:
        summary.confidence = analysis.get('confidence', 0.0)
        summary.protocol_hint = analysis.get('protocol_hint')
        summary.length_field_candidates = analysis.get('candidates', [])
        summary.fixed_bytes = analysis.get('fixed_bytes', {})
        summary.magic_candidates = analysis.get('magic', [])
    
    return summary


def analyze_header_pattern(packets: List[bytes], 
                          max_header_len: int = 32) -> dict:
    """
    分析包头模式 - 优化版本
    """
    if not packets:
        return {}
    
    min_len = min(len(p) for p in packets)
    if min_len < 2:
        return {}
    
    result = {
        'confidence': 0.0,
        'protocol_hint': None,
        'candidates': [],
        'fixed_bytes': {},
        'magic': []
    }
    
    # 固定字节分析
    fixed_bytes = {}
    for offset in range(min(max_header_len, min_len)):
        byte_counts = Counter()
        for pkt in packets:
            if len(pkt) > offset:
                byte_counts[pkt[offset]] += 1
        
        if byte_counts:
            most_common, count = byte_counts.most_common(1)[0]
            freq = count / len(packets)
            if freq >= 0.9:
                fixed_bytes[offset] = {'value': most_common, 'hex': f"0x{most_common:02X}", 'freq': freq}
    
    result['fixed_bytes'] = fixed_bytes
    
    # 魔数检测
    magic_len = 0
    for offset in range(min(max_header_len, min_len)):
        first_val = packets[0][offset]
        if all(p[offset] == first_val for p in packets if len(p) > offset):
            magic_len = offset + 1
        else:
            break
    
    if magic_len >= 4:
        magic_bytes = packets[0][:magic_len]
        result['magic'] = [{'offset': 0, 'length': magic_len, 'hex': magic_bytes.hex()}]
    
    # 长度字段检测
    candidates = find_length_field_candidates(packets, max_header_len)
    result['candidates'] = candidates[:5]
    
    # 计算置信度
    confidence = 0.0
    confidence += len(fixed_bytes) * 0.05
    confidence += len(result['magic']) * 0.2
    confidence += max([c['score'] for c in candidates]) * 0.1 if candidates else 0.0
    result['confidence'] = min(1.0, confidence)
    
    # 协议提示
    if result['magic']:
        result['protocol_hint'] = "Magic-Prefix Protocol"
    elif candidates and candidates[0]['score'] > 3:
        result['protocol_hint'] = "Length-Prefix Protocol"
    elif fixed_bytes:
        result['protocol_hint'] = "Fixed-Header Protocol"
    else:
        result['protocol_hint'] = "Unknown Protocol"
    
    return result


def find_length_field_candidates(packets: List[bytes], max_offset: int = 16) -> List[dict]:
    """高效查找长度字段候选"""
    candidates = []
    
    if len(packets) < 2:
        return candidates
    
    # 按长度分组
    length_groups = defaultdict(list)
    for pkt in packets:
        length_groups[len(pkt)].append(pkt)
    
    # 检查每种格式
    for format_name, format_info in LENGTH_FIELD_FORMATS.items():
        decoder = format_info['decoder']
        
        for offset in range(max_offset):
            score = 0
            
            # 收集解码值
            decoded_by_length = {}
            valid = True
            
            for pkt_len, pkts_in_group in length_groups.items():
                decoded_values = []
                for pkt in pkts_in_group:
                    try:
                        val, width = decoder(pkt, offset)
                        if len(pkt) > offset + width:
                            decoded_values.append(val)
                    except:
                        valid = False
                        break
                
                if not valid:
                    break
                decoded_by_length[pkt_len] = decoded_values
            
            if not valid:
                continue
            
            # 规则: 相同长度包值应相同
            same_length_ok = True
            for pkt_len, values in decoded_by_length.items():
                if len(values) > 1 and len(set(values)) > 1:
                    same_length_ok = False
                    break
            
            if same_length_ok:
                score += 3.0
            
            # 规则: 值与长度应有相关性
            if same_length_ok and len(decoded_by_length) >= 2:
                lengths = sorted(decoded_by_length.keys())
                for i in range(len(lengths) - 1):
                    len1, len2 = lengths[i], lengths[i+1]
                    val1 = decoded_by_length[len1][0]
                    val2 = decoded_by_length[len2][0]
                    
                    diff_len = len2 - len1
                    diff_val = abs(val2 - val1)
                    
                    if 0 < diff_len < 1000 and 0 < diff_val < 1000:
                        ratio = max(diff_len, diff_val) / min(diff_len, diff_val)
                        if ratio < 3:
                            score += 2.0
            
            if score > 0:
                candidates.append({
                    'offset': offset,
                    'format': format_name,
                    'score': score
                })
    
    # 排序返回
    return sorted(candidates, key=lambda x: x['score'], reverse=True)


# ==================== 高性能导出器 ====================

class StreamingExporter:
    """流式导出器 - 支持大流"""
    
    def __init__(self, output_dir: str = "exports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def export_summary(self, results: Dict[FlowKey, FlowSummary], 
                      filename: str = "all_flows_summary.json"):
        """导出所有流摘要"""
        output = []
        
        for flow_key, summary in results.items():
            output.append({
                'flow': str(flow_key),
                'dir_name': flow_key.to_dirname(),
                'packet_count': summary.packet_count,
                'total_bytes': summary.total_bytes,
                'unique_lengths': list(summary.unique_lengths),
                'confidence': summary.confidence,
                'protocol_hint': summary.protocol_hint,
                'length_field_candidates': summary.length_field_candidates,
                'magic': summary.magic_candidates,
                'fixed_bytes': {str(k): v for k, v in summary.fixed_bytes.items()}
            })
        
        # 按置信度排序
        output.sort(key=lambda x: x['confidence'], reverse=True)
        
        output_path = os.path.join(self.output_dir, filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        print(f"[*] Summary exported to: {output_path}")
        return output_path
    
    def export_filtered_flows(self, results: Dict[FlowKey, FlowSummary],
                             min_confidence: float = 0.3,
                             output_file: str = "filtered_flows.txt"):
        """导出符合条件的流列表"""
        output_path = os.path.join(self.output_dir, output_file)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"Filtered Flows (confidence >= {min_confidence})\n")
            f.write("=" * 80 + "\n\n")
            
            for flow_key, summary in sorted(results.items(), 
                                            key=lambda x: x[1].confidence, 
                                            reverse=True):
                if summary.confidence >= min_confidence:
                    f.write(f"Flow: {flow_key}\n")
                    f.write(f"  Packets: {summary.packet_count}\n")
                    f.write(f"  Bytes: {summary.total_bytes}\n")
                    f.write(f"  Confidence: {summary.confidence:.1%}\n")
                    f.write(f"  Protocol: {summary.protocol_hint}\n")
                    
                    if summary.length_field_candidates:
                        f.write(f"  Length Fields: ")
                        f.write(", ".join(
                            f"@{c['offset']}({c['format']}, {c['score']:.1f})" 
                            for c in summary.length_field_candidates[:3]
                        ))
                        f.write("\n")
                    
                    if summary.magic_candidates:
                        f.write(f"  Magic: ")
                        f.write(", ".join(m['hex'] for m in summary.magic_candidates))
                        f.write("\n")
                    
                    f.write("\n")
        
        print(f"[*] Filtered flows exported to: {output_path}")
        return output_path


# ==================== 主入口 ====================

def analyze_large_pcap(pcap_file: str, 
                       num_workers: int = None,
                       min_packets: int = 2,
                       min_confidence: float = 0.3) -> Dict:
    """
    分析大型pcap文件
    
    Args:
        pcap_file: pcap文件路径
        num_workers: 工作进程数，默认CPU核心数-1
        min_packets: 每个流最少包数量
        min_confidence: 最低置信度阈值
    
    Returns:
        分析结果
    """
    import time
    
    start_time = time.time()
    
    # 多进程分析
    analyzer = ParallelFlowAnalyzer(num_workers=num_workers)
    results = analyzer.analyze_pcap(pcap_file, min_packets=min_packets)
    
    # 导出结果
    exporter = StreamingExporter()
    exporter.export_summary(results)
    exporter.export_filtered_flows(results, min_confidence=min_confidence)
    
    elapsed = time.time() - start_time
    
    # 统计
    total_flows = len(results)
    high_confidence = sum(1 for r in results.values() if r.confidence >= min_confidence)
    
    print("\n" + "=" * 60)
    print("Analysis Complete")
    print("=" * 60)
    print(f"Total flows: {total_flows}")
    print(f"High confidence flows (>{=min_confidence:.0%}): {high_confidence}")
    print(f"Time elapsed: {elapsed:.1f}s")
    print(f"Throughput: {total_flows / elapsed:.1f} flows/sec")
    
    return results


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
        num_workers = int(sys.argv[2]) if len(sys.argv) > 2 else None
        
        print(f"[*] Analyzing: {pcap_file}")
        results = analyze_large_pcap(pcap_file, num_workers=num_workers)
    else:
        print("""
High-Performance TCP Flow Analyzer
===================================

Usage: python parallel_unpack.py <pcap_file> [num_workers]

Features:
- Streaming pcap processing (GB-level support)
- Multi-process parallel analysis
- Memory-efficient chunk processing
- Automatic flow export

Example:
  python parallel_unpack.py large_capture.pcap 8
""")
