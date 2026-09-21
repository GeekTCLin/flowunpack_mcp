"""
TCP流导出工具
=============
功能:
1. 按五元组创建目录
2. 导出分析结果(JSON)
3. 导出原始pcap数据
4. 导出解码后的消息
"""

from scapy.all import rdpcap, wrpcap, IP, TCP, Raw
from typing import Dict, List, Tuple, Optional
import os
import json
import struct
from datetime import datetime


class FlowExporter:
    """TCP流导出器"""
    
    def __init__(self, output_dir: str = "exported_flows"):
        self.output_dir = output_dir
        self.exported_count = 0
        
    def _sanitize_filename(self, name: str) -> str:
        """清理文件名中的非法字符"""
        return name.replace(':', '_').replace('/', '_').replace('\\', '_').replace('.', '_')
    
    def _create_flow_dir(self, flow_id: Tuple) -> str:
        """创建流目录"""
        sip, dip, sport, dport = flow_id
        
        # 目录名: SIP-SPORT_DIP-DPORT
        dir_name = f"{sip}_{sport}_{dip}_{dport}"
        dir_name = self._sanitize_filename(dir_name)
        
        flow_dir = os.path.join(self.output_dir, dir_name)
        os.makedirs(flow_dir, exist_ok=True)
        
        return flow_dir
    
    def export_flow(self, flow_id: Tuple, packets: List[bytes], 
                    analysis_result: dict = None,
                    decode_result: dict = None) -> str:
        """
        导出单个流
        
        Args:
            flow_id: 五元组 (sip, dip, sport, dport)
            packets: 原始数据包列表
            analysis_result: 分析结果
            decode_result: 解码结果
        
        Returns:
            导出目录路径
        """
        flow_dir = self._create_flow_dir(flow_id)
        
        # 1. 导出原始pcap
        self._export_pcap(flow_dir, flow_id, packets)
        
        # 2. 导出分析结果
        self._export_analysis(flow_dir, flow_id, analysis_result)
        
        # 3. 导出解码消息
        self._export_decoded(flow_dir, flow_id, packets, decode_result)
        
        # 4. 导出统计信息
        self._export_stats(flow_dir, flow_id, packets)
        
        # 5. 创建摘要文件
        self._export_summary(flow_dir, flow_id, analysis_result)
        
        self.exported_count += 1
        return flow_dir
    
    def _export_pcap(self, flow_dir: str, flow_id: Tuple, packets: List[bytes]):
        """导出pcap文件"""
        pcap_path = os.path.join(flow_dir, "flow.pcap")
        
        # 构建scapy包
        scapy_packets = []
        sip, dip, sport, dport = flow_id
        
        for i, data in enumerate(packets):
            try:
                pkt = IP(src=sip, dst=dip) / TCP(sport=sport, dport=dport) / Raw(load=data)
                scapy_packets.append(pkt)
            except:
                pass
        
        if scapy_packets:
            wrpcap(pcap_path, scapy_packets)
    
    def _export_analysis(self, flow_dir: str, flow_id: Tuple, analysis_result: dict):
        """导出分析结果"""
        if analysis_result is None:
            return
            
        analysis_path = os.path.join(flow_dir, "analysis.json")
        
        # 简化分析结果以便于阅读
        simplified = self._simplify_analysis(analysis_result)
        
        with open(analysis_path, 'w', encoding='utf-8') as f:
            json.dump(simplified, f, indent=2, ensure_ascii=False)
    
    def _simplify_analysis(self, result: dict) -> dict:
        """简化分析结果"""
        simplified = {
            'total_packets': result.get('total_packets', 0),
            'total_bytes': result.get('total_bytes', 0),
            'packet_lengths': result.get('packet_lengths', []),
            'unique_lengths': list(set(result.get('packet_lengths', []))),
            'protocol_hint': None,
            'header_info': {},
            'confidence': 0.0
        }
        
        # 提取协议提示
        header_tmpl = result.get('header_template', {})
        if header_tmpl:
            simplified['protocol_hint'] = header_tmpl.get('likely_protocol')
            simplified['confidence'] = header_tmpl.get('confidence', 0.0)
        
        # 提取包头信息
        header_analysis = result.get('header_analysis', {})
        if header_analysis.get('candidate_offsets'):
            candidates = header_analysis['candidate_offsets'][:3]
            simplified['header_info']['length_field_candidates'] = [
                {'offset': c['offset'], 'score': c['score'], 'format': c.get('best_format')}
                for c in candidates
            ]
        
        fixed_fields = result.get('fixed_fields', {})
        if fixed_fields.get('fixed_bytes'):
            simplified['header_info']['fixed_bytes'] = {
                str(k): {'hex': v['hex'], 'freq': v['frequency']}
                for k, v in list(fixed_fields['fixed_bytes'].items())[:8]
            }
        
        if fixed_fields.get('magic_candidates'):
            simplified['header_info']['magic'] = [
                {'offset': m['offset'], 'length': m['length'], 'hex': m['hex']}
                for m in fixed_fields['magic_candidates']
            ]
        
        return simplified
    
    def _export_decoded(self, flow_dir: str, flow_id: Tuple, 
                        packets: List[bytes], decode_result: dict = None):
        """导出解码后的消息"""
        decoded_path = os.path.join(flow_dir, "decoded_messages.txt")
        
        with open(decoded_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"Flow: {flow_id[0]}:{flow_id[2]} -> {flow_id[1]}:{flow_id[3]}\n")
            f.write(f"Total Packets: {len(packets)}\n")
            f.write("=" * 80 + "\n\n")
            
            for i, data in enumerate(packets):
                f.write(f"[Packet {i+1}]\n")
                f.write(f"Length: {len(data)} bytes\n")
                f.write(f"Hex: {data.hex()}\n")
                
                # 尝试ASCII显示
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
                f.write(f"ASCII: {ascii_str}\n")
                
                # 如果有解码信息
                if decode_result and i < len(decode_result):
                    dec = decode_result[i]
                    if 'header' in dec:
                        f.write(f"Header: {dec['header'].hex()}\n")
                    if 'body' in dec:
                        f.write(f"Body: {dec['body'].hex()}\n")
                
                f.write("-" * 40 + "\n")
    
    def _export_stats(self, flow_dir: str, flow_id: Tuple, packets: List[bytes]):
        """导出统计信息"""
        stats_path = os.path.join(flow_dir, "statistics.txt")
        
        lengths = [len(p) for p in packets]
        
        with open(stats_path, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("Flow Statistics\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Flow ID: {flow_id}\n")
            f.write(f"Source: {flow_id[0]}:{flow_id[2]}\n")
            f.write(f"Destination: {flow_id[1]}:{flow_id[3]}\n\n")
            
            f.write(f"Total Packets: {len(packets)}\n")
            f.write(f"Total Bytes: {sum(lengths)}\n")
            f.write(f"Average Length: {sum(lengths)/len(lengths):.1f}\n\n")
            
            f.write(f"Min Length: {min(lengths)}\n")
            f.write(f"Max Length: {max(lengths)}\n")
            
            # 长度分布
            from collections import Counter
            length_counts = Counter(lengths)
            f.write("\nLength Distribution:\n")
            for length, count in sorted(length_counts.items()):
                bar = '*' * count
                f.write(f"  {length:4d}: {bar} ({count})\n")
            
            # 字节统计
            f.write("\nByte Value Distribution (offset 0-15):\n")
            for offset in range(min(16, min(lengths) if lengths else 0)):
                byte_counts = Counter()
                for pkt in packets:
                    if len(pkt) > offset:
                        byte_counts[pkt[offset]] += 1
                
                most_common = byte_counts.most_common(1)[0]
                pct = most_common[1] / len(packets) * 100
                f.write(f"  Offset {offset:2d}: 0x{most_common[0]:02X} ({pct:.0f}%)\n")
    
    def _export_summary(self, flow_dir: str, flow_id: Tuple, analysis_result: dict):
        """导出摘要信息"""
        summary_path = os.path.join(flow_dir, "README.txt")
        
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write("TCP Flow Analysis Summary\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Flow: {flow_id[0]}:{flow_id[2]} -> {flow_id[1]}:{flow_id[3]}\n")
            f.write(f"Export Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("Files in this directory:\n")
            f.write("-" * 40 + "\n")
            f.write("  flow.pcap           - Original packet data\n")
            f.write("  analysis.json       - Analysis results\n")
            f.write("  decoded_messages.txt - Decoded packet contents\n")
            f.write("  statistics.txt      - Flow statistics\n")
            f.write("  README.txt           - This file\n")
            f.write("\n")
            
            if analysis_result:
                f.write("Analysis Results:\n")
                f.write("-" * 40 + "\n")
                
                header = analysis_result.get('header_template', {})
                if header:
                    f.write(f"  Protocol: {header.get('likely_protocol', 'Unknown')}\n")
                    f.write(f"  Confidence: {header.get('confidence', 0):.1%}\n\n")
                
                fixed = analysis_result.get('fixed_fields', {})
                if fixed.get('magic_candidates'):
                    f.write("  Magic Numbers:\n")
                    for m in fixed['magic_candidates']:
                        f.write(f"    - {m['hex']} at offset {m['offset']}\n")
                
                len_analysis = analysis_result.get('header_analysis', {})
                if len_analysis.get('candidate_offsets'):
                    f.write("\n  Length Field Candidates:\n")
                    for c in len_analysis['candidate_offsets'][:3]:
                        f.write(f"    - Offset {c['offset']}: score={c['score']:.1f}")
                        if 'best_format' in c:
                            f.write(f", format={c['best_format']}")
                        f.write("\n")
    
    def export_all_flows(self, unpacker, min_confidence: float = 0.3,
                          min_packets: int = 2) -> List[str]:
        """
        导出所有符合条件的流
        
        Args:
            unpacker: HeuristicUnpacker实例
            min_confidence: 最低置信度阈值
            min_packets: 最少包数量
        
        Returns:
            导出目录列表
        """
        os.makedirs(self.output_dir, exist_ok=True)
        
        exported_dirs = []
        
        for flow_id, flow in unpacker.flows.items():
            # 只处理正向流 (避免重复)
            if flow_id[0] > flow_id[1]:
                continue
            
            # 检查包数量
            if len(flow.packets) < min_packets:
                continue
            
            # 获取分析结果
            analysis_result = unpacker.analysis_results.get(str(flow_id))
            
            # 检查置信度
            confidence = 0.0
            if analysis_result:
                header = analysis_result.get('header_template', {})
                confidence = header.get('confidence', 0.0)
            
            if confidence >= min_confidence:
                try:
                    flow_dir = self.export_flow(
                        flow_id, 
                        flow.packets,
                        analysis_result
                    )
                    exported_dirs.append(flow_dir)
                    print(f"[+] Exported: {os.path.basename(flow_dir)} (confidence: {confidence:.1%})")
                except Exception as e:
                    print(f"[-] Failed to export {flow_id}: {e}")
        
        return exported_dirs


def export_with_custom_rules(flow_id: Tuple, packets: List[bytes],
                              rules: List[dict],
                              output_dir: str = "custom_export") -> str:
    """
    使用自定义规则导出流
    
    Args:
        flow_id: 五元组
        packets: 数据包列表
        rules: 规则列表，每条规则包含:
            - header_len: 包头长度
            - length_offset: 长度字段偏移
            - length_format: 长度格式 (uint16_be, varint等)
            - magic: 魔数
    """
    exporter = FlowExporter(output_dir)
    flow_dir = exporter._create_flow_dir(flow_id)
    
    # 应用每条规则进行解码
    decoded_results = []
    
    for rule in rules:
        rule_name = rule.get('name', 'unnamed')
        header_len = rule.get('header_len')
        length_offset = rule.get('length_offset')
        length_format = rule.get('length_format', 'uint16_be')
        
        decoded = []
        for i, pkt in enumerate(packets):
            try:
                if header_len:
                    header = pkt[:header_len]
                    body = pkt[header_len:]
                elif length_offset:
                    # 根据格式解码长度
                    width = {
                        'uint8': 1, 'uint16_be': 2, 'uint16_le': 2,
                        'uint32_be': 4, 'uint32_le': 4, 'varint': 4
                    }.get(length_format, 2)
                    
                    if len(pkt) > length_offset + width:
                        if length_format == 'uint16_be':
                            length = int.from_bytes(pkt[length_offset:length_offset+2], 'big')
                        elif length_format == 'uint16_le':
                            length = int.from_bytes(pkt[length_offset:length_offset+2], 'little')
                        elif length_format == 'uint32_be':
                            length = int.from_bytes(pkt[length_offset:length_offset+4], 'big')
                        elif length_format == 'varint':
                            # 简化varint解码
                            length = pkt[length_offset]
                        
                        header = pkt[:length_offset + width]
                        body = pkt[length_offset + width:length_offset + width + length]
                    else:
                        header = pkt
                        body = b''
                else:
                    header = pkt
                    body = b''
                
                decoded.append({
                    'rule': rule_name,
                    'index': i,
                    'header': header,
                    'body': body,
                    'header_hex': header.hex(),
                    'body_hex': body.hex() if body else '',
                    'body_len': len(body)
                })
            except Exception as e:
                decoded.append({
                    'rule': rule_name,
                    'index': i,
                    'error': str(e)
                })
        
        decoded_results.append({
            'rule': rule_name,
            'decoded_packets': decoded
        })
    
    # 导出解码结果
    decoded_path = os.path.join(flow_dir, "custom_decoded.json")
    with open(decoded_path, 'w', encoding='utf-8') as f:
        json.dump(decoded_results, f, indent=2, ensure_ascii=False)
    
    return flow_dir


if __name__ == '__main__':
    # 使用示例
    from heuristic_unpack import HeuristicUnpacker
    
    # 分析pcap
    unpacker = HeuristicUnpacker()
    unpacker.load_pcap('test_data.pcap')
    results = unpacker.analyze_all_flows()
    
    # 导出所有符合条件的流
    exporter = FlowExporter("my_exports")
    exported = exporter.export_all_flows(unpacker, min_confidence=0.2)
    
    print(f"\n[*] Total exported: {len(exported)} flows")
