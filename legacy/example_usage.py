"""
TCP流启发式拆包 - 快速使用示例
"""

from heuristic_unpack import *
import json


def quick_analyze(pcap_file: str):
    """快速分析pcap文件"""
    unpacker = HeuristicUnpacker()
    unpacker.load_pcap(pcap_file)
    
    print(f"\n{'='*70}")
    print("分析结果摘要")
    print('='*70)
    
    results = unpacker.analyze_all_flows()
    
    for flow_key, result in results.items():
        print(f"\nFlow: {flow_key}")
        print(f"  Packets: {result['total_packets']}")
        print(f"  Lengths: {result['packet_lengths']}")
        
        # 显示包头分析
        header = result.get('header_analysis', {})
        if header.get('candidate_offsets'):
            print(f"  Length field candidates: ", end="")
            offsets = [f"@{c['offset']}({c['score']:.1f})" for c in header['candidate_offsets'][:3]]
            print(", ".join(offsets))
        
        # 显示包头模板
        tmpl = result.get('header_template', {})
        if tmpl.get('template'):
            print(f"  Protocol: {tmpl.get('likely_protocol', 'Unknown')}")
            print(f"  Header preview:", end=" ")
            preview = ' '.join(t['hex'] for t in tmpl['template'][:8])
            print(preview)
    
    return unpacker, results


def extract_with_rules(pcap_file: str, rules_file: str = None):
    """使用规则提取消息"""
    unpacker = HeuristicUnpacker()
    unpacker.load_pcap(pcap_file)
    
    # 使用内置规则
    rules = ExtendedRules.common_protocol_rules()
    
    results = {}
    
    for flow_id, flow in unpacker.flows.items():
        if len(flow.packets) >= 2:
            matches = apply_rules_to_flow(flow, rules)
            if matches:
                results[str(flow_id)] = matches
    
    print("\n规则匹配结果:")
    for flow_key, matches in results.items():
        print(f"\n{flow_key}:")
        for m in matches[:3]:
            print(f"  - {m['rule_name']}: score={m['score']:.1f}")
    
    return results


def demo_analysis():
    """演示分析逻辑"""
    print("""
启发式拆包策略说明
==================

1. 固定字节检测
   - 扫描包头每个位置
   - 统计该位置字节在所有包中的分布
   - 频率>90%的认为是固定字节
   - 连续的固定字节可能是魔数

2. 长度字段检测
   - 检查2字节/4字节/1字节宽度
   - 检查大端/小端
   - 相同长度包的长度字段应相同
   - 不同长度包的长度字段应反映差异

3. 模式识别
   - 统计唯一长度值
   - 分析长度分布
   - 识别固定偏移的长度字段

4. 包头模板生成
   - 计算每个偏移最可能的值
   - 标记固定/可变
   - 生成可视化模板

示例协议识别:

协议A (Length-Prefix):
  Header: [长度(2B)][类型(1B)][标志(1B)]...
  识别方法: 检查offset=0处是否有2字节长度
  
协议B (Fixed Header):
  Header: [魔数(4B)][长度(2B)][校验(2B)]
  识别方法: 检查前4字节是否固定
  
协议C (Incremental):
  Header: [递增ID(4B)][长度(2B)][...]
  识别方法: 检查是否有递增模式
""")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
        quick_analyze(pcap_file)
    else:
        demo_analysis()
