"""
创建丰富的模拟TCP测试数据
=========================
测试各种边界情况和协议格式
"""

import struct
import json


# ==================== Varint 编码函数 ====================

def encode_varint(value: int) -> bytes:
    """标准Varint编码"""
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def encode_uleb128(value: int) -> bytes:
    """ULEB128编码"""
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def encode_length(length_value: int, format_name: str) -> bytes:
    """根据格式编码长度值"""
    if format_name == "uint8":
        return struct.pack('B', length_value)
    elif format_name == "uint16_be":
        return struct.pack('>H', length_value)
    elif format_name == "uint16_le":
        return struct.pack('<H', length_value)
    elif format_name == "uint32_be":
        return struct.pack('>I', length_value)
    elif format_name == "uint32_le":
        return struct.pack('<I', length_value)
    elif format_name == "varint":
        return encode_varint(length_value)
    elif format_name == "uleb128":
        return encode_uleb128(length_value)
    else:
        raise ValueError(f"Unknown format: {format_name}")


def decode_length(data: bytes, offset: int, format_name: str) -> int:
    """解码长度值"""
    if format_name == "uint8":
        return data[offset]
    elif format_name == "uint16_be":
        return struct.unpack('>H', data[offset:offset+2])[0]
    elif format_name == "uint16_le":
        return struct.unpack('<H', data[offset:offset+2])[0]
    elif format_name == "uint32_be":
        return struct.unpack('>I', data[offset:offset+4])[0]
    elif format_name == "uint32_le":
        return struct.unpack('<I', data[offset:offset+4])[0]
    elif format_name == "varint":
        return decode_varint(data, offset)[0]
    elif format_name == "uleb128":
        return decode_uleb128(data, offset)[0]
    else:
        raise ValueError(f"Unknown format: {format_name}")


def decode_varint(data: bytes, offset: int = 0) -> tuple:
    """解码Varint"""
    result = 0
    shift = 0
    pos = offset
    while pos < len(data) and pos - offset < 10:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, pos - offset
    return result, pos - offset


def decode_uleb128(data: bytes, offset: int = 0) -> tuple:
    """解码ULEB128"""
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


# ==================== 手动构建PCAP文件 ====================

def create_pcap_header() -> bytes:
    """创建PCAP全局头"""
    return struct.pack('<IHHiIII',
        0xa1b2c3d4,  # magic number
        2, 4,        # version
        0,           # timezone
        0,           # sigfigs
        65535,       # snaplen
        1            # network (LINKTYPE_ETHERNET)
    )


def create_packet_header(data: bytes, timestamp: float) -> bytes:
    """创建数据包头"""
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1000000)
    return struct.pack('<IIII',
        ts_sec, ts_usec,
        len(data),  # captured length
        len(data)   # original length
    )


def create_ethernet_header() -> bytes:
    """创建以太网头"""
    return b'\x00\x00\x00\x00\x00\x01' + b'\x00\x00\x00\x00\x00\x02' + b'\x08\x00'


def create_ip_header(src_ip: str, dst_ip: str, payload_len: int) -> bytes:
    """创建IP头"""
    # 解析IP地址
    src_parts = [int(x) for x in src_ip.split('.')]
    dst_parts = [int(x) for x in dst_ip.split('.')]
    
    src_addr = struct.pack('!4B', *src_parts)
    dst_addr = struct.pack('!4B', *dst_parts)
    
    total_len = 20 + 20 + payload_len  # IP + TCP + payload
    
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45,           # version(4) + IHL(5)
        0,              # DSCP
        total_len,      # total length
        0x1234,         # identification
        0x4000,         # flags + fragment offset
        64,             # TTL
        6,              # protocol (TCP)
        0,              # checksum (0 = let it be wrong)
        src_addr,
        dst_addr
    )
    return ip_header


def create_tcp_header(sport: int, dport: int, seq: int, ack: int, payload_len: int) -> bytes:
    """创建TCP头"""
    data_offset = 5 << 4  # 5 words (20 bytes)
    
    tcp_header = struct.pack('!HHIIBBHHH',
        sport,          # source port
        dport,          # destination port
        seq,            # sequence number
        ack,            # acknowledgment number
        data_offset,    # data offset
        0x18,           # flags (PSH, ACK)
        8192,           # window size
        0,              # checksum (0 = let it be wrong)
        0               # urgent pointer
    )
    return tcp_header


def make_raw_packet(flow_id: int, format_info: dict, body: bytes, timestamp: float = 1.0) -> bytes:
    """创建原始数据包（绕过Scapy校验和问题）"""
    # IP地址
    src_ip = f"10.0.{flow_id + 100}.10"
    dst_ip = f"10.0.{flow_id + 100}.20"
    
    # 端口
    sport = 10000 + flow_id
    dport = 8000 + flow_id
    
    # 构建应用层数据
    app_data = bytearray()
    
    # 添加前缀
    if 'prefix' in format_info:
        app_data.extend(format_info['prefix'])
    
    # 添加前缀填充
    if 'prefix_padding' in format_info:
        app_data.extend(b'\x00' * format_info['prefix_padding'])
    
    # 长度字段位置
    length_offset = len(app_data)
    
    # 添加长度字段占位
    length_width = format_info.get('length_width', 2)
    if length_width is None:
        length_width = 4
    app_data.extend(b'\x00' * length_width)
    
    # 添加后缀填充
    if 'suffix_padding' in format_info:
        app_data.extend(b'\x00' * format_info['suffix_padding'])
    
    # 计算body开始位置
    body_start = len(app_data)
    
    # 编码长度值 = body长度
    length_value = len(body)
    length_bytes = encode_length(length_value, format_info['length_format'])
    
    # 组装应用数据
    app_data = bytes(app_data[:length_offset]) + length_bytes + bytes(app_data[length_offset + length_width:])
    app_data += body
    
    # 构建各层头部
    tcp_header = create_tcp_header(sport, dport, 1000, 0, len(app_data))
    ip_header = create_ip_header(src_ip, dst_ip, len(tcp_header) + len(app_data))
    eth_header = create_ethernet_header()
    
    # 组装完整数据包
    packet = eth_header + ip_header + tcp_header + app_data
    
    return packet


def create_comprehensive_test_packets() -> tuple:
    """创建全面的测试数据包"""
    all_packets = []
    test_info = []
    
    # 所有测试场景
    test_scenarios = [
        # === 长度在包头开始 ===
        {'name': '1B_Length_Head_BE', 'flow_id': 1, 'format': {'length_offset': 0, 'length_format': 'uint8', 'length_width': 1}, 'prefix': b'\xAA', 'bodies': [b'A'*5, b'B'*50, b'C'*100, b'D'*200]},
        {'name': '2B_Length_Head_BE', 'flow_id': 2, 'format': {'length_offset': 0, 'length_format': 'uint16_be', 'length_width': 2}, 'prefix': b'\xBB\xCC', 'bodies': [b'E'*5, b'F'*100, b'G'*255, b'H'*300]},
        {'name': '2B_Length_Head_LE', 'flow_id': 3, 'format': {'length_offset': 0, 'length_format': 'uint16_le', 'length_width': 2}, 'prefix': b'\xDD\xEE', 'bodies': [b'I'*8, b'J'*64, b'K'*200, b'L'*500]},
        {'name': '4B_Length_Head_BE', 'flow_id': 4, 'format': {'length_offset': 0, 'length_format': 'uint32_be', 'length_width': 4}, 'prefix': b'\x11\x22\x33\x44', 'bodies': [b'M'*100, b'N'*1000, b'O'*5000, b'P'*10000]},
        {'name': '4B_Length_Head_LE', 'flow_id': 5, 'format': {'length_offset': 0, 'length_format': 'uint32_le', 'length_width': 4}, 'prefix': b'\x55\x66\x77\x88', 'bodies': [b'Q'*50, b'R'*200, b'S'*1024, b'T'*2048]},
        
        # === 长度在包头中间 ===
        {'name': '2B_Length_Mid_BE', 'flow_id': 10, 'format': {'length_offset': 2, 'length_format': 'uint16_be', 'length_width': 2}, 'prefix_padding': 2, 'bodies': [b'U'*7, b'V'*15, b'W'*30, b'X'*100]},
        {'name': '2B_Length_Mid_LE', 'flow_id': 11, 'format': {'length_offset': 2, 'length_format': 'uint16_le', 'length_width': 2}, 'prefix_padding': 2, 'bodies': [b'Y'*9, b'Z'*20, b'A'*50, b'B'*80]},
        {'name': '4B_Length_Mid_BE', 'flow_id': 12, 'format': {'length_offset': 2, 'length_format': 'uint32_be', 'length_width': 4}, 'prefix_padding': 2, 'bodies': [b'C'*10, b'D'*100, b'E'*500, b'F'*2000]},
        {'name': '1B_Length_Mid', 'flow_id': 13, 'format': {'length_offset': 3, 'length_format': 'uint8', 'length_width': 1}, 'prefix_padding': 3, 'bodies': [b'G'*5, b'H'*12, b'I'*20, b'J'*50]},
        
        # === 长度在包头结尾 ===
        {'name': '2B_Length_End_BE', 'flow_id': 20, 'format': {'length_offset': 4, 'length_format': 'uint16_be', 'length_width': 2}, 'prefix': b'\xFF\xEE\xDD\xCC', 'bodies': [b'K'*10, b'L'*25, b'M'*60, b'N'*120]},
        {'name': '2B_Length_End_LE', 'flow_id': 21, 'format': {'length_offset': 4, 'length_format': 'uint16_le', 'length_width': 2}, 'prefix': b'\xAA\xBB\xCC\xDD', 'bodies': [b'O'*8, b'P'*40, b'Q'*80, b'R'*160]},
        {'name': '4B_Length_End_BE', 'flow_id': 22, 'format': {'length_offset': 4, 'length_format': 'uint32_be', 'length_width': 4}, 'prefix': b'\x12\x34\x56\x78', 'bodies': [b'S'*20, b'T'*200, b'U'*1000, b'V'*5000]},
        
        # === Varint编码 ===
        {'name': 'Varint_Head', 'flow_id': 30, 'format': {'length_offset': 0, 'length_format': 'varint', 'length_width': None}, 'prefix': b'\xAB', 'bodies': [b'W'*5, b'X'*50, b'Y'*200, b'Z'*1000]},
        {'name': 'Varint_Mid', 'flow_id': 31, 'format': {'length_offset': 2, 'length_format': 'varint', 'length_width': None}, 'prefix_padding': 2, 'bodies': [b'A'*10, b'B'*100, b'C'*500, b'D'*2000]},
        {'name': 'ULEB128_Head', 'flow_id': 32, 'format': {'length_offset': 0, 'length_format': 'uleb128', 'length_width': None}, 'prefix': b'\xCD', 'bodies': [b'E'*8, b'F'*80, b'G'*300, b'H'*1500]},
        
        # === 带魔数前缀 ===
        {'name': 'Magic_2B_Len', 'flow_id': 40, 'format': {'length_offset': 4, 'length_format': 'uint16_be', 'length_width': 2}, 'prefix': b'PKTM', 'bodies': [b'I'*12, b'J'*50, b'K'*100, b'L'*200]},
        {'name': 'Magic_4B_Len', 'flow_id': 41, 'format': {'length_offset': 4, 'length_format': 'uint32_be', 'length_width': 4}, 'prefix': b'DATA', 'bodies': [b'M'*15, b'N'*200, b'O'*1000, b'P'*5000]},
        {'name': 'Magic_Varint', 'flow_id': 42, 'format': {'length_offset': 4, 'length_format': 'varint', 'length_width': None}, 'prefix': b'MSGO', 'bodies': [b'Q'*10, b'R'*80, b'S'*500, b'T'*2000]},
        
        # === 边界值测试 ===
        {'name': 'Boundary_0xFF', 'flow_id': 50, 'format': {'length_offset': 0, 'length_format': 'uint8', 'length_width': 1}, 'prefix': b'\x00', 'bodies': [b'A'*100, b'B'*200, b'C'*250, b'D'*255]},
        {'name': 'Boundary_0x100', 'flow_id': 51, 'format': {'length_offset': 0, 'length_format': 'uint16_be', 'length_width': 2}, 'prefix': b'\x00\x00', 'bodies': [b'E'*254, b'F'*255, b'G'*256, b'H'*257]},
        {'name': 'Boundary_0xFFFF', 'flow_id': 52, 'format': {'length_offset': 0, 'length_format': 'uint32_be', 'length_width': 4}, 'prefix': b'\x00'*4, 'bodies': [b'I'*65000, b'J'*65000, b'K'*65000, b'L'*65000]},
        
        # === 多种长度格式混合 ===
        {'name': 'Mixed_Lengths', 'flow_id': 60, 'format': {'length_offset': 0, 'length_format': 'uint16_be', 'length_width': 2}, 'prefix': b'\x01\x00', 'bodies': [b'A'*1, b'B'*10, b'C'*100, b'D'*1000, b'E'*5000]},
        
        # === 相同长度的重复包 ===
        {'name': 'Same_Length_Repeat', 'flow_id': 70, 'format': {'length_offset': 0, 'length_format': 'uint16_be', 'length_width': 2}, 'prefix': b'\xFF\x00', 'bodies': [b'X'*20] * 5},
        
        # === 大数据包 ===
        {'name': 'Large_Data', 'flow_id': 80, 'format': {'length_offset': 0, 'length_format': 'uint32_be', 'length_width': 4}, 'prefix': b'\xAA\xBB\xCC\xDD', 'bodies': [b'Y'*1000, b'Z'*5000, b'A'*10000, b'B'*20000]},
    ]
    
    for scenario in test_scenarios:
        flow_id = scenario['flow_id']
        format_info = scenario['format'].copy()
        
        # 添加前缀/后缀填充信息
        if 'prefix_padding' in scenario:
            format_info['prefix_padding'] = scenario['prefix_padding']
        if 'suffix_padding' in scenario:
            format_info['suffix_padding'] = scenario['suffix_padding']
        
        for i, body in enumerate(scenario['bodies']):
            packet = make_raw_packet(flow_id, format_info, body, timestamp=1.0 + len(all_packets) * 0.001)
            all_packets.append(packet)
            
            # 记录测试信息
            test_info.append({
                'name': scenario['name'],
                'flow_id': flow_id,
                'body_len': len(body),
                'packet_len': len(packet),
                'expected_offset': format_info['length_offset'],
                'expected_format': format_info['length_format'],
                'raw_hex': packet[-len(body)-8:].hex() if len(body) < 100 else f"<large: {len(body)} bytes>"
            })
    
    return all_packets, test_info


def save_test_pcap(filename: str = "comprehensive_test.pcap", info_file: str = "test_info.json"):
    """保存测试pcap和测试信息"""
    print("[*] Generating comprehensive test data (raw format)...")
    
    packets, test_info = create_comprehensive_test_packets()
    
    # 写入PCAP文件
    with open(filename, 'wb') as f:
        f.write(create_pcap_header())
        for pkt in packets:
            f.write(create_packet_header(pkt, 1.0))
            f.write(pkt)
    
    print(f"[*] Test pcap saved to: {filename}")
    print(f"[*] Total packets: {len(packets)}")
    
    # 保存测试信息
    with open(info_file, 'w', encoding='utf-8') as f:
        json.dump(test_info, f, indent=2, ensure_ascii=False)
    print(f"[*] Test info saved to: {info_file}")
    
    # 打印统计
    print("\n" + "=" * 70)
    print("Test Data Summary")
    print("=" * 70)
    
    flows = {}
    for info in test_info:
        name = info['name']
        if name not in flows:
            flows[name] = {
                'count': 0,
                'offset': info['expected_offset'],
                'format': info['expected_format'],
                'packet_lens': []
            }
        flows[name]['count'] += 1
        flows[name]['packet_lens'].append(info['packet_len'])
    
    print(f"\n{'Protocol Name':<25} {'Offset':>8} {'Format':>12} {'Count':>6} {'Packet Sizes':>30}")
    print("-" * 90)
    
    for name, data in sorted(flows.items()):
        sizes = ','.join(str(s) for s in data['packet_lens'][:3])
        if len(data['packet_lens']) > 3:
            sizes += ',...'
        print(f"{name:<25} {data['offset']:>8} {data['format']:>12} {data['count']:>6} {sizes:>30}")
    
    print("\n" + "=" * 70)
    print("Total test scenarios:", len(flows))
    print("Total test packets:", len(packets))
    print("=" * 70)
    
    return packets, test_info


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--comprehensive':
        packets, test_info = save_test_pcap(
            filename="comprehensive_test.pcap",
            info_file="test_info.json"
        )
    else:
        print("Usage: python create_test_data.py --comprehensive")
