"""
Varint 可变长度整数编码/解码工具
===============================
支持:
- Standard Varint (Google Protocol Buffers风格)
- Base128 Varint
- LEB128 (Little Endian Base 128)
"""

def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    解码标准Varint (MSB为继续位)
    
    格式: 每个字节7位数据 + 1位继续位
         如果MSB=1，后面还有字节
         如果MSB=0，这是最后一个字节
    
    返回: (解码值, 消耗的字节数)
    
    示例:
        0x7F          → 127  (1字节)
        0x80 0x01    → 128  (2字节)
        0xFF 0x7F    → 16383 (2字节)
        0x80 0x80 0x01 → 16384 (3字节)
    """
    result = 0
    shift = 0
    pos = offset
    max_bytes = 10  # Varint最大10字节 (64位值)
    
    while pos < len(data) and pos - offset < max_bytes:
        byte = data[pos]
        pos += 1
        
        result |= (byte & 0x7F) << shift
        
        if (byte & 0x80) == 0:
            # 继续位为0，解析完成
            return result, pos - offset
    
    # 解码失败或数据不完整
    return result, pos - offset


def encode_varint(value: int) -> bytes:
    """
    编码为标准Varint
    
    示例:
        127  → 0x7F
        128  → 0x80 0x01
        16383 → 0xFF 0x7F
    """
    if value < 0:
        raise ValueError("Varint cannot encode negative values")
    
    result = bytearray()
    
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    
    result.append(value & 0x7F)
    return bytes(result)


def decode_signed_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    解码有符号Varint (zigzag编码)
    
    Zigzag编码映射:
        0 → 0, -1 → 1, 1 → 2, -2 → 3, 2 → 4, ...
        
    计算公式: (value >> 1) ^ -(value & 1)
    """
    raw_value, num_bytes = decode_varint(data, offset)
    
    # Zigzag解码
    result = (raw_value >> 1) ^ -(raw_value & 1)
    return result, num_bytes


def decode_leb128(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    解码ULEB128 (Unsigned Little-Endian Base 128)
    
    与标准Varint相反，低字节在前，高字节在后
    每个字节7位数据，MSB为继续位
    
    示例:
        [0x7F]     → 127
        [0x80 0x01] → 128
        [0x80 0x02] → 256
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


def decode_sleb128(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    解码SLEB128 (Signed Little-Endian Base 128)
    
    每个字节7位数据，最后一字节包含符号位
    """
    result = 0
    shift = 0
    pos = offset
    byte = 0
    
    while pos < len(data):
        byte = data[pos]
        pos += 1
        
        result |= (byte & 0x7F) << shift
        
        if (byte & 0x80) == 0:
            # 检查符号位
            if shift < 64 and (byte & 0x40):
                result |= -(1 << (shift + 1))
            return result, pos - offset
        
        shift += 7
    
    return result, pos - offset


class LengthFieldDecoder:
    """长度字段解码器 - 支持多种编码格式"""
    
    SUPPORTED_FORMATS = [
        # 名称, 宽度(字节), 端序, 解码函数
        ('uint8', 1, 'big', lambda d, o: (d[o], 1)),
        ('uint16_be', 2, 'big', lambda d, o: (int.from_bytes(d[o:o+2], 'big'), 2)),
        ('uint16_le', 2, 'little', lambda d, o: (int.from_bytes(d[o:o+2], 'little'), 2)),
        ('uint32_be', 4, 'big', lambda d, o: (int.from_bytes(d[o:o+4], 'big'), 4)),
        ('uint32_le', 4, 'little', lambda d, o: (int.from_bytes(d[o:o+4], 'little'), 4)),
        ('uint64_be', 8, 'big', lambda d, o: (int.from_bytes(d[o:o+8], 'big'), 8)),
        ('uint64_le', 8, 'little', lambda d, o: (int.from_bytes(d[o:o+8], 'little'), 8)),
        ('varint', None, 'varint', decode_varint),
        ('signed_varint', None, 'varint', decode_signed_varint),
        ('uleb128', None, 'leb128', decode_leb128),
        ('sleb128', None, 'leb128', decode_sleb128),
    ]
    
    @classmethod
    def try_decode(cls, data: bytes, offset: int = 0) -> List[dict]:
        """
        尝试用所有支持的格式解码
        
        返回每个格式的解码结果和匹配度
        """
        results = []
        
        for name, width, endian, decoder in cls.SUPPORTED_FORMATS:
            try:
                if width and len(data) < offset + width:
                    continue
                
                value, consumed = decoder(data, offset)
                
                results.append({
                    'format': name,
                    'value': value,
                    'width': consumed,  # 实际宽度
                    'offset': offset,
                    'bytes': data[offset:offset+consumed].hex() if len(data) > offset else ''
                })
            except:
                pass
        
        return results
    
    @classmethod
    def validate_length_field(cls, packets: List[bytes], offset: int, 
                               decoder_name: str, expected_header_len: int = 0) -> float:
        """
        验证某个偏移位置是否可能是长度字段
        
        返回匹配度分数 (0-1)
        """
        if decoder_name not in [f[0] for f in cls.SUPPORTED_FORMATS]:
            return 0.0
        
        decoder = dict(cls.SUPPORTED_FORMATS)[decoder_name]
        
        # 按包长度分组
        length_groups: Dict[int, List[int]] = defaultdict(list)
        
        for pkt in packets:
            try:
                value, width = decoder(pkt, offset)
                body_len = len(pkt) - offset - width - expected_header_len
                
                if body_len >= 0:
                    length_groups[body_len].append(value)
            except:
                return 0.0
        
        if not length_groups:
            return 0.0
        
        score = 0.0
        
        # 检查: 相同body长度的包，字段值应该相同
        for body_len, values in length_groups.items():
            if len(values) > 1:
                if len(set(values)) == 1:
                    score += 2.0
                else:
                    return 0.0
        
        # 检查: body长度与字段值的关系
        sorted_lengths = sorted(length_groups.keys())
        if len(sorted_lengths) >= 2:
            # 检查是否存在线性关系: value = a * body_len + b
            for i in range(len(sorted_lengths) - 1):
                for j in range(i + 1, len(sorted_lengths)):
                    len1, len2 = sorted_lengths[i], sorted_lengths[j]
                    val1 = length_groups[len1][0]
                    val2 = length_groups[len2][0]
                    
                    diff_len = len2 - len1
                    diff_val = abs(val2 - val1)
                    
                    if diff_len > 0 and diff_val > 0:
                        ratio = max(diff_len, diff_val) / min(diff_len, diff_val)
                        if ratio < 3:
                            score += 1.0
        
        return min(1.0, score / 10.0)


def detect_length_encoding(packets: List[bytes], offset: int) -> dict:
    """
    检测指定偏移处的长度编码格式
    
    返回最可能的格式及其置信度
    """
    results = []
    
    for name, width, endian, decoder in LengthFieldDecoder.SUPPORTED_FORMATS:
        if width and len(packets[0]) < offset + width:
            continue
        
        try:
            # 收集所有包的解码值
            values = []
            valid = True
            
            for pkt in packets:
                if len(pkt) <= offset:
                    valid = False
                    break
                try:
                    value, _ = decoder(pkt, offset)
                    values.append(value)
                except:
                    valid = False
                    break
            
            if not valid:
                continue
            
            # 分析值分布
            unique_values = len(set(values))
            value_range = max(values) - min(values) if values else 0
            
            results.append({
                'format': name,
                'width': width,
                'unique_values': unique_values,
                'min': min(values),
                'max': max(values),
                'all_same': unique_values == 1
            })
        except:
            pass
    
    return results


if __name__ == '__main__':
    # 测试Varint编解码
    
    print("=" * 60)
    print("Varint 编解码测试")
    print("=" * 60)
    
    # 测试编码
    test_values = [0, 127, 128, 255, 256, 16383, 16384, 65535, 100000, 2**32 - 1]
    
    print("\n[编码测试]")
    print("值".ljust(12), "编码结果".ljust(20), "字节数")
    print("-" * 50)
    
    for val in test_values:
        encoded = encode_varint(val)
        print(str(val).ljust(12), encoded.hex().ljust(20), len(encoded))
    
    # 测试解码
    print("\n[解码测试]")
    test_data = bytes([
        0x7F,                    # 127
        0x80, 0x01,              # 128
        0xFF, 0x7F,              # 16383
        0x80, 0x80, 0x01,        # 16384
        0x80, 0x82, 0x05,        # 300
    ])
    
    pos = 0
    while pos < len(test_data):
        val, num_bytes = decode_varint(test_data, pos)
        encoded = test_data[pos:pos+num_bytes].hex()
        print(f"数据: {encoded.ljust(12)} 偏移: {pos}  解码值: {val}")
        pos += num_bytes
    
    # 测试ULEB128
    print("\n[ULEB128 解码测试]")
    uleb_data = bytes([0x7F, 0x80, 0x01, 0x80, 0x02])
    
    pos = 0
    while pos < len(uleb_data):
        val, num_bytes = decode_leb128(uleb_data, pos)
        encoded = uleb_data[pos:pos+num_bytes].hex()
        print(f"ULEB128: {encoded.ljust(12)} 偏移: {pos}  解码值: {val}")
        pos += num_bytes
