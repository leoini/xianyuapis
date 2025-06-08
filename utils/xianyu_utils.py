import base64
import json
import subprocess
from functools import partial
import time
import hashlib
import struct
import os
from typing import Any, Dict, List

import blackboxprotobuf

subprocess.Popen = partial(subprocess.Popen, encoding="utf-8")
import execjs

def get_js_path():
    """获取JavaScript文件的路径"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(current_dir)
    js_path = os.path.join(root_dir, 'static', 'xianyu_js_version_2.js')
    return js_path

try:
    xianyu_js = execjs.compile(open(get_js_path(), 'r', encoding='utf-8').read())
except Exception as e:
    raise RuntimeError(f"无法加载JavaScript文件: {e}")

def trans_cookies(cookies_str: str) -> dict:
    """将cookies字符串转换为字典"""
    if not cookies_str:
        raise ValueError("cookies不能为空")
        
    cookies = {}
    for cookie in cookies_str.split("; "):
        if "=" in cookie:
            key, value = cookie.split("=", 1)
            cookies[key] = value
    return cookies


def generate_mid() -> str:
    """生成mid"""
    import random
    random_part = int(1000 * random.random())
    timestamp = int(time.time() * 1000)
    return f"{random_part}{timestamp} 0"


def generate_uuid() -> str:
    """生成uuid"""
    timestamp = int(time.time() * 1000)
    return f"-{timestamp}1"


def generate_device_id(user_id: str) -> str:
    """生成设备ID"""
    import random
    
    # 字符集
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    result = []
    
    for i in range(36):
        if i in [8, 13, 18, 23]:
            result.append("-")
        elif i == 14:
            result.append("4")
        else:
            if i == 19:
                # 对于位置19，需要特殊处理
                rand_val = int(16 * random.random())
                result.append(chars[(rand_val & 0x3) | 0x8])
            else:
                rand_val = int(16 * random.random())
                result.append(chars[rand_val])
    
    return ''.join(result) + "-" + user_id


def generate_sign(t: str, token: str, data: str) -> str:
    """生成签名"""
    app_key = "34839810"
    msg = f"{token}&{t}&{app_key}&{data}"
    
    # 使用MD5生成签名
    md5_hash = hashlib.md5()
    md5_hash.update(msg.encode('utf-8'))
    return md5_hash.hexdigest()


class MessagePackDecoder:
    """MessagePack解码器的纯Python实现"""
    
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.length = len(data)
    
    def read_byte(self) -> int:
        if self.pos >= self.length:
            raise ValueError("Unexpected end of data")
        byte = self.data[self.pos]
        self.pos += 1
        return byte
    
    def read_bytes(self, count: int) -> bytes:
        if self.pos + count > self.length:
            raise ValueError("Unexpected end of data")
        result = self.data[self.pos:self.pos + count]
        self.pos += count
        return result
    
    def read_uint8(self) -> int:
        return self.read_byte()
    
    def read_uint16(self) -> int:
        return struct.unpack('>H', self.read_bytes(2))[0]
    
    def read_uint32(self) -> int:
        return struct.unpack('>I', self.read_bytes(4))[0]
    
    def read_uint64(self) -> int:
        return struct.unpack('>Q', self.read_bytes(8))[0]
    
    def read_int8(self) -> int:
        return struct.unpack('>b', self.read_bytes(1))[0]
    
    def read_int16(self) -> int:
        return struct.unpack('>h', self.read_bytes(2))[0]
    
    def read_int32(self) -> int:
        return struct.unpack('>i', self.read_bytes(4))[0]
    
    def read_int64(self) -> int:
        return struct.unpack('>q', self.read_bytes(8))[0]
    
    def read_float32(self) -> float:
        return struct.unpack('>f', self.read_bytes(4))[0]
    
    def read_float64(self) -> float:
        return struct.unpack('>d', self.read_bytes(8))[0]
    
    def read_string(self, length: int) -> str:
        return self.read_bytes(length).decode('utf-8')
    
    def decode_value(self) -> Any:
        """解码单个MessagePack值"""
        if self.pos >= self.length:
            raise ValueError("Unexpected end of data")
            
        format_byte = self.read_byte()
        
        # Positive fixint (0xxxxxxx)
        if format_byte <= 0x7f:
            return format_byte
        
        # Fixmap (1000xxxx)
        elif 0x80 <= format_byte <= 0x8f:
            size = format_byte & 0x0f
            return self.decode_map(size)
        
        # Fixarray (1001xxxx)
        elif 0x90 <= format_byte <= 0x9f:
            size = format_byte & 0x0f
            return self.decode_array(size)
        
        # Fixstr (101xxxxx)
        elif 0xa0 <= format_byte <= 0xbf:
            size = format_byte & 0x1f
            return self.read_string(size)
        
        # nil
        elif format_byte == 0xc0:
            return None
        
        # false
        elif format_byte == 0xc2:
            return False
        
        # true
        elif format_byte == 0xc3:
            return True
        
        # bin 8
        elif format_byte == 0xc4:
            size = self.read_uint8()
            return self.read_bytes(size)
        
        # bin 16
        elif format_byte == 0xc5:
            size = self.read_uint16()
            return self.read_bytes(size)
        
        # bin 32
        elif format_byte == 0xc6:
            size = self.read_uint32()
            return self.read_bytes(size)
        
        # float 32
        elif format_byte == 0xca:
            return self.read_float32()
        
        # float 64
        elif format_byte == 0xcb:
            return self.read_float64()
        
        # uint 8
        elif format_byte == 0xcc:
            return self.read_uint8()
        
        # uint 16
        elif format_byte == 0xcd:
            return self.read_uint16()
        
        # uint 32
        elif format_byte == 0xce:
            return self.read_uint32()
        
        # uint 64
        elif format_byte == 0xcf:
            return self.read_uint64()
        
        # int 8
        elif format_byte == 0xd0:
            return self.read_int8()
        
        # int 16
        elif format_byte == 0xd1:
            return self.read_int16()
        
        # int 32
        elif format_byte == 0xd2:
            return self.read_int32()
        
        # int 64
        elif format_byte == 0xd3:
            return self.read_int64()
        
        # str 8
        elif format_byte == 0xd9:
            size = self.read_uint8()
            return self.read_string(size)
        
        # str 16
        elif format_byte == 0xda:
            size = self.read_uint16()
            return self.read_string(size)
        
        # str 32
        elif format_byte == 0xdb:
            size = self.read_uint32()
            return self.read_string(size)
        
        # array 16
        elif format_byte == 0xdc:
            size = self.read_uint16()
            return self.decode_array(size)
        
        # array 32
        elif format_byte == 0xdd:
            size = self.read_uint32()
            return self.decode_array(size)
        
        # map 16
        elif format_byte == 0xde:
            size = self.read_uint16()
            return self.decode_map(size)
        
        # map 32
        elif format_byte == 0xdf:
            size = self.read_uint32()
            return self.decode_map(size)
        
        # Negative fixint (111xxxxx)
        elif format_byte >= 0xe0:
            return format_byte - 0x100
        
        raise ValueError(f"Unknown format byte: {format_byte:02x}")

    def decode_array(self, size: int) -> List[Any]:
        """解码数组"""
        return [self.decode_value() for _ in range(size)]

    def decode_map(self, size: int) -> Dict[Any, Any]:
        """解码字典"""
        result = {}
        for _ in range(size):
            key = self.decode_value()
            value = self.decode_value()
            result[key] = value
        return result

    def decode(self) -> Any:
        """解码整个MessagePack数据"""
        return self.decode_value()


def decrypt(data: str) -> str:
    """解密消息数据"""
    try:
        # Base64解码
        decoded_data = base64.b64decode(data)
        
        # 使用MessagePack解码器解码数据
        decoder = MessagePackDecoder(decoded_data)
        decoded_value = decoder.decode()
        
        # 如果解码后的值是字典，转换为JSON字符串
        if isinstance(decoded_value, dict):
            def json_serializer(obj):
                if isinstance(obj, bytes):
                    return obj.decode('utf-8', errors='ignore')
                raise TypeError(f"Type {type(obj)} not serializable")
            
            return json.dumps(decoded_value, default=json_serializer)
        
        # 如果是其他类型，尝试转换为字符串
        return str(decoded_value)
        
    except Exception as e:
        raise Exception(f"解密失败: {str(e)}")

if __name__ == '__main__':
    # t = 1741667630548
    # token = 'b7e897bf9767618a32b439c6103fe1cb'
    # data = '{"appKey":"444e9908a51d1cb236a27862abc769c9","deviceId":"ED4CBA2C-5DA0-4154-A902-BF5CB52409E2-3888777108"}'
    # print(generate_sign(t, token, data))
    msg = "ggGLAYEBsjMxNDk2MzcwNjNAZ29vZmlzaAKzNDc5ODMzODkwOTZAZ29vZmlzaAOxMzQxNjU2NTI3NDU0Mi5QTk0EAAXPAAABlbKji20GggFlA4UBoAK6W+aIkeW3suaLjeS4i++8jOW+heS7mOasvl0DoAQaBdoEKnsiY29udGVudFR5cGUiOjI2LCJkeENhcmQiOnsiaXRlbSI6eyJtYWluIjp7ImNsaWNrUGFyYW0iOnsiYXJnMSI6Ik1zZ0NhcmQiLCJhcmdzIjp7InNvdXJjZSI6ImltIiwidGFza19pZCI6IjNleFFKSE9UbVBVMSIsIm1zZ19pZCI6ImNjOGJjMmRmN2M5MzRkZjA4NmUwNTY3Y2I2OWYxNTczIn19LCJleENvbnRlbnQiOnsiYmdDb2xvciI6IiNGRkZGRkYiLCJidXR0b24iOnsiYmdDb2xvciI6IiNGRkU2MEYiLCJib3JkZXJDb2xvciI6IiNGRkU2MEYiLCJjbGlja1BhcmFtIjp7ImFyZzEiOiJNc2dDYXJkQWN0aW9uIiwiYXJncyI6eyJzb3VyY2UiOiJpbSIsInRhc2tfaWQiOiIzZXhRSkhPVG1QVTEiLCJtc2dfaWQiOiJjYzhiYzJkZjdjOTM0ZGYwODZlMDU2N2NiNjlmMTU3MyJ9fSwiZm9udENvbG9yIjoiIzMzMzMzMyIsInRhcmdldFVybCI6ImZsZWFtYXJrZXQ6Ly9hZGp1c3RfcHJpY2U/Zmx1dHRlcj10cnVlJmJpek9yZGVySWQ9MjUwMzY4ODEyNjM1NjYzNjM3MCIsInRleHQiOiLkv67mlLnku7fmoLwifSwiZGVzYyI6Iuivt+WPjOaWueayn+mAmuWPiuaXtuehruiupOS7t+agvCIsImRlc2NDb2xvciI6IiNBM0EzQTMiLCJ0aXRsZSI6IuaIkeW3suaLjeS4i++8jOW+heS7mOasviIsInVwZ3JhZGUiOnsidGFyZ2V0VXJsIjoiaHR0cHM6Ly9oNS5tLmdvb2Zpc2guY29tL2FwcC9pZGxlRmlzaC1GMmUvZm0tZG93bmxhb2QvaG9tZS5odG1sP25vUmVkcmllY3Q9dHJ1ZSZjYW5CYWNrPXRydWUmY2hlY2tWZXJzaW9uPXRydWUiLCJ2ZXJzaW9uIjoiNy43LjkwIn19LCJ0YXJnZXRVcmwiOiJmbGVhbWFya2V0Oi8vb3JkZXJfZGV0YWlsP2lkPTI1MDM2ODgxMjYzNTY2MzYzNzAmcm9sZT1zZWxsZXIifX0sInRlbXBsYXRlIjp7Im5hbWUiOiJpZGxlZmlzaF9tZXNzYWdlX3RyYWRlX2NoYXRfY2FyZCIsInVybCI6Imh0dHBzOi8vZGluYW1pY3guYWxpYmFiYXVzZXJjb250ZW50LmNvbS9wdWIvaWRsZWZpc2hfbWVzc2FnZV90cmFkZV9jaGF0X2NhcmQvMTY2NzIyMjA1Mjc2Ny9pZGxlZmlzaF9tZXNzYWdlX3RyYWRlX2NoYXRfY2FyZC56aXAiLCJ2ZXJzaW9uIjoiMTY2NzIyMjA1Mjc2NyJ9fX0HAQgBCQAK3gAQpmJpelRhZ9oAe3sic291cmNlSWQiOiJDMkM6M2V4UUpIT1RtUFUxIiwidGFza05hbWUiOiLlt7Lmi43kuItf5pyq5LuY5qy+X+WNluWutiIsIm1hdGVyaWFsSWQiOiIzZXhRSkhPVG1QVTEiLCJ0YXNrSWQiOiIzZXhRSkhPVG1QVTEifbFjbG9zZVB1c2hSZWNlaXZlcqVmYWxzZbFjbG9zZVVucmVhZE51bWJlcqVmYWxzZaxkZXRhaWxOb3RpY2W6W+aIkeW3suaLjeS4i++8jOW+heS7mOasvl2nZXh0SnNvbtoBr3sibXNnQXJncyI6eyJ0YXNrX2lkIjoiM2V4UUpIT1RtUFUxIiwic291cmNlIjoiaW0iLCJtc2dfaWQiOiJjYzhiYzJkZjdjOTM0ZGYwODZlMDU2N2NiNjlmMTU3MyJ9LCJxdWlja1JlcGx5IjoiMSIsIm1zZ0FyZzEiOiJNc2dDYXJkIiwidXBkYXRlS2V5IjoiNDc5ODMzODkwOTY6MjUwMzY4ODEyNjM1NjYzNjM3MDoxX25vdF9wYXlfc2VsbGVyIiwibWVzc2FnZUlkIjoiY2M4YmMyZGY3YzkzNGRmMDg2ZTA1NjdjYjY5ZjE1NzMiLCJtdWx0aUNoYW5uZWwiOnsiaHVhd2VpIjoiRVhQUkVTUyIsInhpYW9taSI6IjEwODAwMCIsIm9wcG8iOiJFWFBSRVNTIiwiaG9ub3IiOiJOT1JNQUwiLCJhZ29vIjoicHJvZHVjdCIsInZpdm8iOiJPUkRFUiJ9LCJjb250ZW50VHlwZSI6IjI2IiwiY29ycmVsYXRpb25Hcm91cElkIjoiM2V4UUpIT1RtUFUxX0ZGcjRHT1NuOE9RbyJ9qHJlY2VpdmVyrTIyMDI2NDA5MTgwNzmrcmVkUmVtaW5kZXKy562J5b6F5Lmw5a625LuY5qy+sHJlZFJlbWluZGVyU3R5bGWhMa9yZW1pbmRlckNvbnRlbnS6W+aIkeW3suaLjeS4i++8jOW+heS7mOasvl2ucmVtaW5kZXJOb3RpY2W75Lmw5a625bey5ouN5LiL77yM5b6F5LuY5qy+rXJlbWluZGVyVGl0bGW75Lmw5a625bey5ouN5LiL77yM5b6F5LuY5qy+q3JlbWluZGVyVXJs2gCaZmxlYW1hcmtldDovL21lc3NhZ2VfY2hhdD9pdGVtSWQ9OTAwMDUyNjQ0Mjc3JnBlZXJVc2VySWQ9MzE0OTYzNzA2MyZwZWVyVXNlck5pY2s955S3KioqeSZzaWQ9NDc5ODMzODkwOTYmbWVzc2FnZUlkPWNjOGJjMmRmN2M5MzRkZjA4NmUwNTY3Y2I2OWYxNTczJmFkdj1ub6xzZW5kZXJVc2VySWSqMzE0OTYzNzA2M65zZW5kZXJVc2VyVHlwZaEwq3Nlc3Npb25UeXBloTGqdXBkYXRlSGVhZKR0cnVlDAEDgahuZWVkUHVzaKR0cnVl"
    msg = "ggGLAYEBsjMxNDk2MzcwNjNAZ29vZmlzaAKzNDc5ODMzODkwOTZAZ29vZmlzaAOxMzQxNjU2NTI3NDU0Mi5QTk0EAAXPAAABlbKji20GggFlA4UBoAK6W+aIkeW3suaLjeS4i++8jOW+heS7mOasvl0DoAQaBdoEKnsiY29udGVudFR5cGUiOjI2LCJkeENhcmQiOnsiaXRlbSI6eyJtYWluIjp7ImNsaWNrUGFyYW0iOnsiYXJnMSI6Ik1zZ0NhcmQiLCJhcmdzIjp7InNvdXJjZSI6ImltIiwidGFza19pZCI6IjNleFFKSE9UbVBVMSIsIm1zZ19pZCI6ImNjOGJjMmRmN2M5MzRkZjA4NmUwNTY3Y2I2OWYxNTczIn19LCJleENvbnRlbnQiOnsiYmdDb2xvciI6IiNGRkZGRkYiLCJidXR0b24iOnsiYmdDb2xvciI6IiNGRkU2MEYiLCJib3JkZXJDb2xvciI6IiNGRkU2MEYiLCJjbGlja1BhcmFtIjp7ImFyZzEiOiJNc2dDYXJkQWN0aW9uIiwiYXJncyI6eyJzb3VyY2UiOiJpbSIsInRhc2tfaWQiOiIzZXhRSkhPVG1QVTEiLCJtc2dfaWQiOiJjYzhiYzJkZjdjOTM0ZGYwODZlMDU2N2NiNjlmMTU3MyJ9fSwiZm9udENvbG9yIjoiIzMzMzMzMyIsInRhcmdldFVybCI6ImZsZWFtYXJrZXQ6Ly9hZGp1c3RfcHJpY2U/Zmx1dHRlcj10cnVlJmJpek9yZGVySWQ9MjUwMzY4ODEyNjM1NjYzNjM3MCIsInRleHQiOiLkv67mlLnku7fmoLwifSwiZGVzYyI6Iuivt+WPjOaWueayn+mAmuWPiuaXtuehruiupOS7t+agvCIsImRlc2NDb2xvciI6IiNBM0EzQTMiLCJ0aXRsZSI6IuaIkeW3suaLjeS4i++8jOW+heS7mOasviIsInVwZ3JhZGUiOnsidGFyZ2V0VXJsIjoiaHR0cHM6Ly9oNS5tLmdvb2Zpc2guY29tL2FwcC9pZGxlRmlzaC1GMmUvZm0tZG93bmxhb2QvaG9tZS5odG1sP25vUmVkcmllY3Q9dHJ1ZSZjYW5CYWNrPXRydWUmY2hlY2tWZXJzaW9uPXRydWUiLCJ2ZXJzaW9uIjoiNy43LjkwIn19LCJ0YXJnZXRVcmwiOiJmbGVhbWFya2V0Oi8vb3JkZXJfZGV0YWlsP2lkPTI1MDM2ODgxMjYzNTY2MzYzNzAmcm9sZT1zZWxsZXIifX0sInRlbXBsYXRlIjp7Im5hbWUiOiJpZGxlZmlzaF9tZXNzYWdlX3RyYWRlX2NoYXRfY2FyZCIsInVybCI6Imh0dHBzOi8vZGluYW1pY3guYWxpYmFiYXVzZXJjb250ZW50LmNvbS9wdWIvaWRsZWZpc2hfbWVzc2FnZV90cmFkZV9jaGF0X2NhcmQvMTY2NzIyMjA1Mjc2Ny9pZGxlZmlzaF9tZXNzYWdlX3RyYWRlX2NoYXRfY2FyZC56aXAiLCJ2ZXJzaW9uIjoiMTY2NzIyMjA1Mjc2NyJ9fX0HAQgBCQAK3gAQpmJpelRhZ9oAe3sic291cmNlSWQiOiJDMkM6M2V4UUpIT1RtUFUxIiwidGFza05hbWUiOiLlt7Lmi43kuItf5pyq5LuY5qy+X+WNluWutiIsIm1hdGVyaWFsSWQiOiIzZXhRSkhPVG1QVTEiLCJ0YXNrSWQiOiIzZXhRSkhPVG1QVTEifbFjbG9zZVB1c2hSZWNlaXZlcqVmYWxzZbFjbG9zZVVucmVhZE51bWJlcqVmYWxzZaxkZXRhaWxOb3RpY2W6W+aIkeW3suaLjeS4i++8jOW+heS7mOasvl2nZXh0SnNvbtoBr3sibXNnQXJncyI6eyJ0YXNrX2lkIjoiM2V4UUpIT1RtUFUxIiwic291cmNlIjoiaW0iLCJtc2dfaWQiOiJjYzhiYzJkZjdjOTM0ZGYwODZlMDU2N2NiNjlmMTU3MyJ9LCJxdWlja1JlcGx5IjoiMSIsIm1zZ0FyZzEiOiJNc2dDYXJkIiwidXBkYXRlS2V5IjoiNDc5ODMzODkwOTY6MjUwMzY4ODEyNjM1NjYzNjM3MDoxX25vdF9wYXlfc2VsbGVyIiwibWVzc2FnZUlkIjoiY2M4YmMyZGY3YzkzNGRmMDg2ZTA1NjdjYjY5ZjE1NzMiLCJtdWx0aUNoYW5uZWwiOnsiaHVhd2VpIjoiRVhQUkVTUyIsInhpYW9taSI6IjEwODAwMCIsIm9wcG8iOiJFWFBSRVNTIiwiaG9ub3IiOiJOT1JNQUwiLCJhZ29vIjoicHJvZHVjdCIsInZpdm8iOiJPUkRFUiJ9LCJjb250ZW50VHlwZSI6IjI2IiwiY29ycmVsYXRpb25Hcm91cElkIjoiM2V4UUpIT1RtUFUxX0ZGcjRHT1NuOE9RbyJ9qHJlY2VpdmVyrTIyMDI2NDA5MTgwNzmrcmVkUmVtaW5kZXKy562J5b6F5Lmw5a625LuY5qy+sHJlZFJlbWluZGVyU3R5bGWhMa9yZW1pbmRlckNvbnRlbnS6W+aIkeW3suaLjeS4i++8jOW+heS7mOasvl2ucmVtaW5kZXJOb3RpY2W75Lmw5a625bey5ouN5LiL77yM5b6F5LuY5qy+rXJlbWluZGVyVGl0bGW75Lmw5a625bey5ouN5LiL77yM5b6F5LuY5qy+q3JlbWluZGVyVXJs2gCaZmxlYW1hcmtldDovL21lc3NhZ2VfY2hhdD9pdGVtSWQ9OTAwMDUyNjQ0Mjc3JnBlZXJVc2VySWQ9MzE0OTYzNzA2MyZwZWVyVXNlck5pY2s955S3KioqeSZzaWQ9NDc5ODMzODkwOTYmbWVzc2FnZUlkPWNjOGJjMmRmN2M5MzRkZjA4NmUwNTY3Y2I2OWYxNTczJmFkdj1ub6xzZW5kZXJVc2VySWSqMzE0OTYzNzA2M65zZW5kZXJVc2VyVHlwZaEwq3Nlc3Npb25UeXBloTGqdXBkYXRlSGVhZKR0cnVlDAEDgahuZWVkUHVzaKR0cnVl"

    res = decrypt(msg)
    print(res)