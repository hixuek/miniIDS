#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
入侵检测系统 (Intrusion Detection System)
实现网络流量监控、分析和攻击检测功能
"""

# 导入标准库模块
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
import socket
from datetime import datetime
from urllib.parse import unquote
import json
import os
import queue
import netifaces
if os.geteuid() != 0:
    print("⚠️  当前不是 root 用户，抓包可能失败，请使用 sudo 运行！")

from datetime import datetime
from collections import defaultdict, deque
import subprocess
import sys
from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw, sniff, wrpcap, rdpcap, send, sr1

print("Scapy imports all successful!")

# 全局配置
DEFAULT_CONFIG = {
    'rate_limit': 1000,  # 每秒最大处理包数
    'thresholds': {
        'port_scan': {
            'syn_threshold': 25,    # 10秒内超过25个SYN包
            'tcp_threshold': 20,    # 10秒内超过20个TCP连接
            'udp_threshold': 15,    # 10秒内超过15个ICMP不可达响应
            'time_window': 10       # 10秒时间窗口
        },
        'dos': {
            'syn_threshold': 200,   # 每秒200个SYN包
            'icmp_threshold': 30,   # 每秒30个ICMP包
            'udp_threshold': 200,   # 每秒200个UDP包
            'time_window': 1        # 1秒时间窗口
        }
    }
}

def get_interfaces():
    """获取系统网络接口列表"""
    interfaces = netifaces.interfaces()
    # 确保'any'和'lo'在列表开头
    if 'lo' in interfaces:
        interfaces.remove('lo')
    if 'any' not in interfaces:
        interfaces = ['any'] + interfaces
    interfaces = ['lo'] + interfaces
    return interfaces

class PacketProcessor(threading.Thread):
    """数据包处理线程"""
    def __init__(self, packet_queue, callback):
        super().__init__()
        self.packet_queue = packet_queue
        self.callback = callback
        self.running = True
        self.is_paused = False
        self.daemon = True  # 设置为守护线程

    def run(self):
        while self.running:
            try:
                if not self.is_paused:
                    packet = self.packet_queue.get(timeout=1)
                    if self.callback:
                        self.callback(packet)
                    self.packet_queue.task_done()
                else:
                    # 暂停状态下仍然从队列中获取数据包，但不处理
                    try:
                        self.packet_queue.get(timeout=1)
                        self.packet_queue.task_done()
                    except queue.Empty:
                        pass
                    time.sleep(0.1)  # 减少CPU使用
            except queue.Empty:
                continue
            except Exception as e:
                print(f"数据包处理错误: {e}")

    def stop(self):
        self.running = False

class PacketCapture:
    """抓包模块 - 负责实时网络流量捕获"""

    def __init__(self, callback=None):
        self.callback = callback
        self.is_capturing = False
        self.captured_packets = []
        self.capture_thread = None
        self.interface = None
        self.packet_filter = ""

    def start_capture(self, interface="lo", packet_filter=""):
        """开始抓包"""
        if self.is_capturing:
            return False

        self.interface = interface
        self.packet_filter = packet_filter
        self.is_capturing = True
        self.captured_packets = []

        self.capture_thread = threading.Thread(target=self._capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        return True

    def stop_capture(self):
        """停止抓包"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)

    def _capture_loop(self):
        """抓包循环"""
        try:
            def packet_handler(packet):
                if not self.is_capturing:
                    return False

                self.captured_packets.append(packet)
                if self.callback:
                    self.callback(packet)

            # 使用scapy进行抓包
            sniff(iface=self.interface,
                  filter=self.packet_filter,
                  prn=packet_handler,
                  stop_filter=lambda x: not self.is_capturing)

        except Exception as e:
            pass

    def get_packets(self):
        """获取捕获的数据包"""
        return self.captured_packets.copy()


class PCAPManager:
    """PCAP文件管理模块 - 保存和读取PCAP文件"""

    @staticmethod
    def save_packets(packets, filename):
        """保存数据包到PCAP文件"""
        try:
            wrpcap(filename, packets)
            return True
        except Exception as e:
            print(f"保存PCAP文件错误: {e}")
            return False

    @staticmethod
    def load_packets(filename):
        """从PCAP文件加载数据包"""
        try:
            packets = rdpcap(filename)
            return packets
        except Exception as e:
            print(f"读取PCAP文件错误: {e}")
            return []


class PacketAnalyzer:
    """数据分析模块 - 提取和分析数据包特征"""

    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int),
            'ports': defaultdict(int)
        }

    def analyze_packet(self, packet):
        # packet_info['raw_packet'] = packet  # ✅ 关键补充
        packet_info = {
            'raw_packet': packet,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None,
            'length': len(packet),
            'timestamp': time.time(),
            'http_payload': None,
            'http_uri': None,
            'tcp_flags': None,
            'icmp_type': None
        }

        if IP in packet:
            self.stats['total_packets'] += 1

            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst

            self.stats['src_ips'][packet_info['src_ip']] += 1
            self.stats['dst_ips'][packet_info['dst_ip']] += 1

            if packet.haslayer(TCP):
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                self.stats['ports'][packet_info['dst_port']] += 1

                flags = packet[TCP].flags
                if flags & 0x02:
                    packet_info['tcp_flags'] = 'S'
                elif flags & 0x10:
                    packet_info['tcp_flags'] = 'A'
                elif flags & 0x04:
                    packet_info['tcp_flags'] = 'R'

                # HTTP 提取
                if packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load
                        payload_str = payload.decode('utf-8', errors='ignore')

                        # 确保是HTTP请求
                        if 'GET ' in payload_str or 'POST ' in payload_str:
                            SERVER_PORTS = [80, 8000, 8080, 9097]
                            if TCP in packet and packet[TCP].dport not in SERVER_PORTS:
                                return packet_info  # 🔙 忽略响应数据包

                            packet_info['http_payload'] = payload_str
                            # print("[DEBUG] 捕获到HTTP请求:\n", payload_str)

                            # 提取并解码 URI（避免 URI 含空格导致 split 被截断）
                            headers = payload_str.split('\r\n\r\n')[0]
                            request_line = headers.split('\r\n')[0]

                            try:
                                method, uri = request_line.split(' ', 2)[:2]
                                from urllib.parse import unquote
                                decoded_uri = unquote(uri)
                                packet_info['http_uri'] = decoded_uri
                            except ValueError:
                                # 请求行格式异常，忽略
                                return packet_info

                    except Exception as e:
                        print(f"[DEBUG] Payload decode error: {e}")

            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                self.stats['ports'][packet_info['dst_port']] += 1
                # print(f"[DEBUG][UDP] UDP包: {packet[IP].src} -> {packet[IP].dst}:{packet[UDP].dport}")

            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
                packet_info['icmp_type'] = packet[ICMP].type
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                # print(f"[DEBUG][ICMP] ICMP响应: type={icmp_type}, code={icmp_code}, 来自 {packet[IP].src}")
                # print("[DEBUG] raw_packet 是否存在:", bool(packet_info.get('raw_packet')))

            self.stats['protocols'][packet_info['protocol']] += 1

        return packet_info

    def get_stats(self):
        """获取统计信息"""
        return self.stats.copy()

    def reset_stats(self):
        """重置统计信息"""
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int),
            'ports': defaultdict(int)
        }


class AttackDetector:
    """攻击检测模块 - 检测各种网络攻击"""
    def __init__(self, alert_callback=None, thresholds=None):
        self.alert_callback = alert_callback
        self.detectors = [
            PortScanDetector(alert_callback),
            SQLInjectionDetector(alert_callback),
            XSSDetector(alert_callback),
            DoSDetector(alert_callback)
        ]
        self.thresholds = thresholds or DEFAULT_CONFIG['thresholds']

    def detect_attack(self, packet_info, packet=None):
        """检测所有类型的攻击，可同时返回多个告警"""
        alerts = []
        for detector in self.detectors:
            if hasattr(detector, 'detect'):
                try:
                    result = detector.detect(packet_info, packet) if 'PortScanDetector' in str(type(detector)) else detector.detect(packet_info)
                    if isinstance(result, list):
                        alerts.extend(result)
                    elif result:
                        alerts.append(result)
                except Exception as e:
                    print(f"检测器 {type(detector).__name__} 发生错误: {e}")
        return alerts


class PortScanDetector:
    """端口扫描检测器"""

    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        # 扫描记录
        self.syn_scan_records = defaultdict(lambda: {
            'ports': set(),
            'last_time': 0,
            'count': 0,
            'syn_rate': 0.0  # 添加SYN包速率记录
        })
        self.tcp_scan_records = defaultdict(lambda: {
            'ports': set(),
            'last_time': 0,
            'count': 0,
            'syn_ack_pairs': set()  # 记录合法的SYN-ACK对
        })
        self.udp_scan_records = defaultdict(lambda: {
            'udp_packets': [],  # 记录UDP包的时间戳
            'icmp_unreachable': 0,  # ICMP不可达计数
            'last_time': 0,
            'ports': set(),  # 记录被探测的端口
            'udp_count': 0,  # UDP包计数
            'unreachable_ports': set()  # 记录返回不可达的端口
        })
        
        # 调整阈值到更合理的值
        self.syn_threshold = 25    # 10秒内超过25个SYN包
        self.tcp_threshold = 20     # 10秒内超过20个TCP连接
        self.udp_threshold = 15     # 10秒内超过15个ICMP不可达响应
        self.time_window = 10      # 10秒时间窗口

        # UDP扫描检测的参数
        self.udp_scan_min_ports = 5      # 最少需要探测的不同端口数
        self.udp_scan_max_packets = 50   # 扫描时的最大UDP包数量
        self.udp_scan_min_unreachable_ratio = 0.7  # 最小ICMP不可达比例

    def detect(self, packet_info, packet=None):
        """检测端口扫描"""
        if not packet_info.get('src_ip'):
            return None

        src_ip = packet_info['src_ip']
        timestamp = packet_info['timestamp']
        alerts = []

        # 检测SYN扫描和TCP扫描的代码保持不变...
        # SYN 扫描检测
        if packet_info.get('protocol') == 'TCP' and packet_info.get('tcp_flags') == 'S':
            record = self.syn_scan_records[src_ip]
            if timestamp - record['last_time'] > self.time_window:
                record['ports'].clear()
                record['count'] = 0
            record['ports'].add(packet_info.get('dst_port'))
            record['last_time'] = timestamp
            record['count'] += 1
            
            if len(record['ports']) > self.syn_threshold:
                alert = {
                    'type': 'Port Scan',
                    'severity': 'High',
                    'source_ip': src_ip,
                    'destination_ip': packet_info.get('dst_ip'),
                    'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                    'details': f'检测到来自 {src_ip} 的 SYN 扫描，{self.time_window} 秒内扫描了 {len(record["ports"])} 个端口',
                    'ports_scanned': len(record['ports']),
                    'scan_type': 'SYN'
                }
                alerts.append(alert)
                record['ports'].clear()
                record['count'] = 0

        # TCP ACK 扫描检测
        elif packet_info.get('protocol') == 'TCP' and packet_info.get('tcp_flags') == 'A':
            record = self.tcp_scan_records[src_ip]
            if timestamp - record['last_time'] > self.time_window:
                record['ports'].clear()
                record['count'] = 0
            record['ports'].add(packet_info.get('dst_port'))
            record['last_time'] = timestamp
            record['count'] += 1
            
            if len(record['ports']) > self.tcp_threshold:
                alert = {
                    'type': 'Port Scan',
                    'severity': 'High',
                    'source_ip': src_ip,
                    'destination_ip': packet_info.get('dst_ip'),
                    'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                    'details': f'检测到来自 {src_ip} 的 TCP 扫描，{self.time_window} 秒内访问了 {len(record["ports"])} 个端口',
                    'ports_scanned': len(record['ports']),
                    'scan_type': 'TCP'
                }
                alerts.append(alert)
                record['ports'].clear()
                record['count'] = 0

        # UDP包记录
        elif packet_info.get('protocol') == 'UDP':
            dst_port = packet_info.get('dst_port')
            if dst_port:
                record = self.udp_scan_records[src_ip]
                record['udp_packets'].append(timestamp)
                record['ports'].add(dst_port)
                record['last_time'] = timestamp
                record['udp_count'] += 1
                # print(f"[DEBUG][UDP记录] 添加UDP记录: IP={src_ip}, Port={dst_port}, "
                #       f"当前不同端口数={len(record['ports'])}")

        # --- UDP 扫描检测阶段 ---
        elif packet_info.get('protocol') == 'ICMP' and packet_info.get('icmp_type') == 3:
            try:
                # print("[DEBUG] ========== ICMP包开始分析 ==========")
                packet = packet_info.get('raw_packet')
                # print("[DEBUG] raw_packet 是否存在:", bool(packet))
                # if packet and packet.haslayer(ICMP):
                #     print("[DEBUG] ICMP Payload 长度:", len(bytes(packet[ICMP].payload)))

                if not packet or not packet.haslayer(ICMP):
                    return None

                inner_payload = bytes(packet[ICMP].payload)
                # if len(inner_payload) < 28:
                #     print("[DEBUG][ICMP] Payload 长度不足，跳过")
                #     return None

                # 提取封装的原始 IP 和端口
                inner_src_ip = socket.inet_ntoa(inner_payload[12:16])
                inner_dport = int.from_bytes(inner_payload[22:24], 'big')

                # print(f"[DEBUG][ICMP] ICMP响应封装信息: 源IP={inner_src_ip}, 目标端口={inner_dport}")

                record = self.udp_scan_records.get(inner_src_ip)
                if not record:
                    # print(f"[DEBUG][ICMP] 未找到 inner_src_ip={inner_src_ip} 对应的UDP记录")
                    return None
                # print(f"[DEBUG] 当前udp_scan_records中的IP有: {list(self.udp_scan_records.keys())}")

                if record:
                    record['icmp_unreachable'] += 1
                    record['unreachable_ports'].add(inner_dport)

                    # 清理过期的UDP包记录
                    recent_packets = [t for t in record['udp_packets'] if timestamp - t <= self.time_window]
                    record['udp_packets'] = recent_packets
                    
                    udp_packet_count = len(recent_packets)
                    unique_ports = len(record['ports'])
                    unreachable_ports = len(record['unreachable_ports'])
                    unreachable_ratio = unreachable_ports / unique_ports if unique_ports else 0

                    # print(f"[DEBUG][UDP分析] IP={inner_src_ip}")
                    # print(f" - UDP包数: {udp_packet_count}")
                    # print(f" - 不同端口数: {unique_ports}")
                    # print(f" - 不可达端口数: {unreachable_ports}")
                    # print(f" - 不可达比例: {unreachable_ratio:.2f}")

                    if (
                            unique_ports >= self.udp_scan_min_ports and
                            udp_packet_count <= self.udp_scan_max_packets and
                            unreachable_ratio >= self.udp_scan_min_unreachable_ratio
                    ):
                        # print(f"[DEBUG] unique_ports={unique_ports}, udp_packet_count={udp_packet_count}, "
                        #       f"unreachable_ratio={unreachable_ratio:.2f}")
                        # print(f"[DEBUG] thresholds: min_ports={self.udp_scan_min_ports}, "
                        #       f"max_packets={self.udp_scan_max_packets}, min_unreachable_ratio={self.udp_scan_min_unreachable_ratio}")
                        #
                        # print("[ALERT][UDP Scan] 满足条件，触发UDP扫描告警！")

                        alert = {
                            'type': 'Port Scan',
                            'severity': 'High',
                            'source_ip': inner_src_ip,
                            'destination_ip': packet_info.get('dst_ip'),
                            'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                            'details': (
                                f'检测到来自 {inner_src_ip} 的UDP扫描，'
                                f'{self.time_window}秒内扫描了 {unique_ports} 个端口，'
                                f'不可达端口: {unreachable_ports}个，'
                                f'不可达比例: {unreachable_ratio:.2f}'
                            ),
                            'scan_type': 'UDP',
                            'ports_scanned': unique_ports,
                            'unreachable_ports': unreachable_ports,
                            'unreachable_ratio': unreachable_ratio
                        }

                        alerts.append(alert)

                        # 重置记录避免重复告警
                        record['udp_packets'] = []
                        record['icmp_unreachable'] = 0
                        record['ports'].clear()
                        record['udp_count'] = 0
                        record['unreachable_ports'].clear()
                    # else:
                    #     print("[DEBUG] 未触发UDP扫描告警，原因如下:")
                    #     if unique_ports < self.udp_scan_min_ports:
                    #         print(f" - 探测端口数不足: {unique_ports} < {self.udp_scan_min_ports}")
                    #     if udp_packet_count > self.udp_scan_max_packets:
                    #         print(f" - UDP包数过多: {udp_packet_count} > {self.udp_scan_max_packets}")
                    #     if unreachable_ratio < self.udp_scan_min_unreachable_ratio:
                    #         print(f" - 不可达比例太低: {unreachable_ratio:.2f} < {self.udp_scan_min_unreachable_ratio}")

            except Exception as e:
                print("[ERROR] UDP扫描ICMP处理失败:", e)

        # 发送告警
        for alert in alerts:
            if self.alert_callback:
                self.alert_callback(alert)

        return alerts[0] if alerts else None


class SQLInjectionDetector:
    """SQL注入攻击检测器"""

    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        # SQL注入特征模式
        self.sql_patterns = [
            r"(?i)(select|union|insert|update|delete|drop|exec|alter|create|truncate)",
            r"(?i)('|%27)\s*or\s*('|%27)\s*=\s*('|%27)",  # ' OR '1'='1
            r"(?i)union\s+select",
            r"(?i)exec\s+xp_",
            r"(?i)(--|#|\/\*)",
            r"(?i)(or|and)\s+\d+\s*=\s*\d+",
            r"(?i)(waitfor|delay)\s+",
            r"(?i)(benchmark|sleep)\s*\(",
            r"(?i)(load_file|into\s+file|into\s+outfile)",
            r"(?i)(information_schema|sys\.)",
            r"(?i)(@@version|version\(\))",
            r"(?i)(char|ascii|hex|bin|oct)\s*\(",
            r"(?i)(concat|group_concat)\s*\(",
            r"(?i)(substring|substr|mid)\s*\(",
            r"(?i)(if|case)\s+.*\s+then",
        ]
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_patterns]

    def detect(self, packet_info):
        """检测SQL注入攻击"""
        if not packet_info.get('http_payload'):
            return None

        payload = packet_info['http_payload']

        if not ('GET ' in payload or 'POST ' in payload):
            return None

        try:
            parts = payload.split('\r\n\r\n')
            headers = parts[0]
            body = parts[1] if len(parts) > 1 else ''

            # 提取并安全解析请求行（避免注入导致 split 错位）
            request_line = headers.split('\r\n')[0]
            method, uri, version = '', '', ''
            if request_line.startswith('GET') or request_line.startswith('POST'):
                match = re.match(r'^(GET|POST) (.+?) HTTP/[\d\.]+$', request_line)
                if match:
                    method, uri = match.group(1), match.group(2)

            decoded_uri = unquote(uri)
            decoded_body = unquote(body)
            #
            # print("[DEBUG] SQL检测器原始请求行:", request_line)
            # print("[DEBUG] SQL检测器 URI:", decoded_uri)
            # print("[DEBUG] SQL检测器 Body:", decoded_body)

            # 检查URL参数（GET）
            if '?' in decoded_uri and self._check_sql_injection(decoded_uri):
                return self._create_alert(packet_info, 'URL参数', decoded_uri)

            # 检查POST正文
            if method == 'POST' and decoded_body and self._check_sql_injection(decoded_body):
                return self._create_alert(packet_info, 'POST数据', decoded_body)

        except Exception as e:
            # print("[ERROR] SQL注入检测异常:", e)
            return None

    def _check_sql_injection(self, content):
        """检查内容是否包含SQL注入特征"""
        for pattern in self.compiled_patterns:
            if pattern.search(content):
                # print("[DETECTED] 命中SQL注入规则:", pattern.pattern)
                return True
        return False

    def _create_alert(self, packet_info, location, payload):
        """创建SQL注入告警"""
        alert = {
            'type': 'SQL Injection',
            'severity': 'High',
            'source_ip': packet_info.get('src_ip'),
            'destination_ip': packet_info.get('dst_ip'),
            'timestamp': datetime.fromtimestamp(packet_info['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
            'details': f"检测到SQL注入攻击尝试，位置: {location}，URI: {packet_info.get('http_uri', '未知')}",
            'payload': payload[:200] + '...' if len(payload) > 200 else payload,
            'attack_type': 'SQLi'
        }

        if self.alert_callback:
            self.alert_callback(alert)

        return alert


class XSSDetector:
    """XSS攻击检测器"""
    
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        # XSS攻击特征模式
        self.xss_patterns = [
            # 基本脚本标签
            r"<script[^>]*>.*?</script>",  # 基本脚本标签
            r"<script[^>]*>[^<]*</script>",  # 脚本标签（非贪婪匹配）
            
            # JavaScript协议
            r"javascript:[^\s]+",  # javascript:协议
            
            # 事件处理器
            r"<[^>]*on(click|load|mouseover|error|focus|blur|mouseout|keypress|keydown|keyup)[^>]*>",  # 各种on*事件
            
            # 危险标签
            r"<iframe[^>]*src=[^>]*>",  # iframe标签
            r"<object[^>]*>[^<]*</object>",  # object标签
            r"<embed[^>]*>[^<]*</embed>",  # embed标签
            r"<svg[^>]*onload=[^>]*>",  # SVG onload事件
            
            # JavaScript函数
            r"alert\s*\([^)]*\)",  # alert()函数
            r"eval\s*\([^)]*\)",  # eval()函数
            r"document\.cookie",  # document.cookie
            r"document\.location",  # document.location
            r"document\.write",  # document.write
            r"document\.URL",  # document.URL
            r"localStorage",  # localStorage
            r"sessionStorage",  # sessionStorage
            r"new\s+Function\s*\(",  # new Function()
            r"setTimeout\s*\(",  # setTimeout()
            r"setInterval\s*\(",  # setInterval()
            r"fetch\s*\(",  # fetch()
            r"XMLHttpRequest",  # XMLHttpRequest
            r"Promise\s*\(",  # Promise()
            
            # 编码变体
            r"\\x[0-9a-fA-F]{2}",  # 十六进制编码
            r"\\u[0-9a-fA-F]{4}",  # Unicode编码
            r"&#x[0-9a-fA-F]+;",  # HTML十六进制实体
            r"&#\d+;",  # HTML十进制实体
            r"%[0-9a-fA-F]{2}",  # URL编码
        ]
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.xss_patterns]
    
    def detect(self, packet_info):
        """检测XSS攻击"""
        if not packet_info.get('http_payload'):
            return None
            
        payload_str = packet_info.get('http_payload', '')
        
        # 检查是否是HTTP请求
        if not ('GET ' in payload_str or 'POST ' in payload_str):
            return None
            
        try:
            # 分离请求行和请求体
            parts = payload_str.split('\r\n\r\n')
            headers = parts[0]
            body = parts[1] if len(parts) > 1 else ''
            
            # 提取请求行
            request_line = headers.split('\r\n')[0]
            if ' ' in request_line:
                method, uri, *_ = request_line.split(' ')
                
                # 检查URL中的参数
                if '?' in uri:
                    query_string = uri.split('?')[1]
                    if self._check_xss(query_string):
                        return self._create_alert(packet_info, 'URL参数', query_string)
                
                # 检查POST数据
                if method == 'POST' and body:
                    if self._check_xss(body):
                        return self._create_alert(packet_info, 'POST数据', body)
        except Exception:
            return None

    def _check_xss(self, content):
        """检查内容是否包含XSS特征"""
        for pattern in self.compiled_patterns:
            if pattern.search(content):
                return True
        return False

    def _create_alert(self, packet_info, location, payload):
        """创建XSS攻击告警"""
        alert = {
            'type': 'XSS Attack',
            'severity': 'High',
            'source_ip': packet_info.get('src_ip'),
            'destination_ip': packet_info.get('dst_ip'),
            'timestamp': datetime.fromtimestamp(packet_info['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
            'details': f"检测到XSS攻击尝试，来自 {packet_info.get('src_ip')} 到 {packet_info.get('http_uri', 'unknown URI')}，位置: {location}",
            'payload': payload[:200] + '...' if len(payload) > 200 else payload,
            'attack_type': 'XSS'
        }
        
        if self.alert_callback:
            self.alert_callback(alert)
            
        return alert


class DoSDetector:
    """DoS攻击检测器"""

    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.syn_flood_records = defaultdict(lambda: deque(maxlen=1000))
        self.icmp_flood_records = defaultdict(lambda: deque(maxlen=1000))
        self.udp_flood_records = defaultdict(lambda: deque(maxlen=1000))
        # 调整阈值到更合理的值
        self.time_window = 1       # 1秒时间窗口
        self.syn_threshold = 200   # 每秒200个SYN包
        self.icmp_threshold = 30   # 每秒30个ICMP包
        self.udp_threshold = 200    # 每秒200个UDP包

    def detect(self, packet_info):
        """检测DoS攻击"""
        if not packet_info.get('src_ip'):
            return None

        src_ip = packet_info['src_ip']
        timestamp = packet_info['timestamp']
        alerts = []

        # 检测SYN Flood
        if packet_info.get('protocol') == 'TCP' and packet_info.get('tcp_flags') == 'S':
            self.syn_flood_records[src_ip].append(timestamp)
            
            # 计算时间窗口内的包数
            recent_packets = [t for t in self.syn_flood_records[src_ip]
                            if timestamp - t <= self.time_window]
            
            syn_rate = len(recent_packets) / self.time_window

            if syn_rate > self.syn_threshold:
                alert = {
                    'type': 'DoS Attack',
                    'severity': 'Critical',
                    'source_ip': src_ip,
                    'destination_ip': packet_info.get('dst_ip'),
                    'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                    'details': f'检测到来自 {src_ip} 的SYN Flood攻击，速率: {syn_rate:.2f} 包/秒',
                    'packet_rate': round(syn_rate, 2),
                    'attack_type': 'SYN'
                }
                alerts.append(alert)

        # 检测ICMP Flood
        elif packet_info.get('protocol') == 'ICMP':
            icmp_type = packet_info.get('icmp_type')
            # print(f"[DEBUG] ICMP包类型: {icmp_type} 来自 {src_ip}")

            if icmp_type == 8:  # Echo Request
                self.icmp_flood_records[src_ip].append(timestamp)
                recent_packets = [t for t in self.icmp_flood_records[src_ip] if timestamp - t <= self.time_window]
                icmp_rate = len(recent_packets) / self.time_window
                # print(f"[DEBUG] ICMP速率: {icmp_rate:.2f} 包/秒 来自 {src_ip}")

                if icmp_rate > self.icmp_threshold:
                    # print(f"[DETECTED] ICMP Flood: {icmp_rate:.2f} 包/秒 来自 {src_ip}")
                    alert = {
                        'type': 'DoS Attack',
                        'severity': 'Critical',
                        'source_ip': src_ip,
                        'destination_ip': packet_info.get('dst_ip'),
                        'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                        'details': f'检测到来自 {src_ip} 的ICMP Flood攻击，速率: {icmp_rate:.2f} 包/秒',
                        'packet_rate': round(icmp_rate, 2),
                        'attack_type': 'ICMP'
                    }
                    alerts.append(alert)

        # 检测UDP Flood
        elif packet_info.get('protocol') == 'UDP':
            self.udp_flood_records[src_ip].append(timestamp)
            
            # 计算时间窗口内的包数
            recent_packets = [t for t in self.udp_flood_records[src_ip]
                            if timestamp - t <= self.time_window]
            
            udp_rate = len(recent_packets) / self.time_window
            
            if udp_rate > self.udp_threshold:
                alert = {
                    'type': 'DoS Attack',
                    'severity': 'Critical',
                    'source_ip': src_ip,
                    'destination_ip': packet_info.get('dst_ip'),
                    'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                    'details': f'检测到来自 {src_ip} 的UDP Flood攻击，速率: {udp_rate:.2f} 包/秒',
                    'packet_rate': round(udp_rate, 2),
                    'attack_type': 'UDP'
                }
                alerts.append(alert)

        # 发送告警
        for alert in alerts:
            if self.alert_callback:
                self.alert_callback(alert)

        return alerts[0] if alerts else None


class PacketFilter:
    """数据包过滤模块"""

    def __init__(self):
        self.filters = {
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None
        }

    def set_filter(self, **kwargs):
        """设置过滤条件"""
        for key, value in kwargs.items():
            if key in self.filters:
                self.filters[key] = value

    def clear_filters(self):
        """清除所有过滤条件"""
        for key in self.filters:
            self.filters[key] = None

    def match(self, packet_info):
        """检查数据包是否匹配过滤条件"""
        for key, filter_value in self.filters.items():
            if filter_value is None:
                continue

            packet_value = packet_info.get(key)
            if packet_value is None:
                continue

            # 支持字符串匹配和端口范围匹配
            if isinstance(filter_value, str):
                if str(packet_value) != filter_value:
                    return False
            else:
                if packet_value != filter_value:
                    return False

        return True


class AlertManager:
    """告警和日志模块"""

    def __init__(self, gui_callback=None):
        self.gui_callback = gui_callback
        self.alerts = []
        self.log_file = "ids_alerts.log"
        # 用于存储最近告警的哈希值
        self.recent_alert_hashes = {}
        # 告警去重时间窗口（秒）
        self.dedup_window = 5

    def _get_alert_hash(self, alert):
        """生成告警的唯一哈希值"""
        try:
            # 提取时间戳的秒级部分
            timestamp = datetime.strptime(alert['timestamp'], '%Y-%m-%d %H:%M:%S')
            second_ts = int(timestamp.timestamp())
            
            # 构建用于哈希的关键字段元组
            hash_tuple = (
                alert.get('source_ip', ''),
                alert['type'],
                second_ts
            )
            return hash(hash_tuple)
        except Exception as e:
            print(f"生成告警哈希值时出错: {e}")
            # 如果出错，返回一个唯一的哈希值，确保告警不会被漏掉
            return hash(str(alert) + str(time.time()))

    def _is_duplicate(self, alert):
        """检查是否是重复告警"""
        current_time = time.time()
        alert_hash = self._get_alert_hash(alert)
        
        # 清理过期的哈希值
        self.recent_alert_hashes = {
            h: t for h, t in self.recent_alert_hashes.items()
            if current_time - t <= self.dedup_window
        }
        
        # 检查是否在最近的时间窗口内有相同的告警
        if alert_hash in self.recent_alert_hashes:
            return True
            
        # 记录新的告警哈希值
        self.recent_alert_hashes[alert_hash] = current_time
        return False

    def add_alert(self, alert):
        """添加告警（带去重）"""
        # 检查是否是重复告警
        if self._is_duplicate(alert):
            return False

        self.alerts.append(alert)
        self._log_alert(alert)

        if self.gui_callback:
            self.gui_callback(alert)
            
        return True

    def _log_alert(self, alert):
        """记录告警到日志文件"""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                log_entry = f"[{alert['timestamp']}] {alert['type']} - {alert.get('details', alert.get('description', 'No details'))}\n"
                f.write(log_entry)
        except Exception as e:
            print(f"写入日志文件错误: {e}")

    def get_alerts(self):
        """获取所有告警"""
        return self.alerts.copy()

    def clear_alerts(self):
        """清除告警"""
        self.alerts.clear()
        self.recent_alert_hashes.clear()


class IDSMainWindow:
    """主界面GUI模块"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("入侵检测系统 (IDS)")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)

        # 配置初始化
        self.config = DEFAULT_CONFIG.copy()
        
        # 数据包处理队列
        self.packet_queue = queue.Queue()

        # 核心组件初始化
        self.packet_capture = PacketCapture(self._packet_received)
        self.packet_processor = PacketProcessor(self.packet_queue, self._process_packet)
        self.packet_analyzer = PacketAnalyzer()
        self.attack_detector = AttackDetector(self._on_alert, self.config['thresholds'])
        self.packet_filter = PacketFilter()
        self.alert_manager = AlertManager(self._show_alert)

        # 数据存储
        self.packet_list = []
        self.is_monitoring = False
        
        # 攻击统计
        self.attack_stats = {
            'Port Scan': {'count': 0, 'last_time': None, 'sources': defaultdict(int)},
            'SQL Injection': {'count': 0, 'last_time': None, 'sources': defaultdict(int)},
            'XSS Attack': {'count': 0, 'last_time': None, 'sources': defaultdict(int)},
            'DoS Attack': {'count': 0, 'last_time': None, 'sources': defaultdict(int)}
        }
        
        # 攻击颜色映射
        self.attack_colors = {
            'Port Scan': '#FF6B6B',      # 红色
            'SQL Injection': '#4ECDC4',   # 青色
            'XSS Attack': '#45B7D1',      # 蓝色
            'DoS Attack': '#96CEB4',      # 绿色
        }
        
        # 限速控制
        self.rate_limit = self.config['rate_limit']
        self.packet_count = 0
        self.last_reset = time.time()

        self._create_widgets()
        self._create_menu()
        
        # 启动处理线程
        self.packet_processor.start()

    def _create_menu(self):
        """创建菜单栏"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="保存PCAP", command=self._save_pcap)
        file_menu.add_command(label="加载PCAP", command=self._load_pcap)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit)

    def _create_widgets(self):
        """创建界面组件"""
        # 创建主要的框架
        self._create_control_frame()
        self._create_notebook()
        self._create_status_frame()

    def _create_control_frame(self):
        """创建控制面板"""
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # 抓包控制
        ttk.Label(control_frame, text="网络接口:").pack(side=tk.LEFT)
        self.interface_var = tk.StringVar(value="lo")  # 默认使用lo接口
        interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var,
                                       values=get_interfaces(), width=10)
        interface_combo.pack(side=tk.LEFT, padx=(5, 10))

        # 过滤器
        ttk.Label(control_frame, text="过滤器:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var, width=20)
        filter_entry.pack(side=tk.LEFT, padx=(5, 10))

        # 控制按钮
        self.start_btn = ttk.Button(control_frame, text="开始监控", command=self._start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.pause_btn = ttk.Button(control_frame, text="暂停处理", command=self._pause_monitoring, state=tk.DISABLED)
        self.pause_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="停止监控", command=self._stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(control_frame, text="清除数据", command=self._clear_data).pack(side=tk.LEFT, padx=5)

    def _create_notebook(self):
        """创建标签页"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 数据包列表页
        self._create_packet_tab()

        # 统计分析页
        self._create_stats_tab()

        # 告警页
        self._create_alert_tab()

        # 过滤器页
        self._create_filter_tab()
        
        # 攻击统计页
        self._create_attack_stats_tab()
        
        # 高级设置页
        self._create_settings_tab()

    def _create_packet_tab(self):
        """创建数据包列表页"""
        packet_frame = ttk.Frame(self.notebook)
        self.notebook.add(packet_frame, text="数据包")

        # 创建表格
        columns = ("时间", "源IP", "目标IP", "协议", "源端口", "目标端口", "长度")
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show="headings", height=20)

        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=100)

        # 绑定双击事件
        self.packet_tree.bind('<Double-1>', self._show_packet_details)

        # 滚动条
        v_scrollbar = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=v_scrollbar.set)

        h_scrollbar = ttk.Scrollbar(packet_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.packet_tree.configure(xscrollcommand=h_scrollbar.set)

        # 布局
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")

        packet_frame.grid_rowconfigure(0, weight=1)
        packet_frame.grid_columnconfigure(0, weight=1)

    def _show_packet_details(self, event):
        """显示数据包详情"""
        item = self.packet_tree.selection()[0]
        values = self.packet_tree.item(item)['values']
        
        # 获取对应的完整数据包信息
        packet_time = datetime.strptime(values[0], '%H:%M:%S').time()
        packet_info = None
        
        # 查找匹配的数据包
        for p in self.packet_list:
            p_time = datetime.fromtimestamp(p['timestamp']).time()
            if (p_time == packet_time and 
                p.get('src_ip') == values[1] and 
                p.get('dst_ip') == values[2]):
                packet_info = p
                break
        
        if not packet_info:
            return
            
        # 创建详情窗口
        detail_window = tk.Toplevel(self.root)
        detail_window.title("数据包详情")
        detail_window.geometry("600x400")
        
        # 创建文本区域
        detail_text = scrolledtext.ScrolledText(detail_window, wrap=tk.WORD)
        detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 格式化详情信息
        details = f"""=== 基本信息 ===
时间: {datetime.fromtimestamp(packet_info['timestamp']).strftime('%Y-%m-%d %H:%M:%S.%f')}
协议: {packet_info.get('protocol', 'Unknown')}
长度: {packet_info.get('length', 'Unknown')} bytes

=== IP信息 ===
源IP: {packet_info.get('src_ip', 'Unknown')}
目标IP: {packet_info.get('dst_ip', 'Unknown')}

=== 端口信息 ===
源端口: {packet_info.get('src_port', 'Unknown')}
目标端口: {packet_info.get('dst_port', 'Unknown')}
"""
        
        # 添加TCP标志信息
        if packet_info.get('tcp_flags'):
            details += f"\n=== TCP标志 ===\n{packet_info['tcp_flags']}"
            
        # 添加HTTP信息
        if packet_info.get('http_payload'):
            details += f"\n=== HTTP信息 ===\nURI: {packet_info.get('http_uri', 'Unknown')}\n"
            details += "\n=== HTTP Payload ===\n{}\n".format(packet_info['http_payload'])
            
        # 添加ICMP信息
        if packet_info.get('icmp_type') is not None:
            details += f"\n=== ICMP信息 ===\nType: {packet_info['icmp_type']}"
            
        detail_text.insert(tk.END, details)
        detail_text.configure(state='disabled')  # 设置为只读
        
        # 添加关闭按钮
        ttk.Button(detail_window, text="关闭", command=detail_window.destroy).pack(pady=5)

    def _create_stats_tab(self):
        """创建统计分析页"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="统计分析")

        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=20)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 刷新按钮
        ttk.Button(stats_frame, text="刷新统计", command=self._update_stats).pack(pady=5)

    def _create_alert_tab(self):
        """创建告警页"""
        alert_frame = ttk.Frame(self.notebook)
        self.notebook.add(alert_frame, text="安全告警")

        # 过滤控制
        filter_frame = ttk.Frame(alert_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="告警类型:").pack(side=tk.LEFT)
        self.alert_type_var = tk.StringVar(value="全部")
        alert_types = ["全部", "Port Scan", "SQL Injection", "XSS Attack", "DoS Attack"]
        alert_type_combo = ttk.Combobox(filter_frame, textvariable=self.alert_type_var,
                                      values=alert_types, width=15)
        alert_type_combo.pack(side=tk.LEFT, padx=5)
        
        # 绑定选择事件
        alert_type_combo.bind('<<ComboboxSelected>>', self._filter_alerts)

        # 告警列表
        columns = ("时间", "类型", "严重程度", "源IP", "描述")
        self.alert_tree = ttk.Treeview(alert_frame, columns=columns, show="headings", height=15)

        for col in columns:
            self.alert_tree.heading(col, text=col)
            self.alert_tree.column(col, width=120)

        # 设置告警颜色样式
        style = ttk.Style()
        for attack_type, color in self.attack_colors.items():
            style.configure(f"{attack_type}.Treeview.Item", foreground=color)
            self.alert_tree.tag_configure(attack_type, foreground=color)

        alert_scrollbar = ttk.Scrollbar(alert_frame, orient=tk.VERTICAL, command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=alert_scrollbar.set)

        self.alert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        alert_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 清除告警按钮
        ttk.Button(alert_frame, text="清除告警", command=self._clear_alerts).pack(pady=5)

    def _filter_alerts(self, event=None):
        """过滤告警"""
        selected_type = self.alert_type_var.get()
        
        # 清空当前显示
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)
            
        # 重新添加匹配的告警
        for alert in self.alert_manager.get_alerts():
            if selected_type == "全部" or alert['type'] == selected_type:
                values = (
                    alert['timestamp'],
                    alert['type'],
                    alert['severity'],
                    alert.get('source_ip', ''),
                    alert.get('details', alert.get('description', 'No details'))
                )
                item = self.alert_tree.insert('', 0, values=values)
                if alert['type'] in self.attack_colors:
                    self.alert_tree.item(item, tags=(alert['type'],))

    def _create_filter_tab(self):
        """创建过滤器配置页"""
        filter_frame = ttk.Frame(self.notebook)
        self.notebook.add(filter_frame, text="过滤器")

        # 过滤器设置
        settings_frame = ttk.LabelFrame(filter_frame, text="过滤设置")
        settings_frame.pack(fill=tk.X, padx=5, pady=5)

        # 源IP过滤
        ttk.Label(settings_frame, text="源IP:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.src_ip_var = tk.StringVar()
        ttk.Entry(settings_frame, textvariable=self.src_ip_var).grid(row=0, column=1, padx=5, pady=2)

        # 目标IP过滤
        ttk.Label(settings_frame, text="目标IP:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.dst_ip_var = tk.StringVar()
        ttk.Entry(settings_frame, textvariable=self.dst_ip_var).grid(row=1, column=1, padx=5, pady=2)

        # 协议过滤
        ttk.Label(settings_frame, text="协议:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.protocol_var = tk.StringVar()
        protocol_combo = ttk.Combobox(settings_frame, textvariable=self.protocol_var,
                                      values=["", "TCP", "UDP", "ICMP"])
        protocol_combo.grid(row=2, column=1, padx=5, pady=2)

        # 端口过滤
        ttk.Label(settings_frame, text="目标端口:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.dst_port_var = tk.StringVar()
        ttk.Entry(settings_frame, textvariable=self.dst_port_var).grid(row=3, column=1, padx=5, pady=2)

        # 按钮
        button_frame = ttk.Frame(settings_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="应用过滤", command=self._apply_filter).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="清除过滤", command=self._clear_filter).pack(side=tk.LEFT, padx=5)

    def _create_attack_stats_tab(self):
        """创建攻击统计页"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="攻击统计")

        # 创建左右分栏
        left_frame = ttk.Frame(stats_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        right_frame = ttk.Frame(stats_frame)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 攻击类型统计表格
        columns = ("攻击类型", "总次数", "最后发生时间", "主要来源IP")
        self.attack_stats_tree = ttk.Treeview(left_frame, columns=columns, show="headings", height=10)
        
        for col in columns:
            self.attack_stats_tree.heading(col, text=col)
            self.attack_stats_tree.column(col, width=120)

        # 设置标签样式
        style = ttk.Style()
        for attack_type, color in self.attack_colors.items():
            style.configure(f"{attack_type}.Treeview.Item", foreground=color)

        self.attack_stats_tree.pack(fill=tk.BOTH, expand=True)

        # 图表区域（使用Text小部件模拟，实际项目中可以使用matplotlib）
        self.stats_chart = tk.Text(right_frame, height=20, width=50)
        self.stats_chart.pack(fill=tk.BOTH, expand=True)

        # 刷新按钮
        ttk.Button(stats_frame, text="刷新统计", command=self._update_attack_stats).pack(pady=5)

    def _create_settings_tab(self):
        """创建高级设置页"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="高级设置")

        # 端口扫描设置
        ps_frame = ttk.LabelFrame(settings_frame, text="端口扫描检测设置")
        ps_frame.pack(fill=tk.X, padx=5, pady=5)

        # SYN扫描阈值
        ttk.Label(ps_frame, text="SYN扫描阈值:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.syn_threshold_var = tk.StringVar(value=str(self.config['thresholds']['port_scan']['syn_threshold']))
        ttk.Entry(ps_frame, textvariable=self.syn_threshold_var, width=10).grid(row=0, column=1, padx=5, pady=2)

        # TCP扫描阈值
        ttk.Label(ps_frame, text="TCP扫描阈值:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.tcp_threshold_var = tk.StringVar(value=str(self.config['thresholds']['port_scan']['tcp_threshold']))
        ttk.Entry(ps_frame, textvariable=self.tcp_threshold_var, width=10).grid(row=1, column=1, padx=5, pady=2)

        # UDP扫描阈值
        ttk.Label(ps_frame, text="UDP扫描阈值:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.udp_threshold_var = tk.StringVar(value=str(self.config['thresholds']['port_scan']['udp_threshold']))
        ttk.Entry(ps_frame, textvariable=self.udp_threshold_var, width=10).grid(row=2, column=1, padx=5, pady=2)

        # DoS攻击设置
        dos_frame = ttk.LabelFrame(settings_frame, text="DoS攻击检测设置")
        dos_frame.pack(fill=tk.X, padx=5, pady=5)

        # SYN Flood阈值
        ttk.Label(dos_frame, text="SYN Flood阈值:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.syn_flood_threshold_var = tk.StringVar(value=str(self.config['thresholds']['dos']['syn_threshold']))
        ttk.Entry(dos_frame, textvariable=self.syn_flood_threshold_var, width=10).grid(row=0, column=1, padx=5, pady=2)

        # ICMP Flood阈值
        ttk.Label(dos_frame, text="ICMP Flood阈值:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.icmp_threshold_var = tk.StringVar(value=str(self.config['thresholds']['dos']['icmp_threshold']))
        ttk.Entry(dos_frame, textvariable=self.icmp_threshold_var, width=10).grid(row=1, column=1, padx=5, pady=2)

        # UDP Flood阈值
        ttk.Label(dos_frame, text="UDP Flood阈值:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.udp_flood_threshold_var = tk.StringVar(value=str(self.config['thresholds']['dos']['udp_threshold']))
        ttk.Entry(dos_frame, textvariable=self.udp_flood_threshold_var, width=10).grid(row=2, column=1, padx=5, pady=2)

        # 性能设置
        perf_frame = ttk.LabelFrame(settings_frame, text="性能设置")
        perf_frame.pack(fill=tk.X, padx=5, pady=5)

        # 限速设置
        ttk.Label(perf_frame, text="每秒最大处理包数:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.rate_limit_var = tk.StringVar(value=str(self.config['rate_limit']))
        ttk.Entry(perf_frame, textvariable=self.rate_limit_var, width=10).grid(row=0, column=1, padx=5, pady=2)

        # 保存按钮
        ttk.Button(settings_frame, text="保存设置", command=self._save_settings).pack(pady=10)

    def _save_settings(self):
        """保存设置"""
        try:
            # 更新端口扫描设置
            self.config['thresholds']['port_scan']['syn_threshold'] = int(self.syn_threshold_var.get())
            self.config['thresholds']['port_scan']['tcp_threshold'] = int(self.tcp_threshold_var.get())
            self.config['thresholds']['port_scan']['udp_threshold'] = int(self.udp_threshold_var.get())

            # 更新DoS攻击设置
            self.config['thresholds']['dos']['syn_threshold'] = int(self.syn_flood_threshold_var.get())
            self.config['thresholds']['dos']['icmp_threshold'] = int(self.icmp_threshold_var.get())
            self.config['thresholds']['dos']['udp_threshold'] = int(self.udp_flood_threshold_var.get())

            # 更新性能设置
            self.rate_limit = int(self.rate_limit_var.get())
            self.config['rate_limit'] = self.rate_limit

            # 更新检测器配置
            self.attack_detector = AttackDetector(self._on_alert, self.config['thresholds'])

            messagebox.showinfo("成功", "设置已保存")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的数字")

    def _packet_received(self, packet):
        """接收数据包（快速处理）"""
        self.packet_queue.put(packet)

    def _process_packet(self, packet):
        """处理数据包（异步处理）"""
        current_time = time.time()
        
        # 重置计数器
        if current_time - self.last_reset >= 1:
            self.packet_count = 0
            self.last_reset = current_time
        
        # 限速检查
        if self.packet_count >= self.rate_limit:
            return
        
        self.packet_count += 1
        
        packet_info = self.packet_analyzer.analyze_packet(packet)

        # 应用过滤器
        if not self.packet_filter.match(packet_info):
            return

        self.packet_list.append(packet_info)

        # 检测攻击
        self.attack_detector.detect_attack(packet_info, packet)

        # 更新GUI（在主线程中执行）
        self.root.after(0, self._update_packet_display, packet_info)

    def _update_packet_display(self, packet_info):
        """更新数据包显示"""
        timestamp = datetime.fromtimestamp(packet_info['timestamp']).strftime('%H:%M:%S')

        values = (
            timestamp,
            packet_info.get('src_ip', ''),
            packet_info.get('dst_ip', ''),
            packet_info.get('protocol', ''),
            packet_info.get('src_port', ''),
            packet_info.get('dst_port', ''),
            packet_info.get('length', '')
        )

        self.packet_tree.insert('', 0, values=values)

        # 限制显示的数据包数量
        children = self.packet_tree.get_children()
        if len(children) > 1000:
            self.packet_tree.delete(children[-1])

        # 更新计数
        self.packet_count_var.set(f"包数量: {len(self.packet_list)}")

    def _on_alert(self, alert):
        """处理告警"""
        self.alert_manager.add_alert(alert)

    def _show_alert(self, alert):
        """显示告警"""
        self.root.after(0, self._add_alert_to_tree, alert)

        # 在状态栏显示告警信息
        if alert['severity'] in ['High', 'Critical']:
            alert_text = f"告警: {alert['type']} - {alert['details']}"
            self.status_var.set(alert_text)
            self.root.after(5000, lambda: self.status_var.set(''))  # 5秒后清除告警信息
            # 触发图标闪烁
            self._trigger_alert_icon()

    def _add_alert_to_tree(self, alert):
        """添加告警到树形控件"""
        values = (
            alert['timestamp'],
            alert['type'],
            alert['severity'],
            alert.get('source_ip', ''),
            alert.get('details', alert.get('description', 'No details'))
        )
        item = self.alert_tree.insert('', 0, values=values)
        
        # 设置颜色标记
        if alert['type'] in self.attack_colors:
            self.alert_tree.item(item, tags=(alert['type'],))
        
        # 更新攻击统计
        if alert['type'] in self.attack_stats:
            stats = self.attack_stats[alert['type']]
            stats['count'] += 1
            stats['last_time'] = datetime.strptime(alert['timestamp'], '%Y-%m-%d %H:%M:%S')
            if 'source_ip' in alert:
                stats['sources'][alert['source_ip']] += 1
        
        # 更新统计显示
        self._update_attack_stats()

    def _apply_filter(self):
        """应用过滤器"""
        filters = {}

        if self.src_ip_var.get():
            filters['src_ip'] = self.src_ip_var.get()
        if self.dst_ip_var.get():
            filters['dst_ip'] = self.dst_ip_var.get()
        if self.protocol_var.get():
            filters['protocol'] = self.protocol_var.get()
        if self.dst_port_var.get():
            try:
                filters['dst_port'] = int(self.dst_port_var.get())
            except ValueError:
                messagebox.showerror("错误", "端口必须是数字")
                return

        self.packet_filter.set_filter(**filters)
        self._refresh_packet_display()
        messagebox.showinfo("信息", "过滤器已应用")

    def _clear_filter(self):
        """清除过滤器"""
        self.packet_filter.clear_filters()
        self.src_ip_var.set("")
        self.dst_ip_var.set("")
        self.protocol_var.set("")
        self.dst_port_var.set("")
        self._refresh_packet_display()
        messagebox.showinfo("信息", "过滤器已清除")

    def _refresh_packet_display(self):
        """刷新数据包显示"""
        # 清空当前显示
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)

        # 重新添加匹配的数据包
        for packet_info in reversed(self.packet_list[-1000:]):  # 只显示最新的1000个
            if self.packet_filter.match(packet_info):
                self._update_packet_display(packet_info)

    def _update_stats(self):
        """更新统计信息"""
        stats = self.packet_analyzer.get_stats()

        stats_text = f"""=== 网络流量统计 ===
总数据包数: {stats['total_packets']}

=== 协议统计 ===
"""
        for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:10]:
            proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, f'Protocol {proto}')
            stats_text += f"{proto_name}: {count}\n"

        stats_text += f"\n=== 热门源IP TOP 10 ===\n"
        for ip, count in sorted(stats['src_ips'].items(), key=lambda x: x[1], reverse=True)[:10]:
            stats_text += f"{ip}: {count}\n"

        stats_text += f"\n=== 热门目标IP TOP 10 ===\n"
        for ip, count in sorted(stats['dst_ips'].items(), key=lambda x: x[1], reverse=True)[:10]:
            stats_text += f"{ip}: {count}\n"

        stats_text += f"\n=== 热门端口 TOP 10 ===\n"
        for port, count in sorted(stats['ports'].items(), key=lambda x: x[1], reverse=True)[:10]:
            stats_text += f"Port {port}: {count}\n"

        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(1.0, stats_text)

    def _clear_data(self):
        """清除所有数据"""
        self.packet_list.clear()
        self.packet_analyzer.reset_stats()

        # 清空显示
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)

        self.packet_count_var.set("包数量: 0")
        self.stats_text.delete(1.0, tk.END)
        messagebox.showinfo("信息", "数据已清除")

    def _clear_alerts(self):
        """清除告警"""
        self.alert_manager.clear_alerts()
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)
        messagebox.showinfo("信息", "告警已清除")

    def _save_pcap(self):
        """保存PCAP文件"""
        if not self.packet_list:
            messagebox.showwarning("警告", "没有数据包可保存")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )

        if filename:
            # 从内存中的数据包信息重构scapy包（简化版本）
            packets = self.packet_capture.get_packets()
            if packets and PCAPManager.save_packets(packets, filename):
                messagebox.showinfo("成功", f"PCAP文件已保存到: {filename}")
            else:
                messagebox.showerror("错误", "保存PCAP文件失败")

    def _load_pcap(self):
        """加载PCAP文件"""
        filename = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )

        if filename:
            packets = PCAPManager.load_packets(filename)
            if packets:
                self._clear_data()

                # 分析加载的数据包
                for packet in packets:
                    packet_info = self.packet_analyzer.analyze_packet(packet)
                    self.packet_list.append(packet_info)

                    # 检测攻击
                    self.attack_detector.detect_attack(packet_info)

                # 刷新显示
                self._refresh_packet_display()
                self._update_stats()

                messagebox.showinfo("成功", f"已加载 {len(packets)} 个数据包")
            else:
                messagebox.showerror("错误", "加载PCAP文件失败")

    def _update_attack_stats(self):
        """更新攻击统计信息"""
        # 清空现有显示
        for item in self.attack_stats_tree.get_children():
            self.attack_stats_tree.delete(item)

        # 更新统计表格
        for attack_type, stats in self.attack_stats.items():
            # 获取主要来源IP（取前3个）
            top_sources = sorted(stats['sources'].items(), key=lambda x: x[1], reverse=True)[:3]
            sources_str = ", ".join([f"{ip}({count})" for ip, count in top_sources])
            
            last_time = stats['last_time'].strftime('%Y-%m-%d %H:%M:%S') if stats['last_time'] else "无"
            
            values = (
                attack_type,
                stats['count'],
                last_time,
                sources_str
            )
            
            item = self.attack_stats_tree.insert('', 'end', values=values)
            self.attack_stats_tree.item(item, tags=(attack_type,))

        # 更新图表（ASCII艺术图表示例）
        self.stats_chart.delete(1.0, tk.END)
        chart = "攻击趋势统计图\n"
        chart += "==================\n\n"
        
        max_count = max(stats['count'] for stats in self.attack_stats.values())
        if max_count > 0:
            for attack_type, stats in self.attack_stats.items():
                bar_length = int((stats['count'] / max_count) * 40)
                chart += f"{attack_type:.<20} {'█' * bar_length} ({stats['count']})\n"
        
        self.stats_chart.insert(1.0, chart)

    def _create_status_frame(self):
        """创建状态栏"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=5, pady=2)

        # 左侧状态文本
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)

        # 右侧告警图标和包数量
        right_frame = ttk.Frame(status_frame)
        right_frame.pack(side=tk.RIGHT)

        # 告警图标（红点）
        self.alert_canvas = tk.Canvas(right_frame, width=16, height=16, bg=self.root.cget('bg'), highlightthickness=0)
        self.alert_canvas.pack(side=tk.LEFT, padx=(0, 5))
        self.alert_dot = self.alert_canvas.create_oval(4, 4, 12, 12, fill='red', state='hidden')
        
        # 包数量显示
        self.packet_count_var = tk.StringVar(value="包数量: 0")
        ttk.Label(right_frame, textvariable=self.packet_count_var).pack(side=tk.LEFT)
        
        # 告警图标闪烁状态
        self.alert_blinking = False
        self.blink_count = 0

    def _blink_alert_icon(self):
        """闪烁告警图标"""
        if not self.alert_blinking:
            return

        current_state = self.alert_canvas.itemcget(self.alert_dot, 'state')
        new_state = 'hidden' if current_state == 'normal' else 'normal'
        self.alert_canvas.itemconfigure(self.alert_dot, state=new_state)
        
        self.blink_count += 1
        if self.blink_count < 6:  # 闪烁3次（6个状态变化）
            self.root.after(500, self._blink_alert_icon)
        else:
            self.alert_blinking = False
            self.blink_count = 0
            # 保持图标可见
            self.alert_canvas.itemconfigure(self.alert_dot, state='normal')

    def _trigger_alert_icon(self):
        """触发告警图标闪烁"""
        if not self.alert_blinking:
            self.alert_blinking = True
            self.blink_count = 0
            self._blink_alert_icon()

    def _pause_monitoring(self):
        """暂停/恢复数据包处理"""
        if not hasattr(self, 'is_paused'):
            self.is_paused = False
            
        self.is_paused = not self.is_paused
        
        if self.is_paused:
            self.pause_btn.config(text="继续处理")
            self.status_var.set("已暂停处理数据包")
        else:
            self.pause_btn.config(text="暂停处理")
            self.status_var.set(f"正在监控接口: {self.interface_var.get()}")
            
        # 更新处理器状态
        self.packet_processor.is_paused = self.is_paused

    def _start_monitoring(self):
        """开始监控"""
        interface = self.interface_var.get()
        packet_filter = self.filter_var.get()

        # 确保有足够的权限
        if os.geteuid() != 0:
            messagebox.showerror("错误", "需要root权限才能进行抓包，请使用sudo运行程序")
            return

        if self.packet_capture.start_capture(interface, packet_filter):
            self.is_monitoring = True
            self.start_btn.config(state=tk.DISABLED)
            self.pause_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_var.set(f"正在监控接口: {interface}")
            
            # 显示提示信息
            messagebox.showinfo("提示", "开始监控网络流量。\n\n"
                               "提示：\n"
                               "1. 确保选择了正确的网络接口\n"
                               "2. 如果看不到数据包，请检查网络接口是否活跃\n"
                               "3. 可以使用过滤器来过滤特定类型的流量")
        else:
            messagebox.showerror("错误", "无法开始抓包，请检查网络接口和权限")

    def _stop_monitoring(self):
        """停止监控"""
        # 停止抓包线程
        self.packet_capture.stop_capture()
        
        # 更新状态标志和UI
        self.is_monitoring = False
        self.is_paused = False
        self.start_btn.config(state=tk.NORMAL)
        self.pause_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("监控已停止")
        
        # 更新统计信息
        self._update_stats()
        
        # 如果有捕获的数据包，提示用户是否保存
        if len(self.packet_list) > 0:
            if messagebox.askyesno("保存数据", f"已捕获 {len(self.packet_list)} 个数据包，是否保存为PCAP文件？"):
                self._save_pcap()

    def run(self):
        """启动GUI"""
        try:
            self.root.mainloop()
        finally:
            # 确保在关闭时停止处理线程
            if hasattr(self, 'packet_processor'):
                self.packet_processor.stop()


def main():
    """主函数"""
    app = IDSMainWindow()
    app.run()


if __name__ == "__main__":
    main()
