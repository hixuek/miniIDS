# miniIDS
小型入侵检测系统模拟实现

# 网络入侵检测系统 (Network IDS)

一个基于Python的网络入侵检测系统，具有实时流量监控、攻击检测和可视化分析功能。

## 功能特点

### 1. 实时监控
- 支持多种网络接口监控
- 可配置的数据包过滤器
- 实时流量统计和分析
- 支持暂停/继续处理功能

### 2. 攻击检测
- 端口扫描检测（TCP SYN, TCP Connect, UDP）
- SQL注入攻击检测
- XSS攻击检测
- DoS攻击检测（SYN Flood, ICMP Flood, UDP Flood）

### 3. 可视化界面
- 实时数据包列表
- 攻击告警面板
- 流量统计图表
- 高级配置选项
- 告警图标实时提示

### 4. 高级特性
- 告警去重（5秒内相同特征的告警只报一次）
- 数据包详细信息查看
- 告警类型过滤
- 可配置的检测阈值
- PCAP文件导入/导出

## 系统要求

- Python 3.7+
- Linux系统（需要root权限）
- 支持的网络接口

## 安装步骤

1. 克隆仓库：
```bash
git clone https://github.com/hixuek/miniIDS.git
cd miniIDS
```

2. 创建虚拟环境（推荐）：
```bash
python -m venv env
source env/bin/activate  # Linux/Mac
# 或
.\env\Scripts\activate  # Windows
```

3. 安装依赖：
```bash
pip install -r requirements.txt
```

## 使用方法

1. 以root权限运行：
```bash
sudo $(which python) main.py
```

2. 在GUI界面中：
   - 选择要监控的网络接口
   - 设置可选的过滤器
   - 点击"开始监控"
   - 可以随时暂停/继续/停止监控

## 配置说明

### 检测阈值
可在"高级设置"标签页中配置：

1. 端口扫描检测：
   - SYN扫描阈值：25个/10秒
   - TCP扫描阈值：20个/10秒
   - UDP扫描阈值：最少5个不同端口，70%不可达率

2. DoS攻击检测：
   - SYN Flood：200包/秒
   - ICMP Flood：30包/秒
   - UDP Flood：200包/秒

### 性能设置
- 数据包处理速率限制：1000包/秒
- 告警去重时间窗口：5秒

## 项目结构

```
miniIDS/
├── main.py          # 主程序
├── README.md        # 项目文档
├── requirements.txt # 依赖列表
└── ids_alerts.log   # 告警日志
```

## 主要类说明

- `IDSMainWindow`: GUI主窗口
- `PacketCapture`: 数据包捕获
- `PacketAnalyzer`: 数据包分析
- `AttackDetector`: 攻击检测
- `AlertManager`: 告警管理
- `PacketProcessor`: 数据包处理
- `PCAPManager`: PCAP文件管理

## 注意事项

1. 权限要求：
   - 需要root/管理员权限运行
   - 建议在专用的测试/监控环境中使用

2. 性能考虑：
   - 默认限制处理速率为1000包/秒
   - 可根据系统性能调整相关阈值

3. 安全建议：
   - 定期查看告警日志
   - 适时调整检测阈值
   - 注意误报情况

## 许可证


## 作者

[hixuek]

## 更新日志

### v1.0.0 (2025-05)
- 初始版本发布
- 实现基本的攻击检测功能
- 添加GUI界面
- 支持PCAP文件操作 
