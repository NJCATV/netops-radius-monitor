# RADIUS 实时监控系统 — Agent 操作手册

> 本文件记录 RADIUS 监控项目的背景、目标、技术方案、部署操作步骤，
> 供后续模型（Agent）接手工作时参考。

---

## 一、项目背景

### 1.1 现状

服务器 **172.31.3.117**（Ubuntu 22.04，8C8G，登录凭据：`njcatv / njcatv`）已运行 MRTG 监控部分端口流量，并已使用 Docker 部署了多个业务容器：

```
CONTAINER ID   IMAGE                      PORTS
f59e4a8b3c1e   prom/snmp-exporter:latest  9116/tcp
b5d8c7e2a1f4   prometheus:latest          9090/tcp
c3e1a9d5b7f2   grafana:latest             3000/tcp
8a2c4e6d1b3f   mysql:8.0                  3306/tcp
```

MRTG 监控的原始配置文件位于：
- `/opt/mrtg-2.17.10/etc/mrtg.cfg`
- MRTG 数据输出目录：`/var/www/mrtg/`

### 1.2 目标

在 172.31.3.117 上新建一套**自研 RADIUS 实时监控系统**，技术要求：

| 维度 | 要求 |
|------|------|
| 抓包方式 | 高性能（tcpdump 管道 + 纯 Python 二进制解析，**不用 Scapy**） |
| 数据库 | MySQL（复用现有的 `mysql:8.0` 容器，或新建独立实例） |
| 部署方式 | **Docker Compose**，便于整体移植 |
| 监控范围 | RADIUS 认证报文（UDP 1812/1813），实时入库并 Web 展示 |

---

## 二、技术方案

### 2.1 架构

```
┌─────────────────────────────────────────────────────────┐
│                   物理网络（镜像口）                     │
│           udp/1812 udp/1813 (RADIUS)                    │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│               Docker Compose (172.31.3.117)             │
│                                                        │
│  ┌─────────────┐   ┌──────────────┐   ┌────────────┐  │
│  │  mysql:8.0  │◄──│   sniffer    │   │    web     │  │
│  │  MySQL 8    │   │ (tcpdump管道) │   │  (Flask)   │  │
│  │             │   │ 纯Python解析  │   │  + Gunicorn│  │
│  └─────────────┘   └──────────────┘   └─────┬──────┘  │
│                                              │          │
│                              ┌───────────────┘          │
│                              │  port 5000                │
└──────────────────────────────▼────────────────────────────┘
                               │
                         浏览器访问
                    http://172.31.3.117:5000
```

### 2.2 组件说明

| 组件 | 技术选型 | 说明 |
|------|----------|------|
| **sniffer** | `python:3.11-slim` + tcpdump | tcpdump 以 `-w -` 输出 pcap 二进制流到 stdout，Python 读取流并逐帧解析。无需 Scapy，避免 GIL 限制和第三方依赖问题 |
| **web** | Flask + Gunicorn | 提供 Web 报表页面和 REST API；连接 MySQL 读取认证记录 |
| **mysql** | `mysql:8.0` | 存储 auth_log（原始认证记录）和 user_summary（用户汇总） |

### 2.3 核心模块

| 文件 | 职责 |
|------|------|
| `config.py` | 全局配置：网卡名、MySQL 连接、Web 端口、RADIUS 属性常量、拒绝原因翻译表 |
| `sniffer.py` | 主抓包循环：启动 tcpdump 子进程 → 读取 pcap 流 → 二进制解析 → 异步批量写库 |
| `parser.py` | RADIUS 报文解析：纯 Python 实现，解析 UDP payload 中的 RADIUS 结构体（Code+ID+Length+Auth + TLV 属性），支持 Access-Request/Accept/Reject |
| `db.py` | 数据库操作：连接池管理、建表 SQL、批量写入、单条查询、统计聚合 |
| `web/app.py` | Flask 路由：/（实时报表）、/api/stats、/api/reasons、/api/users |
| `web/templates/index.html` | 深色风格 Web 前端，实时 JS 轮询刷新 |
| `init.sql` | MySQL 初始化：建库、建表、建用户 |
| `docker-compose.yml` | 三服务编排；sniffer 使用 `network_mode: host` + `cap_add: NET_ADMIN/NET_RAW` |
| `Dockerfile` | 多阶段构建：sniffer 阶段（带 tcpdump）、web 阶段（带 gunicorn） |

### 2.4 数据库表设计

```sql
-- auth_log：每条 RADIUS 认证记录
CREATE TABLE auth_log (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    timestamp    DATETIME(3) NOT NULL,
    username     VARCHAR(128) NOT NULL,
    result       ENUM('accept','reject','unknown') NOT NULL,
    reason       VARCHAR(256) DEFAULT NULL,
    reason_level VARCHAR(16)  DEFAULT NULL,
    nas_ip       VARCHAR(45)  DEFAULT NULL,
    framed_ip    VARCHAR(45)  DEFAULT NULL,
    mac          VARCHAR(17)  DEFAULT NULL,
    raw_reply    TEXT          DEFAULT NULL,
    INDEX idx_timestamp (timestamp),
    INDEX idx_username  (username),
    INDEX idx_result    (result)
) ENGINE=InnoDB;

-- user_summary：用户接入汇总（由 web 服务定期刷新）
CREATE TABLE user_summary (
    username      VARCHAR(128) PRIMARY KEY,
    accept_count   INT UNSIGNED DEFAULT 0,
    reject_count   INT UNSIGNED DEFAULT 0,
    total_count    INT UNSIGNED DEFAULT 0,
    accept_rate    DECIMAL(5,2) DEFAULT 0,
    first_seen     DATETIME,
    last_seen      DATETIME,
    last_result    VARCHAR(16),
    updated_at     DATETIME
) ENGINE=InnoDB;
```

### 2.5 抓包解析原理（重点）

**不依赖 Scapy**，核心在 `sniffer.py` 的 `PcapStreamReader`：

1. `subprocess.Popen(['tcpdump', '-i', iface, '-n', '-q', '-s', '65535', '-w', '-', bpf])`
   - `-w -` 让 tcpdump 输出原始 pcap 二进制流到 stdout（而非 human-readable 文本）
2. `PcapStreamReader` 读取 pcap 全局头（24 bytes），识别大小端和纳秒精度，提取 link_type
3. 逐帧读取记录头（16 bytes）→ 获取时间戳和帧长 → 读取帧数据
4. `extract_udp_payload()`：手动解析以太网头（14 bytes，可处理 VLAN tag）→ IP 头（IHL 字段）→ UDP 头（8 bytes）→ payload
5. `parser.py` 解析 RADIUS 结构：`struct.unpack('!BBH16s', header)` 读 Code/ID/Length/Auth，再逐 TLV 读属性

**性能优势**：tcpdump 负责抓包和过滤，Python 只做解析和入库，不存在 Python GIL 瓶颈。

---

## 三、部署操作步骤

> 以下所有 SSH 连接均使用 paramiko（Python），目标服务器 172.31.3.117，凭据 `njcatv / njcatv`。

### 3.1 连接服务器

```python
import paramiko

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('172.31.3.117', username='njcatv', password='njcatv', timeout=15)
```

> ⚠️ Windows PowerShell 执行 Python 时注意编码问题：写入临时 `.py` 脚本文件执行比 `-c` 参数更可靠。

### 3.2 上传项目文件

在本地准备好 `radius_monitor/` 目录后，用 `SFTP` 或 `paramiko` 的 `put` 逐文件上传：

```python
sftp = client.open_sftp()
local_path = 'c:/Users/PC/WorkBuddy/20260514145102/radius_monitor/'
remote_path = '/home/njcatv/radius_monitor/'
sftp.put(local_file, remote_path + filename)  # 逐文件上传
```

### 3.3 在服务器上构建 Docker 镜像并启动

```bash
# 1. 进入项目目录
cd /home/njcatv/radius_monitor

# 2. 指定监听网卡（根据实际网卡名，通常为 eth0 或交换机镜像口对应网卡）
export CAPTURE_IFACE=eth0

# 3. 构建 + 启动（-d 后台运行）
docker compose up -d --build

# 4. 查看容器状态
docker ps | grep radius

# 5. 查看日志确认运行正常
docker logs -f radius_sniffer
docker logs -f radius_web
```

> **关键配置**：sniffer 容器必须使用 `network_mode: host`，否则无法访问物理网卡。
> 抓包网卡的 MAC 地址过滤逻辑在 `parser.py` 中的 `seen_requests` 去重表实现。

### 3.4 验证服务

| 检查项 | 方法 |
|--------|------|
| MySQL 建表成功 | `docker exec radius_mysql mysql -uradius -pradius123 -e "USE radius_monitor; SHOW TABLES;"` |
| sniffer 正在抓包 | `docker logs radius_sniffer` 看是否有 "已解析 N 条认证记录" 日志 |
| Web 服务可访问 | `curl http://localhost:5000/health` 应返回 200 |

---

## 四、现有 MRTG 监控说明（参考）

- MRTG 二进制：`/opt/mrtg-2.17.10/`
- 配置文件：`/opt/mrtg-2.17.10/etc/mrtg.cfg`
- Web 输出：`/var/www/mrtg/`
- MRTG 和自研 RADIUS 监控系统**独立运行，互不影响**

---

## 五、踩坑记录

| 场景 | 问题 | 解决方案 |
|------|------|----------|
| Windows PowerShell 执行含中文输出的 Python | GBK 编码导致 decode 报错 | 用 `sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')` 或直接写入文件 |
| Windows 无 sshpass | 无法免交互 SSH | 使用 Python paramiko 库替代 |
| 抓包网卡选择 | 需要使用物理镜像口而非 Docker 虚拟网卡 | sniffer 容器必须 `network_mode: host` |
| Scapy 在容器中的性能 | GIL 限制 + 第三方依赖 | 改用 tcpdump 管道 + 纯 Python 二进制解析 |

---

## 六、项目文件清单

```
radius_monitor/
├── config.py              # 全局配置
├── db.py                  # MySQL 操作层
├── parser.py              # RADIUS 报文解析
├── sniffer.py             # 抓包入口（主程序）
├── requirements.txt       # Python 依赖
├── init.sql               # MySQL 初始化
├── Dockerfile             # 多阶段镜像构建
├── docker-compose.yml    # 服务编排
├── .env.example           # 环境变量示例
└── web/
    ├── app.py             # Flask 应用
    └── templates/
        └── index.html     # 报表页面
```

---

*最后更新：2026-05-17*
