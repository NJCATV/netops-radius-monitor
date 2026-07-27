# RADIUS Monitor

RADIUS Monitor 是一个面向 RADIUS 认证流量的实时监控系统。它通过 `tcpdump` 抓取 `udp/1812` 和 `udp/1813` 流量，解析认证与计费报文，写入 MySQL，并通过 Flask Web 页面展示实时统计、拒绝原因、风险账号、NAS 分布和最近认证明细。

## 当前生产部署

- 服务器：`172.25.194.213`
- SSH 端口：`5334`
- 项目目录：`/opt/radius_monitor`
- Web 地址：`http://172.25.194.213:5000`
- 抓包网卡：`eno4`
- 数据库：本机 MySQL，库名 `radius_monitor`
- Web 服务：`radius-web.service`
- 抓包服务：`radius-sniffer.service`

> 不要把服务器登录密码、数据库密码等敏感信息写进 README。生产配置放在服务器的 `/opt/radius_monitor/.env`。

## 功能概览

- 实时抓取 RADIUS Authentication 与 Accounting 报文。
- 解析 `Access-Request`、`Access-Accept`、`Access-Reject`、`Accounting-Request`。
- 认证请求和响应配对后计算认证耗时。
- 提取账号、MAC、NAS 设备 IP、设备标识、可读接入端口、原始 NAS-Port、Framed-IP、拒绝原因等字段。
- 账号字段会保留原始 `User-Name`，并提取 `GDF/GDC` 业务账号用于统计展示。
- 将拒绝原因翻译为中文，并标记风险等级。
- Web 页面每 5 秒自动刷新，无外部 CDN 依赖。
- 支持“多终端风险账号”视图：同一个 `GDF/GDC` 账号在当前时间窗口内出现多个不同 MAC 地址时会被列出。
- 抓包写库 worker 使用批量 `executemany()` 写入，适合较高流量下持续采集。
- 支持 CSV 导出最近认证明细。

## 数据流

```text
镜像口 / RADIUS 流量
        |
        v
tcpdump -i eno4 "udp port 1812 or udp port 1813"
        |
        v
sniffer.py 读取 pcap 流
        |
        v
parser.py 解析 RADIUS 报文并配对请求/响应
        |
        v
db.py 写入 MySQL
        |
        v
web/app.py 提供 API 和页面
        |
        v
浏览器实时看板
```

## 项目结构

```text
.
├── config.py                 # 全局配置：抓包网卡、端口、MySQL、RADIUS 常量
├── parser.py                 # RADIUS 报文解析与请求/响应配对
├── sniffer.py                # tcpdump 管道抓包入口和批量写库 worker
├── db.py                     # MySQL 建表、写入、查询接口
├── init.sql                  # MySQL 初始化 SQL，和 db.py DDL 保持一致
├── web/
│   ├── app.py                # Flask Web/API 服务
│   └── templates/index.html  # 实时监控页面
├── requirements.txt          # Python pip 依赖
├── Dockerfile                # Docker 镜像构建文件
├── docker-compose.yml        # Docker Compose 部署文件
└── deploy.sh                 # 旧版脚本化部署参考
```

## 运行配置

运行时通过环境变量配置。生产环境使用 `/opt/radius_monitor/.env`：

```env
CAPTURE_IFACE=eno4
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_DB=radius_monitor
MYSQL_USER=radius
MYSQL_PASS=********
WEB_PORT=5000
UPDATE_USER_MAC_SUMMARY=0
REPORT_VALID_FROM=
```

常用配置说明：

- `CAPTURE_IFACE`：抓包网卡，生产环境当前是 `eno4`。
- `MYSQL_*`：数据库连接信息。
- `WEB_PORT`：Flask/Gunicorn 内部监听端口，当前是 `5000`。
- `UPDATE_USER_MAC_SUMMARY`：是否在抓包热路径同步维护“多终端风险账号”派生表；高流量生产环境默认关闭。页面仍会展示原有历史汇总，并从有效起点后的认证明细即时计算新增风险账号。
- `REPORT_VALID_FROM`：可选的报表有效起点；设置后统计/分布仅使用该时间之后的明细，适用于排除已知漏采的旧数据。
- RADIUS 抓包端口在 `config.py` 中由 `RADIUS_AUTH_PORT`、`RADIUS_ACCT_PORT` 控制，默认 `1812/1813`。

## 生产运维命令

查看服务状态：

```bash
systemctl status radius-web.service
systemctl status radius-sniffer.service
```

重启服务：

```bash
sudo systemctl restart radius-web.service
sudo systemctl restart radius-sniffer.service
```

查看 Web 日志：

```bash
journalctl -u radius-web.service -f
```

查看抓包日志：

```bash
journalctl -u radius-sniffer.service -f
```

验证健康状态：

```bash
curl http://127.0.0.1:5000/health
curl "http://127.0.0.1:5000/api/stats?hours=1"
```

确认抓包流量：

```bash
sudo tcpdump -i eno4 -n "udp port 1812 or udp port 1813"
```

## API

所有 API 返回统一格式：

```json
{
  "ok": true,
  "data": {}
}
```

常用接口：

- `GET /health`：服务和数据库健康检查。
- `GET /api/stats?hours=24`：总量、通过、拒绝、通过率、平均耗时。
- `GET /api/recent?limit=100`：最近认证明细。
- `GET /api/top-reject?hours=24&limit=20`：拒绝次数最多的账号。
- `GET /api/risk-accounts?hours=24`：高风险账号。
- `GET /api/multi-mac-accounts?hours=24&limit=100&min_mac=2`：同一账号多 MAC 拨号风险账号。
- `GET /api/reason-dist?hours=24`：拒绝原因分布。
- `GET /api/nas-dist?hours=24`：NAS 分布。
- `GET /api/timeline?hours=6&interval=5`：趋势图数据。
- `GET /api/user/<username>?limit=50`：单个账号明细。
- `GET /api/export/csv?limit=1000`：导出 CSV。

## 数据表

核心表：

- `auth_log`：认证明细日志。
- `acct_log`：Accounting 明细日志。
- `user_summary`：账号维度汇总。
- `nas_stats`：NAS 维度汇总。

注意：

- 当前实时页面和 API 以 `auth_log` / `acct_log` 明细表为准。
- 为保证高流量下采集实时性，默认不在抓包热路径更新 `user_summary` / `nas_stats`；如果未来需要离线汇总，可通过定时任务从明细表重算。

- `auth_log.raw_username` 保存 RADIUS 报文里的原始 `User-Name`，`auth_log.username` 保存归一化后的业务账号。
- `nas_ip` 来自 `NAS-IP-Address (Attr 4)`，表示发起请求的 NAS/BRAS 设备地址；“NAS 设备分布”按该地址汇总，并不是端口分布。
- `nas_identifier` 来自 `NAS-Identifier (Attr 32)`，例如设备发送的主机/型号标识。
- `nas_port_id` 来自 `NAS-Port-Id (Attr 87)`，是现场报文中最适合展示的接入路径，例如 `slot=0;subslot=0;port=15;vlanid=2418;vlanid2=2227;`。
- `auth_log.nas_port` 和 `acct_log.nas_port` 保存 `NAS-Port (Attr 5)` 的原始 32 位数值。设备可能将槽位、物理口或 VLAN 编码在此数值中，因此不直接将它解释成物理端口。
- 新增端口字段只对升级后新抓取的记录有效，升级前已经落库的明细没有 `NAS-Port-Id` 可回填。
- 生产环境曾发生写库队列丢弃时，应设置 `REPORT_VALID_FROM` 为修复生效时间，避免将漏采历史用于趋势或分布结论。
- `auth_log.ts` 是主要查询时间字段，相关 API 都按该字段过滤时间范围。

## 本地开发

本地开发需要可用 MySQL，并配置环境变量：

```bash
export CAPTURE_IFACE=eth0
export MYSQL_HOST=127.0.0.1
export MYSQL_PORT=3306
export MYSQL_DB=radius_monitor
export MYSQL_USER=radius
export MYSQL_PASS=********
export WEB_PORT=5000
```

安装依赖：

```bash
python3 -m pip install -r requirements.txt
```

启动 Web：

```bash
cd web
python3 app.py
```

启动抓包：

```bash
sudo -E python3 sniffer.py
```

也可以用 Gunicorn：

```bash
cd web
gunicorn --bind 0.0.0.0:5000 --workers 2 --timeout 60 "app:create_app()"
```

## Docker 部署说明

仓库保留了 `Dockerfile` 和 `docker-compose.yml`，可以作为容器化部署参考。当前生产环境没有使用 Docker，而是使用系统 MySQL + systemd，原因是部署服务器已具备 `tcpdump`，systemd 方式更直接、便于抓包权限和服务日志维护。

如果未来切回 Docker，需要重点检查：

- `docker-compose.yml` 中 Web 对外端口映射。
- `sniffer` 是否使用 `network_mode: host`。
- 容器是否具备 `NET_ADMIN` 和 `NET_RAW`。
- 宿主机 `tcpdump` 路径和动态库挂载是否匹配当前系统。
- MySQL 是使用宿主机还是容器内实例。

## 扩展指南

### 新增 RADIUS 属性

1. 在 `config.py` 中增加属性编号常量。
2. 在 `parser.py` 的 `parse_radius_attributes()` 中补充解码规则。
3. 在 `RadiusStreamParser.feed_packet()` 中把字段加入返回记录。
4. 在 `db.py` 中调整 DDL、INSERT 和查询接口。
5. 同步更新 `init.sql`，保证新环境初始化一致。
6. 如需展示，在 `web/app.py` API 和 `web/templates/index.html` 中增加字段。

### 新增拒绝原因翻译

在 `config.py` 的 `REPLY_MSG_TRANSLATION` 中增加映射：

```python
REPLY_MSG_TRANSLATION = {
    "原始 Reply-Message": ("中文原因", "risk_level"),
}
```

`risk_level` 建议使用：

- `high`
- `medium`
- `low`
- `unknown`

### 新增页面图表或统计项

推荐顺序：

1. 在 `db.py` 增加查询函数。
2. 在 `web/app.py` 增加 API 路由。
3. 在 `web/templates/index.html` 增加页面渲染逻辑。
4. 用 `curl` 先验证 API，再打开页面验证 UI。

### 调整抓包口

修改服务器 `/opt/radius_monitor/.env`：

```env
CAPTURE_IFACE=新网卡名
```

然后重启：

```bash
sudo systemctl restart radius-sniffer.service
```

## 故障排查

页面打不开：

```bash
systemctl status radius-web.service
ss -lntp | grep 5000
curl http://127.0.0.1:5000/health
```

页面有空表：

```bash
systemctl status radius-sniffer.service
journalctl -u radius-sniffer.service -n 100 --no-pager
sudo tcpdump -i eno4 -n "udp port 1812 or udp port 1813"
```

数据库异常：

```bash
systemctl status mysql
mysql -uradius -p -h127.0.0.1 radius_monitor
```

DNS 或 apt 异常：

```bash
resolvectl status eno4
cat /etc/netplan/eno4.yaml
sudo netplan apply
```

## 维护建议

- 生产服务器当前项目目录是 `/opt/radius_monitor`，以后更新代码时优先同步这个目录。
- 修改表结构时同时改 `db.py` 和 `init.sql`。
- 修改解析字段时同步检查 Web API 和页面字段名。
- 建议把服务器时区设置为业务期望时区，例如 `Asia/Shanghai`，避免报表时间和现场认知不一致。
- 不要把 `.env`、数据库密码、服务器密码提交到仓库或写进文档。
