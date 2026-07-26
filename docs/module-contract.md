# Radius 监控架构与安全边界

## 设计与数据流

213 从镜像接口采集 RADIUS UDP `1812/1813/3799` 报文，解析认证、Accounting 和 CoA/Disconnect 事件。短暂落库失败时使用本机 SQLite spool 重放，最终批量写入 212 ClickHouse 的 Radius 分析表。

## 数据库

| 存储 | 位置 | 用途 |
| --- | --- | --- |
| SQLite spool | 213 本机 | 断链缓冲与重放，不提交 Git |
| ClickHouse | 212 `:8123` | Radius 明细、会话、终端关联和趋势分析 |
| MySQL | 213 `:3306` | Radius 管理相关数据；应用账号按最小权限配置 |

## 端口与安全

| 接口 | 策略 |
| --- | --- |
| UDP 1812/1813/3799 | 镜像抓包流量，变更前必须核实 NAS/BRAS 来源，不能盲目关闭 |
| MySQL 3306 | 仅本机和 `172.31.0.0/16` |
| 监控 18190 | 仅本机和 233 |
| SSH 5334 | Fail2ban：10 分钟 5 次失败，封禁 24 小时 |

端口守卫模板位于 `deploy/security/`；真实 `.env`、spool、pcap、ClickHouse 凭据和原始报文不得提交。
