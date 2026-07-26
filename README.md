# radius-monitor（213）

213 上的 Radius 采集项目：从镜像接口抓取 UDP 1812/1813（以及必要的 CoA）报文，
解析认证/Accounting 事件，使用 SQLite spool 保证断链重放，并写入 212 ClickHouse。

| 文件 | 责任 |
| --- | --- |
| `sniffer.py` | 抓包主循环、解析调度和采集指标 |
| `parser.py` | RADIUS 报文字段和会话解析 |
| `clickhouse_sink.py` | 批量写入、重试与 spool 回放 |
| `config.py` | 无秘密的配置模型与默认项 |
| `test_clickhouse_sink.py` | sink 单元测试 |
| `verify_clickhouse_sample.py` | 生产样本核验工具 |

运行时 `.env`、spool 数据和真实 ClickHouse 凭据不提交。架构、数据库、端口和安全边界见
[`docs/module-contract.md`](docs/module-contract.md)；跨模块拓扑见 `NJCATV/netops-ops`。
