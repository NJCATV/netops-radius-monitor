"""
radius_monitor/db.py
MySQL 数据库操作层：建表、实时写入、查询接口
"""

import json
import os
import time
import logging
import re
import hashlib
from datetime import datetime, timedelta
from contextlib import contextmanager

import pymysql
from pymysql.cursors import DictCursor
from dbutils.pooled_db import PooledDB

import config

logger = logging.getLogger(__name__)
UPDATE_SUMMARY_TABLES = getattr(config, 'UPDATE_SUMMARY_TABLES', False)
UPDATE_USER_MAC_SUMMARY = getattr(config, 'UPDATE_USER_MAC_SUMMARY', False)
WRITE_AUTH_EVENT_SPAN = getattr(config, 'WRITE_AUTH_EVENT_SPAN', False)
WRITE_AUTH_ROLLUP = getattr(config, 'WRITE_AUTH_ROLLUP', False)
ACCT_DASHBOARD_SAMPLE_ROWS = int(os.getenv('ACCT_DASHBOARD_SAMPLE_ROWS', '1000'))
PARTITION_FUTURE_DAYS = int(os.getenv('PARTITION_FUTURE_DAYS', '7'))


def _daily_partition_clause(retain_days: int = 30, future_days: int = None) -> str:
    """生成按天 RANGE COLUMNS(ts) 分区：保留窗口向前铺满，并预建未来分区。"""
    retain_days = max(1, int(retain_days or 30))
    future_days = PARTITION_FUTURE_DAYS if future_days is None else max(0, int(future_days))
    today = datetime.now().date()
    start_day = today - timedelta(days=retain_days)
    end_day = today + timedelta(days=future_days)
    parts = []
    day = start_day
    while day <= end_day:
        next_day = day + timedelta(days=1)
        parts.append(
            f"    PARTITION p{day:%Y%m%d} VALUES LESS THAN ('{next_day:%Y-%m-%d}')"
        )
        day = next_day
    parts.append("    PARTITION pmax VALUES LESS THAN (MAXVALUE)")
    return ",\n".join(parts)

# ── 连接池 ────────────────────────────────────────────────────────────────────

_pool: PooledDB = None


def init_pool():
    """初始化 MySQL 连接池"""
    global _pool
    _pool = PooledDB(
        creator=pymysql,
        maxconnections=config.DB_POOL_SIZE + config.DB_POOL_OVERFLOW,
        mincached=2,
        maxcached=config.DB_POOL_SIZE,
        blocking=True,
        host=config.DB_HOST,
        port=config.DB_PORT,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME,
        charset='utf8mb4',
        autocommit=True,
        cursorclass=DictCursor,
        connect_timeout=getattr(config, 'DB_CONNECT_TIMEOUT', 5),
        read_timeout=getattr(config, 'DB_READ_TIMEOUT', 20),
        write_timeout=getattr(config, 'DB_WRITE_TIMEOUT', 20),
    )
    logger.info("MySQL 连接池初始化完成 host=%s db=%s", config.DB_HOST, config.DB_NAME)


@contextmanager
def get_conn():
    """获取一个数据库连接（上下文管理器）"""
    conn = _pool.connection()
    try:
        yield conn
    finally:
        conn.close()


# ── 建表 DDL ──────────────────────────────────────────────────────────────────

DDL_AUTH_LOG = """
CREATE TABLE IF NOT EXISTS auth_log (
    id           BIGINT       NOT NULL AUTO_INCREMENT,
    ts           DATETIME(3)  NOT NULL COMMENT '认证响应时间',
    req_ts       DATETIME(3)  NULL     COMMENT '认证请求时间',
    latency_ms   INT          NULL     COMMENT '认证耗时(ms)',
    username     VARCHAR(128) NOT NULL COMMENT '归一化账号名',
    raw_username VARCHAR(256) NULL     COMMENT '原始RADIUS User-Name',
    result       TINYINT      NOT NULL COMMENT '2=Accept 3=Reject',
    reply_msg    VARCHAR(256) NULL     COMMENT '原始 Reply-Message',
    reason_zh    VARCHAR(64)  NULL     COMMENT '中文拒绝原因',
    risk_level   VARCHAR(16)  NULL     COMMENT '风险等级',
    mac_addr     VARCHAR(20)  NULL     COMMENT 'MAC地址(规范化)',
    calling_sta  VARCHAR(64)  NULL     COMMENT 'Calling-Station-Id原始值',
    called_sta   VARCHAR(64)  NULL     COMMENT 'Called-Station-Id',
    nas_ip       VARCHAR(46)  NULL     COMMENT '来源NAS IP',
    nas_port     BIGINT       NULL     COMMENT 'NAS端口号(Attr 5)',
    nas_identifier VARCHAR(128) NULL   COMMENT 'NAS-Identifier(Attr 32)',
    nas_port_id  VARCHAR(128) NULL     COMMENT '可读接入端口NAS-Port-Id(Attr 87)',
    nas_port_type INT         NULL     COMMENT 'NAS-Port-Type(Attr 61)',
    framed_ip    VARCHAR(46)  NULL     COMMENT '分配IP(Framed-IP)',
    src_ip       VARCHAR(46)  NULL     COMMENT '报文源IP',
    PRIMARY KEY (id),
    INDEX idx_stats     (ts, result, latency_ms),
    INDEX idx_reason    (ts, result, reason_zh),
    INDEX idx_top_reject (ts, result, username),
    INDEX idx_nas_dist  (ts, nas_ip, result),
    INDEX idx_username_ts (username, ts),
    INDEX idx_multi_mac_window (ts, username, mac_addr, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='RADIUS认证明细日志'
"""

DDL_USER_SUMMARY = """
CREATE TABLE IF NOT EXISTS user_summary (
    username     VARCHAR(128) NOT NULL,
    accept_cnt   INT          NOT NULL DEFAULT 0,
    reject_cnt   INT          NOT NULL DEFAULT 0,
    mac_list     JSON         NULL     COMMENT '关联MAC列表',
    nas_list     JSON         NULL     COMMENT '来源NAS列表',
    main_reason  VARCHAR(64)  NULL     COMMENT '最多的拒绝原因',
    last_seen    DATETIME(3)  NULL     COMMENT '最后出现时间',
    first_seen   DATETIME(3)  NULL     COMMENT '首次出现时间',
    updated_at   DATETIME(3)  NULL     COMMENT '汇总更新时间',
    PRIMARY KEY (username),
    INDEX idx_reject_cnt (reject_cnt),
    INDEX idx_last_seen  (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='账号维度汇总'
"""

DDL_NAS_STATS = """
CREATE TABLE IF NOT EXISTS nas_stats (
    nas_ip       VARCHAR(46)  NOT NULL,
    total_cnt    INT          NOT NULL DEFAULT 0,
    accept_cnt   INT          NOT NULL DEFAULT 0,
    reject_cnt   INT          NOT NULL DEFAULT 0,
    last_seen    DATETIME(3)  NULL,
    updated_at   DATETIME(3)  NULL,
    PRIMARY KEY (nas_ip),
    INDEX idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='NAS维度统计'
"""

DDL_ACCT_LOG = f"""
CREATE TABLE IF NOT EXISTS acct_log (
    id                BIGINT       NOT NULL AUTO_INCREMENT,
    ts                DATETIME(3)  NOT NULL COMMENT '计费报文时间',
    username          VARCHAR(128) NULL COMMENT '归一化账号名',
    raw_username      VARCHAR(256) NULL COMMENT '原始RADIUS User-Name',
    acct_status_type  INT          NULL COMMENT '1=Start 2=Stop 3=Interim-Update',
    acct_session_id   VARCHAR(128) NULL,
    input_octets      BIGINT       NULL,
    input_gigawords   BIGINT       NULL,
    output_octets     BIGINT       NULL,
    output_gigawords  BIGINT       NULL,
    mac_addr          VARCHAR(20)  NULL,
    calling_sta       VARCHAR(64)  NULL,
    called_sta        VARCHAR(64)  NULL,
    nas_ip            VARCHAR(46)  NULL,
    nas_identifier    VARCHAR(128) NULL,
    nas_port          BIGINT       NULL,
    nas_port_id       VARCHAR(128) NULL COMMENT '可读接入端口NAS-Port-Id(Attr 87)',
    nas_port_type     INT          NULL COMMENT 'NAS-Port-Type(Attr 61)',
    framed_ip         VARCHAR(46)  NULL,
    src_ip            VARCHAR(46)  NULL,
    dst_ip            VARCHAR(46)  NULL,
    PRIMARY KEY (id, ts),
    INDEX idx_ts       (ts, id),
    INDEX idx_acct_user_ts (username, ts),
    INDEX idx_acct_session_ts (acct_session_id, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='RADIUS Accounting日志'
PARTITION BY RANGE COLUMNS(ts) (
{_daily_partition_clause(getattr(config, 'ACCT_RETAIN_DAYS', 30))}
)
"""

DDL_USER_MAC_SUMMARY = """
CREATE TABLE IF NOT EXISTS user_mac_summary (
    username    VARCHAR(128) NOT NULL COMMENT '归一化GDF/GDC账号',
    mac_addr    VARCHAR(20)  NOT NULL COMMENT 'MAC地址',
    total_cnt   INT          NOT NULL DEFAULT 0,
    accept_cnt  INT          NOT NULL DEFAULT 0,
    reject_cnt  INT          NOT NULL DEFAULT 0,
    nas_ip      VARCHAR(46)  NULL,
    nas_port    BIGINT       NULL,
    nas_identifier VARCHAR(128) NULL,
    nas_port_id VARCHAR(128) NULL,
    main_reason VARCHAR(64)  NULL,
    first_seen  DATETIME(3)  NULL,
    last_seen   DATETIME(3)  NULL,
    updated_at  DATETIME(3)  NULL,
    PRIMARY KEY (username, mac_addr),
    INDEX idx_last_seen (last_seen),
    INDEX idx_username_seen (username, last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='账号-MAC维度多终端风险汇总'
"""

DDL_AUTH_EVENT_SPAN = """
CREATE TABLE IF NOT EXISTS auth_event_span (
    id              BIGINT       NOT NULL AUTO_INCREMENT,
    event_key       CHAR(64)     NOT NULL COMMENT '滑动合并维度哈希',
    first_seen      DATETIME(3)  NOT NULL COMMENT '连续事件段首次出现时间',
    last_seen       DATETIME(3)  NOT NULL COMMENT '连续事件段最后出现时间',
    request_count   INT          NOT NULL DEFAULT 1 COMMENT '事件段内请求次数',
    latest_req_ts   DATETIME(3)  NULL     COMMENT '最近一次请求时间',
    latency_ms      INT          NULL     COMMENT '最近一次认证耗时(ms)',
    latency_count   INT          NOT NULL DEFAULT 0,
    latency_sum_ms  BIGINT       NOT NULL DEFAULT 0,
    latency_min_ms  INT          NULL,
    latency_max_ms  INT          NULL,
    username        VARCHAR(128) NOT NULL,
    raw_username    VARCHAR(256) NULL,
    result          TINYINT      NOT NULL COMMENT '2=Accept 3=Reject',
    reply_msg       VARCHAR(256) NULL,
    reason_zh       VARCHAR(64)  NULL,
    risk_level      VARCHAR(16)  NULL,
    mac_addr        VARCHAR(20)  NULL,
    calling_sta     VARCHAR(64)  NULL,
    called_sta      VARCHAR(64)  NULL,
    nas_ip          VARCHAR(46)  NULL,
    nas_port        BIGINT       NULL,
    nas_identifier  VARCHAR(128) NULL,
    nas_port_id     VARCHAR(128) NULL,
    nas_port_type   INT          NULL,
    framed_ip       VARCHAR(46)  NULL,
    src_ip          VARCHAR(46)  NULL,
    updated_at      DATETIME(3)  NOT NULL,
    PRIMARY KEY (id),
    INDEX idx_event_key_seen (event_key, last_seen),
    INDEX idx_recent (last_seen, id),
    INDEX idx_user_seen (username, last_seen),
    INDEX idx_mac_seen (mac_addr, last_seen),
    INDEX idx_multi_mac_seen (username, mac_addr, last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='RADIUS认证滑动事件段'
"""

DDL_AUTH_ROLLUP_10M = """
CREATE TABLE IF NOT EXISTS auth_rollup_10m (
    rollup_key      CHAR(64)     NOT NULL COMMENT '固定10分钟聚合维度哈希',
    bucket_start    DATETIME(3)  NOT NULL COMMENT '10分钟时间桶起点',
    first_seen      DATETIME(3)  NOT NULL,
    last_seen       DATETIME(3)  NOT NULL,
    request_count   INT          NOT NULL DEFAULT 1,
    accept_count    INT          NOT NULL DEFAULT 0,
    reject_count    INT          NOT NULL DEFAULT 0,
    latency_count   INT          NOT NULL DEFAULT 0,
    latency_sum_ms  BIGINT       NOT NULL DEFAULT 0,
    latency_min_ms  INT          NULL,
    latency_max_ms  INT          NULL,
    username        VARCHAR(128) NOT NULL,
    raw_username    VARCHAR(256) NULL,
    result          TINYINT      NOT NULL COMMENT '2=Accept 3=Reject',
    reply_msg       VARCHAR(256) NULL,
    reason_zh       VARCHAR(64)  NULL,
    risk_level      VARCHAR(16)  NULL,
    mac_addr        VARCHAR(20)  NULL,
    calling_sta     VARCHAR(64)  NULL,
    called_sta      VARCHAR(64)  NULL,
    nas_ip          VARCHAR(46)  NULL,
    nas_port        BIGINT       NULL,
    nas_identifier  VARCHAR(128) NULL,
    nas_port_id     VARCHAR(128) NULL,
    nas_port_type   INT          NULL,
    framed_ip       VARCHAR(46)  NULL,
    src_ip          VARCHAR(46)  NULL,
    updated_at      DATETIME(3)  NOT NULL,
    PRIMARY KEY (rollup_key),
    INDEX idx_recent (last_seen, rollup_key),
    INDEX idx_user_seen (username, last_seen),
    INDEX idx_mac_seen (mac_addr, last_seen),
    INDEX idx_multi_mac_seen (username, mac_addr, last_seen),
    INDEX idx_bucket_result (bucket_start, result),
    INDEX idx_top_reject (bucket_start, result, username),
    INDEX idx_reason (bucket_start, result, reason_zh),
    INDEX idx_nas_dist (bucket_start, nas_ip, result),
    INDEX idx_user_bucket (username, bucket_start),
    INDEX idx_multi_mac_bucket (bucket_start, username, mac_addr)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='RADIUS认证10分钟固定桶聚合'
"""

DDL_AUTH_RECENT_LOG = f"""
CREATE TABLE IF NOT EXISTS auth_recent_log (
    id             BIGINT       NOT NULL AUTO_INCREMENT,
    ts             DATETIME(3)  NOT NULL COMMENT '认证响应时间',
    req_ts         DATETIME(3)  NULL,
    latency_ms     INT          NULL,
    username       VARCHAR(128) NOT NULL,
    raw_username   VARCHAR(256) NULL,
    result         TINYINT      NOT NULL COMMENT '2=Accept 3=Reject',
    reply_msg      VARCHAR(256) NULL,
    reason_zh      VARCHAR(64)  NULL,
    risk_level     VARCHAR(16)  NULL,
    mac_addr       VARCHAR(20)  NULL,
    calling_sta    VARCHAR(64)  NULL,
    called_sta     VARCHAR(64)  NULL,
    nas_ip         VARCHAR(46)  NULL,
    nas_port       BIGINT       NULL,
    nas_identifier VARCHAR(128) NULL,
    nas_port_id    VARCHAR(128) NULL,
    nas_port_type  INT          NULL,
    framed_ip      VARCHAR(46)  NULL,
    src_ip         VARCHAR(46)  NULL,
    created_at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id, ts),
    INDEX idx_ts (ts, id),
    INDEX idx_user_ts (username, ts),
    INDEX idx_mac_ts (mac_addr, ts),
    INDEX idx_user_mac_ts (username, mac_addr, ts),
    INDEX idx_recent_multi (ts, username, mac_addr, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='RADIUS认证实时追加明细'
PARTITION BY RANGE COLUMNS(ts) (
{_daily_partition_clause(getattr(config, 'RETAIN_DAYS', 30))}
)
"""

DDL_AUTH_STAT_10M = """
CREATE TABLE IF NOT EXISTS auth_stat_10m (
    bucket_start   DATETIME(3) NOT NULL,
    request_count  BIGINT      NOT NULL DEFAULT 0,
    accept_count   BIGINT      NOT NULL DEFAULT 0,
    reject_count   BIGINT      NOT NULL DEFAULT 0,
    latency_count  BIGINT      NOT NULL DEFAULT 0,
    latency_sum_ms BIGINT      NOT NULL DEFAULT 0,
    latency_min_ms INT         NULL,
    latency_max_ms INT         NULL,
    first_seen     DATETIME(3) NULL,
    last_seen      DATETIME(3) NULL,
    updated_at     DATETIME(3) NOT NULL,
    PRIMARY KEY (bucket_start),
    INDEX idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='认证10分钟低维总量统计'
"""

DDL_AUTH_REASON_10M = """
CREATE TABLE IF NOT EXISTS auth_reason_10m (
    bucket_start   DATETIME(3) NOT NULL,
    result         TINYINT     NOT NULL,
    reason_zh      VARCHAR(64) NOT NULL DEFAULT '',
    request_count  BIGINT      NOT NULL DEFAULT 0,
    first_seen     DATETIME(3) NULL,
    last_seen      DATETIME(3) NULL,
    updated_at     DATETIME(3) NOT NULL,
    PRIMARY KEY (bucket_start, result, reason_zh),
    INDEX idx_reason_window (bucket_start, result, request_count)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='认证10分钟拒绝原因统计'
"""

DDL_AUTH_NAS_10M = """
CREATE TABLE IF NOT EXISTS auth_nas_10m (
    bucket_start   DATETIME(3) NOT NULL,
    nas_ip         VARCHAR(46) NOT NULL DEFAULT '',
    request_count  BIGINT      NOT NULL DEFAULT 0,
    accept_count   BIGINT      NOT NULL DEFAULT 0,
    reject_count   BIGINT      NOT NULL DEFAULT 0,
    first_seen     DATETIME(3) NULL,
    last_seen      DATETIME(3) NULL,
    updated_at     DATETIME(3) NOT NULL,
    PRIMARY KEY (bucket_start, nas_ip),
    INDEX idx_nas_window (bucket_start, request_count)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='认证10分钟NAS统计'
"""

DDL_AUTH_USER_10M = f"""
CREATE TABLE IF NOT EXISTS auth_user_10m (
    bucket_start   DATETIME(3)  NOT NULL,
    username       VARCHAR(128) NOT NULL,
    request_count  BIGINT       NOT NULL DEFAULT 0,
    accept_count   BIGINT       NOT NULL DEFAULT 0,
    reject_count   BIGINT       NOT NULL DEFAULT 0,
    main_reason    VARCHAR(64)  NULL,
    first_seen     DATETIME(3)  NULL,
    last_seen      DATETIME(3)  NULL,
    updated_at     DATETIME(3)  NOT NULL,
    PRIMARY KEY (bucket_start, username),
    INDEX idx_user_window (bucket_start, reject_count, username),
    INDEX idx_username_bucket (username, bucket_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='认证10分钟账号统计'
PARTITION BY RANGE COLUMNS(bucket_start) (
{_daily_partition_clause(getattr(config, 'AUTH_USER_RETAIN_DAYS', 30))}
)
"""

DDL_AUTH_USER_MAC_10M = f"""
CREATE TABLE IF NOT EXISTS auth_user_mac_10m (
    bucket_start    DATETIME(3)  NOT NULL,
    username        VARCHAR(128) NOT NULL,
    mac_addr        VARCHAR(20)  NOT NULL DEFAULT '',
    request_count   BIGINT       NOT NULL DEFAULT 0,
    accept_count    BIGINT       NOT NULL DEFAULT 0,
    reject_count    BIGINT       NOT NULL DEFAULT 0,
    nas_ip          VARCHAR(46)  NULL,
    nas_port        BIGINT       NULL,
    nas_identifier  VARCHAR(128) NULL,
    nas_port_id     VARCHAR(128) NULL,
    main_reason     VARCHAR(64)  NULL,
    first_seen      DATETIME(3)  NULL,
    last_seen       DATETIME(3)  NULL,
    updated_at      DATETIME(3)  NOT NULL,
    PRIMARY KEY (bucket_start, username, mac_addr),
    INDEX idx_multi_window (bucket_start, username, mac_addr),
    INDEX idx_username_bucket (username, bucket_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='认证10分钟账号MAC统计'
PARTITION BY RANGE COLUMNS(bucket_start) (
{_daily_partition_clause(getattr(config, 'AUTH_USER_MAC_RETAIN_DAYS', 30))}
)
"""


def init_db():
    """建表（幂等）"""
    with get_conn() as conn:
        with conn.cursor() as cur:
            for ddl in (
                DDL_ACCT_LOG,
                DDL_AUTH_RECENT_LOG,
                DDL_AUTH_STAT_10M,
                DDL_AUTH_REASON_10M,
                DDL_AUTH_NAS_10M,
                DDL_AUTH_USER_10M,
                DDL_AUTH_USER_MAC_10M,
            ):
                cur.execute(ddl)
            _ensure_column(cur, 'acct_log', 'raw_username',
                           "VARCHAR(256) NULL COMMENT '原始RADIUS User-Name' AFTER username")
            _ensure_column(cur, 'acct_log', 'input_gigawords',
                           "BIGINT NULL COMMENT 'Acct-Input-Gigawords(Attr 52)' AFTER input_octets")
            _ensure_column(cur, 'acct_log', 'output_gigawords',
                           "BIGINT NULL COMMENT 'Acct-Output-Gigawords(Attr 53)' AFTER output_octets")
            _ensure_column(cur, 'acct_log', 'nas_port_id',
                           "VARCHAR(128) NULL COMMENT '可读接入端口NAS-Port-Id(Attr 87)'")
            _ensure_column(cur, 'acct_log', 'nas_port_type',
                           "INT NULL COMMENT 'NAS-Port-Type(Attr 61)'")
            _ensure_index(cur, 'auth_recent_log', 'idx_recent_multi',
                          'CREATE INDEX idx_recent_multi ON auth_recent_log (ts, username, mac_addr, id)')
    logger.info("数据库表结构初始化完成")


def _ensure_column(cur, table_name: str, column_name: str, column_def: str):
    cur.execute(
        """
        SELECT COUNT(*) AS cnt
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
          AND COLUMN_NAME = %s
        """,
        (table_name, column_name),
    )
    if not cur.fetchone()['cnt']:
        cur.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def}")


def _ensure_index(cur, table_name: str, index_name: str, create_sql: str):
    cur.execute(
        """
        SELECT COUNT(*) AS cnt
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
          AND INDEX_NAME = %s
        """,
        (table_name, index_name),
    )
    if not cur.fetchone()['cnt']:
        cur.execute(create_sql)


# ── 写入接口 ──────────────────────────────────────────────────────────────────

INSERT_AUTH_LOG = """
INSERT INTO auth_log
    (ts, req_ts, latency_ms, username, raw_username, result, reply_msg, reason_zh,
     risk_level, mac_addr, calling_sta, called_sta, nas_ip, nas_port,
     nas_identifier, nas_port_id, nas_port_type, framed_ip, src_ip)
VALUES
    (%(ts)s, %(req_ts)s, %(latency_ms)s, %(username)s, %(raw_username)s, %(result)s,
     %(reply_msg)s, %(reason_zh)s, %(risk_level)s,
     %(mac_addr)s, %(calling_sta)s, %(called_sta)s,
     %(nas_ip)s, %(nas_port)s, %(nas_identifier)s, %(nas_port_id)s,
     %(nas_port_type)s, %(framed_ip)s, %(src_ip)s)
"""

INSERT_ACCT_LOG = """
INSERT INTO acct_log
    (ts, username, raw_username, acct_status_type, acct_session_id, input_octets,
     input_gigawords, output_octets, output_gigawords,
     mac_addr, calling_sta, called_sta, nas_ip,
     nas_identifier, nas_port, nas_port_id, nas_port_type, framed_ip, src_ip, dst_ip)
VALUES
    (%(ts)s, %(username)s, %(raw_username)s, %(acct_status_type)s, %(acct_session_id)s,
     %(input_octets)s, %(input_gigawords)s, %(output_octets)s, %(output_gigawords)s,
     %(mac_addr)s, %(calling_sta)s,
     %(called_sta)s, %(nas_ip)s, %(nas_identifier)s, %(nas_port)s,
     %(nas_port_id)s, %(nas_port_type)s, %(framed_ip)s, %(src_ip)s, %(dst_ip)s)
"""

UPSERT_USER_SUMMARY = """
INSERT INTO user_summary
    (username, accept_cnt, reject_cnt, mac_list, nas_list,
     main_reason, last_seen, first_seen, updated_at)
VALUES
    (%(username)s, %(accept_d)s, %(reject_d)s,
     JSON_ARRAY(%(mac)s), JSON_ARRAY(%(nas)s),
     %(main_reason)s, %(ts)s, %(ts)s, NOW(3))
ON DUPLICATE KEY UPDATE
    accept_cnt  = accept_cnt  + VALUES(accept_cnt),
    reject_cnt  = reject_cnt  + VALUES(reject_cnt),
    mac_list    = mac_list,
    nas_list    = nas_list,
    main_reason = IF(%(reject_d)s > 0, %(main_reason)s, main_reason),
    last_seen   = GREATEST(COALESCE(last_seen, %(ts)s), %(ts)s),
    updated_at  = NOW(3)
"""

UPSERT_NAS_STATS = """
INSERT INTO nas_stats
    (nas_ip, total_cnt, accept_cnt, reject_cnt, last_seen, updated_at)
VALUES
    (%(nas_ip)s, %(total_d)s, %(accept_d)s, %(reject_d)s, %(ts)s, NOW(3))
ON DUPLICATE KEY UPDATE
    total_cnt  = total_cnt  + VALUES(total_cnt),
    accept_cnt = accept_cnt + VALUES(accept_cnt),
    reject_cnt = reject_cnt + VALUES(reject_cnt),
    last_seen  = GREATEST(COALESCE(last_seen, %(ts)s), %(ts)s),
    updated_at = NOW(3)
"""

UPSERT_USER_MAC_SUMMARY = """
INSERT INTO user_mac_summary
    (username, mac_addr, total_cnt, accept_cnt, reject_cnt, nas_ip, nas_port,
     nas_identifier, nas_port_id, main_reason, first_seen, last_seen, updated_at)
VALUES
    (%(username)s, %(mac_addr)s, %(total_d)s, %(accept_d)s, %(reject_d)s,
     %(nas_ip)s, %(nas_port)s, %(nas_identifier)s, %(nas_port_id)s,
     %(main_reason)s, %(first_seen)s, %(last_seen)s, NOW(3))
ON DUPLICATE KEY UPDATE
    total_cnt   = total_cnt + VALUES(total_cnt),
    accept_cnt  = accept_cnt + VALUES(accept_cnt),
    reject_cnt  = reject_cnt + VALUES(reject_cnt),
    nas_ip      = COALESCE(VALUES(nas_ip), nas_ip),
    nas_port    = COALESCE(VALUES(nas_port), nas_port),
    nas_identifier = COALESCE(VALUES(nas_identifier), nas_identifier),
    nas_port_id = COALESCE(VALUES(nas_port_id), nas_port_id),
    main_reason = IF(VALUES(reject_cnt) > 0, VALUES(main_reason), main_reason),
    first_seen  = LEAST(COALESCE(first_seen, VALUES(first_seen)), VALUES(first_seen)),
    last_seen   = GREATEST(COALESCE(last_seen, VALUES(last_seen)), VALUES(last_seen)),
    updated_at  = NOW(3)
"""

INSERT_AUTH_EVENT_SPAN = """
INSERT INTO auth_event_span
    (event_key, first_seen, last_seen, request_count, latest_req_ts, latency_ms,
     latency_count, latency_sum_ms, latency_min_ms, latency_max_ms,
     username, raw_username, result, reply_msg, reason_zh, risk_level,
     mac_addr, calling_sta, called_sta, nas_ip, nas_port,
     nas_identifier, nas_port_id, nas_port_type, framed_ip, src_ip, updated_at)
VALUES
    (%(event_key)s, %(first_seen)s, %(last_seen)s, %(request_count)s, %(latest_req_ts)s,
     %(latency_ms)s, %(latency_count)s, %(latency_sum_ms)s, %(latency_min_ms)s,
     %(latency_max_ms)s, %(username)s, %(raw_username)s, %(result)s, %(reply_msg)s,
     %(reason_zh)s, %(risk_level)s, %(mac_addr)s, %(calling_sta)s, %(called_sta)s,
     %(nas_ip)s, %(nas_port)s, %(nas_identifier)s, %(nas_port_id)s,
     %(nas_port_type)s, %(framed_ip)s, %(src_ip)s, NOW(3))
"""

UPDATE_AUTH_EVENT_SPAN = """
UPDATE auth_event_span
SET
    first_seen = LEAST(first_seen, %(first_seen)s),
    last_seen = GREATEST(last_seen, %(last_seen)s),
    request_count = request_count + %(request_count)s,
    latest_req_ts = %(latest_req_ts)s,
    latency_ms = %(latency_ms)s,
    latency_count = latency_count + %(latency_count)s,
    latency_sum_ms = latency_sum_ms + %(latency_sum_ms)s,
    latency_min_ms = CASE
        WHEN %(latency_min_ms)s IS NULL THEN latency_min_ms
        WHEN latency_min_ms IS NULL THEN %(latency_min_ms)s
        ELSE LEAST(latency_min_ms, %(latency_min_ms)s)
    END,
    latency_max_ms = CASE
        WHEN %(latency_max_ms)s IS NULL THEN latency_max_ms
        WHEN latency_max_ms IS NULL THEN %(latency_max_ms)s
        ELSE GREATEST(latency_max_ms, %(latency_max_ms)s)
    END,
    raw_username = %(raw_username)s,
    reply_msg = %(reply_msg)s,
    risk_level = %(risk_level)s,
    calling_sta = %(calling_sta)s,
    called_sta = %(called_sta)s,
    nas_ip = %(nas_ip)s,
    nas_port = %(nas_port)s,
    nas_identifier = %(nas_identifier)s,
    nas_port_type = %(nas_port_type)s,
    framed_ip = %(framed_ip)s,
    updated_at = NOW(3)
WHERE id = %(span_id)s
"""

UPSERT_AUTH_ROLLUP_10M = """
INSERT INTO auth_rollup_10m
    (rollup_key, bucket_start, first_seen, last_seen, request_count,
     accept_count, reject_count, latency_count, latency_sum_ms,
     latency_min_ms, latency_max_ms, username, raw_username, result,
     reply_msg, reason_zh, risk_level, mac_addr, calling_sta, called_sta,
     nas_ip, nas_port, nas_identifier, nas_port_id, nas_port_type,
     framed_ip, src_ip, updated_at)
VALUES
    (%(rollup_key)s, %(bucket_start)s, %(first_seen)s, %(last_seen)s,
     %(request_count)s, %(accept_count)s, %(reject_count)s, %(latency_count)s,
     %(latency_sum_ms)s, %(latency_min_ms)s, %(latency_max_ms)s,
     %(username)s, %(raw_username)s, %(result)s, %(reply_msg)s, %(reason_zh)s,
     %(risk_level)s, %(mac_addr)s, %(calling_sta)s, %(called_sta)s,
     %(nas_ip)s, %(nas_port)s, %(nas_identifier)s, %(nas_port_id)s,
     %(nas_port_type)s, %(framed_ip)s, %(src_ip)s, NOW(3))
ON DUPLICATE KEY UPDATE
    request_count = request_count + VALUES(request_count),
    accept_count = accept_count + VALUES(accept_count),
    reject_count = reject_count + VALUES(reject_count),
    first_seen = LEAST(first_seen, VALUES(first_seen)),
    last_seen = GREATEST(last_seen, VALUES(last_seen)),
    latency_count = latency_count + VALUES(latency_count),
    latency_sum_ms = latency_sum_ms + VALUES(latency_sum_ms),
    latency_min_ms = CASE
        WHEN VALUES(latency_min_ms) IS NULL THEN latency_min_ms
        WHEN latency_min_ms IS NULL THEN VALUES(latency_min_ms)
        ELSE LEAST(latency_min_ms, VALUES(latency_min_ms))
    END,
    latency_max_ms = CASE
        WHEN VALUES(latency_max_ms) IS NULL THEN latency_max_ms
        WHEN latency_max_ms IS NULL THEN VALUES(latency_max_ms)
        ELSE GREATEST(latency_max_ms, VALUES(latency_max_ms))
    END,
    raw_username = VALUES(raw_username),
    reply_msg = VALUES(reply_msg),
    risk_level = VALUES(risk_level),
    calling_sta = VALUES(calling_sta),
    called_sta = VALUES(called_sta),
    nas_ip = VALUES(nas_ip),
    nas_port = VALUES(nas_port),
    nas_identifier = VALUES(nas_identifier),
    nas_port_type = VALUES(nas_port_type),
    framed_ip = VALUES(framed_ip),
    updated_at = NOW(3)
"""

INSERT_AUTH_RECENT_LOG = """
INSERT INTO auth_recent_log
    (ts, req_ts, latency_ms, username, raw_username, result, reply_msg,
     reason_zh, risk_level, mac_addr, calling_sta, called_sta, nas_ip,
     nas_port, nas_identifier, nas_port_id, nas_port_type, framed_ip, src_ip)
VALUES
    (%(ts)s, %(req_ts)s, %(latency_ms)s, %(username)s, %(raw_username)s,
     %(result)s, %(reply_msg)s, %(reason_zh)s, %(risk_level)s,
     %(mac_addr)s, %(calling_sta)s, %(called_sta)s, %(nas_ip)s,
     %(nas_port)s, %(nas_identifier)s, %(nas_port_id)s, %(nas_port_type)s,
     %(framed_ip)s, %(src_ip)s)
"""

UPSERT_AUTH_STAT_10M = """
INSERT INTO auth_stat_10m
    (bucket_start, request_count, accept_count, reject_count, latency_count,
     latency_sum_ms, latency_min_ms, latency_max_ms, first_seen, last_seen, updated_at)
VALUES
    (%(bucket_start)s, %(request_count)s, %(accept_count)s, %(reject_count)s,
     %(latency_count)s, %(latency_sum_ms)s, %(latency_min_ms)s, %(latency_max_ms)s,
     %(first_seen)s, %(last_seen)s, NOW(3))
ON DUPLICATE KEY UPDATE
    request_count = request_count + VALUES(request_count),
    accept_count = accept_count + VALUES(accept_count),
    reject_count = reject_count + VALUES(reject_count),
    latency_count = latency_count + VALUES(latency_count),
    latency_sum_ms = latency_sum_ms + VALUES(latency_sum_ms),
    latency_min_ms = CASE
        WHEN VALUES(latency_min_ms) IS NULL THEN latency_min_ms
        WHEN latency_min_ms IS NULL THEN VALUES(latency_min_ms)
        ELSE LEAST(latency_min_ms, VALUES(latency_min_ms))
    END,
    latency_max_ms = CASE
        WHEN VALUES(latency_max_ms) IS NULL THEN latency_max_ms
        WHEN latency_max_ms IS NULL THEN VALUES(latency_max_ms)
        ELSE GREATEST(latency_max_ms, VALUES(latency_max_ms))
    END,
    first_seen = LEAST(COALESCE(first_seen, VALUES(first_seen)), VALUES(first_seen)),
    last_seen = GREATEST(COALESCE(last_seen, VALUES(last_seen)), VALUES(last_seen)),
    updated_at = NOW(3)
"""

UPSERT_AUTH_REASON_10M = """
INSERT INTO auth_reason_10m
    (bucket_start, result, reason_zh, request_count, first_seen, last_seen, updated_at)
VALUES
    (%(bucket_start)s, %(result)s, %(reason_zh)s, %(request_count)s,
     %(first_seen)s, %(last_seen)s, NOW(3))
ON DUPLICATE KEY UPDATE
    request_count = request_count + VALUES(request_count),
    first_seen = LEAST(COALESCE(first_seen, VALUES(first_seen)), VALUES(first_seen)),
    last_seen = GREATEST(COALESCE(last_seen, VALUES(last_seen)), VALUES(last_seen)),
    updated_at = NOW(3)
"""

UPSERT_AUTH_NAS_10M = """
INSERT INTO auth_nas_10m
    (bucket_start, nas_ip, request_count, accept_count, reject_count,
     first_seen, last_seen, updated_at)
VALUES
    (%(bucket_start)s, %(nas_ip)s, %(request_count)s, %(accept_count)s,
     %(reject_count)s, %(first_seen)s, %(last_seen)s, NOW(3))
ON DUPLICATE KEY UPDATE
    request_count = request_count + VALUES(request_count),
    accept_count = accept_count + VALUES(accept_count),
    reject_count = reject_count + VALUES(reject_count),
    first_seen = LEAST(COALESCE(first_seen, VALUES(first_seen)), VALUES(first_seen)),
    last_seen = GREATEST(COALESCE(last_seen, VALUES(last_seen)), VALUES(last_seen)),
    updated_at = NOW(3)
"""

UPSERT_AUTH_USER_10M = """
INSERT INTO auth_user_10m
    (bucket_start, username, request_count, accept_count, reject_count,
     main_reason, first_seen, last_seen, updated_at)
VALUES
    (%(bucket_start)s, %(username)s, %(request_count)s, %(accept_count)s,
     %(reject_count)s, %(main_reason)s, %(first_seen)s, %(last_seen)s, NOW(3))
ON DUPLICATE KEY UPDATE
    request_count = request_count + VALUES(request_count),
    accept_count = accept_count + VALUES(accept_count),
    reject_count = reject_count + VALUES(reject_count),
    main_reason = COALESCE(VALUES(main_reason), main_reason),
    first_seen = LEAST(COALESCE(first_seen, VALUES(first_seen)), VALUES(first_seen)),
    last_seen = GREATEST(COALESCE(last_seen, VALUES(last_seen)), VALUES(last_seen)),
    updated_at = NOW(3)
"""

UPSERT_AUTH_USER_MAC_10M = """
INSERT INTO auth_user_mac_10m
    (bucket_start, username, mac_addr, request_count, accept_count, reject_count,
     nas_ip, nas_port, nas_identifier, nas_port_id, main_reason,
     first_seen, last_seen, updated_at)
VALUES
    (%(bucket_start)s, %(username)s, %(mac_addr)s, %(request_count)s,
     %(accept_count)s, %(reject_count)s, %(nas_ip)s, %(nas_port)s,
     %(nas_identifier)s, %(nas_port_id)s, %(main_reason)s,
     %(first_seen)s, %(last_seen)s, NOW(3))
ON DUPLICATE KEY UPDATE
    request_count = request_count + VALUES(request_count),
    accept_count = accept_count + VALUES(accept_count),
    reject_count = reject_count + VALUES(reject_count),
    nas_ip = COALESCE(VALUES(nas_ip), nas_ip),
    nas_port = COALESCE(VALUES(nas_port), nas_port),
    nas_identifier = COALESCE(VALUES(nas_identifier), nas_identifier),
    nas_port_id = COALESCE(VALUES(nas_port_id), nas_port_id),
    main_reason = COALESCE(VALUES(main_reason), main_reason),
    first_seen = LEAST(COALESCE(first_seen, VALUES(first_seen)), VALUES(first_seen)),
    last_seen = GREATEST(COALESCE(last_seen, VALUES(last_seen)), VALUES(last_seen)),
    updated_at = NOW(3)
"""


def _fmt_ts(ts_str):
    if not ts_str or ts_str == '—':
        return None
    try:
        datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S.%f')
        return ts_str
    except Exception:
        pass
    try:
        datetime.strptime(ts_str, '%H:%M:%S.%f')
        today = datetime.now().strftime('%Y-%m-%d')
        return f"{today} {ts_str}"
    except Exception:
        return None


def _parse_ts(ts_val):
    if isinstance(ts_val, datetime):
        return ts_val
    if not ts_val:
        return datetime.now()
    for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S'):
        try:
            return datetime.strptime(str(ts_val), fmt)
        except Exception:
            pass
    return datetime.now()


def _fmt_dt(dt: datetime) -> str:
    return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


def _bucket_start_10m(ts_val) -> str:
    dt = _parse_ts(ts_val)
    bucket_minute = (dt.minute // 10) * 10
    bucket = dt.replace(minute=bucket_minute, second=0, microsecond=0)
    return _fmt_dt(bucket)


def _stable_key(*parts) -> str:
    normalized = ['<NULL>' if part is None else str(part) for part in parts]
    return hashlib.sha256('\x1f'.join(normalized).encode('utf-8')).hexdigest()


def _build_auth_rollup_row(row: dict):
    latency_ms = row.get('latency_ms')
    has_latency = latency_ms is not None
    result = row.get('result')
    bucket_start = _bucket_start_10m(row.get('ts'))
    rollup_key = _stable_key(
        bucket_start, row.get('username'), row.get('src_ip'), row.get('mac_addr'),
        row.get('nas_port_id'), result,
    )
    return {
        **row,
        'rollup_key': rollup_key,
        'bucket_start': bucket_start,
        'first_seen': row.get('ts') or _fmt_dt(datetime.now()),
        'last_seen': row.get('ts') or _fmt_dt(datetime.now()),
        'request_count': 1,
        'accept_count': 1 if result == 2 else 0,
        'reject_count': 1 if result == 3 else 0,
        'latency_count': 1 if has_latency else 0,
        'latency_sum_ms': latency_ms if has_latency else 0,
        'latency_min_ms': latency_ms,
        'latency_max_ms': latency_ms,
    }


def _build_low_rollup_rows(row: dict):
    latency_ms = row.get('latency_ms')
    has_latency = latency_ms is not None
    result = row.get('result')
    bucket_start = _bucket_start_10m(row.get('ts'))
    first_seen = row.get('ts') or _fmt_dt(datetime.now())
    last_seen = row.get('ts') or _fmt_dt(datetime.now())
    accept_count = 1 if result == 2 else 0
    reject_count = 1 if result == 3 else 0
    base = {
        'bucket_start': bucket_start,
        'request_count': 1,
        'accept_count': accept_count,
        'reject_count': reject_count,
        'latency_count': 1 if has_latency else 0,
        'latency_sum_ms': latency_ms if has_latency else 0,
        'latency_min_ms': latency_ms,
        'latency_max_ms': latency_ms,
        'first_seen': first_seen,
        'last_seen': last_seen,
    }
    reason = row.get('reason_zh') or ''
    nas_ip = row.get('nas_ip') or ''
    main_reason = reason or None
    stat_row = base.copy()
    reason_row = {
        'bucket_start': bucket_start,
        'result': result,
        'reason_zh': reason,
        'request_count': 1,
        'first_seen': first_seen,
        'last_seen': last_seen,
    }
    nas_row = {
        'bucket_start': bucket_start,
        'nas_ip': nas_ip,
        'request_count': 1,
        'accept_count': accept_count,
        'reject_count': reject_count,
        'first_seen': first_seen,
        'last_seen': last_seen,
    }
    user_row = {
        'bucket_start': bucket_start,
        'username': row.get('username'),
        'request_count': 1,
        'accept_count': accept_count,
        'reject_count': reject_count,
        'main_reason': main_reason if result == 3 else None,
        'first_seen': first_seen,
        'last_seen': last_seen,
    }
    user_mac_row = {
        'bucket_start': bucket_start,
        'username': row.get('username'),
        'mac_addr': row.get('mac_addr') or '',
        'request_count': 1,
        'accept_count': accept_count,
        'reject_count': reject_count,
        'nas_ip': row.get('nas_ip'),
        'nas_port': row.get('nas_port'),
        'nas_identifier': row.get('nas_identifier'),
        'nas_port_id': row.get('nas_port_id'),
        'main_reason': main_reason if result == 3 else None,
        'first_seen': first_seen,
        'last_seen': last_seen,
    }
    return stat_row, reason_row, nas_row, user_row, user_mac_row


def _build_auth_event_row(row: dict):
    latency_ms = row.get('latency_ms')
    has_latency = latency_ms is not None
    event_key = _stable_key(
        row.get('username'), row.get('src_ip'), row.get('mac_addr'),
        row.get('nas_port_id'), row.get('result'),
    )
    return {
        **row,
        'event_key': event_key,
        'first_seen': row.get('ts') or _fmt_dt(datetime.now()),
        'last_seen': row.get('ts') or _fmt_dt(datetime.now()),
        'request_count': 1,
        'latest_req_ts': row.get('req_ts'),
        'latency_count': 1 if has_latency else 0,
        'latency_sum_ms': latency_ms if has_latency else 0,
        'latency_min_ms': latency_ms,
        'latency_max_ms': latency_ms,
    }


def _merge_metric_row(target: dict, source: dict):
    target['request_count'] += source['request_count']
    target['first_seen'] = min(target['first_seen'], source['first_seen'])
    target['last_seen'] = max(target['last_seen'], source['last_seen'])
    target['latency_count'] += source['latency_count']
    target['latency_sum_ms'] += source['latency_sum_ms']
    if source['latency_min_ms'] is not None:
        if target['latency_min_ms'] is None:
            target['latency_min_ms'] = source['latency_min_ms']
        else:
            target['latency_min_ms'] = min(target['latency_min_ms'], source['latency_min_ms'])
    if source['latency_max_ms'] is not None:
        if target['latency_max_ms'] is None:
            target['latency_max_ms'] = source['latency_max_ms']
        else:
            target['latency_max_ms'] = max(target['latency_max_ms'], source['latency_max_ms'])
    if source['last_seen'] >= target['last_seen']:
        for key in (
            'raw_username', 'reply_msg', 'risk_level', 'calling_sta', 'called_sta',
            'nas_ip', 'nas_port', 'nas_identifier', 'nas_port_type', 'framed_ip',
            'latest_req_ts', 'latency_ms',
        ):
            if key in source:
                target[key] = source[key]


def _collapse_rollup_rows(rollup_rows: list) -> list:
    merged = {}
    for row in rollup_rows:
        key = row['rollup_key']
        current = merged.get(key)
        if not current:
            merged[key] = row.copy()
            continue
        current['accept_count'] += row['accept_count']
        current['reject_count'] += row['reject_count']
        _merge_metric_row(current, row)
    return list(merged.values())


def _merge_count_row(target: dict, source: dict, metric_keys=('request_count',)):
    for key in metric_keys:
        target[key] += source[key]
    target['first_seen'] = min(target['first_seen'], source['first_seen'])
    target['last_seen'] = max(target['last_seen'], source['last_seen'])
    if source.get('main_reason'):
        target['main_reason'] = source['main_reason']
    if source.get('last_seen') >= target.get('last_seen'):
        for key in ('nas_ip', 'nas_port', 'nas_identifier', 'nas_port_id'):
            if key in source and source.get(key):
                target[key] = source[key]


def _collapse_keyed_rows(rows: list, key_fields: tuple, metric_keys=('request_count',)) -> list:
    merged = {}
    for row in rows:
        key = tuple(row.get(field) for field in key_fields)
        current = merged.get(key)
        if not current:
            merged[key] = row.copy()
            continue
        _merge_count_row(current, row, metric_keys)
    return list(merged.values())


def _collapse_stat_rows(rows: list) -> list:
    merged = {}
    for row in rows:
        key = row['bucket_start']
        current = merged.get(key)
        if not current:
            merged[key] = row.copy()
            continue
        _merge_metric_row(current, row)
        current['accept_count'] += row['accept_count']
        current['reject_count'] += row['reject_count']
    return list(merged.values())


def _collapse_auth_event_rows(span_rows: list) -> list:
    collapsed = []
    by_key = {}
    for row in sorted(span_rows, key=lambda item: (item['event_key'], item.get('last_seen') or '')):
        event_key = row['event_key']
        current = by_key.get(event_key)
        if current:
            current_last = _parse_ts(current.get('last_seen'))
            row_ts = _parse_ts(row.get('last_seen'))
            if row_ts - current_last <= timedelta(minutes=10):
                _merge_metric_row(current, row)
                continue
        current = row.copy()
        by_key[event_key] = current
        collapsed.append(current)
    return collapsed


def _upsert_auth_event_spans(cur, span_rows: list):
    """维护滑动 10 分钟事件段：同维度且距离上一条不超过 10 分钟则累加。"""
    collapsed_rows = sorted(_collapse_auth_event_rows(span_rows), key=lambda item: item.get('last_seen') or '')
    if not collapsed_rows:
        return

    event_keys = sorted({row['event_key'] for row in collapsed_rows})
    min_cutoff = min(_parse_ts(row.get('last_seen')) - timedelta(minutes=10) for row in collapsed_rows)
    placeholders = ','.join(['%s'] * len(event_keys))
    cur.execute(
        f"""
        SELECT id, event_key, last_seen
        FROM auth_event_span FORCE INDEX (idx_event_key_seen)
        WHERE event_key IN ({placeholders}) AND last_seen >= %s
        ORDER BY event_key, last_seen DESC, id DESC
        """,
        (*event_keys, _fmt_dt(min_cutoff)),
    )
    latest_by_key = {}
    for existing in cur.fetchall():
        latest_by_key.setdefault(existing['event_key'], existing)

    insert_rows = []
    update_rows = []
    for span_row in collapsed_rows:
        ts = _parse_ts(span_row.get('last_seen'))
        cutoff = _fmt_dt(ts - timedelta(minutes=10))
        existing = latest_by_key.get(span_row['event_key'])
        if existing and _parse_ts(existing.get('last_seen')) >= _parse_ts(cutoff):
            span_row['span_id'] = existing['id']
            update_rows.append(span_row)
        else:
            insert_rows.append(span_row)

    if insert_rows:
        cur.executemany(INSERT_AUTH_EVENT_SPAN, insert_rows)
    for span_row in update_rows:
        cur.execute(UPDATE_AUTH_EVENT_SPAN, span_row)


def _build_auth_rows(rec: dict):
    """把解析后的认证记录整理为认证写库参数。"""
    is_accept = 1 if rec['result_code'] == 2 else 0
    is_reject = 0 if rec['result_code'] == 2 else 1

    ts_val     = _fmt_ts(rec.get('resp_ts'))
    req_ts_val = _fmt_ts(rec.get('req_ts'))
    raw_username = rec.get('raw_username') or rec.get('username') or '(空)'
    username = rec.get('username') or raw_username
    if not _is_gdf_account(username):
        return None, None, None

    # 计算延迟
    latency_ms = None
    try:
        if ts_val and req_ts_val:
            fmt = '%Y-%m-%d %H:%M:%S.%f'
            t1  = datetime.strptime(req_ts_val, fmt)
            t2  = datetime.strptime(ts_val, fmt)
            latency_ms = max(0, int((t2 - t1).total_seconds() * 1000))
    except Exception:
        pass

    row = {
        'ts':          ts_val,
        'req_ts':      req_ts_val,
        'latency_ms':  latency_ms,
        'username':    username[:128],
        'raw_username': raw_username[:256],
        'result':      rec.get('result_code', 3),
        'reply_msg':   (rec.get('reply_raw') or '')[:256],
        'reason_zh':   (rec.get('reason_zh') or '')[:64],
        'risk_level':  (rec.get('risk') or 'unknown')[:16],
        'mac_addr':    (rec.get('mac_addr') or '')[:20] or None,
        'calling_sta': (rec.get('calling_sta') or '')[:64] or None,
        'called_sta':  (rec.get('called_sta') or '')[:64] or None,
        'nas_ip':      (rec.get('nas_ip') or '')[:46] or None,
        'nas_port':    rec.get('nas_port'),
        'nas_identifier': (rec.get('nas_identifier') or '')[:128] or None,
        'nas_port_id': (rec.get('nas_port_id') or '')[:128] or None,
        'nas_port_type': rec.get('nas_port_type'),
        'framed_ip':   (rec.get('framed_ip') or '')[:46] or None,
        'src_ip':      (rec.get('src_ip') or '')[:46] or None,
    }

    summary_row = {
        'username':    row['username'],
        'accept_d':    is_accept,
        'reject_d':    is_reject,
        'mac':         row['mac_addr'],
        'nas':         row['nas_ip'],
        'main_reason': row['reason_zh'] or None,
        'ts':          ts_val or datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
    }

    nas_row = {
        'nas_ip':   row['nas_ip'] or 'unknown',
        'total_d':  1,
        'accept_d': is_accept,
        'reject_d': is_reject,
        'ts':       ts_val or datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
    }

    return row, summary_row, nas_row


def _build_accounting_row(rec: dict):
    """把解析后的 Accounting 记录整理为 acct_log 写库参数。"""
    raw_username = rec.get('raw_username') or rec.get('username') or ''
    username = rec.get('username') or raw_username
    if not _is_gdf_account(username):
        return None
    return {
        'ts':               _fmt_ts(rec.get('ts')) or datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
        'username':         username[:128] or None,
        'raw_username':     raw_username[:256] or None,
        'acct_status_type': rec.get('acct_status_type'),
        'acct_session_id':  (rec.get('acct_session_id') or '')[:128] or None,
        'input_octets':     rec.get('input_octets'),
        'input_gigawords':  rec.get('input_gigawords'),
        'output_octets':    rec.get('output_octets'),
        'output_gigawords': rec.get('output_gigawords'),
        'mac_addr':         (rec.get('mac_addr') or '')[:20] or None,
        'calling_sta':      (rec.get('calling_sta') or '')[:64] or None,
        'called_sta':       (rec.get('called_sta') or '')[:64] or None,
        'nas_ip':           (rec.get('nas_ip') or '')[:46] or None,
        'nas_identifier':   (rec.get('nas_identifier') or '')[:128] or None,
        'nas_port':         rec.get('nas_port'),
        'nas_port_id':      (rec.get('nas_port_id') or '')[:128] or None,
        'nas_port_type':    rec.get('nas_port_type'),
        'framed_ip':        (rec.get('framed_ip') or '')[:46] or None,
        'src_ip':           (rec.get('src_ip') or '')[:46] or None,
        'dst_ip':           (rec.get('dst_ip') or '')[:46] or None,
    }


def _is_gdf_account(username: str) -> bool:
    return bool(username and re.fullmatch(r'(?:GD[FC][0-9]+|[0-9]+)', username, flags=re.IGNORECASE))


def insert_auth_record(rec: dict):
    """
    将单条认证记录写入数据库。
    rec 结构参见 parser.py parse_radius_pair()
    """
    row, summary_row, nas_row = _build_auth_rows(rec)
    if row is None:
        return
    stat_row, reason_row, low_nas_row, user_row, user_mac_row = _build_low_rollup_rows(row)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(UPSERT_AUTH_STAT_10M, stat_row)
            cur.execute(INSERT_AUTH_RECENT_LOG, row)
            if getattr(config, 'WRITE_AUTH_RISK', False):
                cur.execute(UPSERT_AUTH_REASON_10M, reason_row)
                cur.execute(UPSERT_AUTH_NAS_10M, low_nas_row)
                cur.execute(UPSERT_AUTH_USER_10M, user_row)
                cur.execute(UPSERT_AUTH_USER_MAC_10M, user_mac_row)
            if WRITE_AUTH_ROLLUP:
                cur.execute(UPSERT_AUTH_ROLLUP_10M, _build_auth_rollup_row(row))
            if WRITE_AUTH_EVENT_SPAN:
                _upsert_auth_event_spans(cur, [_build_auth_event_row(row)])


def insert_accounting_record(rec: dict):
    """写入一条 RADIUS Accounting 记录。"""
    if not getattr(config, 'WRITE_ACCOUNTING_LOG', False):
        return
    row = _build_accounting_row(rec)
    if row is None:
        return
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(INSERT_ACCT_LOG, row)


def bulk_insert_accounting_records(recs: list):
    """批量写入 Accounting 明细。认证写入和计费写入分离后只处理 acct_log。"""
    if not getattr(config, 'WRITE_ACCOUNTING_LOG', False):
        return

    acct_rows = []
    for rec in recs:
        try:
            if rec.get('record_type') != 'accounting':
                continue
            acct_row = _build_accounting_row(rec)
            if acct_row is not None:
                acct_rows.append(acct_row)
        except Exception as e:
            logger.warning("整理计费写库记录失败 username=%s err=%s", rec.get('username'), e)

    if not acct_rows:
        return

    with get_conn() as conn:
        try:
            conn.begin()
            with conn.cursor() as cur:
                cur.executemany(INSERT_ACCT_LOG, acct_rows)
            conn.commit()
        except Exception:
            conn.rollback()
            raise


# ── 批量写入（高吞吐） ─────────────────────────────────────────────────────────

def bulk_insert_auth_records(recs: list, include_realtime: bool = True, include_risk: bool = True):
    """批量写入认证记录和聚合表。Accounting 明细由独立 writer 处理。"""
    auth_rows = []
    span_rows = []
    rollup_rows = []
    stat_rows = []
    reason_rows = []
    low_nas_rows = []
    user_rows = []
    user_mac_rows = []
    summary_map = {}
    nas_map = {}
    mac_summary_map = {}

    for rec in recs:
        try:
            if rec.get('record_type') == 'accounting':
                continue
            else:
                row, summary_row, nas_row = _build_auth_rows(rec)
                if row is None:
                    continue
                auth_rows.append(row)
                if WRITE_AUTH_EVENT_SPAN:
                    span_rows.append(_build_auth_event_row(row))
                rollup_rows.append(_build_auth_rollup_row(row))
                stat_row, reason_row, low_nas_row, user_row, user_mac_row = _build_low_rollup_rows(row)
                stat_rows.append(stat_row)
                reason_rows.append(reason_row)
                low_nas_rows.append(low_nas_row)
                user_rows.append(user_row)
                user_mac_rows.append(user_mac_row)

                if UPDATE_SUMMARY_TABLES:
                    user_key = summary_row['username']
                    merged_summary = summary_map.setdefault(user_key, {
                        'username': user_key,
                        'accept_d': 0,
                        'reject_d': 0,
                        'mac': summary_row['mac'],
                        'nas': summary_row['nas'],
                        'main_reason': summary_row['main_reason'],
                        'ts': summary_row['ts'],
                    })
                    merged_summary['accept_d'] += summary_row['accept_d']
                    merged_summary['reject_d'] += summary_row['reject_d']
                    if not merged_summary['mac'] and summary_row['mac']:
                        merged_summary['mac'] = summary_row['mac']
                    if not merged_summary['nas'] and summary_row['nas']:
                        merged_summary['nas'] = summary_row['nas']
                    if summary_row['reject_d'] > 0 and summary_row['main_reason']:
                        merged_summary['main_reason'] = summary_row['main_reason']
                    if summary_row['ts'] and summary_row['ts'] > merged_summary['ts']:
                        merged_summary['ts'] = summary_row['ts']

                    nas_key = nas_row['nas_ip']
                    merged_nas = nas_map.setdefault(nas_key, {
                        'nas_ip': nas_key,
                        'total_d': 0,
                        'accept_d': 0,
                        'reject_d': 0,
                        'ts': nas_row['ts'],
                    })
                    merged_nas['total_d'] += nas_row['total_d']
                    merged_nas['accept_d'] += nas_row['accept_d']
                    merged_nas['reject_d'] += nas_row['reject_d']
                    if nas_row['ts'] and nas_row['ts'] > merged_nas['ts']:
                        merged_nas['ts'] = nas_row['ts']

                if UPDATE_USER_MAC_SUMMARY and row['mac_addr'] and _is_gdf_account(row['username']):
                    mac_key = (row['username'].upper(), row['mac_addr'])
                    mac_row = mac_summary_map.setdefault(mac_key, {
                        'username': row['username'].upper(),
                        'mac_addr': row['mac_addr'],
                        'total_d': 0,
                        'accept_d': 0,
                        'reject_d': 0,
                        'nas_ip': row['nas_ip'],
                        'nas_port': row['nas_port'],
                        'nas_identifier': row['nas_identifier'],
                        'nas_port_id': row['nas_port_id'],
                        'main_reason': row['reason_zh'] or None,
                        'first_seen': row['ts'],
                        'last_seen': row['ts'],
                    })
                    mac_row['total_d'] += 1
                    mac_row['accept_d'] += 1 if row['result'] == 2 else 0
                    mac_row['reject_d'] += 1 if row['result'] == 3 else 0
                    if row['result'] == 3 and row['reason_zh']:
                        mac_row['main_reason'] = row['reason_zh']
                    if row['nas_ip']:
                        mac_row['nas_ip'] = row['nas_ip']
                    if row['nas_port'] is not None:
                        mac_row['nas_port'] = row['nas_port']
                    if row['nas_identifier']:
                        mac_row['nas_identifier'] = row['nas_identifier']
                    if row['nas_port_id']:
                        mac_row['nas_port_id'] = row['nas_port_id']
                    if row['ts'] and (not mac_row['first_seen'] or row['ts'] < mac_row['first_seen']):
                        mac_row['first_seen'] = row['ts']
                    if row['ts'] and (not mac_row['last_seen'] or row['ts'] > mac_row['last_seen']):
                        mac_row['last_seen'] = row['ts']
        except Exception as e:
            logger.warning("整理写库记录失败 username=%s err=%s", rec.get('username'), e)

    if not auth_rows:
        return

    with get_conn() as conn:
        try:
            conn.begin()
            with conn.cursor() as cur:
                if auth_rows and include_realtime:
                    for stat_row in _collapse_stat_rows(stat_rows):
                        cur.execute(UPSERT_AUTH_STAT_10M, stat_row)
                    cur.executemany(INSERT_AUTH_RECENT_LOG, auth_rows)
                    if WRITE_AUTH_ROLLUP:
                        for rollup_row in _collapse_rollup_rows(rollup_rows):
                            cur.execute(UPSERT_AUTH_ROLLUP_10M, rollup_row)
                    if WRITE_AUTH_EVENT_SPAN:
                        _upsert_auth_event_spans(cur, span_rows)
                if auth_rows and include_risk and getattr(config, 'WRITE_AUTH_RISK', False):
                    for reason_row in _collapse_keyed_rows(reason_rows, ('bucket_start', 'result', 'reason_zh')):
                        cur.execute(UPSERT_AUTH_REASON_10M, reason_row)
                    for low_nas_row in _collapse_keyed_rows(
                        low_nas_rows,
                        ('bucket_start', 'nas_ip'),
                        ('request_count', 'accept_count', 'reject_count'),
                    ):
                        cur.execute(UPSERT_AUTH_NAS_10M, low_nas_row)
                    for user_row in _collapse_keyed_rows(
                        user_rows,
                        ('bucket_start', 'username'),
                        ('request_count', 'accept_count', 'reject_count'),
                    ):
                        cur.execute(UPSERT_AUTH_USER_10M, user_row)
                    for user_mac_row in _collapse_keyed_rows(
                        user_mac_rows,
                        ('bucket_start', 'username', 'mac_addr'),
                        ('request_count', 'accept_count', 'reject_count'),
                    ):
                        cur.execute(UPSERT_AUTH_USER_MAC_10M, user_mac_row)
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def bulk_insert_auth_realtime_records(recs: list):
    """写入实时认证路径：首页统计和最近认证记录优先。"""
    return bulk_insert_auth_records(recs, include_realtime=True, include_risk=False)


def bulk_insert_auth_risk_records(recs: list):
    """写入风险分析路径，允许相对实时路径略有延迟。"""
    return bulk_insert_auth_records(recs, include_realtime=False, include_risk=True)


# ── 查询接口 ──────────────────────────────────────────────────────────────────

def _report_since(hours: int) -> str:
    """返回报表窗口起点，并跳过已知不完整的历史采集区间。"""
    since = datetime.now() - timedelta(hours=hours)
    valid_from = getattr(config, 'REPORT_VALID_FROM', '').strip()
    if valid_from:
        try:
            since = max(since, datetime.strptime(valid_from, '%Y-%m-%d %H:%M:%S'))
        except ValueError:
            logger.warning("忽略无效 REPORT_VALID_FROM=%s", valid_from)
    return since.strftime('%Y-%m-%d %H:%M:%S')


def _report_time_filter(
    hours: int,
    start_ts: str = None,
    end_ts: str = None,
    column: str = 'ts',
):
    """生成报表时间过滤条件；日期范围优先，未传则兼容最近 N 小时。"""
    since = start_ts or _report_since(hours)
    where = [f"{column} >= %s"]
    params = [since]
    if end_ts:
        where.append(f"{column} < %s")
        params.append(end_ts)
    return " AND ".join(where), params


def query_stats(hours: int = 24) -> dict:
    """查询过去 N 小时的顶层统计。优先使用10分钟聚合表，避免扫描原始明细。"""
    since = _report_since(hours)
    sql = """
        SELECT
            COALESCE(SUM(request_count), 0) AS total,
            COALESCE(SUM(accept_count), 0) AS accepts,
            COALESCE(SUM(reject_count), 0) AS rejects,
            ROUND(COALESCE(SUM(accept_count), 0) / NULLIF(SUM(request_count), 0) * 100, 1)
                AS accept_rate,
            ROUND(COALESCE(SUM(reject_count), 0) / NULLIF(SUM(request_count), 0) * 100, 1)
                AS reject_rate,
            ROUND(SUM(latency_sum_ms) / NULLIF(SUM(latency_count), 0), 1)
                AS avg_latency_ms
        FROM auth_stat_10m
        WHERE bucket_start >= %s
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (since,))
            row = cur.fetchone()
    return row or {}


def query_health() -> None:
    """执行轻量连接探测，避免健康检查扫描明细日志。"""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")


def query_ingest_status() -> dict:
    """Return lightweight freshness metrics for captured packet timestamps."""
    sql = """
        SELECT
            NOW(3) AS db_now,
            (
                SELECT last_seen
                FROM auth_stat_10m FORCE INDEX (idx_last_seen)
                WHERE last_seen IS NOT NULL
                ORDER BY last_seen DESC
                LIMIT 1
            ) AS last_response_ts,
            NULL AS last_request_ts,
            TIMESTAMPDIFF(
                SECOND,
                (
                    SELECT last_seen
                    FROM auth_stat_10m FORCE INDEX (idx_last_seen)
                    WHERE last_seen IS NOT NULL
                    ORDER BY last_seen DESC
                    LIMIT 1
                ),
                NOW(3)
            ) AS auth_response_lag_seconds,
            NULL AS auth_request_lag_seconds,
            (
                SELECT ts
                FROM acct_log FORCE INDEX (idx_ts)
                ORDER BY ts DESC
                LIMIT 1
            ) AS last_accounting_ts,
            TIMESTAMPDIFF(
                SECOND,
                (
                    SELECT ts
                    FROM acct_log FORCE INDEX (idx_ts)
                    ORDER BY ts DESC
                    LIMIT 1
                ),
                NOW(3)
            ) AS accounting_lag_seconds
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchone() or {}


def query_recent_records(limit: int = 100) -> list:
    """查询最近 N 条认证记录。"""
    sql = """
        SELECT ts, ts AS first_seen, ts AS last_seen, 1 AS request_count,
               username, raw_username, result, reason_zh, mac_addr,
               nas_ip, nas_identifier, nas_port_id, nas_port_type, nas_port,
               latency_ms,
               reply_msg
        FROM auth_recent_log FORCE INDEX (idx_ts)
        ORDER BY ts DESC, id DESC
        LIMIT %s
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (limit,))
            return cur.fetchall()


def _normalize_mac_filter(mac_addr: str) -> str:
    """将常见 MAC 输入格式统一为数据库中的小写冒号格式。"""
    value = (mac_addr or '').strip().lower()
    compact = re.sub(r'[^0-9a-f]', '', value)
    if len(compact) == 12:
        return ':'.join(compact[i:i + 2] for i in range(0, 12, 2))
    return value


def query_auth_records(
    hours: int = 3,
    username: str = '',
    mac_addr: str = '',
    result: int = None,
    limit: int = 500,
) -> list:
    """按时间窗口、账号和 MAC 查询认证记录。"""
    since = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    username = (username or '').strip().upper()
    mac_addr = _normalize_mac_filter(mac_addr)
    params = [since]
    where = ["ts >= %s"]
    index_hint = "FORCE INDEX (idx_ts)"
    if username:
        where.append("username = %s")
        params.append(username)
        index_hint = "FORCE INDEX (idx_user_ts)"
    if mac_addr:
        where.append("mac_addr = %s")
        params.append(mac_addr)
        index_hint = (
            "FORCE INDEX (idx_user_mac_ts)"
            if username else "FORCE INDEX (idx_mac_ts)"
        )
    if result in (2, 3):
        where.append("result = %s")
        params.append(result)
    params.append(limit)
    sql = f"""
        SELECT ts, ts AS first_seen, ts AS last_seen, 1 AS request_count,
               username, raw_username, result, reason_zh, mac_addr,
               nas_ip, nas_identifier, nas_port_id, nas_port_type, nas_port,
               framed_ip, src_ip,
               latency_ms,
               reply_msg
        FROM auth_recent_log {index_hint}
        WHERE {' AND '.join(where)}
        ORDER BY ts DESC, id DESC
        LIMIT %s
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def query_accounting_dashboard(limit: int = 100) -> dict:
    """返回最近 Accounting 样本的轻量会话视图，避免全表时间窗口聚合。"""
    sample_limit = max(limit, min(ACCT_DASHBOARD_SAMPLE_ROWS, 20000))
    stats_sql = """
        WITH sample AS (
            SELECT id, ts, username, raw_username, acct_status_type, acct_session_id,
                   input_octets, input_gigawords, output_octets, output_gigawords,
                   mac_addr, framed_ip, nas_ip, nas_identifier, nas_port_id, nas_port
            FROM acct_log FORCE INDEX (idx_ts)
            ORDER BY ts DESC, id DESC
            LIMIT %s
        ),
        ranked AS (
            SELECT sample.*,
                   CASE
                     WHEN NULLIF(acct_session_id, '') IS NULL THEN CONCAT('event:', id)
                     ELSE CONCAT_WS('|', COALESCE(nas_ip, ''), acct_session_id)
                   END AS session_key,
                   ROW_NUMBER() OVER (
                     PARTITION BY CASE
                       WHEN NULLIF(acct_session_id, '') IS NULL THEN CONCAT('event:', id)
                       ELSE CONCAT_WS('|', COALESCE(nas_ip, ''), acct_session_id)
                     END
                     ORDER BY ts DESC, id DESC
                   ) AS latest_rank
            FROM sample
        )
        SELECT
            (SELECT COUNT(*) FROM sample) AS report_count,
            (SELECT COALESCE(SUM(acct_status_type = 1), 0) FROM sample) AS start_count,
            (SELECT COALESCE(SUM(acct_status_type = 2), 0) FROM sample) AS stop_count,
            COUNT(*) AS session_count,
            COALESCE(SUM(acct_status_type IN (1, 3)), 0) AS active_sessions,
            COALESCE(SUM(COALESCE(input_gigawords, 0) * 4294967296 + COALESCE(input_octets, 0)), 0) AS input_bytes,
            COALESCE(SUM(COALESCE(output_gigawords, 0) * 4294967296 + COALESCE(output_octets, 0)), 0) AS output_bytes,
            COALESCE(SUM(
                COALESCE(input_gigawords, 0) * 4294967296 + COALESCE(input_octets, 0)
                + COALESCE(output_gigawords, 0) * 4294967296 + COALESCE(output_octets, 0)
            ), 0) AS total_bytes,
            MAX(ts) AS last_seen
        FROM ranked
        WHERE latest_rank = 1
    """
    sessions_sql = """
        WITH sample AS (
            SELECT id, ts, username, raw_username, acct_status_type, acct_session_id,
                   input_octets, input_gigawords, output_octets, output_gigawords,
                   mac_addr, framed_ip, nas_ip, nas_identifier, nas_port_id, nas_port
            FROM acct_log FORCE INDEX (idx_ts)
            ORDER BY ts DESC, id DESC
            LIMIT %s
        ),
        ranked AS (
            SELECT sample.*,
                   ROW_NUMBER() OVER (
                     PARTITION BY CASE
                       WHEN NULLIF(acct_session_id, '') IS NULL THEN CONCAT('event:', id)
                       ELSE CONCAT_WS('|', COALESCE(nas_ip, ''), acct_session_id)
                     END
                     ORDER BY ts DESC, id DESC
                   ) AS latest_rank
            FROM sample
        )
        SELECT ts, username, raw_username, acct_status_type, acct_session_id,
               input_octets, input_gigawords, output_octets, output_gigawords,
               COALESCE(input_gigawords, 0) * 4294967296 + COALESCE(input_octets, 0) AS input_bytes,
               COALESCE(output_gigawords, 0) * 4294967296 + COALESCE(output_octets, 0) AS output_bytes,
               COALESCE(input_gigawords, 0) * 4294967296 + COALESCE(input_octets, 0)
                   + COALESCE(output_gigawords, 0) * 4294967296 + COALESCE(output_octets, 0) AS total_bytes,
               mac_addr, framed_ip, nas_ip, nas_identifier, nas_port_id, nas_port
        FROM ranked
        WHERE latest_rank = 1
        ORDER BY ts DESC, id DESC
        LIMIT %s
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(stats_sql, (sample_limit,))
            stats = cur.fetchone() or {}
            cur.execute(sessions_sql, (sample_limit, limit))
            sessions = cur.fetchall()
    return {'stats': stats, 'sessions': sessions}


def query_accounting_records(username: str, hours: int = 48, limit: int = 300) -> list:
    """按账号查询最近 Accounting 历史记录。"""
    username = (username or '').strip().upper()
    if not username:
        return []
    hours = max(1, min(int(hours or 48), int(getattr(config, 'ACCT_RETAIN_DAYS', 2)) * 24))
    limit = min(max(int(limit or 300), 1), 1000)
    since = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    sql = """
        SELECT ts, username, raw_username, acct_status_type, acct_session_id,
               input_octets, input_gigawords, output_octets, output_gigawords,
               COALESCE(input_gigawords, 0) * 4294967296 + COALESCE(input_octets, 0) AS input_bytes,
               COALESCE(output_gigawords, 0) * 4294967296 + COALESCE(output_octets, 0) AS output_bytes,
               COALESCE(input_gigawords, 0) * 4294967296 + COALESCE(input_octets, 0)
                   + COALESCE(output_gigawords, 0) * 4294967296 + COALESCE(output_octets, 0) AS total_bytes,
               mac_addr, calling_sta, framed_ip, nas_ip, nas_identifier,
               nas_port_id, nas_port, src_ip, dst_ip
        FROM acct_log FORCE INDEX (idx_acct_user_ts)
        WHERE username = %s AND ts >= %s
        ORDER BY ts DESC, id DESC
        LIMIT %s
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (username, since, limit))
            return cur.fetchall()


def query_top_reject_users(
    limit: int = 20,
    hours: int = 24,
    start_ts: str = None,
    end_ts: str = None,
) -> list:
    """查询拒绝次数最多的账号。使用账号10分钟汇总表，避免扫描认证明细。"""
    time_where, time_params = _report_time_filter(hours, start_ts, end_ts, column='bucket_start')
    sql = f"""
        SELECT
            username,
            SUM(reject_count)          AS reject_cnt,
            SUM(accept_count)          AS accept_cnt,
            SUM(request_count)         AS total_cnt,
            0                          AS mac_count,
            0                          AS nas_count,
            MAX(main_reason)           AS last_reason,
            MAX(last_seen)             AS last_seen,
            ''                         AS mac_list,
            ''                         AS nas_list
        FROM auth_user_10m FORCE INDEX (idx_user_window)
        WHERE {time_where}
        GROUP BY username
        HAVING reject_cnt > 0
        ORDER BY reject_cnt DESC, last_seen DESC
        LIMIT %s
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (*time_params, limit))
            return cur.fetchall()


def query_risk_accounts(
    hours: int = 24,
    start_ts: str = None,
    end_ts: str = None,
    page: int = 1,
    page_size: int = 100,
    min_count: int = 100,
) -> dict:
    """高请求账号分页列表。使用账号10分钟汇总表，避免扫描认证明细。"""
    time_where, time_params = _report_time_filter(hours, start_ts, end_ts, column='bucket_start')
    page = max(1, int(page or 1))
    page_size = min(max(1, int(page_size or 100)), 500)
    min_count = max(0, int(min_count or 0))
    offset = (page - 1) * page_size
    rows_sql = f"""
        SELECT
            username,
            SUM(request_count) AS total_cnt,
            SUM(reject_count) AS reject_cnt,
            SUM(accept_count) AS accept_cnt,
            '' AS mac_list,
            '' AS nas_list,
            '' AS nas_ports,
            '' AS nas_port_ids,
            MAX(last_seen) AS last_seen
        FROM auth_user_10m FORCE INDEX (idx_user_window)
        WHERE {time_where}
        GROUP BY username
        HAVING total_cnt > %s
        ORDER BY reject_cnt DESC, total_cnt DESC, last_seen DESC
        LIMIT %s OFFSET %s
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(rows_sql, (*time_params, min_count, page_size + 1, offset))
            rows = cur.fetchall()
    has_next = len(rows) > page_size
    rows = rows[:page_size]
    return {
        'rows': rows,
        'total': offset + len(rows) + (1 if has_next else 0),
        'page': page,
        'page_size': page_size,
        'min_count': min_count,
        'has_next': has_next,
    }


def query_multi_mac_accounts(
    hours: int = 24,
    start_ts: str = None,
    end_ts: str = None,
    limit: int = 100,
    min_mac: int = 2,
) -> list:
    """
    同一 GDF/GDC 账号在时间窗口内出现多个 MAC，即多终端拨号风险。

    使用账号-MAC 10分钟汇总表，避免扫描认证明细。
    """
    time_where, time_params = _report_time_filter(hours, start_ts, end_ts, column='bucket_start')
    summary_sql = f"""
        WITH per_mac AS (
            SELECT
                username, mac_addr,
                SUM(request_count) AS total_cnt,
                SUM(accept_count) AS accept_cnt,
                SUM(reject_count) AS reject_cnt,
                MAX(nas_ip) AS nas_ip,
                MAX(last_seen) AS last_seen
            FROM auth_user_mac_10m FORCE INDEX (idx_multi_window)
            WHERE {time_where}
              AND mac_addr <> ''
            GROUP BY username, mac_addr
        )
        SELECT
            username,
            SUM(total_cnt) AS total_cnt,
            SUM(accept_cnt) AS accept_cnt,
            SUM(reject_cnt) AS reject_cnt,
            COUNT(*) AS mac_count,
            COUNT(DISTINCT nas_ip) AS nas_count,
            MAX(last_seen) AS last_seen
        FROM per_mac
        GROUP BY username
        HAVING mac_count >= %s
        ORDER BY mac_count DESC, total_cnt DESC, reject_cnt DESC
        LIMIT %s
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(summary_sql, (*time_params, min_mac, limit))
            summary_rows = cur.fetchall()
    if not summary_rows:
        return []

    usernames = [row['username'] for row in summary_rows]
    placeholders = ','.join(['%s'] * len(usernames))
    detail_sql = f"""
        WITH per_mac_totals AS (
            SELECT
                username, mac_addr,
                SUM(request_count) AS total_cnt,
                SUM(accept_count) AS accept_cnt,
                SUM(reject_count) AS reject_cnt,
                MAX(nas_ip) AS nas_ip,
                MAX(nas_port) AS nas_port,
                MAX(nas_identifier) AS nas_identifier,
                MAX(nas_port_id) AS nas_port_id,
                MAX(last_seen) AS last_seen
            FROM auth_user_mac_10m FORCE INDEX (idx_multi_window)
            WHERE {time_where}
              AND username IN ({placeholders})
              AND mac_addr <> ''
            GROUP BY username, mac_addr
        )
        SELECT
            username, mac_addr, total_cnt, accept_cnt, reject_cnt,
            nas_ip, nas_identifier, nas_port_id, nas_port,
            last_seen
        FROM per_mac_totals totals
        ORDER BY username, last_seen DESC
    """
    detail_params = (*time_params, *usernames)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(detail_sql, detail_params)
            detail_rows = cur.fetchall()

    details_by_user = {}
    for detail in detail_rows:
        details_by_user.setdefault(detail.pop('username'), []).append(detail)
    for summary in summary_rows:
        summary['mac_details'] = details_by_user.get(summary['username'], [])
    return summary_rows


def query_reason_distribution(hours: int = 24) -> list:
    """拒绝原因分布。使用低维原因统计表。"""
    since = _report_since(hours)
    sql = """
        SELECT reason_zh, SUM(request_count) AS cnt
        FROM auth_reason_10m FORCE INDEX (idx_reason_window)
        WHERE bucket_start >= %s AND result = 3
        GROUP BY reason_zh
        ORDER BY cnt DESC
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (since,))
            return cur.fetchall()


def query_nas_distribution(hours: int = 24) -> list:
    """按 NAS-IP-Address (Attr 4) 聚合的 NAS 设备认证分布。使用低维NAS统计表。"""
    since = _report_since(hours)
    sql = """
        SELECT nas_ip,
               SUM(request_count) AS total,
               SUM(accept_count)  AS accepts,
               SUM(reject_count)  AS rejects,
               MAX(last_seen)     AS last_seen
        FROM auth_nas_10m FORCE INDEX (idx_nas_window)
        WHERE bucket_start >= %s AND nas_ip <> ''
        GROUP BY nas_ip
        ORDER BY total DESC
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (since,))
            return cur.fetchall()


def query_timeline(hours: int = 6, interval_min: int = 5) -> list:
    """按时间分段统计认证量（折线图数据）。底层使用低维总量统计表。"""
    since = _report_since(hours)
    bucket_seconds = max(60, min(interval_min, 60) * 60)
    sql = """
        SELECT
            DATE_FORMAT(
                FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(bucket_start) / %s) * %s),
                '%%Y-%%m-%%d %%H:%%i'
            ) AS bucket,
            SUM(accept_count) AS accepts,
            SUM(reject_count) AS rejects
        FROM auth_stat_10m
        WHERE bucket_start >= %s
        GROUP BY bucket
        ORDER BY bucket
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (bucket_seconds, bucket_seconds, since))
            return cur.fetchall()


def query_user_detail(username: str, limit: int = 50) -> list:
    """查询单个账号的认证记录。"""
    sql = """
        SELECT ts, ts AS first_seen, ts AS last_seen, 1 AS request_count,
               raw_username, result, reason_zh, mac_addr, nas_ip,
               nas_identifier, nas_port_id, nas_port_type, nas_port,
               reply_msg,
               latency_ms,
               framed_ip
        FROM auth_recent_log FORCE INDEX (idx_user_ts)
        WHERE username = %s
        ORDER BY ts DESC, id DESC
        LIMIT %s
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (username, limit))
            return cur.fetchall()


def _table_exists(cur, table: str) -> bool:
    cur.execute(
        """
        SELECT COUNT(*) AS cnt
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
        """,
        (table,),
    )
    row = cur.fetchone() or {}
    return int(row.get('cnt') or 0) > 0


def _table_partitions(cur, table: str) -> set:
    cur.execute(
        """
        SELECT PARTITION_NAME
        FROM information_schema.PARTITIONS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
          AND PARTITION_NAME IS NOT NULL
        """,
        (table,),
    )
    return {row['PARTITION_NAME'] for row in cur.fetchall()}


def _ensure_future_partitions(cur, table: str, days_ahead: int = None):
    partitions = _table_partitions(cur, table)
    if not partitions or 'pmax' not in partitions:
        return False

    days_ahead = PARTITION_FUTURE_DAYS if days_ahead is None else max(0, int(days_ahead))
    today = datetime.now().date()
    for offset in range(days_ahead + 1):
        day = today + timedelta(days=offset)
        name = f"p{day:%Y%m%d}"
        if name in partitions:
            continue
        next_day = day + timedelta(days=1)
        cur.execute(
            f"""
            ALTER TABLE {table} REORGANIZE PARTITION pmax INTO (
                PARTITION {name} VALUES LESS THAN ('{next_day:%Y-%m-%d}'),
                PARTITION pmax VALUES LESS THAN (MAXVALUE)
            )
            """
        )
        partitions.add(name)
    return True


def _cleanup_table_partitions(cur, table: str, cutoff_dt: datetime) -> int | None:
    partitions = _table_partitions(cur, table)
    if not partitions:
        return None

    _ensure_future_partitions(cur, table)
    partitions = _table_partitions(cur, table)
    cutoff_day = cutoff_dt.date()
    drop_names = []
    for name in partitions:
        match = re.fullmatch(r'p(\d{8})', name or '')
        if not match:
            continue
        day = datetime.strptime(match.group(1), '%Y%m%d').date()
        if day < cutoff_day:
            drop_names.append(name)
    if not drop_names:
        return 0

    drop_sql = ', '.join(sorted(drop_names))
    cur.execute(f"ALTER TABLE {table} DROP PARTITION {drop_sql}")
    logger.info("%s 分区清理 drop_partitions=%s", table, drop_sql)
    return len(drop_names)


def _delete_old_rows_batched(
    cur,
    table: str,
    column: str,
    cutoff: str,
    batch_size: int,
    max_batches: int = None,
) -> int:
    if not _table_exists(cur, table):
        return 0
    deleted = 0
    batch_size = max(100, int(batch_size or 5000))
    batches = 0
    while True:
        cur.execute(
            f"DELETE FROM {table} WHERE {column} < %s ORDER BY {column} LIMIT %s",
            (cutoff, batch_size),
        )
        batches += 1
        deleted += cur.rowcount
        if cur.rowcount < batch_size:
            break
        if max_batches and batches >= max_batches:
            logger.info(
                "清理 %s 达到单次批次上限 max_batches=%s deleted=%s",
                table, max_batches, deleted,
            )
            break
    return deleted


def cleanup_old_records(retain_days: int = None):
    """清理超过保留期的历史记录"""
    days = retain_days or config.RETAIN_DAYS
    cutoff_dt = datetime.now() - timedelta(days=days)
    cutoff = cutoff_dt.strftime('%Y-%m-%d %H:%M:%S')
    auth_tables = (
        ('auth_stat_10m', 'bucket_start', cutoff),
        ('auth_reason_10m', 'bucket_start', cutoff),
        ('auth_nas_10m', 'bucket_start', cutoff),
    )
    user_days = int(getattr(config, 'AUTH_USER_RETAIN_DAYS', 30))
    user_cutoff_dt = datetime.now() - timedelta(days=user_days)
    user_cutoff = user_cutoff_dt.strftime('%Y-%m-%d %H:%M:%S')
    user_mac_days = int(getattr(config, 'AUTH_USER_MAC_RETAIN_DAYS', 30))
    user_mac_cutoff_dt = datetime.now() - timedelta(days=user_mac_days)
    user_mac_cutoff = user_mac_cutoff_dt.strftime('%Y-%m-%d %H:%M:%S')
    acct_days = int(getattr(config, 'ACCT_RETAIN_DAYS', 30))
    acct_cutoff_dt = datetime.now() - timedelta(days=acct_days)
    acct_cutoff = acct_cutoff_dt.strftime('%Y-%m-%d %H:%M:%S')
    deleted = 0
    dropped = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for table, table_cutoff_dt, table_cutoff in (
                ('auth_recent_log', cutoff_dt, cutoff),
                ('acct_log', acct_cutoff_dt, acct_cutoff),
                ('auth_user_10m', user_cutoff_dt, user_cutoff),
                ('auth_user_mac_10m', user_mac_cutoff_dt, user_mac_cutoff),
            ):
                dropped_partitions = _cleanup_table_partitions(cur, table, table_cutoff_dt)
                if dropped_partitions is None:
                    batch_size = max(100, int(getattr(config, 'AUTH_CLEANUP_BATCH_SIZE', 5000)))
                    max_batches = max(1, int(getattr(config, 'AUTH_CLEANUP_MAX_BATCHES', 10)))
                    if table == 'acct_log':
                        batch_size = max(100, int(getattr(config, 'ACCT_CLEANUP_BATCH_SIZE', 1000)))
                        max_batches = max(1, int(getattr(config, 'ACCT_CLEANUP_MAX_BATCHES', 10)))
                    column = 'bucket_start' if table in ('auth_user_10m', 'auth_user_mac_10m') else 'ts'
                    deleted += _delete_old_rows_batched(
                        cur, table, column, table_cutoff, batch_size, max_batches
                    )
                else:
                    dropped += dropped_partitions

            auth_batch_size = max(100, int(getattr(config, 'AUTH_CLEANUP_BATCH_SIZE', 5000)))
            auth_max_batches = max(1, int(getattr(config, 'AUTH_CLEANUP_MAX_BATCHES', 10)))
            for table, column, table_cutoff in auth_tables:
                deleted += _delete_old_rows_batched(
                    cur, table, column, table_cutoff, auth_batch_size, auth_max_batches
                )
    logger.info(
        "清理历史记录 auth_cutoff=%s acct_cutoff=%s dropped_partitions=%d deleted=%d",
        cutoff, acct_cutoff, dropped, deleted,
    )
    return deleted
