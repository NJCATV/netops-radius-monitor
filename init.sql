-- MySQL 初始化脚本
-- 建库时自动执行（由 docker-entrypoint-initdb.d 触发）

SET NAMES utf8mb4;
SET time_zone = '+08:00';

USE radius_monitor;

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
    PARTITION pmax VALUES LESS THAN (MAXVALUE)
);

CREATE TABLE IF NOT EXISTS acct_log (
    id                BIGINT       NOT NULL AUTO_INCREMENT,
    ts                DATETIME(3)  NOT NULL COMMENT '计费报文时间',
    username          VARCHAR(128) NULL COMMENT '归一化账号名',
    raw_username      VARCHAR(256) NULL COMMENT '原始RADIUS User-Name',
    acct_status_type  INT          NULL COMMENT '1=Start 2=Stop 3=Interim-Update',
    acct_session_id   VARCHAR(128) NULL,
    input_octets      BIGINT       NULL,
    output_octets     BIGINT       NULL,
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
    PARTITION pmax VALUES LESS THAN (MAXVALUE)
);

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='认证10分钟低维总量统计';
