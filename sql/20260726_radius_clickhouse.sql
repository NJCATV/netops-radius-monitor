CREATE DATABASE IF NOT EXISTS radius_monitor_ch;

CREATE TABLE IF NOT EXISTS radius_monitor_ch.radius_events
(
    event_id String,
    event_time DateTime64(3, 'Asia/Shanghai'),
    event_type LowCardinality(String),
    username String,
    raw_username String,
    subscriber_id String,
    nas_ip String,
    nas_identifier String,
    nas_port UInt32,
    nas_port_id String,
    nas_port_type UInt32,
    service_type UInt32,
    framed_protocol UInt32,
    calling_sta String,
    mac_addr String,
    called_sta String,
    framed_ip String,
    framed_ip_netmask String,
    class_attr String,
    src_ip String,
    dst_ip String,
    src_port UInt16,
    dst_port UInt16,
    packet_identifier UInt8,
    result_code UInt8,
    result LowCardinality(String),
    reply_raw String,
    reason_zh LowCardinality(String),
    risk LowCardinality(String),
    acct_status_type UInt8,
    acct_session_id String,
    acct_multi_session_id String,
    acct_authentic UInt32,
    acct_session_time UInt32,
    connect_info String,
    error_cause UInt32,
    input_total UInt64,
    output_total UInt64,
    input_delta UInt64,
    output_delta UInt64,
    input_packets UInt64,
    output_packets UInt64,
    terminate_cause UInt32,
    event_timestamp UInt32,
    acct_delay_time UInt32,
    input_average_rate UInt64,
    output_average_rate UInt64,
    product_id String,
    counter_rollback UInt8,
    ingested_at DateTime64(3, 'Asia/Shanghai') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(event_time)
ORDER BY (event_type, toDate(event_time), username, event_time, event_id)
TTL toDateTime(event_time) + INTERVAL 180 DAY DELETE
SETTINGS index_granularity = 8192;

ALTER TABLE radius_monitor_ch.radius_events
    ADD INDEX IF NOT EXISTS idx_nas_ip nas_ip TYPE bloom_filter GRANULARITY 4;
ALTER TABLE radius_monitor_ch.radius_events
    ADD INDEX IF NOT EXISTS idx_mac mac_addr TYPE bloom_filter GRANULARITY 4;
ALTER TABLE radius_monitor_ch.radius_events
    ADD INDEX IF NOT EXISTS idx_session acct_session_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE radius_monitor_ch.radius_events
    ADD INDEX IF NOT EXISTS idx_username username TYPE bloom_filter GRANULARITY 4;
ALTER TABLE radius_monitor_ch.radius_events
    ADD INDEX IF NOT EXISTS idx_subscriber subscriber_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE radius_monitor_ch.radius_events
    ADD INDEX IF NOT EXISTS idx_framed_ip framed_ip TYPE bloom_filter GRANULARITY 4;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS subscriber_id String AFTER raw_username;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS acct_delay_time UInt32 AFTER event_timestamp;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS input_average_rate UInt64 AFTER acct_delay_time;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS output_average_rate UInt64 AFTER input_average_rate;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS product_id String AFTER output_average_rate;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS counter_rollback UInt8 AFTER product_id;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS service_type UInt32 AFTER nas_port_type;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS framed_protocol UInt32 AFTER service_type;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS framed_ip_netmask String AFTER framed_ip;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS class_attr String AFTER framed_ip_netmask;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS src_port UInt16 AFTER dst_ip;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS dst_port UInt16 AFTER src_port;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS packet_identifier UInt8 AFTER dst_port;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS acct_multi_session_id String AFTER acct_session_id;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS acct_authentic UInt32 AFTER acct_multi_session_id;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS connect_info String AFTER acct_session_time;
ALTER TABLE radius_monitor_ch.radius_events ADD COLUMN IF NOT EXISTS error_cause UInt32 AFTER connect_info;

CREATE TABLE IF NOT EXISTS radius_monitor_ch.radius_collector_metrics
(
    event_id String,
    metric_time DateTime('Asia/Shanghai'),
    captured_packets UInt64,
    parsed_records UInt64,
    auth_records UInt64,
    accounting_records UInt64,
    control_records UInt64,
    challenge_records UInt64,
    interim_sampled_out UInt64,
    pending_auth_requests UInt64,
    unmatched_auth_responses UInt64,
    expired_auth_requests UInt64,
    pending_auth_evictions UInt64,
    malformed_packets UInt64,
    accounting_responses UInt64,
    unknown_radius_codes UInt64,
    tcpdump_captured UInt64,
    tcpdump_received_by_filter UInt64,
    tcpdump_kernel_dropped UInt64,
    sink_accepted UInt64,
    sink_spooled UInt64,
    sink_sent UInt64,
    sink_retries UInt64,
    spool_pending Int64,
    spool_bytes UInt64,
    last_error String,
    ingested_at DateTime64(3, 'Asia/Shanghai') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(metric_time)
ORDER BY (metric_time, event_id)
TTL toDateTime(metric_time) + INTERVAL 365 DAY DELETE;

ALTER TABLE radius_monitor_ch.radius_collector_metrics
    ADD COLUMN IF NOT EXISTS tcpdump_captured UInt64 AFTER pending_auth_requests;
ALTER TABLE radius_monitor_ch.radius_collector_metrics
    ADD COLUMN IF NOT EXISTS tcpdump_received_by_filter UInt64 AFTER tcpdump_captured;
ALTER TABLE radius_monitor_ch.radius_collector_metrics
    ADD COLUMN IF NOT EXISTS tcpdump_kernel_dropped UInt64 AFTER tcpdump_received_by_filter;
ALTER TABLE radius_monitor_ch.radius_collector_metrics
    ADD COLUMN IF NOT EXISTS control_records UInt64 AFTER accounting_records;
ALTER TABLE radius_monitor_ch.radius_collector_metrics
    ADD COLUMN IF NOT EXISTS challenge_records UInt64 AFTER control_records;
ALTER TABLE radius_monitor_ch.radius_collector_metrics
    ADD COLUMN IF NOT EXISTS unmatched_auth_responses UInt64 AFTER pending_auth_requests;
ALTER TABLE radius_monitor_ch.radius_collector_metrics
    ADD COLUMN IF NOT EXISTS expired_auth_requests UInt64 AFTER unmatched_auth_responses;
ALTER TABLE radius_monitor_ch.radius_collector_metrics
    ADD COLUMN IF NOT EXISTS pending_auth_evictions UInt64 AFTER expired_auth_requests;
ALTER TABLE radius_monitor_ch.radius_collector_metrics
    ADD COLUMN IF NOT EXISTS malformed_packets UInt64 AFTER pending_auth_evictions;
ALTER TABLE radius_monitor_ch.radius_collector_metrics
    ADD COLUMN IF NOT EXISTS accounting_responses UInt64 AFTER malformed_packets;
ALTER TABLE radius_monitor_ch.radius_collector_metrics
    ADD COLUMN IF NOT EXISTS unknown_radius_codes UInt64 AFTER accounting_responses;

CREATE VIEW IF NOT EXISTS radius_monitor_ch.radius_auth_recent AS
SELECT *
FROM radius_monitor_ch.radius_events
WHERE event_type = 'auth';

CREATE VIEW IF NOT EXISTS radius_monitor_ch.radius_accounting_recent AS
SELECT *
FROM radius_monitor_ch.radius_events
WHERE event_type = 'accounting';

CREATE VIEW IF NOT EXISTS radius_monitor_ch.radius_control_recent AS
SELECT *
FROM radius_monitor_ch.radius_events
WHERE event_type = 'control';

-- Long-term operational rollups keep trend/evidence queries cheap even when
-- raw packet-derived events grow to tens of millions of rows per day.
CREATE TABLE IF NOT EXISTS radius_monitor_ch.radius_auth_rollup_10m
(
    bucket DateTime('Asia/Shanghai'),
    username String,
    mac_addr String,
    nas_ip String,
    reason_zh LowCardinality(String),
    requests AggregateFunction(sum, UInt64),
    accepts AggregateFunction(sum, UInt64),
    rejects AggregateFunction(sum, UInt64),
    challenges AggregateFunction(sum, UInt64),
    last_seen AggregateFunction(max, DateTime64(3, 'Asia/Shanghai'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket,username,mac_addr,nas_ip,reason_zh)
TTL bucket + INTERVAL 400 DAY DELETE;

CREATE TABLE IF NOT EXISTS radius_monitor_ch.radius_accounting_rollup_1h
(
    bucket DateTime('Asia/Shanghai'),
    username String,
    mac_addr String,
    nas_ip String,
    input_bytes AggregateFunction(sum, UInt64),
    output_bytes AggregateFunction(sum, UInt64),
    starts AggregateFunction(sum, UInt64),
    stops AggregateFunction(sum, UInt64),
    interims AggregateFunction(sum, UInt64),
    nas_restarts AggregateFunction(sum, UInt64),
    sessions AggregateFunction(uniqCombined64, String),
    last_seen AggregateFunction(max, DateTime64(3, 'Asia/Shanghai'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket,username,mac_addr,nas_ip)
TTL bucket + INTERVAL 400 DAY DELETE;

-- Do not attach materialized views to radius_events under radius_writer.
-- That account intentionally has INSERT-only privileges; ClickHouse would
-- evaluate the source SELECT as the invoker and block all ingestion. Populate
-- these rollup tables from a separately scheduled least-privilege aggregation
-- account after its operational window and backfill policy are approved.
