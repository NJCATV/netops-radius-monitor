"""Durable ClickHouse sink for the RADIUS packet collector.

Records first enter a local SQLite WAL spool.  The sender removes them only
after ClickHouse confirms the insert, so a database outage does not turn into
silent packet-analysis data loss.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import requests

import config

logger = logging.getLogger(__name__)

EVENT_COLUMNS = (
    "event_id", "event_time", "event_type", "username", "raw_username", "subscriber_id",
    "nas_ip", "nas_identifier", "nas_port", "nas_port_id", "nas_port_type",
    "service_type", "framed_protocol", "calling_sta", "mac_addr", "called_sta",
    "framed_ip", "framed_ip_netmask", "class_attr",
    "src_ip", "dst_ip", "src_port", "dst_port", "packet_identifier",
    "result_code", "result", "reply_raw", "reason_zh", "risk",
    "acct_status_type", "acct_session_id", "acct_multi_session_id",
    "acct_authentic", "acct_session_time", "connect_info", "error_cause",
    "input_total", "output_total", "input_delta", "output_delta",
    "input_packets", "output_packets", "terminate_cause", "event_timestamp",
    "acct_delay_time", "input_average_rate", "output_average_rate", "product_id",
    "counter_rollback",
)


def _text(value) -> str:
    return "" if value is None else str(value)


def _uint(value) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _radius_total(octets, gigawords) -> int:
    return ((_uint(gigawords) << 32) + _uint(octets)) * max(1, config.RADIUS_COUNTER_SCALE)


def _event_id(record: dict) -> str:
    stable = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


class RadiusClickHouseSink:
    """Asynchronously spool and deliver RADIUS events without dual writes."""

    def __init__(self):
        spool = Path(config.SPOOL_PATH)
        spool.parent.mkdir(parents=True, exist_ok=True)
        self.spool_path = spool
        self.queue: queue.Queue[tuple[str, dict]] = queue.Queue(maxsize=config.SPOOL_QUEUE_SIZE)
        self._stop = threading.Event()
        self._wake_sender = threading.Event()
        self._spool_thread = threading.Thread(target=self._spool_loop, name="radius-spool", daemon=True)
        self._sender_thread = threading.Thread(target=self._sender_loop, name="radius-clickhouse", daemon=True)
        self.accepted = 0
        self.spooled = 0
        self.sent = 0
        self.retries = 0
        self.last_error = ""
        self._last_state_cleanup = 0.0
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(str(self.spool_path), timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS spool (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE(target, event_id)
                );
                CREATE INDEX IF NOT EXISTS idx_spool_target_id ON spool(target, id);
                CREATE TABLE IF NOT EXISTS session_state (
                    session_key TEXT PRIMARY KEY,
                    input_total INTEGER NOT NULL,
                    output_total INTEGER NOT NULL,
                    last_event_time TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS seen_events (
                    event_id TEXT PRIMARY KEY,
                    seen_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_seen_events_time ON seen_events(seen_at);
                """
            )

    def start(self):
        self._spool_thread.start()
        self._sender_thread.start()
        logger.info("ClickHouse 持久化写入已启动 spool=%s pending=%d", self.spool_path, self.pending_count())

    def put(self, record: dict):
        # Blocking here is intentional: backpressure is observable and preferable
        # to silently discarding authentication/accounting evidence.
        self.queue.put(("radius_events", dict(record)))
        self.accepted += 1

    def publish_metrics(self, metrics: dict):
        payload = dict(metrics)
        payload.setdefault("metric_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        payload.update(self.snapshot())
        metric_id = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        payload["event_id"] = metric_id
        self.queue.put(("radius_collector_metrics", payload))

    def stop(self, timeout=20):
        self._stop.set()
        self._spool_thread.join(timeout=timeout)
        self._wake_sender.set()
        self._sender_thread.join(timeout=timeout)
        logger.info("ClickHouse 写入停止 accepted=%d spooled=%d sent=%d pending=%d",
                    self.accepted, self.spooled, self.sent, self.pending_count())

    def pending_count(self) -> int:
        try:
            with self._connection() as conn:
                return int(conn.execute("SELECT count(*) FROM spool").fetchone()[0])
        except Exception:
            return -1

    def snapshot(self) -> dict:
        return {
            "sink_accepted": self.accepted,
            "sink_spooled": self.spooled,
            "sink_sent": self.sent,
            "sink_retries": self.retries,
            "spool_pending": self.pending_count(),
            "spool_bytes": self._spool_bytes(),
            "last_error": self.last_error[:500],
        }

    def _spool_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(f"{self.spool_path}{suffix}")
            except OSError:
                pass
        return total

    def _spool_loop(self):
        conn = self._connect()
        try:
            while not self._stop.is_set() or not self.queue.empty():
                batch = []
                try:
                    batch.append(self.queue.get(timeout=0.25))
                except queue.Empty:
                    continue
                while len(batch) < 500:
                    try:
                        batch.append(self.queue.get_nowait())
                    except queue.Empty:
                        break
                try:
                    with conn:
                        for target, raw in batch:
                            payload = self._normalize_event(conn, raw) if target == "radius_events" else raw
                            if payload is None:
                                continue
                            event_id = payload["event_id"]
                            conn.execute(
                                "INSERT OR IGNORE INTO spool(target,event_id,payload,created_at) VALUES(?,?,?,?)",
                                (target, event_id, json.dumps(payload, ensure_ascii=False, separators=(",", ":")), time.time()),
                            )
                    self.spooled += len(batch)
                    if self._spool_bytes() > config.SPOOL_MAX_BYTES:
                        logger.critical("SQLite spool 超过上限 %d bytes，采集将施加背压但不丢弃", config.SPOOL_MAX_BYTES)
                        while self._spool_bytes() > config.SPOOL_MAX_BYTES and not self._stop.is_set():
                            self._wake_sender.set()
                            time.sleep(1)
                    self._wake_sender.set()
                except Exception as exc:
                    self.last_error = f"spool: {exc}"
                    logger.exception("本地持久化失败，将重试: %s", exc)
                    for item in batch:
                        self.queue.put(item)
                    time.sleep(1)
        finally:
            conn.close()

    def _normalize_event(self, conn, raw: dict) -> dict:
        source_event_id = _event_id(raw)
        if conn.execute("SELECT 1 FROM seen_events WHERE event_id=?", (source_event_id,)).fetchone():
            return None
        conn.execute("INSERT INTO seen_events(event_id,seen_at) VALUES(?,?)", (source_event_id, time.time()))
        now = time.time()
        if now - self._last_state_cleanup >= 3600:
            conn.execute("DELETE FROM seen_events WHERE seen_at < ?", (now - 6 * 3600,))
            conn.execute("DELETE FROM session_state WHERE updated_at < ?", (now - 2 * 86400,))
            self._last_state_cleanup = now
        is_acct = raw.get("record_type") == "accounting"
        record_type = raw.get("record_type")
        is_control = record_type == "control"
        event_time = raw.get("ts") if (is_acct or is_control) else raw.get("resp_ts") or raw.get("req_ts")
        input_total = _radius_total(raw.get("input_octets"), raw.get("input_gigawords")) if is_acct else 0
        output_total = _radius_total(raw.get("output_octets"), raw.get("output_gigawords")) if is_acct else 0
        input_delta = output_delta = 0
        counter_rollback = 0
        session_id = _text(raw.get("acct_session_id"))
        if is_acct and session_id:
            session_key = "|".join((
                _text(raw.get("username")),
                _text(raw.get("nas_ip") or raw.get("src_ip")),
                session_id,
            ))
            previous = conn.execute(
                "SELECT input_total,output_total FROM session_state WHERE session_key=?", (session_key,)
            ).fetchone()
            if previous:
                counter_rollback = int(
                    input_total < int(previous[0]) or output_total < int(previous[1])
                )
                input_delta = input_total - int(previous[0]) if input_total >= int(previous[0]) else input_total
                output_delta = output_total - int(previous[1]) if output_total >= int(previous[1]) else output_total
            conn.execute(
                """INSERT INTO session_state(session_key,input_total,output_total,last_event_time,updated_at)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(session_key) DO UPDATE SET input_total=excluded.input_total,
                   output_total=excluded.output_total,last_event_time=excluded.last_event_time,
                   updated_at=excluded.updated_at""",
                (session_key, input_total, output_total, _text(event_time), time.time()),
            )
            if _uint(raw.get("acct_status_type")) == 2:
                conn.execute("DELETE FROM session_state WHERE session_key=?", (session_key,))

        normalized = {
            "event_time": _text(event_time),
            "event_type": "accounting" if is_acct else "control" if is_control else "auth",
            "username": _text(raw.get("username")),
            "raw_username": _text(raw.get("raw_username")),
            "subscriber_id": _text(raw.get("subscriber_id")),
            "nas_ip": _text(raw.get("nas_ip")),
            "nas_identifier": _text(raw.get("nas_identifier")),
            "nas_port": _uint(raw.get("nas_port")),
            "nas_port_id": _text(raw.get("nas_port_id")),
            "nas_port_type": _uint(raw.get("nas_port_type")),
            "service_type": _uint(raw.get("service_type")),
            "framed_protocol": _uint(raw.get("framed_protocol")),
            "calling_sta": _text(raw.get("calling_sta")),
            "mac_addr": _text(raw.get("mac_addr")),
            "called_sta": _text(raw.get("called_sta")),
            "framed_ip": _text(raw.get("framed_ip")),
            "framed_ip_netmask": _text(raw.get("framed_ip_netmask")),
            "class_attr": _text(raw.get("class_attr")),
            "src_ip": _text(raw.get("src_ip")),
            "dst_ip": _text(raw.get("dst_ip")),
            "src_port": _uint(raw.get("src_port")),
            "dst_port": _uint(raw.get("dst_port")),
            "packet_identifier": _uint(raw.get("packet_identifier")),
            "result_code": _uint(raw.get("result_code")),
            "result": _text(raw.get("result")),
            "reply_raw": _text(raw.get("reply_raw")),
            "reason_zh": _text(raw.get("reason_zh")),
            "risk": _text(raw.get("risk")),
            "acct_status_type": _uint(raw.get("acct_status_type")),
            "acct_session_id": session_id,
            "acct_multi_session_id": _text(raw.get("acct_multi_session_id")),
            "acct_authentic": _uint(raw.get("acct_authentic")),
            "acct_session_time": _uint(raw.get("acct_session_time")),
            "connect_info": _text(raw.get("connect_info")),
            "error_cause": _uint(raw.get("error_cause")),
            "input_total": input_total,
            "output_total": output_total,
            "input_delta": max(0, input_delta),
            "output_delta": max(0, output_delta),
            "input_packets": _uint(raw.get("input_packets")),
            "output_packets": _uint(raw.get("output_packets")),
            "terminate_cause": _uint(raw.get("terminate_cause")),
            "event_timestamp": _uint(raw.get("event_timestamp")),
            "acct_delay_time": _uint(raw.get("acct_delay_time")),
            "input_average_rate": _uint(raw.get("input_average_rate")),
            "output_average_rate": _uint(raw.get("output_average_rate")),
            "product_id": _text(raw.get("product_id")),
            "counter_rollback": counter_rollback,
        }
        normalized["event_id"] = source_event_id
        return {column: normalized[column] for column in EVENT_COLUMNS}

    def _sender_loop(self):
        delay = 1.0
        while not self._stop.is_set() or self.pending_count() > 0:
            sent_any = False
            try:
                with self._connection() as conn:
                    for target in ("radius_events", "radius_collector_metrics"):
                        rows = conn.execute(
                            "SELECT id,payload FROM spool WHERE target=? ORDER BY id LIMIT ?",
                            (target, config.CLICKHOUSE_BATCH_SIZE),
                        ).fetchall()
                        if not rows:
                            continue
                        payload = "\n".join(item[1] for item in rows) + "\n"
                        self._insert(target, payload)
                        self.last_error = ""
                        ids = [item[0] for item in rows]
                        with conn:
                            conn.executemany("DELETE FROM spool WHERE id=?", ((item,) for item in ids))
                        self.sent += len(rows)
                        sent_any = True
                if sent_any:
                    delay = 1.0
                    continue
            except Exception as exc:
                self.retries += 1
                self.last_error = f"clickhouse: {exc}"
                if self.retries == 1 or self.retries % 10 == 0:
                    logger.error("ClickHouse 写入失败，数据保留在 spool 等待重放: %s", exc)
                delay = min(delay * 2, 30)
            self._wake_sender.wait(delay)
            self._wake_sender.clear()

    def _insert(self, table: str, payload: str):
        query = f"INSERT INTO {config.CLICKHOUSE_DATABASE}.{table} FORMAT JSONEachRow"
        response = requests.post(
            config.CLICKHOUSE_URL,
            params={"query": query},
            data=payload.encode("utf-8"),
            auth=(config.CLICKHOUSE_USER, config.CLICKHOUSE_PASSWORD),
            timeout=(config.CLICKHOUSE_CONNECT_TIMEOUT, config.CLICKHOUSE_READ_TIMEOUT),
            verify=config.CLICKHOUSE_VERIFY_TLS,
            headers={"Content-Type": "application/x-ndjson"},
        )
        if response.status_code != 200:
            raise RuntimeError(f"HTTP {response.status_code}: {response.text[:500]}")
