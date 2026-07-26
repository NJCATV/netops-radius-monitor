"""Write a bounded synthetic sample through the real durable sink."""

import time

from clickhouse_sink import RadiusClickHouseSink


def main():
    sink = RadiusClickHouseSink()
    sink.start()
    marker = "__RADIUS_MIGRATION_PROBE__"
    sink.put({
        "username": marker,
        "raw_username": marker,
        "nas_ip": "127.0.0.1",
        "resp_ts": "2026-07-26 11:40:00.000",
        "req_ts": "2026-07-26 11:39:59.990",
        "result_code": 2,
        "result": "Access-Accept",
        "matched": True,
    })
    accounting = {
        "record_type": "accounting",
        "username": marker,
        "raw_username": marker,
        "nas_ip": "127.0.0.1",
        "acct_session_id": "migration-probe-session",
        "acct_status_type": 3,
    }
    sink.put({**accounting, "ts": "2026-07-26 11:40:01.000", "input_octets": 100, "output_octets": 200})
    sink.put({**accounting, "ts": "2026-07-26 11:45:01.000", "input_octets": 160, "output_octets": 290})
    deadline = time.time() + 20
    while sink.sent < 3 and time.time() < deadline:
        time.sleep(0.1)
    snapshot = sink.snapshot()
    sink.stop()
    if sink.sent < 3 or sink.pending_count() != 0:
        raise SystemExit(f"sample failed: {snapshot}")
    print("sample_ok sent=3 pending=0")


if __name__ == "__main__":
    main()
