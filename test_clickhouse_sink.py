import importlib
import os
import tempfile
import time
import unittest
from unittest.mock import patch
import struct


class FakeResponse:
    status_code = 200
    text = ""


class ClickHouseSinkTest(unittest.TestCase):
    @staticmethod
    def _avp(attr_type, value):
        if isinstance(value, int):
            value = struct.pack("!I", value)
        return bytes([attr_type, len(value) + 2]) + value

    @classmethod
    def _packet(cls, code, identifier, *attributes):
        body = b"".join(attributes)
        return bytes([code, identifier]) + struct.pack("!H", 20 + len(body)) + b"\x00" * 16 + body

    def test_huawei_vsa_is_preserved_and_preferred(self):
        import parser
        subscriber = b"GDF12345678"
        mac = b"AA-BB-CC-DD-EE-FF"
        vsa_subscriber = struct.pack("!I", 2011) + bytes([138, len(subscriber) + 2]) + subscriber
        vsa_mac = struct.pack("!I", 2011) + bytes([153, len(mac) + 2]) + mac
        attributes = (
            bytes([26, len(vsa_subscriber) + 2]) + vsa_subscriber
            + bytes([26, len(vsa_mac) + 2]) + vsa_mac
        )
        attrs = parser.parse_radius_attributes(attributes)
        self.assertEqual(
            parser._vsa_text(attrs, 2011, 138), "GDF12345678"
        )
        self.assertEqual(
            parser.normalize_mac(parser._vsa_text(attrs, 2011, 153)),
            "aa:bb:cc:dd:ee:ff",
        )
        self.assertEqual(parser.normalize_mac("aabb.ccdd.eeff"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parser.normalize_mac("AABBCCDDEEFF"), "aa:bb:cc:dd:ee:ff")

    def test_spool_replay_and_accounting_delta(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["SPOOL_PATH"] = os.path.join(temp_dir, "spool.sqlite3")
            os.environ["CLICKHOUSE_BATCH_SIZE"] = "50"
            os.environ["RADIUS_COUNTER_SCALE"] = "1024"
            import config
            import clickhouse_sink
            importlib.reload(config)
            importlib.reload(clickhouse_sink)

            payloads = []

            def successful_post(*args, **kwargs):
                payloads.append(kwargs["data"].decode("utf-8"))
                return FakeResponse()

            sink = clickhouse_sink.RadiusClickHouseSink()
            with patch.object(clickhouse_sink.requests, "post", side_effect=successful_post):
                sink.start()
                base = {
                    "record_type": "accounting",
                    "username": "GDF12345",
                    "nas_ip": "10.0.0.1",
                    "acct_session_id": "session-1",
                    "acct_status_type": 3,
                }
                sink.put({**base, "ts": "2026-07-26 10:00:00.000", "input_octets": 100, "output_octets": 200})
                second = {**base, "ts": "2026-07-26 10:05:00.000", "input_octets": 160, "output_octets": 290}
                sink.put(second)
                sink.put(second)  # mirrored duplicate must not become a second flow delta
                deadline = time.time() + 5
                while sink.sent < 2 and time.time() < deadline:
                    time.sleep(0.05)
                sink.stop()

            self.assertEqual(sink.pending_count(), 0)
            body = "\n".join(payloads)
            self.assertIn('"input_delta":61440', body)
            self.assertIn('"output_delta":92160', body)

    def test_access_challenge_and_accept_response_attributes_are_kept(self):
        import parser
        stream = parser.RadiusStreamParser()
        request = self._packet(
            1, 17,
            self._avp(1, b"GDF12345678"),
            self._avp(31, b"AA-BB-CC-DD-EE-FF"),
        )
        challenge = self._packet(11, 17, self._avp(18, b"continue"))
        self.assertIsNone(stream.feed_packet("10.0.0.2", "10.0.0.3", 40000, 1812, request, 1.0))
        record = stream.feed_packet("10.0.0.3", "10.0.0.2", 1812, 40000, challenge, 1.1)
        self.assertEqual(record["result_code"], 11)
        self.assertEqual(record["mac_addr"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(record["packet_identifier"], 17)

    def test_dynamic_authorization_packet_is_passively_parsed(self):
        import parser
        stream = parser.RadiusStreamParser()
        packet = self._packet(
            45, 9,
            self._avp(1, b"GDF87654321"),
            self._avp(44, b"session-9"),
            self._avp(101, 503),
        )
        record = stream.feed_packet("10.0.0.3", "10.0.0.2", 3799, 51000, packet, 2.0)
        self.assertEqual(record["record_type"], "control")
        self.assertEqual(record["result"], "CoA-NAK")
        self.assertEqual(record["error_cause"], 503)
        self.assertEqual(record["acct_session_id"], "session-9")

    def test_session_key_includes_username_and_marks_counter_rollback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["SPOOL_PATH"] = os.path.join(temp_dir, "spool.sqlite3")
            os.environ["RADIUS_COUNTER_SCALE"] = "1024"
            import config
            import clickhouse_sink
            importlib.reload(config)
            importlib.reload(clickhouse_sink)
            sink = clickhouse_sink.RadiusClickHouseSink()
            with sink._connection() as conn:
                base = {
                    "record_type": "accounting", "nas_ip": "10.0.0.1",
                    "acct_session_id": "shared-id", "acct_status_type": 3,
                    "ts": "2026-07-26 10:00:00.000",
                }
                first = sink._normalize_event(conn, {**base, "username": "GDF10001", "input_octets": 100})
                other = sink._normalize_event(conn, {**base, "username": "GDF10002", "input_octets": 80})
                rollback = sink._normalize_event(
                    conn, {**base, "username": "GDF10001", "ts": "2026-07-26 10:01:00.000", "input_octets": 50}
                )
            self.assertEqual(first["input_delta"], 0)
            self.assertEqual(other["input_delta"], 0)
            self.assertEqual(rollback["input_delta"], 50 * 1024)
            self.assertEqual(rollback["counter_rollback"], 1)

    def test_control_record_normalization_keeps_protocol_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["SPOOL_PATH"] = os.path.join(temp_dir, "spool.sqlite3")
            import config
            import clickhouse_sink
            importlib.reload(config)
            importlib.reload(clickhouse_sink)
            sink = clickhouse_sink.RadiusClickHouseSink()
            with sink._connection() as conn:
                normalized = sink._normalize_event(conn, {
                    "record_type": "control", "ts": "2026-07-26 12:00:00.000",
                    "username": "GDF12345", "result_code": 42, "result": "Disconnect-NAK",
                    "error_cause": 503, "src_port": 3799, "dst_port": 51000,
                    "packet_identifier": 8, "acct_session_id": "session-control",
                })
            self.assertEqual(normalized["event_type"], "control")
            self.assertEqual(normalized["error_cause"], 503)
            self.assertEqual(normalized["src_port"], 3799)
            self.assertEqual(normalized["packet_identifier"], 8)


if __name__ == "__main__":
    unittest.main()
