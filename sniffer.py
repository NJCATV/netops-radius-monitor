"""
radius_monitor/sniffer.py
高性能抓包入口：基于 tcpdump 管道 + libpcap 解析
无需 Scapy，直接读取 pcap 二进制流，性能更好，支持高流量环境。
"""

import os
import sys
import struct
import logging
import subprocess
import threading
import time
import faulthandler
import signal
import re
from datetime import datetime
from queue import Queue, Empty, Full
import fcntl

import config
from parser import RadiusStreamParser

if config.STORAGE_BACKEND == 'clickhouse':
    from clickhouse_sink import RadiusClickHouseSink
    db = None
else:
    import db
    RadiusClickHouseSink = None

logger = logging.getLogger(__name__)


# ── pcap 文件格式常量 ──────────────────────────────────────────────────────────
PCAP_MAGIC_LE    = 0xd4c3b2a1
PCAP_MAGIC_BE    = 0xa1b2c3d4
PCAP_MAGIC_NS_LE = 0x4d3cb2a1
PCAP_MAGIC_NS_BE = 0xa1b23c4d


class PcapStreamReader:
    def __init__(self, stream, timeout=5.0):
        self.stream    = stream
        self.is_le     = True
        self.ns_prec   = False
        self.link_type = 1
        self._read_global_header(timeout)

    def _read_exact(self, n: int, timeout=5.0) -> bytes | None:
        buf = b''
        start = time.time()
        while len(buf) < n:
            remaining = timeout - (time.time() - start)
            if remaining <= 0:
                return None
            # 非阻塞读取
            try:
                chunk = self.stream.read(min(n - len(buf), 4096))
            except BlockingIOError:
                time.sleep(0.05)
                continue
            if not chunk:
                return None
            buf += chunk
        return buf

    def _read_global_header(self, timeout=5.0):
        hdr = self._read_exact(24, timeout)
        if not hdr:
            raise EOFError(f"等待 pcap 全局头超时（{timeout}s 内无数据）")
        magic = hdr[:4]
        if magic == b'\xd4\xc3\xb2\xa1':
            self.is_le   = True
            self.ns_prec = False
        elif magic == b'\x4d\x3c\xb2\xa1':
            self.is_le   = True
            self.ns_prec = True
        elif magic == b'\xa1\xb2\xc3\xd4':
            self.is_le   = False
            self.ns_prec = False
        elif magic == b'\xa1\xb2\x3c\x4d':
            self.is_le   = False
            self.ns_prec = True
        else:
            raise ValueError(f"Unknown pcap magic: {magic.hex()}")
        endian       = '<' if self.is_le else '>'
        self.link_type = struct.unpack(endian + 'I', hdr[20:24])[0]
        logger.info("pcap 流已就绪 (link_type=%s, ns=%s)", self.link_type, self.ns_prec)

    def __iter__(self):
        endian = '<' if self.is_le else '>'
        while True:
            rec_hdr = self._read_exact(16)
            if not rec_hdr:
                logger.warning("pcap 流结束")
                return
            ts_sec, ts_frac, inc_len, orig_len = struct.unpack(endian + '4I', rec_hdr)
            pkt_time = ts_sec + (ts_frac / 1e9 if self.ns_prec else ts_frac / 1e6)
            data = self._read_exact(inc_len)
            if not data:
                return
            yield pkt_time, data


# ── 以太网 → IP → UDP 解析 ────────────────────────────────────────────────────

def extract_udp_payload(frame: bytes, link_type: int):
    """
    link_type 可能的值：
    - 1         Ethernet
    - 101 / 228 Raw IPv4 / IPv4
    - 113       Linux cooked capture v1
    - 276       Linux cooked capture v2
    """
    try:
        if link_type == 1:
            if len(frame) < 14:
                return None
            eth_type = struct.unpack('!H', frame[12:14])[0]
            if eth_type in (0x8100, 0x88A8):
                if len(frame) < 18:
                    return None
                ip_offset = 18
                eth_type = struct.unpack('!H', frame[16:18])[0]
                while eth_type in (0x8100, 0x88A8):
                    if len(frame) < ip_offset + 4:
                        return None
                    eth_type = struct.unpack('!H', frame[ip_offset + 2:ip_offset + 4])[0]
                    ip_offset += 4
            else:
                ip_offset = 14
            if eth_type != 0x0800:
                return None
        elif link_type in (101, 228):
            ip_offset = 0
        elif link_type == 113:
            if len(frame) < 16:
                return None
            eth_type = struct.unpack('!H', frame[14:16])[0]
            if eth_type != 0x0800:
                return None
            ip_offset = 16
        elif link_type == 276:
            if len(frame) < 20:
                return None
            eth_type = struct.unpack('!H', frame[0:2])[0]
            if eth_type != 0x0800:
                return None
            ip_offset = 20
        else:
            logger.debug("未知 link_type: %s，跳过帧", link_type)
            return None

        ip_data = frame[ip_offset:]
        if len(ip_data) < 20:
            return None
        version_ihl = ip_data[0]
        version     = (version_ihl >> 4)
        ihl         = (version_ihl & 0xF) * 4
        if version != 4:
            return None
        protocol = ip_data[9]
        if protocol != 17:
            return None
        fragment = struct.unpack('!H', ip_data[6:8])[0]
        if fragment & 0x1FFF:
            return None
        src_ip = '.'.join(str(b) for b in ip_data[12:16])
        dst_ip = '.'.join(str(b) for b in ip_data[16:20])
        udp_data = ip_data[ihl:]
        if len(udp_data) < 8:
            return None
        src_port, dst_port = struct.unpack('!HH', udp_data[:4])
        udp_length = struct.unpack('!H', udp_data[4:6])[0]
        if udp_length < 8 or udp_length > len(udp_data):
            return None
        udp_payload = udp_data[8:udp_length]
        return src_ip, dst_ip, src_port, dst_port, udp_payload
    except Exception:
        return None


# ── 写库 Worker ────────────────────────────────────────────────────────────────

class DBWriter:
    FLUSH_TIMEOUT = 1.0

    def __init__(self, name: str, write_func, batch_size: int):
        self.name = name
        self.write_func = write_func
        self.batch_size = max(1, int(batch_size))
        self.queue  = Queue(maxsize=int(getattr(config, 'WRITER_QUEUE_SIZE', 50000)))
        self._stop  = threading.Event()
        self.dropped = 0
        self.written = 0
        self._thread = threading.Thread(target=self._run, daemon=True, name=f'{name}-writer')

    def start(self):
        self._thread.start()
        logger.info("%sWriter 线程启动 batch_size=%d queue_size=%d", self.name, self.batch_size, self.queue.maxsize)

    def put(self, rec: dict):
        try:
            self.queue.put_nowait(rec)
        except Full:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 1000 == 0:
                logger.warning("%sWriter 队列已满，累计丢弃 %d 条记录", self.name, self.dropped)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)

    def _run(self):
        batch = []
        last_flush = time.monotonic()
        while not self._stop.is_set():
            try:
                rec = self.queue.get(timeout=0.2)
                batch.append(rec)
            except Empty:
                pass

            now = time.monotonic()
            if len(batch) >= self.batch_size or (batch and now - last_flush >= self.FLUSH_TIMEOUT):
                try:
                    started = time.monotonic()
                    self.write_func(batch)
                    elapsed = time.monotonic() - started
                    self.written += len(batch)
                    logger.info(
                        "%sWriter 已写入 %d 条，本批 %d 条耗时 %.3fs，队列剩余 %d，丢弃 %d",
                        self.name, self.written, len(batch), elapsed, self.queue.qsize(), self.dropped,
                    )
                except Exception as e:
                    logger.error("%sWriter 批量写库失败: %s", self.name, e)
                batch = []
                last_flush = time.monotonic()

        if batch:
            try:
                self.write_func(batch)
            except Exception as e:
                logger.error("%sWriter 退出刷写失败: %s", self.name, e)


class AccountingSampler:
    """对高频 Interim-Update 做内存降采样，Start/Stop 始终保留。"""

    def __init__(self, interval_seconds: int):
        self.interval = max(0, int(interval_seconds or 0))
        self.last_seen = {}
        self.dropped_interim = 0

    def should_keep(self, rec: dict) -> bool:
        if rec.get('record_type') != 'accounting':
            return True
        if self.interval <= 0:
            return True
        if rec.get('acct_status_type') != 3:
            return True

        key = (
            rec.get('nas_ip') or rec.get('src_ip') or '',
            rec.get('acct_session_id') or rec.get('username') or rec.get('framed_ip') or rec.get('mac_addr') or '',
        )
        if not key[1]:
            return True
        ts_value = _record_epoch(rec.get('ts')) or time.time()
        previous = self.last_seen.get(key)
        if previous is not None and ts_value - previous < self.interval:
            self.dropped_interim += 1
            return False
        self.last_seen[key] = ts_value
        if len(self.last_seen) > 200000:
            cutoff = ts_value - max(self.interval * 5, 300)
            self.last_seen = {item_key: item_ts for item_key, item_ts in self.last_seen.items() if item_ts >= cutoff}
        return True


def _record_epoch(value):
    if not value:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.strptime(value, '%Y-%m-%d %H:%M:%S.%f').timestamp()
        except ValueError:
            try:
                return datetime.strptime(value, '%Y-%m-%d %H:%M:%S').timestamp()
            except ValueError:
                return None
    return None


def _has_matched_username(rec: dict) -> bool:
    if rec.get('record_type') == 'accounting' and rec.get('acct_status_type') in (7, 8, 15):
        return bool(rec.get('nas_ip') or rec.get('src_ip'))
    if rec.get('record_type') == 'control':
        return bool(
            (rec.get('username') and rec.get('username') != '(未匹配)')
            or rec.get('acct_session_id')
            or rec.get('mac_addr')
            or rec.get('nas_ip')
        )
    return bool(rec.get('username') and rec.get('username') != '(未匹配)')


# ── 主抓包循环 ────────────────────────────────────────────────────────────────

def run_sniffer():
    try:
        faulthandler.register(signal.SIGUSR1, all_threads=True)
    except Exception:
        pass

    parser = RadiusStreamParser()
    ch_sink = None
    auth_realtime_writer = None
    auth_risk_writer = None
    acct_writer = None
    if config.STORAGE_BACKEND == 'clickhouse':
        ch_sink = RadiusClickHouseSink()
        ch_sink.start()
    elif config.STORAGE_BACKEND == 'mysql':
        db.init_pool()
        db.init_db()
        auth_realtime_writer = DBWriter(
            'AuthRealtime',
            db.bulk_insert_auth_realtime_records,
            getattr(config, 'AUTH_REALTIME_WRITER_BATCH_SIZE', getattr(config, 'AUTH_WRITER_BATCH_SIZE', 1000)),
        )
        auth_risk_writer = DBWriter(
            'AuthRisk',
            db.bulk_insert_auth_risk_records,
            getattr(config, 'AUTH_RISK_WRITER_BATCH_SIZE', 2000),
        ) if getattr(config, 'WRITE_AUTH_RISK', True) else None
        acct_writer = DBWriter(
            'Acct', db.bulk_insert_accounting_records, getattr(config, 'ACCT_WRITER_BATCH_SIZE', 2000)
        ) if getattr(config, 'WRITE_ACCOUNTING_LOG', False) else None
        auth_realtime_writer.start()
        if auth_risk_writer:
            auth_risk_writer.start()
        else:
            logger.info("AuthRiskWriter 未启用 WRITE_AUTH_RISK=0")
        if acct_writer:
            acct_writer.start()
        else:
            logger.info("AcctWriter 未启用 WRITE_ACCOUNTING_LOG=0")
    else:
        raise RuntimeError(f"不支持的 STORAGE_BACKEND={config.STORAGE_BACKEND!r}")

    acct_sampler = AccountingSampler(getattr(config, 'ACCT_INTERIM_SAMPLE_SECONDS', 60))

    iface = config.CAPTURE_IFACE
    bpf   = config.CAPTURE_FILTER

    cmd = [
        'tcpdump',
        '-i', iface,
        '-n', '-q',
        '-s', str(config.CAPTURE_SNAPLEN),
        '-B', str(config.CAPTURE_BUFFER_KIB),
        '-U',               # 无缓冲立即写出
        '-w', '-',          # pcap 二进制流到 stdout
        bpf,
    ]
    logger.info("启动抓包: %s", ' '.join(cmd))

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        # 将 stderr 设为非阻塞，避免管道填满导致 tcpdump 阻塞
        flags = fcntl.fcntl(proc.stderr, fcntl.F_GETFL)
        fcntl.fcntl(proc.stderr, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        time.sleep(1.5)

        # 消费 stderr 中的启动消息（非阻塞）
        try:
            stderr_out = proc.stderr.read()
            if stderr_out:
                logger.info("tcpdump stderr: %s", stderr_out.decode(errors='replace').strip()[:200])
        except (BlockingIOError, OSError):
            pass

        # 检查进程是否异常退出
        if proc.poll() is not None:
            stderr_data = proc.stderr.read()
            logger.error("tcpdump 启动失败，退出码=%d，stderr=%s",
                         proc.returncode, stderr_data.decode(errors='replace'))
            return

        pcap_reader = PcapStreamReader(proc.stdout, timeout=5.0)
        tcpdump_stats = {
            'tcpdump_captured': 0,
            'tcpdump_received_by_filter': 0,
            'tcpdump_kernel_dropped': 0,
        }

        def drain_tcpdump_stderr():
            patterns = (
                ('tcpdump_captured', re.compile(r'(\d+) packets captured')),
                ('tcpdump_received_by_filter', re.compile(r'(\d+) packets received by filter')),
                ('tcpdump_kernel_dropped', re.compile(r'(\d+) packets dropped by kernel')),
            )
            while proc.poll() is None:
                try:
                    chunk = proc.stderr.read(4096)
                except (BlockingIOError, OSError):
                    time.sleep(0.1)
                    continue
                if not chunk:
                    time.sleep(0.1)
                    continue
                message = chunk.decode(errors='replace').strip()
                for key, pattern in patterns:
                    match = pattern.search(message)
                    if match:
                        tcpdump_stats[key] = int(match.group(1))
                if message:
                    logger.info("tcpdump: %s", message[:500])

        threading.Thread(target=drain_tcpdump_stderr, daemon=True, name='tcpdump-stderr').start()
        pkt_count  = 0
        parsed_count = 0
        auth_count = 0
        acct_count = 0
        control_count = 0
        challenge_count = 0
        last_metrics = time.monotonic()

        for pkt_time, frame in pcap_reader:
            pkt_count += 1

            extracted = extract_udp_payload(frame, pcap_reader.link_type)
            if not extracted:
                continue
            src_ip, dst_ip, src_port, dst_port, udp_payload = extracted

            if src_port not in config.RADIUS_CAPTURE_PORTS and dst_port not in config.RADIUS_CAPTURE_PORTS:
                continue

            rec = parser.feed_packet(src_ip, dst_ip, src_port, dst_port, udp_payload, pkt_time)
            if rec:
                if not _has_matched_username(rec):
                    continue
                parsed_count += 1
                if rec.get('record_type') == 'accounting':
                    if acct_sampler.should_keep(rec):
                        if ch_sink:
                            ch_sink.put(rec)
                        elif acct_writer:
                            acct_writer.put(rec)
                        acct_count += 1
                elif rec.get('record_type') == 'control':
                    if ch_sink:
                        ch_sink.put(rec)
                        control_count += 1
                    else:
                        logger.warning("控制报文仅支持 ClickHouse 存储，当前记录已跳过")
                else:
                    if ch_sink:
                        ch_sink.put(rec)
                    else:
                        auth_realtime_writer.put(rec)
                        if auth_risk_writer:
                            auth_risk_writer.put(rec)
                    auth_count += 1
                    if rec.get('result_code') == 11:
                        challenge_count += 1
                if parsed_count % max(1, config.COLLECTOR_LOG_EVERY) == 0:
                    risk_queue = auth_risk_writer.queue.qsize() if auth_risk_writer else 0
                    risk_written = auth_risk_writer.written if auth_risk_writer else 0
                    risk_dropped = auth_risk_writer.dropped if auth_risk_writer else 0
                    acct_queue = acct_writer.queue.qsize() if acct_writer else 0
                    acct_written = acct_writer.written if acct_writer else 0
                    acct_dropped = acct_writer.dropped if acct_writer else 0
                    if ch_sink:
                        logger.info(
                            "已解析 %d 条 auth=%d acct=%d control=%d challenge=%d 抓包帧=%d spool=%s Interim降采样=%d",
                            parsed_count, auth_count, acct_count, control_count, challenge_count, pkt_count,
                            ch_sink.snapshot(), acct_sampler.dropped_interim,
                        )
                    else:
                        logger.info(
                            "已解析 %d 条记录 auth=%d acct=%d（抓包帧数 %d，Auth实时队列 %d/写入 %d/丢弃 %d，Auth风险队列 %d/写入 %d/丢弃 %d，Acct队列 %d/写入 %d/丢弃 %d，Interim降采样 %d）",
                            parsed_count, auth_count, acct_count, pkt_count,
                            auth_realtime_writer.queue.qsize(), auth_realtime_writer.written, auth_realtime_writer.dropped,
                            risk_queue, risk_written, risk_dropped,
                            acct_queue, acct_written, acct_dropped,
                            acct_sampler.dropped_interim,
                        )

            if ch_sink and time.monotonic() - last_metrics >= config.COLLECTOR_METRICS_INTERVAL:
                ch_sink.publish_metrics({
                    'captured_packets': pkt_count,
                    'parsed_records': parsed_count,
                    'auth_records': auth_count,
                    'accounting_records': acct_count,
                    'control_records': control_count,
                    'challenge_records': challenge_count,
                    'interim_sampled_out': acct_sampler.dropped_interim,
                    'pending_auth_requests': len(parser.pending),
                    'unmatched_auth_responses': parser.unmatched_auth_responses,
                    'expired_auth_requests': parser.expired_auth_requests,
                    'pending_auth_evictions': parser.pending_evictions,
                    'malformed_packets': parser.malformed_packets,
                    'accounting_responses': parser.accounting_responses,
                    'unknown_radius_codes': parser.unknown_codes,
                    **tcpdump_stats,
                })
                try:
                    proc.send_signal(signal.SIGUSR1)
                except OSError:
                    pass
                last_metrics = time.monotonic()

            if pkt_count % 500 == 0:
                parser.gc_expired()

            if pkt_count % 1000 == 0 and proc.poll() is not None:
                stderr_data = proc.stderr.read()
                logger.error("tcpdump 意外退出，退出码=%d，stderr=%s",
                             proc.returncode, stderr_data.decode(errors='replace'))
                break

    except KeyboardInterrupt:
        logger.info("收到中断信号，正在退出...")
    except Exception as e:
        logger.exception("抓包异常: %s", e)
    finally:
        if auth_realtime_writer:
            auth_realtime_writer.stop()
        if auth_risk_writer:
            auth_risk_writer.stop()
        if acct_writer:
            acct_writer.stop()
        if ch_sink:
            ch_sink.publish_metrics({
                'captured_packets': locals().get('pkt_count', 0),
                'parsed_records': locals().get('parsed_count', 0),
                'auth_records': locals().get('auth_count', 0),
                'accounting_records': locals().get('acct_count', 0),
                'control_records': locals().get('control_count', 0),
                'challenge_records': locals().get('challenge_count', 0),
                'interim_sampled_out': acct_sampler.dropped_interim,
                'pending_auth_requests': len(parser.pending),
                'unmatched_auth_responses': parser.unmatched_auth_responses,
                'expired_auth_requests': parser.expired_auth_requests,
                'pending_auth_evictions': parser.pending_evictions,
                'malformed_packets': parser.malformed_packets,
                'accounting_responses': parser.accounting_responses,
                'unknown_radius_codes': parser.unknown_codes,
                **locals().get('tcpdump_stats', {}),
            })
            ch_sink.stop()
        if proc:
            proc.terminate()
        logger.info("抓包结束")


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    )
    run_sniffer()
