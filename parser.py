"""
radius_monitor/parser.py
RADIUS 报文解析层：从 libpcap 数据包中提取认证信息
"""

import logging
import re
import struct
from datetime import datetime

import config

logger = logging.getLogger(__name__)

ACCOUNT_PATTERN = re.compile(r'(GD[FC]\d{4,})', re.IGNORECASE)
NUMERIC_ACCOUNT_PATTERN = re.compile(r'^\d{4,}$')


# ── RADIUS 属性解析 ────────────────────────────────────────────────────────────

def parse_radius_attributes(data: bytes) -> dict:
    """
    解析 RADIUS 属性字节流，返回 {attr_type: value_str} 字典。
    RADIUS AVP 格式：Type(1B) Length(1B) Value(Length-2 B)
    """
    attrs = {}
    vsa = {}
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            break
        attr_type = data[offset]
        attr_len  = data[offset + 1]
        if attr_len < 2 or offset + attr_len > len(data):
            break
        val_bytes = data[offset + 2: offset + attr_len]
        # Vendor-Specific 可以在一个报文中出现多次，不能像普通属性一样覆盖。
        if attr_type == config.RADIUS_ATTR_VENDOR_SPECIFIC:
            _merge_vendor_specific(vsa, val_bytes)
            offset += attr_len
            continue
        # 解码值
        if attr_type in (config.RADIUS_ATTR_USER_NAME,
                         config.RADIUS_ATTR_CALLING_STA,
                         config.RADIUS_ATTR_CALLED_STA,
                         config.RADIUS_ATTR_REPLY_MSG,
                         config.RADIUS_ATTR_ACCT_SESSION_ID,
                         config.RADIUS_ATTR_ACCT_MULTI_SESSION_ID,
                         config.RADIUS_ATTR_NAS_IDENTIFIER,
                         config.RADIUS_ATTR_NAS_PORT_ID,
                         config.RADIUS_ATTR_CLASS,
                         config.RADIUS_ATTR_CONNECT_INFO):
            try:
                val = val_bytes.decode('utf-8', errors='replace').strip('\x00')
            except Exception:
                val = val_bytes.hex()
        elif attr_type in (config.RADIUS_ATTR_NAS_IP,
                           config.RADIUS_ATTR_FRAMED_IP,
                           config.RADIUS_ATTR_FRAMED_IP_NETMASK):
            if len(val_bytes) == 4:
                val = '.'.join(str(b) for b in val_bytes)
            else:
                val = val_bytes.hex()
        elif attr_type in (config.RADIUS_ATTR_NAS_PORT,
                           config.RADIUS_ATTR_SERVICE_TYPE,
                           config.RADIUS_ATTR_FRAMED_PROTOCOL,
                           config.RADIUS_ATTR_NAS_PORT_TYPE,
                           config.RADIUS_ATTR_ACCT_STATUS_TYPE,
                           config.RADIUS_ATTR_ACCT_INPUT_OCTETS,
                           config.RADIUS_ATTR_ACCT_OUTPUT_OCTETS,
                           config.RADIUS_ATTR_ACCT_SESSION_TIME,
                           config.RADIUS_ATTR_ACCT_INPUT_PACKETS,
                           config.RADIUS_ATTR_ACCT_OUTPUT_PACKETS,
                           config.RADIUS_ATTR_ACCT_TERMINATE_CAUSE,
                           config.RADIUS_ATTR_ACCT_INPUT_GIGAWORDS,
                           config.RADIUS_ATTR_ACCT_OUTPUT_GIGAWORDS,
                           config.RADIUS_ATTR_ACCT_DELAY_TIME,
                           config.RADIUS_ATTR_ACCT_AUTHENTIC,
                           config.RADIUS_ATTR_ERROR_CAUSE,
                           config.RADIUS_ATTR_EVENT_TIMESTAMP):
            val = struct.unpack('!I', val_bytes)[0] if len(val_bytes) == 4 else None
        else:
            val = val_bytes.decode('utf-8', errors='replace').strip('\x00')
        attrs[attr_type] = val
        offset += attr_len
    attrs["_vsa"] = vsa
    return attrs


def _merge_vendor_specific(target: dict, value: bytes):
    """解析 RFC 2865 Vendor-Specific 容器，保留同一厂商下的多个子属性。"""
    offset = 0
    while offset + 6 <= len(value):
        vendor_id = struct.unpack("!I", value[offset:offset + 4])[0]
        subtype = value[offset + 4]
        sub_len = value[offset + 5]
        if sub_len < 2 or offset + 4 + sub_len > len(value):
            break
        sub_value = value[offset + 6:offset + 4 + sub_len]
        target.setdefault(vendor_id, {})[subtype] = sub_value
        offset += 4 + sub_len


def _vsa_bytes(attrs: dict, vendor: int, subtype: int) -> bytes:
    return attrs.get("_vsa", {}).get(vendor, {}).get(subtype, b"")


def _vsa_text(attrs: dict, vendor: int, subtype: int) -> str:
    value = _vsa_bytes(attrs, vendor, subtype)
    return value.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()


def _vsa_uint(attrs: dict, vendor: int, subtype: int) -> int:
    value = _vsa_bytes(attrs, vendor, subtype)
    return struct.unpack("!I", value[:4])[0] if len(value) >= 4 else 0


def parse_radius_packet(udp_payload: bytes):
    """
    解析 RADIUS UDP 报文。
    RADIUS 报文头格式：Code(1B) Identifier(1B) Length(2B) Authenticator(16B) Attributes...
    返回 (code, identifier, attrs_dict) 或 None（格式错误时）
    """
    if len(udp_payload) < 20:
        return None
    code       = udp_payload[0]
    identifier = udp_payload[1]
    length     = struct.unpack('!H', udp_payload[2:4])[0]
    if length < 20 or length > len(udp_payload):
        return None
    attr_data = udp_payload[20:length]
    attrs = parse_radius_attributes(attr_data)
    return code, identifier, attrs


def normalize_mac(mac_str: str) -> str:
    """将 MAC 统一规范化为 xx:xx:xx:xx:xx:xx 小写格式"""
    if not mac_str:
        return mac_str
    compact = re.sub(r'[^0-9a-fA-F]', '', str(mac_str)).lower()
    if len(compact) == 12:
        return ':'.join(compact[index:index + 2] for index in range(0, 12, 2))
    return str(mac_str).strip().lower()


def normalize_username(username: str) -> str:
    """
    将 RADIUS User-Name 归一化为业务账号。

    现场报文中会出现带控制字符、随机前缀或形如
    a:<token>::GDFxxxx 的 User-Name。原始值仍由 raw_username 保存，
    这里优先提取 GDF/GDC 业务账号；整串纯数字账号也保留。
    """
    if not username:
        return username
    matches = list(ACCOUNT_PATTERN.finditer(username))
    if matches:
        return matches[-1].group(1).upper()
    cleaned = ''.join(ch for ch in username if ch >= ' ' and ch != '\x7f').strip()
    if NUMERIC_ACCOUNT_PATTERN.fullmatch(cleaned):
        return cleaned
    return '(未匹配)'


def parse_reply_message(msg_raw: str):
    """返回 (reason_zh, risk_level)"""
    if not msg_raw:
        return None, 'unknown'
    tr = config.REPLY_MSG_TRANSLATION.get(msg_raw)
    if tr:
        return tr[0], tr[1]
    return msg_raw, 'unknown'


# ── 实时流式解析器 ─────────────────────────────────────────────────────────────

class RadiusStreamParser:
    """
    有状态解析器：缓存 Access-Request，配对 Accept/Reject，
    每次调用 feed_packet() 返回完整配对记录（或 None）。
    """

    def __init__(self, max_pending: int = 10000, ttl_sec: int = 30):
        self.pending     = {}
        self.max_pending = max_pending
        self.ttl_sec     = ttl_sec
        self._last_gc    = time.monotonic() if True else 0
        self.malformed_packets = 0
        self.unmatched_auth_responses = 0
        self.expired_auth_requests = 0
        self.pending_evictions = 0
        self.accounting_responses = 0
        self.unknown_codes = 0

    @staticmethod
    def _request_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, ident: int):
        return src_ip, src_port, dst_ip, dst_port, ident

    @staticmethod
    def _response_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, ident: int):
        return dst_ip, dst_port, src_ip, src_port, ident

    def feed_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                    udp_payload: bytes, pkt_time: float) -> dict | None:
        """
        喂入一个 UDP 报文（已确认是 1812/1813 端口）。
        返回：配对成功的记录 dict，或 None（等待配对/非认证报文）。
        """
        import time
        parsed = parse_radius_packet(udp_payload)
        if parsed is None:
            self.malformed_packets += 1
            return None
        code, ident, attrs = parsed

        ts_str = datetime.fromtimestamp(pkt_time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        if code == 1:   # Access-Request
            calling_sta = attrs.get(config.RADIUS_ATTR_CALLING_STA)
            vendor_mac = _vsa_text(
                attrs, config.RADIUS_VENDOR_HUAWEI, config.HUAWEI_VSA_MAC_ADDRESS
            )
            subscriber_id = _vsa_text(
                attrs, config.RADIUS_VENDOR_HUAWEI, config.HUAWEI_VSA_SUBSCRIBER_ID
            )
            nas_port_val = attrs.get(config.RADIUS_ATTR_NAS_PORT)
            raw_username = attrs.get(config.RADIUS_ATTR_USER_NAME, '')
            self.pending[self._request_key(src_ip, dst_ip, src_port, dst_port, ident)] = {
                'username':    normalize_username(raw_username or subscriber_id),
                'raw_username': raw_username,
                'subscriber_id': subscriber_id,
                'nas_ip':      attrs.get(config.RADIUS_ATTR_NAS_IP) or src_ip,
                'nas_identifier': attrs.get(config.RADIUS_ATTR_NAS_IDENTIFIER),
                'nas_port':    nas_port_val,
                'nas_port_id': attrs.get(config.RADIUS_ATTR_NAS_PORT_ID),
                'nas_port_type': attrs.get(config.RADIUS_ATTR_NAS_PORT_TYPE),
                'service_type': attrs.get(config.RADIUS_ATTR_SERVICE_TYPE),
                'framed_protocol': attrs.get(config.RADIUS_ATTR_FRAMED_PROTOCOL),
                'calling_sta': calling_sta,
                'mac_addr':    normalize_mac(vendor_mac or calling_sta) if (vendor_mac or calling_sta) else None,
                'called_sta':  attrs.get(config.RADIUS_ATTR_CALLED_STA),
                'framed_ip':   attrs.get(config.RADIUS_ATTR_FRAMED_IP),
                'framed_ip_netmask': attrs.get(config.RADIUS_ATTR_FRAMED_IP_NETMASK),
                'class_attr': attrs.get(config.RADIUS_ATTR_CLASS),
                'connect_info': attrs.get(config.RADIUS_ATTR_CONNECT_INFO),
                'packet_identifier': ident,
                'req_ts':      ts_str,
                'src_ip':      src_ip,
                'dst_ip':      dst_ip,
                'src_port':    src_port,
                'dst_port':    dst_port,
                '_ts':         time.monotonic(),
            }
            # 防止内存无限增长：超过上限时按 FIFO 淘汰旧记录
            if len(self.pending) > self.max_pending:
                oldest = next(iter(self.pending))
                self.pending.pop(oldest, None)
                self.pending_evictions += 1
            return None

        elif code in (2, 3, 11):   # Accept / Reject / Challenge
            key = self._response_key(src_ip, dst_ip, src_port, dst_port, ident)
            req = self.pending.pop(key, None)
            if req is None:
                self.unmatched_auth_responses += 1
                return None

            reply_raw = attrs.get(config.RADIUS_ATTR_REPLY_MSG, '')
            reason_zh, risk = parse_reply_message(reply_raw)

            return {
                'username':    req['username'],
                'raw_username': req.get('raw_username'),
                'subscriber_id': req.get('subscriber_id'),
                'nas_ip':      req['nas_ip'],
                'nas_identifier': req['nas_identifier'],
                'nas_port':    req['nas_port'],
                'nas_port_id': req['nas_port_id'],
                'nas_port_type': req['nas_port_type'],
                'service_type': attrs.get(config.RADIUS_ATTR_SERVICE_TYPE) or req.get('service_type'),
                'framed_protocol': attrs.get(config.RADIUS_ATTR_FRAMED_PROTOCOL) or req.get('framed_protocol'),
                'calling_sta': req['calling_sta'],
                'mac_addr':    req['mac_addr'],
                'called_sta':  req['called_sta'],
                'framed_ip':   attrs.get(config.RADIUS_ATTR_FRAMED_IP) or req['framed_ip'],
                'framed_ip_netmask': attrs.get(config.RADIUS_ATTR_FRAMED_IP_NETMASK) or req.get('framed_ip_netmask'),
                'class_attr': attrs.get(config.RADIUS_ATTR_CLASS) or req.get('class_attr'),
                'connect_info': attrs.get(config.RADIUS_ATTR_CONNECT_INFO) or req.get('connect_info'),
                'packet_identifier': ident,
                'src_port':    req['src_port'],
                'dst_port':    req['dst_port'],
                'req_ts':      req['req_ts'],
                'src_ip':      req['src_ip'],
                'dst_ip':      req['dst_ip'],
                'resp_ts':     ts_str,
                'result_code': code,
                'result':      config.RADIUS_CODE.get(code, f'code={code}'),
                'reply_raw':   reply_raw,
                'reason_zh':   reason_zh,
                'risk':        risk,
                'matched':     True,
            }

        elif code == 4:   # Accounting-Request
            calling_sta = attrs.get(config.RADIUS_ATTR_CALLING_STA)
            vendor_mac = _vsa_text(
                attrs, config.RADIUS_VENDOR_HUAWEI, config.HUAWEI_VSA_MAC_ADDRESS
            )
            subscriber_id = _vsa_text(
                attrs, config.RADIUS_VENDOR_HUAWEI, config.HUAWEI_VSA_SUBSCRIBER_ID
            )
            raw_username = attrs.get(config.RADIUS_ATTR_USER_NAME, '')
            return {
                'record_type':   'accounting',
                'username':      normalize_username(raw_username or subscriber_id),
                'raw_username':  raw_username,
                'subscriber_id': subscriber_id,
                'nas_ip':        attrs.get(config.RADIUS_ATTR_NAS_IP) or src_ip,
                'nas_identifier': attrs.get(config.RADIUS_ATTR_NAS_IDENTIFIER),
                'nas_port':      attrs.get(config.RADIUS_ATTR_NAS_PORT),
                'nas_port_id':   attrs.get(config.RADIUS_ATTR_NAS_PORT_ID),
                'nas_port_type': attrs.get(config.RADIUS_ATTR_NAS_PORT_TYPE),
                'service_type': attrs.get(config.RADIUS_ATTR_SERVICE_TYPE),
                'framed_protocol': attrs.get(config.RADIUS_ATTR_FRAMED_PROTOCOL),
                'calling_sta':   calling_sta,
                'mac_addr':      normalize_mac(vendor_mac or calling_sta) if (vendor_mac or calling_sta) else None,
                'called_sta':    attrs.get(config.RADIUS_ATTR_CALLED_STA),
                'framed_ip':     attrs.get(config.RADIUS_ATTR_FRAMED_IP),
                'framed_ip_netmask': attrs.get(config.RADIUS_ATTR_FRAMED_IP_NETMASK),
                'class_attr':    attrs.get(config.RADIUS_ATTR_CLASS),
                'acct_status_type': attrs.get(config.RADIUS_ATTR_ACCT_STATUS_TYPE),
                'acct_session_id': attrs.get(config.RADIUS_ATTR_ACCT_SESSION_ID),
                'acct_multi_session_id': attrs.get(config.RADIUS_ATTR_ACCT_MULTI_SESSION_ID),
                'acct_authentic': attrs.get(config.RADIUS_ATTR_ACCT_AUTHENTIC),
                'acct_session_time': attrs.get(config.RADIUS_ATTR_ACCT_SESSION_TIME),
                'input_octets':  attrs.get(config.RADIUS_ATTR_ACCT_INPUT_OCTETS),
                'input_gigawords': attrs.get(config.RADIUS_ATTR_ACCT_INPUT_GIGAWORDS),
                'output_octets': attrs.get(config.RADIUS_ATTR_ACCT_OUTPUT_OCTETS),
                'output_gigawords': attrs.get(config.RADIUS_ATTR_ACCT_OUTPUT_GIGAWORDS),
                'input_packets': attrs.get(config.RADIUS_ATTR_ACCT_INPUT_PACKETS),
                'output_packets': attrs.get(config.RADIUS_ATTR_ACCT_OUTPUT_PACKETS),
                'terminate_cause': attrs.get(config.RADIUS_ATTR_ACCT_TERMINATE_CAUSE),
                'acct_delay_time': attrs.get(config.RADIUS_ATTR_ACCT_DELAY_TIME),
                'event_timestamp': attrs.get(config.RADIUS_ATTR_EVENT_TIMESTAMP),
                'input_average_rate': _vsa_uint(
                    attrs, config.RADIUS_VENDOR_HUAWEI, config.HUAWEI_VSA_INPUT_AVERAGE_RATE
                ),
                'output_average_rate': _vsa_uint(
                    attrs, config.RADIUS_VENDOR_HUAWEI, config.HUAWEI_VSA_OUTPUT_AVERAGE_RATE
                ),
                'product_id': _vsa_text(
                    attrs, config.RADIUS_VENDOR_HUAWEI, config.HUAWEI_VSA_PRODUCT_ID
                ),
                'connect_info': attrs.get(config.RADIUS_ATTR_CONNECT_INFO),
                'packet_identifier': ident,
                'src_ip':        src_ip,
                'dst_ip':        dst_ip,
                'src_port':      src_port,
                'dst_port':      dst_port,
                'ts':            ts_str,
            }

        elif code in (40, 41, 42, 43, 44, 45):
            calling_sta = attrs.get(config.RADIUS_ATTR_CALLING_STA)
            vendor_mac = _vsa_text(
                attrs, config.RADIUS_VENDOR_HUAWEI, config.HUAWEI_VSA_MAC_ADDRESS
            )
            subscriber_id = _vsa_text(
                attrs, config.RADIUS_VENDOR_HUAWEI, config.HUAWEI_VSA_SUBSCRIBER_ID
            )
            raw_username = attrs.get(config.RADIUS_ATTR_USER_NAME, '')
            return {
                'record_type': 'control',
                'username': normalize_username(raw_username or subscriber_id),
                'raw_username': raw_username,
                'subscriber_id': subscriber_id,
                'nas_ip': attrs.get(config.RADIUS_ATTR_NAS_IP) or (
                    dst_ip if code in (40, 43) else src_ip
                ),
                'nas_identifier': attrs.get(config.RADIUS_ATTR_NAS_IDENTIFIER),
                'nas_port': attrs.get(config.RADIUS_ATTR_NAS_PORT),
                'nas_port_id': attrs.get(config.RADIUS_ATTR_NAS_PORT_ID),
                'nas_port_type': attrs.get(config.RADIUS_ATTR_NAS_PORT_TYPE),
                'service_type': attrs.get(config.RADIUS_ATTR_SERVICE_TYPE),
                'framed_protocol': attrs.get(config.RADIUS_ATTR_FRAMED_PROTOCOL),
                'calling_sta': calling_sta,
                'mac_addr': normalize_mac(vendor_mac or calling_sta) if (vendor_mac or calling_sta) else None,
                'called_sta': attrs.get(config.RADIUS_ATTR_CALLED_STA),
                'framed_ip': attrs.get(config.RADIUS_ATTR_FRAMED_IP),
                'framed_ip_netmask': attrs.get(config.RADIUS_ATTR_FRAMED_IP_NETMASK),
                'class_attr': attrs.get(config.RADIUS_ATTR_CLASS),
                'acct_session_id': attrs.get(config.RADIUS_ATTR_ACCT_SESSION_ID),
                'acct_multi_session_id': attrs.get(config.RADIUS_ATTR_ACCT_MULTI_SESSION_ID),
                'error_cause': attrs.get(config.RADIUS_ATTR_ERROR_CAUSE),
                'event_timestamp': attrs.get(config.RADIUS_ATTR_EVENT_TIMESTAMP),
                'connect_info': attrs.get(config.RADIUS_ATTR_CONNECT_INFO),
                'packet_identifier': ident,
                'result_code': code,
                'result': config.RADIUS_CODE.get(code, f'code={code}'),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'ts': ts_str,
            }

        elif code == 5:
            self.accounting_responses += 1
            return None

        elif code not in config.RADIUS_CODE:
            self.unknown_codes += 1

        # Accounting-Response is intentionally not stored; the request carries
        # the counters and session attributes needed for operations analysis.
        return None

    def gc_expired(self):
        """清理超时未配对的 pending 请求（防内存泄漏）"""
        import time
        now = time.monotonic()
        if now - self._last_gc < 10:   # 每 10 秒 GC 一次
            return
        self._last_gc = now
        cutoff = now - self.ttl_sec
        expired = [k for k, v in self.pending.items()
                   if v.get('_ts', now) < cutoff]
        self.expired_auth_requests += len(expired)
        for k in expired:
            self.pending.pop(k, None)


import time  # noqa: E402 – 放在底部避免循环引用
