"""
radius_monitor/config.py
全局配置：网络接口、MySQL 连接、服务端口等
"""

import os

# ── 抓包配置 ──────────────────────────────────────────────────────────────────
CAPTURE_IFACE   = os.getenv('CAPTURE_IFACE', 'eno1')       # 监听网卡（镜像口）
CAPTURE_SNAPLEN = 65535                                     # 最大抓包长度
CAPTURE_BUFFER_KIB = int(os.getenv('CAPTURE_BUFFER_KIB', '8192'))
CAPTURE_PROMISC = True                                      # 混杂模式
RADIUS_AUTH_PORT = int(os.getenv('RADIUS_AUTH_PORT', '1812'))
RADIUS_ACCT_PORT = int(os.getenv('RADIUS_ACCT_PORT', '1813'))
RADIUS_COA_PORT = int(os.getenv('RADIUS_COA_PORT', '3799'))
CAPTURE_AUTH = os.getenv('CAPTURE_AUTH', '1') == '1'
CAPTURE_ACCOUNTING = os.getenv('CAPTURE_ACCOUNTING', '0') == '1'
# 只做镜像口被动观察，不发送 CoA/Disconnect，不改变任何用户会话。
CAPTURE_CONTROL = os.getenv('CAPTURE_CONTROL', '1') == '1'
WRITE_ACCOUNTING_LOG = os.getenv('WRITE_ACCOUNTING_LOG', '0') == '1'
ACCT_INTERIM_SAMPLE_SECONDS = int(os.getenv('ACCT_INTERIM_SAMPLE_SECONDS', '60'))
AUTH_WRITER_BATCH_SIZE = int(os.getenv('AUTH_WRITER_BATCH_SIZE', '1000'))
AUTH_REALTIME_WRITER_BATCH_SIZE = int(os.getenv('AUTH_REALTIME_WRITER_BATCH_SIZE', str(AUTH_WRITER_BATCH_SIZE)))
AUTH_RISK_WRITER_BATCH_SIZE = int(os.getenv('AUTH_RISK_WRITER_BATCH_SIZE', '2000'))
ACCT_WRITER_BATCH_SIZE = int(os.getenv('ACCT_WRITER_BATCH_SIZE', '2000'))
WRITER_QUEUE_SIZE = int(os.getenv('WRITER_QUEUE_SIZE', '50000'))

# ── 存储配置 ─────────────────────────────────────────────────────────────────
# 生产切换时设置为 clickhouse；保留 mysql 仅用于紧急回退，二者不会同时写入。
STORAGE_BACKEND = os.getenv('STORAGE_BACKEND', 'mysql').strip().lower()
CLICKHOUSE_URL = os.getenv('CLICKHOUSE_URL', 'http://172.25.194.212:8123').rstrip('/')
CLICKHOUSE_DATABASE = os.getenv('CLICKHOUSE_DATABASE', 'radius_monitor_ch')
CLICKHOUSE_USER = os.getenv('CLICKHOUSE_USER', 'radius_writer')
CLICKHOUSE_PASSWORD = os.getenv('CLICKHOUSE_PASSWORD', '')
CLICKHOUSE_CONNECT_TIMEOUT = float(os.getenv('CLICKHOUSE_CONNECT_TIMEOUT', '3'))
CLICKHOUSE_READ_TIMEOUT = float(os.getenv('CLICKHOUSE_READ_TIMEOUT', '20'))
CLICKHOUSE_BATCH_SIZE = int(os.getenv('CLICKHOUSE_BATCH_SIZE', '1000'))
CLICKHOUSE_FLUSH_SECONDS = float(os.getenv('CLICKHOUSE_FLUSH_SECONDS', '1'))
CLICKHOUSE_VERIFY_TLS = os.getenv('CLICKHOUSE_VERIFY_TLS', '1') == '1'
SPOOL_PATH = os.getenv('SPOOL_PATH', '/var/lib/radius-monitor/spool.sqlite3')
SPOOL_QUEUE_SIZE = int(os.getenv('SPOOL_QUEUE_SIZE', '50000'))
SPOOL_MAX_BYTES = int(os.getenv('SPOOL_MAX_BYTES', str(20 * 1024 * 1024 * 1024)))
# 现场华为 RADIUS+ 的 Acct-Input/Output-Octets 实际以 KiB 上报。
# ClickHouse 对外统一存字节，避免前端和查询层各自猜测单位。
RADIUS_COUNTER_SCALE = int(os.getenv('RADIUS_COUNTER_SCALE', '1024'))
COLLECTOR_METRICS_INTERVAL = int(os.getenv('COLLECTOR_METRICS_INTERVAL', '60'))
COLLECTOR_LOG_EVERY = int(os.getenv('COLLECTOR_LOG_EVERY', '5000'))

_capture_ports = []
if CAPTURE_AUTH:
    _capture_ports.append(RADIUS_AUTH_PORT)
if CAPTURE_ACCOUNTING:
    _capture_ports.append(RADIUS_ACCT_PORT)
if CAPTURE_CONTROL:
    _capture_ports.append(RADIUS_COA_PORT)
RADIUS_CAPTURE_PORTS = set(_capture_ports)
CAPTURE_FILTER = os.getenv(
    'CAPTURE_FILTER',
    ' or '.join(f'udp port {port}' for port in _capture_ports) or f'udp port {RADIUS_AUTH_PORT}',
)  # BPF 过滤器

# ── MySQL 配置 ────────────────────────────────────────────────────────────────
DB_HOST     = os.getenv('MYSQL_HOST', '127.0.0.1')
DB_PORT     = int(os.getenv('MYSQL_PORT', '3306'))
DB_NAME     = os.getenv('MYSQL_DB',   'radius_monitor')
DB_USER     = os.getenv('MYSQL_USER', 'radius')
DB_PASSWORD = os.getenv('MYSQL_PASS', '')
DB_POOL_SIZE     = 5
DB_POOL_OVERFLOW = 10
DB_CONNECT_TIMEOUT = int(os.getenv('MYSQL_CONNECT_TIMEOUT', '5'))
DB_READ_TIMEOUT    = int(os.getenv('MYSQL_READ_TIMEOUT', '20'))
DB_WRITE_TIMEOUT   = int(os.getenv('MYSQL_WRITE_TIMEOUT', '20'))

# ── Web 服务配置 ──────────────────────────────────────────────────────────────
WEB_HOST    = '0.0.0.0'
WEB_PORT    = int(os.getenv('WEB_PORT', '5000'))
WEB_DEBUG   = False
REDIS_URL   = os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/0')
API_CACHE_PREFIX = os.getenv('API_CACHE_PREFIX', 'radius_monitor')

# ── 数据保留配置 ──────────────────────────────────────────────────────────────
RETAIN_DAYS     = int(os.getenv('RETAIN_DAYS', '30'))     # 认证明细保留天数
ACCT_RETAIN_DAYS = int(os.getenv('ACCT_RETAIN_DAYS', '30'))  # acct_log 单独保留天数
ACCT_CLEANUP_BATCH_SIZE = int(os.getenv('ACCT_CLEANUP_BATCH_SIZE', '1000'))
AUTH_CLEANUP_BATCH_SIZE = int(os.getenv('AUTH_CLEANUP_BATCH_SIZE', '5000'))
AUTH_CLEANUP_MAX_BATCHES = int(os.getenv('AUTH_CLEANUP_MAX_BATCHES', '10'))
ACCT_CLEANUP_MAX_BATCHES = int(os.getenv('ACCT_CLEANUP_MAX_BATCHES', '10'))
AUTH_USER_RETAIN_DAYS = int(os.getenv('AUTH_USER_RETAIN_DAYS', '1'))
AUTH_USER_MAC_RETAIN_DAYS = int(os.getenv('AUTH_USER_MAC_RETAIN_DAYS', '3'))
SUMMARY_INTERVAL = 60    # user_summary 刷新间隔（秒）
# 高吞吐采集时优先保证明细入库；多终端派生汇总可在低流量场景显式开启。
UPDATE_USER_MAC_SUMMARY = os.getenv('UPDATE_USER_MAC_SUMMARY', '0') == '1'
# 高吞吐场景默认使用固定10分钟桶 auth_rollup_10m 承接认证实时明细。
# 旧的 auth_event_span 滑动事件段需要先查询再逐行 UPDATE，写入压力大；仅回退排障时开启。
WRITE_AUTH_EVENT_SPAN = os.getenv('WRITE_AUTH_EVENT_SPAN', '0') == '1'
WRITE_AUTH_ROLLUP = os.getenv('WRITE_AUTH_ROLLUP', '0') == '1'
WRITE_AUTH_RISK = os.getenv('WRITE_AUTH_RISK', '0') == '1'
# 该时间之前的历史明细可能因采集队列丢弃而不适合作为报表统计基数。
REPORT_VALID_FROM = os.getenv('REPORT_VALID_FROM', '')

# ── RADIUS 常量 ───────────────────────────────────────────────────────────────
RADIUS_ATTR_USER_NAME    = 1
RADIUS_ATTR_NAS_IP       = 4
RADIUS_ATTR_NAS_PORT     = 5
RADIUS_ATTR_SERVICE_TYPE = 6
RADIUS_ATTR_FRAMED_PROTOCOL = 7
RADIUS_ATTR_FRAMED_IP_NETMASK = 9
RADIUS_ATTR_CLASS = 25
RADIUS_ATTR_NAS_IDENTIFIER = 32
RADIUS_ATTR_NAS_PORT_TYPE = 61
RADIUS_ATTR_NAS_PORT_ID  = 87
RADIUS_ATTR_CALLED_STA   = 30
RADIUS_ATTR_CALLING_STA  = 31
RADIUS_ATTR_REPLY_MSG    = 18
RADIUS_ATTR_FRAMED_IP    = 8
RADIUS_ATTR_ACCT_STATUS_TYPE = 40
RADIUS_ATTR_ACCT_DELAY_TIME = 41
RADIUS_ATTR_ACCT_INPUT_OCTETS = 42
RADIUS_ATTR_ACCT_OUTPUT_OCTETS = 43
RADIUS_ATTR_ACCT_SESSION_ID = 44
RADIUS_ATTR_ACCT_AUTHENTIC = 45
RADIUS_ATTR_ACCT_SESSION_TIME = 46
RADIUS_ATTR_ACCT_INPUT_PACKETS = 47
RADIUS_ATTR_ACCT_OUTPUT_PACKETS = 48
RADIUS_ATTR_ACCT_TERMINATE_CAUSE = 49
RADIUS_ATTR_ACCT_MULTI_SESSION_ID = 50
RADIUS_ATTR_ACCT_INPUT_GIGAWORDS = 52
RADIUS_ATTR_ACCT_OUTPUT_GIGAWORDS = 53
RADIUS_ATTR_EVENT_TIMESTAMP = 55
RADIUS_ATTR_CONNECT_INFO = 77
RADIUS_ATTR_ERROR_CAUSE = 101
RADIUS_ATTR_VENDOR_SPECIFIC = 26

RADIUS_VENDOR_HUAWEI = 2011
RADIUS_VENDOR_H3C = 25506
HUAWEI_VSA_INPUT_AVERAGE_RATE = 1
HUAWEI_VSA_OUTPUT_AVERAGE_RATE = 2
HUAWEI_VSA_FIRST_DNS = 15
HUAWEI_VSA_SECOND_DNS = 16
HUAWEI_VSA_PRODUCT_ID = 22
HUAWEI_VSA_SUBSCRIBER_ID = 138
HUAWEI_VSA_MAC_ADDRESS = 153

RADIUS_CODE = {
    1:  'Access-Request',
    2:  'Access-Accept',
    3:  'Access-Reject',
    4:  'Accounting-Request',
    5:  'Accounting-Response',
    11: 'Access-Challenge',
    40: 'Disconnect-Request',
    41: 'Disconnect-ACK',
    42: 'Disconnect-NAK',
    43: 'CoA-Request',
    44: 'CoA-ACK',
    45: 'CoA-NAK',
}

# ── 拒绝原因翻译表 ─────────────────────────────────────────────────────────────
REPLY_MSG_TRANSLATION = {
    '006:Search Err or User not exists':               ('账号不存在',     'high'),
    '020:Your loginname have Non-printable Character': ('账号含非法字符', 'medium'),
    '002:Your password is error , please check':       ('密码错误',       'medium'),
    '018:User not any subscription':                   ('账号未订购服务', 'low'),
    '007:User State Err':                              ('账号状态异常',   'medium'),
    '014:User subscription Time error':                ('订购时间异常',   'low'),
}

# 风险账号关键词
RISK_USERNAME_PATTERNS = [
    'admin', 'root', 'administrator', 'test', 'guest',
    'backup', 'operator', 'user', 'user1', 'user01',
]

# ── 拒绝原因配色（Web 报表用） ──────────────────────────────────────────────────
REASON_COLOR = {
    '账号不存在':      '#ef5350',
    '账号含非法字符':  '#f9a825',
    '密码错误':        '#ab47bc',
    '账号未订购服务':  '#42a5f5',
    '账号状态异常':    '#ff7043',
    '订购时间异常':    '#26a69a',
    '未知':            '#888888',
}
REASON_BG = {
    '账号不存在':      '#2d1010',
    '账号含非法字符':  '#2d2000',
    '密码错误':        '#1a0f2d',
    '账号未订购服务':  '#0d1a2d',
    '账号状态异常':    '#2d1500',
    '订购时间异常':    '#0d2d2d',
    '未知':            '#1a1a1a',
}
