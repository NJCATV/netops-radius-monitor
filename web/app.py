"""
radius_monitor/web/app.py
Flask Web 报表服务：提供 REST API 和实时报表页面
"""

import logging
from datetime import datetime, timedelta
import time
import json
from flask import Flask, jsonify, request, render_template

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import config
import db

logger = logging.getLogger(__name__)
app = Flask(__name__)
_CACHE = {}
_REDIS = None
CACHE_SECONDS = 30


# ── 工具函数 ──────────────────────────────────────────────────────────────────

def _hours_param(default=24, max_hours=720):
    try:
        return max(1, min(int(request.args.get('hours', default)), max_hours))
    except Exception:
        return default


def _date_range_params(max_days=30):
    """解析前端日期范围。返回 start_date, end_date, start_ts, end_ts_exclusive。"""
    start_arg = (request.args.get('start_date') or '').strip()
    end_arg = (request.args.get('end_date') or '').strip()
    if not start_arg and not end_arg:
        return None, None, None, None

    try:
        start_day = datetime.strptime(start_arg or end_arg, '%Y-%m-%d').date()
        end_day = datetime.strptime(end_arg or start_arg, '%Y-%m-%d').date()
    except ValueError:
        return None, None, None, None

    if end_day < start_day:
        start_day, end_day = end_day, start_day

    max_days = max(1, int(max_days or 30))
    if (end_day - start_day).days + 1 > max_days:
        end_day = start_day + timedelta(days=max_days - 1)

    start_ts = datetime.combine(start_day, datetime.min.time()).strftime('%Y-%m-%d %H:%M:%S')
    end_ts = datetime.combine(end_day + timedelta(days=1), datetime.min.time()).strftime('%Y-%m-%d %H:%M:%S')
    return f'{start_day:%Y-%m-%d}', f'{end_day:%Y-%m-%d}', start_ts, end_ts


def _json_value(value):
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {k: _json_value(v) for k, v in value.items()}
    return value


def _jsonify_rows(rows):
    """将查询结果中的 datetime 等特殊类型转为字符串"""
    return [_json_value(row) for row in rows]


def _cache_key(key):
    return f"{config.API_CACHE_PREFIX}:api:{json.dumps(key, ensure_ascii=False, sort_keys=True)}"


def _get_redis():
    global _REDIS
    if _REDIS is not None:
        return _REDIS
    try:
        import redis
        client = redis.Redis.from_url(config.REDIS_URL, socket_timeout=0.2, socket_connect_timeout=0.2)
        client.ping()
        _REDIS = client
    except Exception as exc:
        logger.info("Redis API缓存不可用，使用进程内缓存: %s", exc)
        _REDIS = False
    return _REDIS or None


def _cached(key, loader, ttl=CACHE_SECONDS):
    """短时缓存耗费较高的报表聚合，避免多个页面重复扫描明细表。"""
    redis_client = _get_redis()
    redis_key = _cache_key(key)
    if redis_client:
        try:
            cached = redis_client.get(redis_key)
            if cached:
                return json.loads(cached)
            lock_key = f"{redis_key}:lock"
            locked = redis_client.set(lock_key, "1", nx=True, ex=20)
            if not locked:
                stale = redis_client.get(f"{redis_key}:stale")
                if stale:
                    return json.loads(stale)
                time.sleep(0.15)
                cached = redis_client.get(redis_key)
                if cached:
                    return json.loads(cached)
            value = _json_value(loader())
            payload = json.dumps(value, ensure_ascii=False, default=str)
            redis_client.setex(redis_key, ttl, payload)
            redis_client.setex(f"{redis_key}:stale", max(ttl * 10, 300), payload)
            if locked:
                redis_client.delete(lock_key)
            return value
        except Exception as exc:
            logger.warning("Redis API缓存失败，回退进程缓存: %s", exc)

    now = time.monotonic()
    cached = _CACHE.get(key)
    if cached and now - cached[0] < ttl:
        return cached[1]
    value = _json_value(loader())
    _CACHE[key] = (now, value)
    return value


# ── 主报表页 ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template(
        'index.html',
        report_valid_from=config.REPORT_VALID_FROM,
    )


@app.route('/records')
@app.route('/risk')
@app.route('/risk/reject')
@app.route('/risk/multi')
@app.route('/accounting')
def spa_routes():
    return index()


# ── REST API ──────────────────────────────────────────────────────────────────

@app.route('/api/stats')
def api_stats():
    """顶层统计概览"""
    hours = _hours_param(24)
    data = dict(_cached(('stats', hours), lambda: db.query_stats(hours)))
    # 格式化数值
    for k in ('total', 'accepts', 'rejects'):
        data[k] = int(data.get(k) or 0)
    data['accept_rate']   = float(data.get('accept_rate') or 0)
    data['reject_rate']   = float(data.get('reject_rate') or 0)
    data['avg_latency_ms'] = round(float(data.get('avg_latency_ms') or 0), 1)
    data['hours']         = hours
    return jsonify({'ok': True, 'data': data})


@app.route('/api/recent')
def api_recent():
    """最近认证明细"""
    limit = min(int(request.args.get('limit', 100)), 500)
    rows  = db.query_recent_records(limit)
    return jsonify({'ok': True, 'data': _jsonify_rows(rows)})


@app.route('/api/records/search')
def api_records_search():
    """按时间窗口、账号和 MAC 查询认证历史记录。"""
    hours = _hours_param(3, max_hours=720)
    limit = min(max(int(request.args.get('limit', 300)), 1), 1000)
    username = (request.args.get('username') or '').strip().upper()
    mac_addr = (request.args.get('mac') or '').strip()
    result = request.args.get('result')
    try:
        result_code = int(result) if result else None
    except Exception:
        result_code = None
    if result_code not in (2, 3):
        result_code = None
    rows = db.query_auth_records(
        hours=hours,
        username=username,
        mac_addr=mac_addr,
        result=result_code,
        limit=limit,
    )
    return jsonify({'ok': True, 'data': _jsonify_rows(rows)})


@app.route('/api/accounting/dashboard')
def api_accounting_dashboard():
    """最近计费样本的轻量会话看板"""
    limit = min(max(int(request.args.get('limit', 80)), 1), 300)
    data = _cached(('accounting-dashboard', limit), lambda: db.query_accounting_dashboard(limit))
    stats = dict(data.get('stats') or {})
    for key in (
        'report_count', 'start_count', 'stop_count', 'session_count',
        'active_sessions', 'input_bytes', 'output_bytes', 'total_bytes',
    ):
        stats[key] = int(stats.get(key) or 0)
    return jsonify({
        'ok': True,
        'data': {
            'stats': _json_value(stats),
            'sessions': _jsonify_rows(data.get('sessions') or []),
        },
    })


@app.route('/api/accounting/search')
def api_accounting_search():
    hours = _hours_param(48, max_hours=max(int(getattr(config, 'ACCT_RETAIN_DAYS', 30)) * 24, 1))
    limit = min(max(int(request.args.get('limit', 300)), 1), 1000)
    username = (request.args.get('username') or '').strip().upper()
    if not username:
        return jsonify({'ok': True, 'data': []})
    rows = db.query_accounting_records(username=username, hours=hours, limit=limit)
    return jsonify({'ok': True, 'data': _jsonify_rows(rows)})


@app.route('/api/top-reject')
def api_top_reject():
    """拒绝次数最多的账号"""
    hours = _hours_param(24)
    start_date, end_date, start_ts, end_ts = _date_range_params(max_days=30)
    limit = min(int(request.args.get('limit', 20)), 100)
    rows = _cached(
        ('top-reject', hours, start_date, end_date, limit),
        lambda: db.query_top_reject_users(limit, hours, start_ts=start_ts, end_ts=end_ts),
    )
    return jsonify({'ok': True, 'data': _jsonify_rows(rows)})


@app.route('/api/risk-accounts')
def api_risk_accounts():
    """高风险账号"""
    hours = _hours_param(24)
    start_date, end_date, start_ts, end_ts = _date_range_params(max_days=30)
    page = max(int(request.args.get('page', 1)), 1)
    page_size = min(max(int(request.args.get('page_size', 100)), 1), 500)
    min_count = max(int(request.args.get('min_count', 100)), 0)
    data = _cached(
        ('risk-accounts', hours, start_date, end_date, page, page_size, min_count),
        lambda: db.query_risk_accounts(
            hours=hours,
            start_ts=start_ts,
            end_ts=end_ts,
            page=page,
            page_size=page_size,
            min_count=min_count,
        ),
    )
    return jsonify({
        'ok': True,
        'data': {
            'rows': _jsonify_rows(data.get('rows') or []),
            'total': int(data.get('total') or 0),
            'page': int(data.get('page') or page),
            'page_size': int(data.get('page_size') or page_size),
            'min_count': int(data.get('min_count') or min_count),
            'has_next': bool(data.get('has_next')),
        },
    })


@app.route('/api/multi-mac-accounts')
def api_multi_mac_accounts():
    """同一 GDF/GDC 账号多 MAC 拨号风险"""
    hours = _hours_param(24)
    start_date, end_date, start_ts, end_ts = _date_range_params(max_days=30)
    limit = min(int(request.args.get('limit', 100)), 500)
    min_mac = max(2, int(request.args.get('min_mac', 2)))
    rows = _cached(
        ('multi-mac-accounts', hours, start_date, end_date, limit, min_mac),
        lambda: db.query_multi_mac_accounts(
            hours=hours,
            start_ts=start_ts,
            end_ts=end_ts,
            limit=limit,
            min_mac=min_mac,
        ),
    )
    return jsonify({'ok': True, 'data': _jsonify_rows(rows)})


def api_reason_dist():
    """拒绝原因分布"""
    hours = _hours_param(24)
    rows = _cached(('reason-dist', hours), lambda: db.query_reason_distribution(hours))
    return jsonify({'ok': True, 'data': _jsonify_rows(rows)})


def api_nas_dist():
    """NAS 分布"""
    hours = _hours_param(24)
    rows = _cached(('nas-dist', hours), lambda: db.query_nas_distribution(hours))
    return jsonify({'ok': True, 'data': _jsonify_rows(rows)})


@app.route('/api/timeline')
def api_timeline():
    """时间轴折线图数据"""
    hours        = _hours_param(6)
    interval_min = int(request.args.get('interval', 5))
    rows = _cached(('timeline', hours, interval_min), lambda: db.query_timeline(hours, interval_min))
    return jsonify({'ok': True, 'data': _jsonify_rows(rows)})


@app.route('/api/user/<username>')
def api_user_detail(username):
    """单个账号明细"""
    limit = min(int(request.args.get('limit', 50)), 200)
    rows  = db.query_user_detail(username, limit)
    return jsonify({'ok': True, 'data': _jsonify_rows(rows), 'username': username})


@app.route('/api/export/csv')
def api_export_csv():
    """导出最近记录为 CSV"""
    import io, csv
    from flask import Response
    limit = min(int(request.args.get('limit', 1000)), 5000)
    rows  = db.query_recent_records(limit)
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            clean = {}
            for k, v in row.items():
                clean[k] = v.strftime('%Y-%m-%d %H:%M:%S') if isinstance(v, datetime) else v
            writer.writerow(clean)
    csv_content = output.getvalue()
    return Response(
        csv_content,
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': 'attachment; filename=radius_log.csv'},
    )


# ── 健康检查 ──────────────────────────────────────────────────────────────────

@app.route('/health')
def health():
    try:
        db.query_health()
        return jsonify({'ok': True, 'db': 'connected'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 503


# ── 启动 ──────────────────────────────────────────────────────────────────────

@app.route('/api/ingest/status')
def api_ingest_status():
    try:
        data = db.query_ingest_status()
        return jsonify({'ok': True, 'data': _json_value(data)})
    except Exception as e:
        logger.exception("查询采集状态失败: %s", e)
        return jsonify({'ok': False, 'error': str(e)}), 503


def create_app():
    db.init_pool()
    db.init_db()
    return app


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    )
    application = create_app()
    application.run(
        host=config.WEB_HOST,
        port=config.WEB_PORT,
        debug=config.WEB_DEBUG,
    )
