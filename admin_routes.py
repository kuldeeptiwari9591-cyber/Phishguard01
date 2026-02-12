"""
PhishGuard Admin Panel - Route Definitions
All admin-related Flask routes: auth, dashboard, scan history, analytics, etc.

Credentials loaded from admin_config.json (run create_admin.py once to create it).
Falls back to environment variables if the file is absent (for Render/cloud deploy).
"""

from flask import Blueprint, request, jsonify, session, send_from_directory
from functools import wraps
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
import logging

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# ─────────────────────────────────────────────
# CREDENTIAL LOADER
# ─────────────────────────────────────────────

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'admin_config.json')
# ─────────────────────────────────────────────
# ADMIN USER MANAGEMENT (MULTI-ADMIN SYSTEM)
# ─────────────────────────────────────────────

ADMIN_USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'admin_users.json')

def _load_admin_users():
    """Load the admin users database."""
    if os.path.exists(ADMIN_USERS_FILE):
        try:
            with open(ADMIN_USERS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading admin users: {e}")
    
    # Default structure
    return {
        "super_admin": {
            "username": "Kuldeep9399",
            "password": "kuldeep@9399",
            "role": "super_admin",
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        "admins": [],
        "api_settings": {
            "google_safe_browsing": {"enabled": True, "usage_count": 0, "last_used": None},
            "virustotal": {"enabled": True, "usage_count": 0, "last_used": None},
            "whoisxml": {"enabled": True, "usage_count": 0, "last_used": None},
            "screenshot": {"enabled": True, "usage_count": 0, "last_used": None}
        }
    }

def _save_admin_users(data):
    """Save admin users database."""
    try:
        with open(ADMIN_USERS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving admin users: {e}")
        return False

def check_credentials_multi(username: str, password: str) -> dict:
    """
    Check credentials against multi-admin system.
    Returns: {"valid": bool, "role": str, "username": str} or None
    """
    import hmac
    
    users = _load_admin_users()
    
    # Check super admin
    sa = users.get("super_admin", {})
    if hmac.compare_digest(username.strip(), sa.get("username", "")) and        hmac.compare_digest(password, sa.get("password", "")):
        return {"valid": True, "role": "super_admin", "username": username}
    
    # Check regular admins
    for admin in users.get("admins", []):
        if admin.get("active", True) and            hmac.compare_digest(username.strip(), admin.get("username", "")) and            hmac.compare_digest(password, admin.get("password", "")):
            return {"valid": True, "role": "admin", "username": username}
    
    return None

def is_super_admin():
    """Check if current session user is super admin."""
    return session.get('admin_role') == 'super_admin'

def require_super_admin(f):
    """Decorator to require super admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in') or not is_super_admin():
            return jsonify({'error': 'Super admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

def increment_api_usage(api_name: str):
    """Increment API usage counter."""
    users = _load_admin_users()
    api_settings = users.get("api_settings", {})
    if api_name in api_settings:
        api_settings[api_name]["usage_count"] = api_settings[api_name].get("usage_count", 0) + 1
        api_settings[api_name]["last_used"] = datetime.now(timezone.utc).isoformat()
        users["api_settings"] = api_settings
        _save_admin_users(users)



def _load_credentials():
    """
    Load plain-text admin credentials.
    Priority:  admin_config.json  →  env vars  →  default admin/admin123
    """
    # 1. Try admin_config.json first (created by create_admin.py)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
            user = cfg.get('admin_username', '').strip()
            pw   = cfg.get('admin_password', '').strip()
            if user and pw:
                logger.info("[Admin] Credentials loaded from admin_config.json")
                return user, pw
        except Exception as e:
            logger.warning(f"[Admin] Could not read admin_config.json: {e}")

    # 2. Try environment variables (for Render / cloud deploy)
    env_user = os.getenv('ADMIN_USERNAME', '').strip()
    env_pw   = os.getenv('ADMIN_PASSWORD', '').strip()
    if env_user and env_pw:
        logger.info("[Admin] Credentials loaded from environment variables")
        return env_user, env_pw

    # 3. Fallback default — warns loudly
    logger.warning("[Admin] Using default credentials! Run: python create_admin.py")
    return 'admin', 'admin123'


def check_credentials(username: str, password: str) -> bool:
    """Simple plain-text credential check."""
    import hmac
    stored_user, stored_pw = _load_credentials()
    return (hmac.compare_digest(username.strip(), stored_user) and
            hmac.compare_digest(password, stored_pw))


# ─────────────────────────────────────────────
# DECORATORS
# ─────────────────────────────────────────────

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            if request.is_json:
                return jsonify({'error': 'Unauthorized', 'redirect': '/admin/login'}), 401
            from flask import redirect
            return redirect('/admin/login')
        return f(*args, **kwargs)
    return decorated


def log_admin_action(db, action: str, details: str = ''):
    """Write an entry to the admin_logs collection."""
    if db is None:
        return
    try:
        db.admin_logs.insert_one({
            'admin':     session.get('admin_user', 'unknown'),
            'action':    action,
            'details':   details,
            'ip':        request.remote_addr or '',
            'timestamp': datetime.now(timezone.utc)
        })
    except Exception as e:
        logger.error(f"Admin log error: {e}")



# ─────────────────────────────────────────────
# STATIC PAGE ROUTES
# ─────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@admin_bp.route('/login')
def admin_login_page():
    """Serve the admin login HTML page."""
    if session.get('admin_logged_in'):
        from flask import redirect
        return redirect('/admin/dashboard')
    return send_from_directory(BASE_DIR, 'admin_login.html')


@admin_bp.route('/dashboard')
@require_admin
def admin_dashboard_page():
    """Serve the admin panel SPA."""
    return send_from_directory(BASE_DIR, 'admin_panel.html')


@admin_bp.route('/<path:subpath>')
def admin_spa_fallback(subpath):
    """
    SPA fallback for admin sub-routes.
    Redirects to login if not authenticated, otherwise serves the SPA.
    """
    if not subpath.startswith('api/'):
        if session.get('admin_logged_in'):
            return send_from_directory(BASE_DIR, 'admin_panel.html')
        from flask import redirect
        return redirect('/admin/login')
    from flask import abort
    abort(404)


# ─────────────────────────────────────────────
# AUTH ENDPOINTS
# ─────────────────────────────────────────────

@admin_bp.route('/api/login', methods=['POST'])
def admin_login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    logger.info(f"[Admin] Login attempt - username: '{username}'")

    if not username or not password:
        logger.warning("[Admin] Login failed - missing credentials")
        return jsonify({'success': False, 'error': 'Username and password required'}), 400

    # Check against multi-admin system
    auth_result = check_credentials_multi(username, password)
    
    if auth_result and auth_result.get('valid'):
        session['admin_logged_in'] = True
        session['admin_user'] = username
        session['admin_role'] = auth_result.get('role', 'admin')
        session.permanent = True

        from flask import current_app
        db = current_app.config.get('DB')
        log_admin_action(db, 'LOGIN', f'{auth_result["role"]} {username} logged in')
        logger.info(f"[Admin] ✅ Login successful: {username} (role: {auth_result['role']})")

        return jsonify({
            'success': True, 
            'message': 'Login successful',
            'role': auth_result['role']
        })

    logger.warning(f"[Admin] ❌ Failed login - username: '{username}'")
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401


@admin_bp.route('/api/logout', methods=['POST'])
@require_admin
def admin_logout():
    from flask import current_app
    db = current_app.config.get('DB')
    log_admin_action(db, 'LOGOUT', '')
    session.clear()
    return jsonify({'success': True})


@admin_bp.route('/api/me', methods=['GET'])
def admin_me():
    if session.get('admin_logged_in'):
        return jsonify({'logged_in': True, 'username': session.get('admin_user')})
    return jsonify({'logged_in': False})


# ─────────────────────────────────────────────
# DASHBOARD OVERVIEW
# ─────────────────────────────────────────────

@admin_bp.route('/api/dashboard', methods=['GET'])
@require_admin
def admin_dashboard():
    from flask import current_app
    db = current_app.config.get('DB')

    if db is None:
        return jsonify({'error': 'Database not available'}), 503

    try:
        total_scans = db.analyses.count_documents({})
        high_risk   = db.analyses.count_documents({'risk_level': 'HIGH'})
        suspicious  = db.analyses.count_documents({'risk_level': 'SUSPICIOUS'})
        safe        = db.analyses.count_documents({'risk_level': 'SAFE'})
        reports     = db.reports.count_documents({}) if 'reports' in db.list_collection_names() else 0

        # Recent 5 scans
        recent_cursor = db.analyses.find(
            {}, {'url': 1, 'domain': 1, 'risk_level': 1, 'risk_score': 1, 'timestamp': 1}
        ).sort('timestamp', -1).limit(5)

        recent = []
        for doc in recent_cursor:
            recent.append({
                'id': str(doc['_id']),
                'url': doc.get('url', ''),
                'domain': doc.get('domain', ''),
                'risk_level': doc.get('risk_level', 'UNKNOWN'),
                'risk_score': doc.get('risk_score', 0),
                'timestamp': doc.get('timestamp', datetime.now()).isoformat()
                    if isinstance(doc.get('timestamp'), datetime)
                    else str(doc.get('timestamp', ''))
            })

        log_admin_action(db, 'VIEW_DASHBOARD', '')

        return jsonify({
            'total_scans': total_scans,
            'high_risk': high_risk,
            'suspicious': suspicious,
            'safe': safe,
            'total_reports': reports,
            'recent_activity': recent
        })

    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return jsonify({'error': str(e)}), 500


# ─────────────────────────────────────────────
# SCAN HISTORY
# ─────────────────────────────────────────────

@admin_bp.route('/api/scans', methods=['GET'])
@require_admin
def admin_scans():
    from flask import current_app
    db = current_app.config.get('DB')
    if db is None:
        return jsonify({'scans': [], 'total': 0})

    try:
        page       = max(1, int(request.args.get('page', 1)))
        per_page   = min(100, int(request.args.get('per_page', 25)))
        risk_filter = request.args.get('risk', '')
        search_q   = request.args.get('q', '').strip()

        query = {}
        if risk_filter in ('HIGH', 'SUSPICIOUS', 'SAFE', 'LOW'):
            query['risk_level'] = risk_filter
        if search_q:
            query['$or'] = [
                {'url':    {'$regex': search_q, '$options': 'i'}},
                {'domain': {'$regex': search_q, '$options': 'i'}}
            ]

        total = db.analyses.count_documents(query)
        docs  = list(
            db.analyses.find(query, {
                'url': 1, 'domain': 1, 'risk_level': 1,
                'risk_score': 1, 'timestamp': 1, 'context': 1
            })
            .sort('timestamp', -1)
            .skip((page - 1) * per_page)
            .limit(per_page)
        )

        scans = []
        for doc in docs:
            ts = doc.get('timestamp')
            scans.append({
                'id': str(doc['_id']),
                'url': doc.get('url', ''),
                'domain': doc.get('domain', ''),
                'risk_level': doc.get('risk_level', 'UNKNOWN'),
                'risk_score': doc.get('risk_score', 0),
                'context': doc.get('context', 'GENERAL'),
                'timestamp': ts.isoformat() if isinstance(ts, datetime) else str(ts or '')
            })

        return jsonify({'scans': scans, 'total': total, 'page': page, 'per_page': per_page})

    except Exception as e:
        logger.error(f"Admin scans error: {e}")
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/scans/<scan_id>', methods=['GET'])
@require_admin
def admin_scan_detail(scan_id):
    from flask import current_app
    from bson.objectid import ObjectId
    db = current_app.config.get('DB')
    if db is None:
        return jsonify({'error': 'Database not available'}), 503

    try:
        doc = db.analyses.find_one({'_id': ObjectId(scan_id)})
        if not doc:
            return jsonify({'error': 'Not found'}), 404

        analysis = doc.get('full_analysis', {})
        # Attach screenshot URLs
        for field in ('screenshot_path', 'thumbnail_path'):
            if analysis.get(field):
                fname = os.path.basename(analysis[field])
                key = field.replace('_path', '_url')
                analysis[key] = f'/screenshots/{fname}'

        log_admin_action(db, 'VIEW_SCAN', scan_id)
        return jsonify({'id': str(doc['_id']), 'analysis': analysis})

    except Exception as e:
        logger.error(f"Admin scan detail error: {e}")
        return jsonify({'error': str(e)}), 500


# ─────────────────────────────────────────────
# DOMAIN REPUTATION
# ─────────────────────────────────────────────

@admin_bp.route('/api/domains', methods=['GET'])
@require_admin
def admin_domains():
    from flask import current_app
    db = current_app.config.get('DB')
    if db is None:
        return jsonify({'domains': []})

    try:
        search_q = request.args.get('q', '').strip()
        page     = max(1, int(request.args.get('page', 1)))
        per_page = min(100, int(request.args.get('per_page', 25)))

        pipeline = [
            {'$group': {
                '_id': '$domain',
                'first_seen':       {'$min': '$timestamp'},
                'last_scanned':     {'$max': '$timestamp'},
                'total_scans':      {'$sum': 1},
                'phishing_count':   {'$sum': {'$cond': [{'$eq': ['$risk_level', 'HIGH']}, 1, 0]}},
                'avg_risk_score':   {'$avg': '$risk_score'},
                'blacklist_hits':   {'$sum': {'$cond': [{'$gt': ['$risk_score', 70]}, 1, 0]}}
            }},
            {'$sort': {'total_scans': -1}}
        ]

        if search_q:
            pipeline.insert(0, {'$match': {'domain': {'$regex': search_q, '$options': 'i'}}})

        all_domains = list(db.analyses.aggregate(pipeline))
        total = len(all_domains)
        page_domains = all_domains[(page - 1) * per_page: page * per_page]

        result = []
        for d in page_domains:
            fs = d.get('first_seen')
            ls = d.get('last_scanned')
            result.append({
                'domain':         d['_id'] or 'unknown',
                'first_seen':     fs.isoformat() if isinstance(fs, datetime) else str(fs or ''),
                'last_scanned':   ls.isoformat() if isinstance(ls, datetime) else str(ls or ''),
                'total_scans':    d['total_scans'],
                'phishing_count': d['phishing_count'],
                'avg_risk_score': round(d.get('avg_risk_score') or 0, 1),
                'blacklist_hits': d['blacklist_hits']
            })

        return jsonify({'domains': result, 'total': total, 'page': page, 'per_page': per_page})

    except Exception as e:
        logger.error(f"Admin domains error: {e}")
        return jsonify({'error': str(e)}), 500


# ─────────────────────────────────────────────
# USER REPORTS
# ─────────────────────────────────────────────

@admin_bp.route('/api/reports', methods=['GET'])
@require_admin
def admin_reports():
    from flask import current_app
    db = current_app.config.get('DB')
    if db is None:
        return jsonify({'reports': []})

    try:
        page     = max(1, int(request.args.get('page', 1)))
        per_page = min(100, int(request.args.get('per_page', 25)))

        collections = db.list_collection_names()
        if 'reports' not in collections:
            return jsonify({'reports': [], 'total': 0})

        total = db.reports.count_documents({})
        docs  = list(db.reports.find({}).sort('last_reported', -1)
                     .skip((page - 1) * per_page).limit(per_page))

        reports = []
        for doc in docs:
            lr = doc.get('last_reported')
            reports.append({
                'id':            str(doc['_id']),
                'url':           doc.get('url', ''),
                'report_type':   doc.get('report_type', 'phishing'),
                'report_count':  doc.get('report_count', 1),
                'last_reported': lr.isoformat() if isinstance(lr, datetime) else str(lr or ''),
                'reporter_ip':   doc.get('reporter_ip_hash', '')[:12] + '...'
                                 if doc.get('reporter_ip_hash') else ''
            })

        log_admin_action(db, 'VIEW_REPORTS', '')
        return jsonify({'reports': reports, 'total': total, 'page': page, 'per_page': per_page})

    except Exception as e:
        logger.error(f"Admin reports error: {e}")
        return jsonify({'error': str(e)}), 500


# ─────────────────────────────────────────────
# SCREENSHOTS
# ─────────────────────────────────────────────

@admin_bp.route('/api/screenshots', methods=['GET'])
@require_admin
def admin_screenshots():
    from flask import current_app
    db = current_app.config.get('DB')
    screenshot_dir = current_app.config.get('SCREENSHOT_DIR', 'screenshots')

    page     = max(1, int(request.args.get('page', 1)))
    per_page = min(50, int(request.args.get('per_page', 12)))

    try:
        screenshots = []
        if os.path.isdir(screenshot_dir):
            files = sorted(
                [f for f in os.listdir(screenshot_dir) if f.lower().endswith(('.png', '.jpg', '.jpeg'))],
                key=lambda x: os.path.getmtime(os.path.join(screenshot_dir, x)),
                reverse=True
            )
            total = len(files)
            paged = files[(page - 1) * per_page: page * per_page]
            for fname in paged:
                fpath = os.path.join(screenshot_dir, fname)
                mtime = os.path.getmtime(fpath)
                screenshots.append({
                    'filename':  fname,
                    'url':       f'/screenshots/{fname}',
                    'timestamp': datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(),
                    'size_kb':   round(os.path.getsize(fpath) / 1024, 1),
                    'status':    'cached'
                })
        else:
            total = 0

        return jsonify({'screenshots': screenshots, 'total': total, 'page': page, 'per_page': per_page})

    except Exception as e:
        logger.error(f"Admin screenshots error: {e}")
        return jsonify({'error': str(e)}), 500


# ─────────────────────────────────────────────
# SYSTEM HEALTH
# ─────────────────────────────────────────────

@admin_bp.route('/api/health', methods=['GET'])
@require_admin
def admin_health():
    from flask import current_app
    import requests as req_lib

    db            = current_app.config.get('DB')
    screenshot_dir = current_app.config.get('SCREENSHOT_DIR', 'screenshots')

    def check_api(url, timeout=5):
        try:
            r = req_lib.get(url, timeout=timeout)
            return 'operational' if r.status_code < 500 else 'degraded'
        except Exception:
            return 'unavailable'

    # Google Safe Browsing ping
    gsb_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
    gsb_status = 'configured' if gsb_key else 'not_configured'

    # VirusTotal ping
    vt_key = os.getenv('VIRUSTOTAL_API_KEY', '')
    vt_status = 'configured' if vt_key else 'not_configured'

    # WHOIS
    whois_key = os.getenv('WHOISXML_API_KEY', '')
    whois_status = 'configured' if whois_key else 'not_configured'

    # Screenshot API
    ss_key = os.getenv('SCREENSHOT_API_KEY', '')
    ss_status = 'configured' if ss_key else 'not_configured'

    # DB status
    db_status = 'disconnected'
    if db is not None:
        try:
            db.command('ping')
            db_status = 'connected'
        except Exception:
            db_status = 'error'

    screenshot_available = os.path.isdir(screenshot_dir)

    return jsonify({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'components': {
            'database':           db_status,
            'screenshots':        'available' if screenshot_available else 'unavailable',
            'google_safe_browsing': gsb_status,
            'virustotal':         vt_status,
            'whois':              whois_status,
            'screenshot_service': ss_status
        },
        'overall': 'healthy' if db_status == 'connected' else 'degraded'
    })


# ─────────────────────────────────────────────
# ANALYTICS
# ─────────────────────────────────────────────

@admin_bp.route('/api/analytics', methods=['GET'])
@require_admin
def admin_analytics():
    from flask import current_app
    db = current_app.config.get('DB')
    if db is None:
        return jsonify({'error': 'Database not available'}), 503

    try:
        days = int(request.args.get('days', 7))
        since = datetime.now(timezone.utc) - timedelta(days=days)

        # Daily scan counts
        daily_pipeline = [
            {'$match': {'timestamp': {'$gte': since}}},
            {'$group': {
                '_id': {
                    'year':  {'$year': '$timestamp'},
                    'month': {'$month': '$timestamp'},
                    'day':   {'$dayOfMonth': '$timestamp'}
                },
                'count': {'$sum': 1},
                'high':  {'$sum': {'$cond': [{'$eq': ['$risk_level', 'HIGH']}, 1, 0]}}
            }},
            {'$sort': {'_id.year': 1, '_id.month': 1, '_id.day': 1}}
        ]
        daily_raw = list(db.analyses.aggregate(daily_pipeline))
        daily = []
        for d in daily_raw:
            dt_str = f"{d['_id']['year']}-{d['_id']['month']:02d}-{d['_id']['day']:02d}"
            daily.append({'date': dt_str, 'count': d['count'], 'high_risk': d['high']})

        # Top 10 most-scanned domains
        top_domains = list(db.analyses.aggregate([
            {'$match': {'timestamp': {'$gte': since}}},
            {'$group': {'_id': '$domain', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 10}
        ]))

        # Top reported domains (if collection exists)
        top_reported = []
        if 'reports' in db.list_collection_names():
            top_reported = list(db.reports.aggregate([
                {'$group': {'_id': '$url', 'count': {'$sum': '$report_count'}}},
                {'$sort': {'count': -1}},
                {'$limit': 10}
            ]))

        # Risk distribution
        risk_dist = list(db.analyses.aggregate([
            {'$match': {'timestamp': {'$gte': since}}},
            {'$group': {'_id': '$risk_level', 'count': {'$sum': 1}}}
        ]))

        log_admin_action(db, 'VIEW_ANALYTICS', f'days={days}')

        return jsonify({
            'daily_scans': daily,
            'top_domains': [{'domain': d['_id'] or 'unknown', 'count': d['count']} for d in top_domains],
            'top_reported': [{'url': d['_id'], 'count': d['count']} for d in top_reported],
            'risk_distribution': [{'level': d['_id'], 'count': d['count']} for d in risk_dist],
            'period_days': days
        })

    except Exception as e:
        logger.error(f"Analytics error: {e}")
        return jsonify({'error': str(e)}), 500


# ─────────────────────────────────────────────
# ADMIN ACTIVITY LOGS
# ─────────────────────────────────────────────

@admin_bp.route('/api/logs', methods=['GET'])
@require_admin
def admin_logs():
    from flask import current_app
    db = current_app.config.get('DB')
    if db is None:
        return jsonify({'logs': []})

    try:
        page     = max(1, int(request.args.get('page', 1)))
        per_page = min(100, int(request.args.get('per_page', 50)))

        collections = db.list_collection_names()
        if 'admin_logs' not in collections:
            return jsonify({'logs': [], 'total': 0})

        total = db.admin_logs.count_documents({})
        docs  = list(db.admin_logs.find({}, {'_id': 0})
                     .sort('timestamp', -1)
                     .skip((page - 1) * per_page).limit(per_page))

        logs = []
        for doc in docs:
            ts = doc.get('timestamp')
            logs.append({
                'admin':     doc.get('admin', ''),
                'action':    doc.get('action', ''),
                'details':   doc.get('details', ''),
                'ip':        doc.get('ip', ''),
                'timestamp': ts.isoformat() if isinstance(ts, datetime) else str(ts or '')
            })

        return jsonify({'logs': logs, 'total': total, 'page': page, 'per_page': per_page})

    except Exception as e:
        logger.error(f"Admin logs error: {e}")
        return jsonify({'error': str(e)}), 500


# ─────────────────────────────────────────────
# EXPORT
# ─────────────────────────────────────────────

@admin_bp.route('/api/export/scans', methods=['GET'])
@require_admin
def export_scans():
    from flask import current_app, make_response
    import csv, io
    db = current_app.config.get('DB')
    if db is None:
        return jsonify({'error': 'Database not available'}), 503

    try:
        risk_filter = request.args.get('risk', '')
        query = {}
        if risk_filter in ('HIGH', 'SUSPICIOUS', 'SAFE', 'LOW'):
            query['risk_level'] = risk_filter

        docs = list(db.analyses.find(query, {
            'url': 1, 'domain': 1, 'risk_level': 1, 'risk_score': 1, 'timestamp': 1
        }).sort('timestamp', -1).limit(5000))

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'URL', 'Domain', 'Risk Level', 'Risk Score', 'Timestamp'])
        for doc in docs:
            ts = doc.get('timestamp')
            writer.writerow([
                str(doc['_id']),
                doc.get('url', ''),
                doc.get('domain', ''),
                doc.get('risk_level', ''),
                doc.get('risk_score', 0),
                ts.isoformat() if isinstance(ts, datetime) else str(ts or '')
            ])

        log_admin_action(db, 'EXPORT_SCANS', f'risk={risk_filter}, count={len(docs)}')

        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=phishguard_scans.csv'
        return response

    except Exception as e:
        logger.error(f"Export error: {e}")
        return jsonify({'error': str(e)}), 500


# ═════════════════════════════════════════════════════════════════════════════
# SUPER ADMIN - ADMIN MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════

@admin_bp.route('/api/super/admins', methods=['GET'])
@require_super_admin
def get_all_admins():
    """Get list of all admins (super admin only)."""
    users = _load_admin_users()
    
    admin_list = []
    # Add super admin
    sa = users.get('super_admin', {})
    admin_list.append({
        'username': sa.get('username'),
        'role': 'super_admin',
        'created_at': sa.get('created_at'),
        'active': True
    })
    
    # Add regular admins
    for admin in users.get('admins', []):
        admin_list.append({
            'username': admin.get('username'),
            'role': 'admin',
            'created_at': admin.get('created_at'),
            'active': admin.get('active', True)
        })
    
    return jsonify({'admins': admin_list})


@admin_bp.route('/api/super/admins', methods=['POST'])
@require_super_admin
def create_admin():
    """Create a new admin (max 4 regular admins)."""
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required'}), 400
    
    if len(username) < 3 or len(password) < 6:
        return jsonify({'success': False, 'error': 'Username ≥3 chars, password ≥6 chars'}), 400
    
    users = _load_admin_users()
    
    # Check limit (max 4 regular admins)
    if len(users.get('admins', [])) >= 4:
        return jsonify({'success': False, 'error': 'Maximum 4 admins allowed'}), 400
    
    # Check if username already exists
    if users['super_admin']['username'] == username:
        return jsonify({'success': False, 'error': 'Username already exists'}), 400
    
    for admin in users.get('admins', []):
        if admin['username'] == username:
            return jsonify({'success': False, 'error': 'Username already exists'}), 400
    
    # Add new admin
    new_admin = {
        'username': username,
        'password': password,
        'role': 'admin',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'active': True
    }
    
    users['admins'].append(new_admin)
    
    if _save_admin_users(users):
        from flask import current_app
        db = current_app.config.get('DB')
        log_admin_action(db, 'CREATE_ADMIN', f'Created admin: {username}')
        return jsonify({'success': True, 'message': f'Admin {username} created'})
    else:
        return jsonify({'success': False, 'error': 'Failed to save'}), 500


@admin_bp.route('/api/super/admins/<username>', methods=['DELETE'])
@require_super_admin
def delete_admin(username):
    """Delete an admin."""
    users = _load_admin_users()
    
    if users['super_admin']['username'] == username:
        return jsonify({'success': False, 'error': 'Cannot delete super admin'}), 400
    
    admins = users.get('admins', [])
    users['admins'] = [a for a in admins if a['username'] != username]
    
    if len(users['admins']) < len(admins):
        if _save_admin_users(users):
            from flask import current_app
            db = current_app.config.get('DB')
            log_admin_action(db, 'DELETE_ADMIN', f'Deleted admin: {username}')
            return jsonify({'success': True, 'message': f'Admin {username} deleted'})
    
    return jsonify({'success': False, 'error': 'Admin not found'}), 404


@admin_bp.route('/api/super/admins/<username>/toggle', methods=['POST'])
@require_super_admin
def toggle_admin(username):
    """Enable/disable an admin."""
    users = _load_admin_users()
    
    for admin in users.get('admins', []):
        if admin['username'] == username:
            admin['active'] = not admin.get('active', True)
            if _save_admin_users(users):
                from flask import current_app
                db = current_app.config.get('DB')
                status = 'enabled' if admin['active'] else 'disabled'
                log_admin_action(db, 'TOGGLE_ADMIN', f'{status.title()} admin: {username}')
                return jsonify({'success': True, 'active': admin['active']})
    
    return jsonify({'success': False, 'error': 'Admin not found'}), 404


# ═════════════════════════════════════════════════════════════════════════════
# SUPER ADMIN - API MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════

@admin_bp.route('/api/super/api-settings', methods=['GET'])
@require_super_admin
def get_api_settings():
    """Get API usage and settings."""
    users = _load_admin_users()
    api_settings = users.get('api_settings', {})
    
    return jsonify({
        'settings': api_settings,
        'total_usage': sum(s.get('usage_count', 0) for s in api_settings.values())
    })


@admin_bp.route('/api/super/api-settings/<api_name>/toggle', methods=['POST'])
@require_super_admin
def toggle_api(api_name):
    """Enable/disable an API."""
    valid_apis = ['google_safe_browsing', 'virustotal', 'whoisxml', 'screenshot']
    
    if api_name not in valid_apis:
        return jsonify({'success': False, 'error': 'Invalid API name'}), 400
    
    users = _load_admin_users()
    api_settings = users.get('api_settings', {})
    
    if api_name in api_settings:
        api_settings[api_name]['enabled'] = not api_settings[api_name].get('enabled', True)
        users['api_settings'] = api_settings
        
        if _save_admin_users(users):
            from flask import current_app
            db = current_app.config.get('DB')
            status = 'enabled' if api_settings[api_name]['enabled'] else 'disabled'
            log_admin_action(db, 'TOGGLE_API', f'{status.title()} API: {api_name}')
            
            return jsonify({
                'success': True,
                'api': api_name,
                'enabled': api_settings[api_name]['enabled']
            })
    
    return jsonify({'success': False, 'error': 'Failed to update'}), 500


@admin_bp.route('/api/super/api-settings/reset-counters', methods=['POST'])
@require_super_admin
def reset_api_counters():
    """Reset all API usage counters."""
    users = _load_admin_users()
    api_settings = users.get('api_settings', {})
    
    for api_name in api_settings:
        api_settings[api_name]['usage_count'] = 0
        api_settings[api_name]['last_used'] = None
    
    users['api_settings'] = api_settings
    
    if _save_admin_users(users):
        from flask import current_app
        db = current_app.config.get('DB')
        log_admin_action(db, 'RESET_API_COUNTERS', 'Reset all API counters')
        return jsonify({'success': True, 'message': 'Counters reset'})
    
    return jsonify({'success': False, 'error': 'Failed to reset'}), 500
