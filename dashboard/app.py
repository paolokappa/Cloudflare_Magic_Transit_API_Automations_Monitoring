#!/usr/bin/env python3
"""
Cloudflare Magic Transit Dashboard
Version: 2.0.0
Author: GOLINE SOC

Real-time dashboard for monitoring Cloudflare Magic Transit infrastructure.

Changelog:
- v1.5.0: Database logging and Telegram notifications for manual actions
- v1.4.0: Advertise/Withdraw buttons with 15-min constraint enforcement
- v1.3.0: GOLINE logo in header-right, timestamp color fix, static files
- v1.2.0: Embedded Cloudflare logo (base64), stat card descriptions with tooltips
- v1.1.0: Parallel prefix loading, improved header with Cloudflare logo
- v1.0.0: Initial release
"""

import os
import sys
import json
import sqlite3
import socket
import requests
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from functools import wraps
import bcrypt
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate secure secret key

# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(BASE_DIR, "config", "settings.json")
PREFIX_FILE = os.path.join(BASE_DIR, "config", "prefix_mapping.json")
AUTH_FILE = os.path.join(BASE_DIR, "config", "auth.json")
DB_FILE = os.path.join(BASE_DIR, "db", "magic_transit.db")

# Load configuration
def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def load_prefixes():
    with open(PREFIX_FILE, 'r') as f:
        return json.load(f)

def load_auth():
    """Load authentication configuration"""
    with open(AUTH_FILE, 'r') as f:
        return json.load(f)

def save_auth(auth_data):
    """Save authentication configuration"""
    with open(AUTH_FILE, 'w') as f:
        json.dump(auth_data, f, indent=2)

def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({"success": False, "error": "Authentication required"}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def load_version():
    """Load version from docs/DASHBOARD.md (safe for GitHub distribution)"""
    import re
    try:
        dashboard_md = os.path.join(BASE_DIR, "docs", "DASHBOARD.md")
        with open(dashboard_md, 'r') as f:
            # Read first 10 lines where version is defined
            for _ in range(10):
                line = f.readline()
                # Match: **Version**: 2.4.2
                match = re.search(r'\*\*Version\*\*:\s*(\d+\.\d+\.\d+)', line)
                if match:
                    return match.group(1)
    except:
        pass
    return "2.4.0"  # fallback

# Cloudflare API
CONFIG = load_config()
ACCOUNT_ID = CONFIG['cloudflare']['account_id']
API_TOKEN = CONFIG['cloudflare']['api_token']
API_BASE = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}"

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

# Global API Key for rules (some endpoints need it)
AUTH_EMAIL = CONFIG['cloudflare'].get('auth_email', '')
AUTH_KEY = CONFIG['cloudflare'].get('global_api_key', '')

HEADERS_GLOBAL = {
    "X-Auth-Email": AUTH_EMAIL,
    "X-Auth-Key": AUTH_KEY,
    "Content-Type": "application/json"
}

# Debug: print if credentials are loaded
if not AUTH_KEY:
    print("WARNING: global_api_key not found in config!")

# DDoS Managed Ruleset
DDOS_L4_RULESET_ID = "3b64149bfa6e4220bbbc2bd6db589552"
DDOS_L4_ROOT_ID = "108b5719d12e4169a0ac2e4f499d8bae"  # Account root ruleset for overrides

# =============================================================================
# DATABASE HELPERS
# =============================================================================

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def query_db(query, args=(), one=False):
    conn = get_db_connection()
    cur = conn.execute(query, args)
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

def get_prefix_calm_status():
    """Get calm status for all prefixes from autowithdraw daemon tracking"""
    try:
        rows = query_db("""
            SELECT prefix, advertised, under_attack, calm_since,
                   last_attack_packets, last_attack_mbps, mitigation_systems, updated_at
            FROM prefix_calm_status
        """)
        result = {}
        for row in rows:
            prefix = row['prefix']
            calm_since = row['calm_since']
            calm_minutes = 0
            time_to_withdraw = 0

            if calm_since and row['advertised'] and not row['under_attack']:
                # Calculate calm time in minutes
                try:
                    calm_dt = datetime.strptime(calm_since, '%Y-%m-%d %H:%M:%S')
                    elapsed = (datetime.utcnow() - calm_dt).total_seconds() / 60
                    calm_minutes = round(elapsed, 1)
                    # Time until auto-withdraw (15 min calm period)
                    time_to_withdraw = max(0, round(15 - elapsed, 1))
                except:
                    pass

            result[prefix] = {
                'under_attack': bool(row['under_attack']),
                'calm_since': calm_since,
                'calm_minutes': calm_minutes,
                'time_to_withdraw': time_to_withdraw,
                'dropped_packets': row['last_attack_packets'] or 0,
                'dropped_mbps': row['last_attack_mbps'] or 0,
                'mitigation_systems': row['mitigation_systems'].split(',') if row['mitigation_systems'] else [],
                'last_updated': row['updated_at']
            }
        return result
    except Exception as e:
        print(f"Error getting prefix calm status: {e}")
        return {}

# =============================================================================
# API HELPERS
# =============================================================================

def cf_api_get(endpoint):
    """Make GET request to Cloudflare API"""
    try:
        url = f"{API_BASE}/{endpoint}"
        response = requests.get(url, headers=HEADERS, timeout=10)
        return response.json()
    except Exception as e:
        return {"success": False, "error": str(e)}

def cf_api_get_global(url):
    """Make GET request using Global API Key"""
    try:
        response = requests.get(url, headers=HEADERS_GLOBAL, timeout=10)
        return response.json()
    except Exception as e:
        return {"success": False, "error": str(e)}

def resolve_hostname(ip):
    """Resolve IP to hostname with short timeout. Returns hostname or empty string."""
    if not ip or ip == '-':
        return ''
    try:
        socket.setdefaulttimeout(0.5)  # 500ms timeout
        hostname = socket.gethostbyaddr(ip)[0]
        # Return short hostname (first part before domain)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ''
    finally:
        socket.setdefaulttimeout(None)

# =============================================================================
# ROUTES - PAGES
# =============================================================================

@app.route('/')
@login_required
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html', version=load_version())

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "cloudflare-dashboard",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username', '')
        password = data.get('password', '')

        try:
            auth = load_auth()
            stored_hash = auth.get('password_hash', '')

            # Verify password
            if username == auth.get('username') and bcrypt.checkpw(
                password.encode('utf-8'),
                stored_hash.encode('utf-8')
            ):
                session['logged_in'] = True
                session['username'] = username
                if request.is_json:
                    return jsonify({"success": True, "message": "Login successful"})
                return redirect(url_for('dashboard'))
            else:
                if request.is_json:
                    return jsonify({"success": False, "error": "Invalid credentials"}), 401
                return render_template('login.html', error="Invalid username or password", version=load_version())

        except Exception as e:
            if request.is_json:
                return jsonify({"success": False, "error": str(e)}), 500
            return render_template('login.html', error="Authentication error", version=load_version())

    # GET request - show login form
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return render_template('login.html', version=load_version())

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_password():
    """Change user password"""
    try:
        data = request.get_json()
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')

        # Validation
        if not current_password or not new_password:
            return jsonify({"success": False, "error": "All fields are required"}), 400

        if new_password != confirm_password:
            return jsonify({"success": False, "error": "New passwords do not match"}), 400

        if len(new_password) < 8:
            return jsonify({"success": False, "error": "Password must be at least 8 characters"}), 400

        # Verify current password
        auth = load_auth()
        stored_hash = auth.get('password_hash', '')

        if not bcrypt.checkpw(current_password.encode('utf-8'), stored_hash.encode('utf-8')):
            return jsonify({"success": False, "error": "Current password is incorrect"}), 401

        # Generate new hash and save
        new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        auth['password_hash'] = new_hash
        auth['last_changed'] = datetime.now(timezone.utc).isoformat()
        save_auth(auth)

        return jsonify({"success": True, "message": "Password changed successfully"})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# =============================================================================
# ROUTES - API ENDPOINTS
# =============================================================================

def fetch_prefix_status(cidr, info):
    """Fetch single prefix status from Cloudflare API (for parallel execution)"""
    prefix_id = info.get('prefix_id', info.get('id', ''))
    bgp_prefix_id = info.get('bgp_prefix_id', '')

    if not prefix_id or not bgp_prefix_id:
        return {
            "cidr": cidr,
            "description": info.get('description', ''),
            "advertised": None,
            "status": "unknown",
            "error": "Missing prefix IDs"
        }

    # Query Cloudflare API for prefix status
    endpoint = f"addressing/prefixes/{prefix_id}/bgp/prefixes/{bgp_prefix_id}"
    data = cf_api_get(endpoint)

    if data.get('success') and data.get('result'):
        prefix_result = data['result']
        on_demand = prefix_result.get('on_demand', {})

        return {
            "cidr": cidr,
            "description": info.get('description', ''),
            "advertised": on_demand.get('advertised', False),
            "advertised_modified_at": on_demand.get('advertised_modified_at', ''),
            "status": "advertised" if on_demand.get('advertised') else "withdrawn",
            "on_demand_enabled": on_demand.get('on_demand_enabled', False)
        }
    else:
        return {
            "cidr": cidr,
            "description": info.get('description', ''),
            "advertised": None,
            "status": "error",
            "error": data.get('errors', [{}])[0].get('message', 'Unknown error') if data.get('errors') else 'API error'
        }

@app.route('/api/prefixes')
@login_required
def api_prefixes():
    """Get BGP prefix status from Cloudflare API with calm status from autowithdraw daemon"""
    try:
        prefix_data = load_prefixes()
        prefixes = prefix_data.get('prefixes', prefix_data)  # Handle both formats
        result = []

        # Get calm status from database (populated by autowithdraw daemon)
        calm_status = get_prefix_calm_status()

        # Use ThreadPoolExecutor for parallel API calls
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(fetch_prefix_status, cidr, info): cidr
                for cidr, info in prefixes.items()
            }

            for future in as_completed(futures):
                try:
                    prefix_result = future.result()

                    # Merge calm status data
                    cidr = prefix_result['cidr']
                    if cidr in calm_status:
                        cs = calm_status[cidr]
                        prefix_result['under_attack'] = cs['under_attack']
                        prefix_result['calm_minutes'] = cs['calm_minutes']
                        prefix_result['time_to_withdraw'] = cs['time_to_withdraw']
                        prefix_result['dropped_packets'] = cs['dropped_packets']
                        prefix_result['dropped_mbps'] = cs['dropped_mbps']
                        prefix_result['calm_last_updated'] = cs['last_updated']
                    else:
                        # No calm status data yet
                        prefix_result['under_attack'] = None
                        prefix_result['calm_minutes'] = 0
                        prefix_result['time_to_withdraw'] = 0

                    result.append(prefix_result)
                except Exception as e:
                    cidr = futures[future]
                    result.append({
                        "cidr": cidr,
                        "description": "",
                        "advertised": None,
                        "status": "error",
                        "error": str(e)
                    })

        # Sort by CIDR for consistent ordering
        result.sort(key=lambda x: x['cidr'])

        return jsonify({"success": True, "prefixes": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/attacks')
@login_required
def api_attacks():
    """Get recent attack events from database"""
    try:
        rows = query_db("""
            SELECT id, event_type, alert_type, prefix, attack_id, attack_vector,
                   target_ip, target_port, protocol, severity, action_taken, created_at
            FROM attack_events
            ORDER BY created_at DESC
            LIMIT 50
        """)

        attacks = []
        for row in rows:
            # Format timestamp as ISO 8601 with UTC indicator
            # SQLite CURRENT_TIMESTAMP is in UTC, add 'Z' suffix
            timestamp = row['created_at']
            if timestamp and not timestamp.endswith('Z') and '+' not in timestamp:
                timestamp = timestamp.replace(' ', 'T') + 'Z'

            attacks.append({
                "id": row['id'],
                "event_type": row['event_type'],
                "alert_type": row['alert_type'],
                "prefix": row['prefix'],
                "attack_id": row['attack_id'],
                "attack_vector": row['attack_vector'],
                "target_ip": row['target_ip'],
                "target_port": row['target_port'],
                "protocol": row['protocol'],
                "severity": row['severity'],
                "action_taken": row['action_taken'],
                "timestamp": timestamp
            })

        return jsonify({"success": True, "attacks": attacks})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/attacks/<int:attack_id>')
@login_required
def api_attack_detail(attack_id):
    """Get detailed information for a single attack event"""
    try:
        row = query_db("""
            SELECT id, event_type, alert_type, attack_id, policy_id, policy_name,
                   prefix, target_ip, target_port, protocol, attack_vector,
                   packets_per_second, megabits_per_second, severity, action_taken,
                   raw_payload, created_at
            FROM attack_events
            WHERE id = ?
        """, (attack_id,), one=True)

        if not row:
            return jsonify({"success": False, "error": "Event not found"}), 404

        # Format timestamp as ISO 8601 with UTC indicator
        timestamp = row['created_at']
        if timestamp and not timestamp.endswith('Z') and '+' not in timestamp:
            timestamp = timestamp.replace(' ', 'T') + 'Z'

        # Parse raw_payload JSON if available
        raw_payload = None
        extra_data = {}
        if row['raw_payload']:
            try:
                raw_payload = json.loads(row['raw_payload'])
                # Extract useful fields from payload
                if isinstance(raw_payload, dict):
                    data = raw_payload.get('data', {})
                    extra_data = {
                        'account_name': data.get('account_name'),
                        'rule_name': data.get('rule_name'),
                        'rule_id': data.get('rule_id'),
                        'rule_description': data.get('rule_description'),
                        'ruleset_id': data.get('ruleset_id'),
                        'mitigation': data.get('mitigation'),
                        'max_rate': data.get('max_rate'),
                        'start_time': data.get('start_time'),
                        'dashboard_link': data.get('dashboard_link'),
                        'action': data.get('action'),
                        'text': raw_payload.get('text', '')
                    }
            except json.JSONDecodeError:
                pass

        event = {
            "id": row['id'],
            "event_type": row['event_type'],
            "alert_type": row['alert_type'],
            "attack_id": row['attack_id'],
            "policy_id": row['policy_id'],
            "policy_name": row['policy_name'],
            "prefix": row['prefix'],
            "target_ip": row['target_ip'],
            "target_port": row['target_port'],
            "protocol": row['protocol'],
            "attack_vector": row['attack_vector'],
            "packets_per_second": row['packets_per_second'],
            "megabits_per_second": row['megabits_per_second'],
            "severity": row['severity'],
            "action_taken": row['action_taken'],
            "timestamp": timestamp,
            **extra_data
        }

        return jsonify({"success": True, "event": event})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/analytics')
@login_required
def api_analytics():
    """Get recent network analytics events from database"""
    try:
        rows = query_db("""
            SELECT id, event_datetime, attack_id, attack_vector, rule_name,
                   source_ip, colo_country, destination_ip, destination_port,
                   protocol, packets, bits, outcome, notified_at
            FROM network_analytics_events
            ORDER BY id DESC
            LIMIT 100
        """)

        events = []
        for row in rows:
            # Format timestamps as ISO 8601 with UTC indicator
            event_datetime = row['event_datetime']
            if event_datetime and not event_datetime.endswith('Z') and '+' not in event_datetime:
                event_datetime = event_datetime.replace(' ', 'T') + 'Z' if ' ' in event_datetime else event_datetime + 'Z'

            timestamp = row['notified_at']
            if timestamp and not timestamp.endswith('Z') and '+' not in timestamp:
                timestamp = timestamp.replace(' ', 'T') + 'Z'

            events.append({
                "id": row['id'],
                "event_datetime": event_datetime,
                "attack_id": row['attack_id'],
                "attack_vector": row['attack_vector'],
                "rule_name": row['rule_name'],
                "source_ip": row['source_ip'],
                "source_country": row['colo_country'],
                "dest_ip": row['destination_ip'],
                "dest_port": row['destination_port'],
                "protocol": row['protocol'],
                "packets_dropped": row['packets'],
                "bits_dropped": row['bits'],
                "outcome": row['outcome'],
                "timestamp": timestamp
            })

        return jsonify({"success": True, "events": events})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/analytics/<int:analytics_id>')
@login_required
def api_analytics_detail(analytics_id):
    """Get detailed information for a single network analytics event"""
    try:
        row = query_db("""
            SELECT id, event_hash, attack_id, event_datetime, attack_vector,
                   rule_name, rule_id, source_ip, source_port,
                   source_asn, source_asn_name, source_country,
                   destination_ip, destination_port, protocol, tcp_flags,
                   colo_code, colo_country, packets, bits, outcome,
                   mitigation_reason, notified_at, raw_data
            FROM network_analytics_events
            WHERE id = ?
        """, (analytics_id,), one=True)

        if not row:
            return jsonify({"success": False, "error": "Event not found"}), 404

        # Format timestamps as ISO 8601 with UTC indicator
        event_datetime = row['event_datetime']
        if event_datetime and not event_datetime.endswith('Z') and '+' not in event_datetime:
            event_datetime = event_datetime.replace(' ', 'T') + 'Z' if ' ' in event_datetime else event_datetime + 'Z'

        notified_at = row['notified_at']
        if notified_at and not notified_at.endswith('Z') and '+' not in notified_at:
            notified_at = notified_at.replace(' ', 'T') + 'Z'

        # Parse raw_data JSON if available
        raw_data = None
        colo_city = None
        verdict = None
        if row['raw_data']:
            try:
                raw_data = json.loads(row['raw_data'])
                if isinstance(raw_data, dict):
                    dimensions = raw_data.get('dimensions', {})
                    colo_city = dimensions.get('coloCity')
                    verdict = dimensions.get('verdict')
            except json.JSONDecodeError:
                pass

        # Calculate human-readable values
        bits = row['bits'] or 0
        packets = row['packets'] or 0
        mbps = bits / 1_000_000 if bits else 0
        kpps = packets / 1000 if packets else 0

        # Lookup rule description from attack_events (webhooks contain rule_description)
        rule_description = None
        if row['rule_id']:
            desc_row = query_db("""
                SELECT raw_payload FROM attack_events
                WHERE raw_payload LIKE ?
                ORDER BY id DESC LIMIT 1
            """, (f'%{row["rule_id"]}%',), one=True)
            if desc_row and desc_row['raw_payload']:
                try:
                    payload = json.loads(desc_row['raw_payload'])
                    rule_description = payload.get('data', {}).get('rule_description')
                except:
                    pass

        event = {
            "id": row['id'],
            "event_hash": row['event_hash'],
            "attack_id": row['attack_id'],
            "event_datetime": event_datetime,
            "attack_vector": row['attack_vector'],
            "rule_name": row['rule_name'],
            "rule_id": row['rule_id'],
            "rule_description": rule_description,
            "source_ip": row['source_ip'],
            "source_port": row['source_port'],
            "source_asn": row['source_asn'],
            "source_asn_name": row['source_asn_name'],
            "source_country": row['source_country'],
            "destination_ip": row['destination_ip'],
            "destination_port": row['destination_port'],
            "protocol": row['protocol'],
            "tcp_flags": row['tcp_flags'],
            "colo_code": row['colo_code'],
            "colo_country": row['colo_country'],
            "colo_city": colo_city,
            "packets": packets,
            "bits": bits,
            "mbps": round(mbps, 2),
            "kpps": round(kpps, 2),
            "outcome": row['outcome'],
            "verdict": verdict,
            "mitigation_reason": row['mitigation_reason'],
            "notified_at": notified_at
        }

        return jsonify({"success": True, "event": event})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/rules')
@login_required
def api_rules():
    """Get MNM rules from Cloudflare API (legacy endpoint)"""
    return api_mnm_rules()

@app.route('/api/mnm-rules')
@login_required
def api_mnm_rules():
    """Get MNM rules from Cloudflare API"""
    try:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/mnm/rules"
        data = cf_api_get_global(url)

        if data.get('success'):
            rules = data.get('result', [])
            # Categorize rules
            categorized = {
                "threshold": [],
                "zscore": [],
                "advanced_ddos": []
            }

            for rule in rules:
                rule_type = rule.get('type', 'unknown')
                rule_info = {
                    "id": rule.get('id'),
                    "name": rule.get('name'),
                    "prefixes": rule.get('prefixes', []),
                    "automatic_advertisement": rule.get('automatic_advertisement'),
                    "bandwidth_threshold": rule.get('bandwidth_threshold'),
                    "packet_threshold": rule.get('packet_threshold'),
                    "duration": rule.get('duration')
                }

                if rule_type == 'threshold':
                    categorized["threshold"].append(rule_info)
                elif rule_type == 'zscore':
                    categorized["zscore"].append(rule_info)
                elif rule_type == 'advanced_ddos':
                    categorized["advanced_ddos"].append(rule_info)

            return jsonify({
                "success": True,
                "rules": categorized,
                "total": len(rules)
            })
        else:
            return jsonify({"success": False, "error": "Failed to fetch rules"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/mnm-rules', methods=['POST'])
@login_required
def api_mnm_rules_create():
    """Create a new MNM rule"""
    try:
        data = request.get_json()
        rule_type = data.get('type')
        prefix = data.get('prefix')
        auto_adv = data.get('automatic_advertisement', True)

        if not prefix:
            return jsonify({"success": False, "error": "Prefix is required"}), 400

        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/mnm/rules"

        if rule_type == 'bps':
            # Bandwidth threshold rule
            threshold_gbps = data.get('threshold', 4)
            duration_mins = data.get('duration', 1)

            # Validate BPS threshold (1-100 Gbps)
            if threshold_gbps < 1 or threshold_gbps > 100:
                return jsonify({"success": False, "error": "Threshold must be between 1 and 100 Gbps"}), 400

            # Validate duration (1-60 minutes)
            if duration_mins < 1 or duration_mins > 60:
                return jsonify({"success": False, "error": "Duration must be between 1 and 60 minutes"}), 400

            rule_data = {
                "name": f"DDoS Protection BPS {prefix.replace('/', '-')}",
                "type": "threshold",
                "prefixes": [prefix],
                "bandwidth_threshold": threshold_gbps * 1000000000,  # Convert Gbps to bps
                "duration": f"{duration_mins}m0s",
                "automatic_advertisement": auto_adv
            }

        elif rule_type == 'pps':
            # Packet threshold rule
            threshold_kpps = data.get('threshold', 500)
            duration_mins = data.get('duration', 1)

            # Validate PPS threshold (10-10000 kpps)
            if threshold_kpps < 10 or threshold_kpps > 10000:
                return jsonify({"success": False, "error": "Threshold must be between 10 and 10,000 kpps"}), 400

            # Validate duration (1-60 minutes)
            if duration_mins < 1 or duration_mins > 60:
                return jsonify({"success": False, "error": "Duration must be between 1 and 60 minutes"}), 400

            rule_data = {
                "name": f"DDoS Protection PPS {prefix.replace('/', '-')}",
                "type": "threshold",
                "prefixes": [prefix],
                "packet_threshold": threshold_kpps * 1000,  # Convert kpps to pps
                "duration": f"{duration_mins}m0s",
                "automatic_advertisement": auto_adv
            }

        elif rule_type == 'sflow':
            # Advanced DDoS (sFlow) rule
            rule_data = {
                "name": f"sFlow-DDoS-Attack-{prefix.replace('/', '-').replace(':', '-')}",
                "type": "advanced_ddos",
                "prefixes": [prefix],
                "automatic_advertisement": auto_adv,
                "prefix_match": "subnet"
            }

        else:
            return jsonify({"success": False, "error": f"Invalid rule type: {rule_type}"}), 400

        # Create the rule
        response = requests.post(url, headers=HEADERS_GLOBAL, json=rule_data, timeout=30)
        result = response.json()

        if result.get('success'):
            return jsonify({
                "success": True,
                "message": "Rule created successfully",
                "rule": result.get('result')
            })
        else:
            errors = result.get('errors', [])
            error_msg = errors[0].get('message') if errors else 'Unknown error'
            return jsonify({"success": False, "error": error_msg}), 400

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/mnm-rules/<rule_id>', methods=['DELETE'])
@login_required
def api_mnm_rules_delete(rule_id):
    """Delete an MNM rule"""
    try:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/mnm/rules/{rule_id}"

        response = requests.delete(url, headers=HEADERS_GLOBAL, timeout=30)
        result = response.json()

        if result.get('success'):
            return jsonify({
                "success": True,
                "message": "Rule deleted successfully"
            })
        else:
            errors = result.get('errors', [])
            error_msg = errors[0].get('message') if errors else 'Unknown error'
            return jsonify({"success": False, "error": error_msg}), 400

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/mnm-rules/<rule_id>', methods=['PUT'])
@login_required
def api_mnm_rules_update(rule_id):
    """Update an MNM rule"""
    try:
        data = request.get_json()

        # Build update payload - only include fields that were provided
        update_data = {}

        if 'automatic_advertisement' in data:
            update_data['automatic_advertisement'] = data['automatic_advertisement']

        if 'bandwidth_threshold' in data:
            # Validate BPS threshold (1-100 Gbps = 1B-100B bps)
            bps = data['bandwidth_threshold']
            gbps = bps / 1000000000
            if gbps < 1 or gbps > 100:
                return jsonify({"success": False, "error": "Threshold must be between 1 and 100 Gbps"}), 400
            update_data['bandwidth_threshold'] = bps

        if 'packet_threshold' in data:
            # Validate PPS threshold (10-10000 kpps = 10k-10M pps)
            pps = data['packet_threshold']
            kpps = pps / 1000
            if kpps < 10 or kpps > 10000:
                return jsonify({"success": False, "error": "Threshold must be between 10 and 10,000 kpps"}), 400
            update_data['packet_threshold'] = pps

        if 'duration' in data:
            # Validate duration (1-60 minutes)
            duration_str = data['duration']
            try:
                # Parse duration string like "5m0s"
                duration_mins = int(duration_str.replace('m0s', '').replace('m', ''))
                if duration_mins < 1 or duration_mins > 60:
                    return jsonify({"success": False, "error": "Duration must be between 1 and 60 minutes"}), 400
            except:
                pass  # If parsing fails, let Cloudflare API handle validation
            update_data['duration'] = duration_str

        if not update_data:
            return jsonify({"success": False, "error": "No fields to update"}), 400

        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/mnm/rules/{rule_id}"

        response = requests.patch(url, headers=HEADERS_GLOBAL, json=update_data, timeout=30)
        result = response.json()

        if result.get('success'):
            return jsonify({
                "success": True,
                "message": "Rule updated successfully",
                "rule": result.get('result')
            })
        else:
            errors = result.get('errors', [])
            error_msg = errors[0].get('message') if errors else 'Unknown error'
            return jsonify({"success": False, "error": error_msg}), 400

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/ddos-sensitivity')
@login_required
def api_ddos_sensitivity():
    """Get DDoS L3/4 Managed Ruleset status"""
    try:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/rulesets/{DDOS_L4_RULESET_ID}"
        data = cf_api_get_global(url)

        if data.get('success'):
            ruleset = data.get('result', {})
            rules = ruleset.get('rules', [])

            # Count by action
            action_counts = {}
            for rule in rules:
                action = rule.get('action', 'unknown')
                action_counts[action] = action_counts.get(action, 0) + 1

            return jsonify({
                "success": True,
                "ruleset_name": ruleset.get('name', 'Unknown'),
                "total_rules": len(rules),
                "action_counts": action_counts,
                "last_updated": ruleset.get('last_updated', '')
            })
        else:
            return jsonify({"success": False, "error": "Failed to fetch DDoS ruleset"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/ddos-rules')
@app.route('/api/ddos-rules/<action>')
@login_required
def api_ddos_rules(action=None):
    """Get detailed DDoS L3/4 rules, optionally filtered by action"""
    try:
        # 1. Get managed ruleset (default values)
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/rulesets/{DDOS_L4_RULESET_ID}"
        data = cf_api_get_global(url)

        if not data.get('success'):
            return jsonify({"success": False, "error": "Failed to fetch DDoS ruleset"})

        ruleset = data.get('result', {})
        rules = ruleset.get('rules', [])

        # 2. Get root ruleset (overrides)
        overrides = {}
        root_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/rulesets/{DDOS_L4_ROOT_ID}"
        root_data = cf_api_get_global(root_url)

        if root_data.get('success'):
            root_rules = root_data.get('result', {}).get('rules', [])
            for root_rule in root_rules:
                action_params = root_rule.get('action_parameters', {})
                if action_params.get('id') == DDOS_L4_RULESET_ID:
                    override_rules = action_params.get('overrides', {}).get('rules', [])
                    for override in override_rules:
                        overrides[override.get('id')] = override

        # 3. Merge overrides into rules
        formatted_rules = []
        for rule in rules:
            rule_id = rule.get('id', '')
            override = overrides.get(rule_id, {})

            # Get effective values (override takes precedence)
            effective_action = override.get('action', rule.get('action', 'unknown'))
            effective_sensitivity = override.get('sensitivity_level',
                rule.get('action_parameters', {}).get('sensitivity_level', 'default'))

            # Check if rule is editable (has allowed_override_actions and not read-only)
            allowed_actions = rule.get('allowed_override_actions', [])
            categories = rule.get('categories', [])
            is_editable = len(allowed_actions) > 0 and 'read-only' not in categories

            formatted_rules.append({
                "id": rule_id,
                "description": rule.get('description', 'No description'),
                "action": effective_action,
                "enabled": rule.get('enabled', True),
                "expression": rule.get('expression', ''),
                "categories": categories,
                "sensitivity_level": effective_sensitivity,
                "allowed_actions": allowed_actions,
                "is_editable": is_editable,
                "has_override": rule_id in overrides
            })

        # Filter by action if specified (after merging overrides)
        if action:
            formatted_rules = [r for r in formatted_rules if r.get('action') == action]

        return jsonify({
            "success": True,
            "ruleset_name": ruleset.get('name', 'Unknown'),
            "filter_action": action,
            "total_rules": len(formatted_rules),
            "rules": formatted_rules,
            "last_updated": ruleset.get('last_updated', '')
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/api/ddos-rules/<rule_id>/update', methods=['POST'])
@login_required
def api_ddos_rule_update(rule_id):
    """Update a DDoS rule action via override"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        new_action = data.get('action')
        sensitivity = data.get('sensitivity_level')

        if not new_action:
            return jsonify({"success": False, "error": "Action is required"}), 400

        # Valid actions
        valid_actions = ['block', 'log', 'ddos_dynamic']
        if new_action not in valid_actions:
            return jsonify({"success": False, "error": f"Invalid action. Must be one of: {', '.join(valid_actions)}"}), 400

        # Build the override rule
        override_rule = {
            "action": "execute",
            "action_parameters": {
                "id": DDOS_L4_RULESET_ID,
                "overrides": {
                    "rules": [{
                        "id": rule_id,
                        "action": new_action
                    }]
                }
            },
            "expression": "true",
            "enabled": True
        }

        # Add sensitivity if provided
        if sensitivity:
            override_rule["action_parameters"]["overrides"]["rules"][0]["sensitivity_level"] = sensitivity

        # Get current overrides to merge with new one
        root_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/rulesets/{DDOS_L4_ROOT_ID}"
        current = cf_api_get_global(root_url)

        if current.get('success'):
            existing_rules = current.get('result', {}).get('rules', [])

            # Find existing execute rule for our ruleset
            updated = False
            for existing_rule in existing_rules:
                action_params = existing_rule.get('action_parameters', {})
                if action_params.get('id') == DDOS_L4_RULESET_ID:
                    # Merge our override into existing overrides
                    overrides = action_params.get('overrides', {})
                    rule_overrides = overrides.get('rules', [])

                    # Update or add our rule override
                    found = False
                    for i, ro in enumerate(rule_overrides):
                        if ro.get('id') == rule_id:
                            rule_overrides[i] = {"id": rule_id, "action": new_action}
                            if sensitivity:
                                rule_overrides[i]["sensitivity_level"] = sensitivity
                            found = True
                            break

                    if not found:
                        rule_override = {"id": rule_id, "action": new_action}
                        if sensitivity:
                            rule_override["sensitivity_level"] = sensitivity
                        rule_overrides.append(rule_override)

                    existing_rule['action_parameters']['overrides']['rules'] = rule_overrides
                    updated = True
                    break

            if updated:
                # Update with merged rules
                update_payload = {"rules": existing_rules}
            else:
                # No existing execute rule, add our new one
                existing_rules.append(override_rule)
                update_payload = {"rules": existing_rules}
        else:
            # No existing root ruleset, create with our override
            update_payload = {"rules": [override_rule]}

        # Apply the update
        response = requests.put(
            root_url,
            headers=HEADERS_GLOBAL,
            json=update_payload,
            timeout=30
        )

        result = response.json()
        if result.get('success'):
            return jsonify({
                "success": True,
                "message": f"Rule updated to '{new_action}' successfully",
                "rule_id": rule_id,
                "new_action": new_action
            })
        else:
            errors = result.get('errors', [])
            error_msg = errors[0].get('message', str(errors)) if errors else 'Unknown error'
            return jsonify({"success": False, "error": error_msg}), 500

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ddos-overrides')
@login_required
def api_ddos_overrides():
    """Get custom DDoS override rules (rules with custom expressions)"""
    try:
        # Get root ruleset (contains all overrides)
        root_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/rulesets/{DDOS_L4_ROOT_ID}"
        root_data = cf_api_get_global(root_url)

        if not root_data.get('success'):
            return jsonify({"success": False, "error": "Failed to fetch DDoS overrides"})

        root_rules = root_data.get('result', {}).get('rules', [])

        # Filter for custom override rules (expression != "true")
        # These are user-created rules with specific filters
        custom_overrides = []
        for rule in root_rules:
            expression = rule.get('expression', 'true')
            # Skip rules with expression "true" - those are global overrides
            if expression and expression.strip().lower() != 'true':
                action_params = rule.get('action_parameters', {})
                override_rules = action_params.get('overrides', {}).get('rules', [])

                # Get sensitivity level from override
                sensitivity = 'default'
                target_rule_id = None
                if override_rules:
                    sensitivity = override_rules[0].get('sensitivity_level', 'default')
                    target_rule_id = override_rules[0].get('id')

                custom_overrides.append({
                    "id": rule.get('id'),
                    "description": rule.get('description', 'No description'),
                    "expression": expression,
                    "enabled": rule.get('enabled', True),
                    "sensitivity_level": sensitivity,
                    "target_rule_id": target_rule_id,
                    "last_updated": rule.get('last_updated', ''),
                    "version": rule.get('version', '')
                })

        return jsonify({
            "success": True,
            "total": len(custom_overrides),
            "overrides": custom_overrides,
            "last_updated": root_data.get('result', {}).get('last_updated', '')
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ddos-overrides', methods=['POST'])
@login_required
def api_ddos_overrides_create():
    """Create a new custom DDoS override rule"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        # Required fields
        expression = data.get('expression', '').strip()
        description = data.get('description', '').strip()
        sensitivity = data.get('sensitivity_level', 'low')
        target_rule_id = data.get('target_rule_id')
        enabled = data.get('enabled', True)

        if not expression:
            return jsonify({"success": False, "error": "Expression is required"}), 400
        if not description:
            return jsonify({"success": False, "error": "Description is required"}), 400
        if not target_rule_id:
            return jsonify({"success": False, "error": "Target rule ID is required"}), 400

        # Validate sensitivity
        valid_sensitivities = ['default', 'medium', 'low', 'eoff']
        if sensitivity not in valid_sensitivities:
            return jsonify({"success": False, "error": f"Invalid sensitivity. Must be one of: {', '.join(valid_sensitivities)}"}), 400

        # Get current ruleset
        root_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/rulesets/{DDOS_L4_ROOT_ID}"
        current = cf_api_get_global(root_url)

        if not current.get('success'):
            return jsonify({"success": False, "error": "Failed to fetch current ruleset"}), 500

        existing_rules = current.get('result', {}).get('rules', [])

        # Build new override rule
        new_rule = {
            "action": "execute",
            "action_parameters": {
                "id": DDOS_L4_RULESET_ID,
                "overrides": {
                    "rules": [{
                        "id": target_rule_id,
                        "sensitivity_level": sensitivity
                    }]
                }
            },
            "expression": expression,
            "description": description,
            "enabled": enabled
        }

        # Add to existing rules
        existing_rules.append(new_rule)

        # Update ruleset
        response = requests.put(
            root_url,
            headers=HEADERS_GLOBAL,
            json={"rules": existing_rules},
            timeout=30
        )

        result = response.json()
        if result.get('success'):
            return jsonify({
                "success": True,
                "message": "Override created successfully",
                "description": description
            })
        else:
            errors = result.get('errors', [])
            error_msg = errors[0].get('message', str(errors)) if errors else 'Unknown error'
            return jsonify({"success": False, "error": error_msg}), 400

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ddos-overrides/<override_id>', methods=['PUT'])
@login_required
def api_ddos_overrides_update(override_id):
    """Update an existing custom DDoS override rule"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        # Get current ruleset
        root_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/rulesets/{DDOS_L4_ROOT_ID}"
        current = cf_api_get_global(root_url)

        if not current.get('success'):
            return jsonify({"success": False, "error": "Failed to fetch current ruleset"}), 500

        existing_rules = current.get('result', {}).get('rules', [])

        # Find and update the rule
        found = False
        for rule in existing_rules:
            if rule.get('id') == override_id:
                found = True

                # Update fields if provided
                if 'expression' in data:
                    expression = data['expression'].strip()
                    if not expression:
                        return jsonify({"success": False, "error": "Expression cannot be empty"}), 400
                    rule['expression'] = expression

                if 'description' in data:
                    rule['description'] = data['description'].strip()

                if 'enabled' in data:
                    rule['enabled'] = data['enabled']

                if 'sensitivity_level' in data:
                    sensitivity = data['sensitivity_level']
                    valid_sensitivities = ['default', 'medium', 'low', 'eoff']
                    if sensitivity not in valid_sensitivities:
                        return jsonify({"success": False, "error": f"Invalid sensitivity. Must be one of: {', '.join(valid_sensitivities)}"}), 400

                    # Update sensitivity in overrides
                    if 'action_parameters' in rule and 'overrides' in rule['action_parameters']:
                        override_rules = rule['action_parameters']['overrides'].get('rules', [])
                        if override_rules:
                            override_rules[0]['sensitivity_level'] = sensitivity

                break

        if not found:
            return jsonify({"success": False, "error": "Override not found"}), 404

        # Update ruleset
        response = requests.put(
            root_url,
            headers=HEADERS_GLOBAL,
            json={"rules": existing_rules},
            timeout=30
        )

        result = response.json()
        if result.get('success'):
            return jsonify({
                "success": True,
                "message": "Override updated successfully",
                "override_id": override_id
            })
        else:
            errors = result.get('errors', [])
            error_msg = errors[0].get('message', str(errors)) if errors else 'Unknown error'
            return jsonify({"success": False, "error": error_msg}), 400

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ddos-overrides/<override_id>', methods=['DELETE'])
@login_required
def api_ddos_overrides_delete(override_id):
    """Delete a custom DDoS override rule"""
    try:
        # Get current ruleset
        root_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/rulesets/{DDOS_L4_ROOT_ID}"
        current = cf_api_get_global(root_url)

        if not current.get('success'):
            return jsonify({"success": False, "error": "Failed to fetch current ruleset"}), 500

        existing_rules = current.get('result', {}).get('rules', [])

        # Find and remove the rule
        original_count = len(existing_rules)
        existing_rules = [r for r in existing_rules if r.get('id') != override_id]

        if len(existing_rules) == original_count:
            return jsonify({"success": False, "error": "Override not found"}), 404

        # Update ruleset
        response = requests.put(
            root_url,
            headers=HEADERS_GLOBAL,
            json={"rules": existing_rules},
            timeout=30
        )

        result = response.json()
        if result.get('success'):
            return jsonify({
                "success": True,
                "message": "Override deleted successfully",
                "override_id": override_id
            })
        else:
            errors = result.get('errors', [])
            error_msg = errors[0].get('message', str(errors)) if errors else 'Unknown error'
            return jsonify({"success": False, "error": error_msg}), 400

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ddos-overrides/validate', methods=['POST'])
@login_required
def api_ddos_overrides_validate():
    """Validate a DDoS override expression syntax"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        expression = data.get('expression', '').strip()
        if not expression:
            return jsonify({"success": False, "error": "Expression is required"}), 400

        # Basic syntax validation for common patterns
        errors = []

        # Check for balanced parentheses
        if expression.count('(') != expression.count(')'):
            errors.append("Unbalanced parentheses")

        # Check for valid operators
        valid_operators = ['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'contains', 'matches', 'in', 'not', 'and', 'or']

        # Check for common field names
        valid_fields = [
            'ip.src', 'ip.dst', 'ip.proto', 'ip.proto.num',
            'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport',
            'ip.geoip.country', 'ip.geoip.asnum',
            'cf.edge.server_port', 'cf.colo.id'
        ]

        # Check for quoted strings
        import re
        # Look for unquoted IP addresses that should be quoted or use proper syntax
        # ip.dst eq 185.54.80.30 is valid (no quotes needed for IPs)

        # Check expression doesn't start/end with operators
        words = expression.lower().split()
        if words and words[0] in ['and', 'or']:
            errors.append("Expression cannot start with 'and' or 'or'")
        if words and words[-1] in ['and', 'or', 'not']:
            errors.append("Expression cannot end with 'and', 'or', or 'not'")

        # Check for empty comparison values
        if ' eq ' in expression.lower() and expression.lower().endswith(' eq '):
            errors.append("Missing value after 'eq' operator")

        if errors:
            return jsonify({
                "success": False,
                "valid": False,
                "errors": errors
            })

        return jsonify({
            "success": True,
            "valid": True,
            "message": "Expression syntax appears valid"
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/ddos-overrides/<override_id>/move', methods=['POST'])
@login_required
def api_ddos_overrides_move(override_id):
    """Move a DDoS override rule to a new position

    Supports three modes:
    - direction: "up" or "down" - move relative to current position
    - index: number (1-based) - move to exact position
    - before/after: rule_id - move before/after specific rule
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        # Build position object based on request
        position = {}

        if 'direction' in data:
            # Get current rules to find adjacent rule IDs
            root_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/rulesets/{DDOS_L4_ROOT_ID}"
            current = cf_api_get_global(root_url)

            if not current.get('success'):
                return jsonify({"success": False, "error": "Failed to fetch current ruleset"}), 500

            existing_rules = current.get('result', {}).get('rules', [])
            rule_ids = [r.get('id') for r in existing_rules]

            try:
                current_index = rule_ids.index(override_id)
            except ValueError:
                return jsonify({"success": False, "error": "Rule not found in ruleset"}), 404

            if data['direction'] == 'up':
                if current_index == 0:
                    return jsonify({"success": False, "error": "Rule is already at the top"}), 400
                # Move before the rule that's currently above us
                position = {"before": rule_ids[current_index - 1]}
            elif data['direction'] == 'down':
                if current_index >= len(rule_ids) - 1:
                    return jsonify({"success": False, "error": "Rule is already at the bottom"}), 400
                # Move after the rule that's currently below us
                position = {"after": rule_ids[current_index + 1]}
            else:
                return jsonify({"success": False, "error": "Invalid direction. Use 'up' or 'down'"}), 400

        elif 'index' in data:
            # Move to exact position (1-based)
            position = {"index": int(data['index'])}

        elif 'before' in data:
            position = {"before": data['before']}

        elif 'after' in data:
            position = {"after": data['after']}

        else:
            return jsonify({"success": False, "error": "Must specify direction, index, before, or after"}), 400

        # Use PATCH to move the rule
        patch_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/rulesets/{DDOS_L4_ROOT_ID}/rules/{override_id}"
        response = requests.patch(
            patch_url,
            headers=HEADERS_GLOBAL,
            json={"position": position},
            timeout=30
        )

        result = response.json()
        if result.get('success'):
            return jsonify({
                "success": True,
                "message": "Rule moved successfully"
            })
        else:
            errors = result.get('errors', [])
            error_msg = errors[0].get('message', str(errors)) if errors else 'Unknown error'
            return jsonify({"success": False, "error": error_msg}), 400

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/ddos-rules')
@app.route('/ddos-rules/<action>')
@login_required
def page_ddos_rules(action=None):
    """Page to display DDoS rules"""
    return render_template('ddos_rules.html', action=action, version=load_version())

@app.route('/mnm-rules')
@login_required
def page_mnm_rules():
    """Page to manage MNM rules"""
    return render_template('mnm_rules.html', version=load_version())

@app.route('/api/services')
@login_required
def api_services():
    """Get systemd service status"""
    import subprocess
    from email.utils import parsedate_to_datetime

    services = [
        "cloudflare-webhook",
        "cloudflare-analytics-monitor",
        "cloudflare-autowithdraw",
        "cloudflare-dashboard"
    ]

    result = []
    for service in services:
        try:
            status = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True, text=True, timeout=5
            )
            is_active = status.stdout.strip() == "active"

            # Get service description from systemd
            description = service  # Fallback to service name
            desc_result = subprocess.run(
                ["systemctl", "show", service, "--property=Description", "--value"],
                capture_output=True, text=True, timeout=5
            )
            if desc_result.returncode == 0 and desc_result.stdout.strip():
                description = desc_result.stdout.strip()

            # Get uptime if active
            uptime = ""
            if is_active:
                uptime_result = subprocess.run(
                    ["systemctl", "show", service, "--property=ActiveEnterTimestamp"],
                    capture_output=True, text=True, timeout=5
                )
                if uptime_result.returncode == 0:
                    raw_time = uptime_result.stdout.strip().replace("ActiveEnterTimestamp=", "")
                    # Convert systemd timestamp to ISO format
                    # Format: "Tue 2026-01-20 20:35:59 CET" -> ISO
                    try:
                        # Parse the date part (ignore day name and timezone name)
                        # "Tue 2026-01-20 20:35:59 CET" -> "2026-01-20 20:35:59"
                        parts = raw_time.split()
                        if len(parts) >= 3:
                            date_str = f"{parts[1]} {parts[2]}"  # "2026-01-20 20:35:59"
                            dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                            # Assume local timezone (CET = UTC+1)
                            uptime = dt.strftime("%Y-%m-%dT%H:%M:%S+01:00")
                    except:
                        uptime = raw_time  # Fallback to original

            result.append({
                "name": service,
                "description": description,
                "status": "active" if is_active else "inactive",
                "uptime": uptime
            })
        except Exception as e:
            result.append({
                "name": service,
                "status": "error",
                "error": str(e)
            })

    return jsonify({"success": True, "services": result})

@app.route('/api/stats')
@login_required
def api_stats():
    """Get summary statistics"""
    try:
        # Database stats - only count real attacks (START events), not END/ADVERTISE/WITHDRAW
        attack_count = query_db("SELECT COUNT(*) as count FROM attack_events WHERE event_type = 'START'", one=True)
        analytics_count = query_db("SELECT COUNT(*) as count FROM network_analytics_events", one=True)
        webhook_count = query_db("SELECT COUNT(*) as count FROM webhook_events", one=True)
        withdrawal_count = query_db("SELECT COUNT(*) as count FROM withdrawal_history", one=True)

        # Recent activity (last 24h) - use SQLite datetime() for correct comparison
        recent_attacks = query_db(
            "SELECT COUNT(*) as count FROM attack_events WHERE event_type = 'START' AND created_at > datetime('now', '-24 hours')",
            one=True
        )
        recent_analytics = query_db(
            "SELECT COUNT(*) as count FROM network_analytics_events WHERE notified_at > datetime('now', '-24 hours')",
            one=True
        )

        return jsonify({
            "success": True,
            "stats": {
                "total_attacks": attack_count['count'] if attack_count else 0,
                "total_analytics": analytics_count['count'] if analytics_count else 0,
                "total_webhooks": webhook_count['count'] if webhook_count else 0,
                "total_withdrawals": withdrawal_count['count'] if withdrawal_count else 0,
                "attacks_24h": recent_attacks['count'] if recent_attacks else 0,
                "analytics_24h": recent_analytics['count'] if recent_analytics else 0
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/network-flow')
@login_required
def api_network_flow():
    """Get real-time network flow statistics from MNM Flow Data GraphQL API (last 24h)"""
    try:
        # Use current time as end, 24 hours ago as start
        now = datetime.now(timezone.utc)
        start_time = (now - timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%SZ')
        end_time = now.strftime('%Y-%m-%dT%H:%M:%SZ')

        # GraphQL query for MNM Flow Data - separate queries for totals and top values
        # This avoids hitting the 10000 limit when combining all dimensions
        query = """
        query GetNetworkFlow($accountTag: String!, $datetimeStart: Time!, $datetimeEnd: Time!) {
            viewer {
                accounts(filter: { accountTag: $accountTag }) {
                    # Total traffic (no dimensions = aggregate total)
                    total: mnmFlowDataAdaptiveGroups(
                        filter: {
                            datetime_geq: $datetimeStart
                            datetime_leq: $datetimeEnd
                        }
                        limit: 1
                    ) {
                        sum {
                            packets
                            bits
                        }
                    }
                    # Top protocols
                    byProtocol: mnmFlowDataAdaptiveGroups(
                        filter: {
                            datetime_geq: $datetimeStart
                            datetime_leq: $datetimeEnd
                        }
                        limit: 10
                        orderBy: [sum_bits_DESC]
                    ) {
                        dimensions {
                            protocolString
                        }
                        sum {
                            bits
                        }
                    }
                    # Top routers (GOLINE: 185.54.80.1, 185.54.80.2)
                    byRouter: mnmFlowDataAdaptiveGroups(
                        filter: {
                            datetime_geq: $datetimeStart
                            datetime_leq: $datetimeEnd
                        }
                        limit: 10
                        orderBy: [sum_bits_DESC]
                    ) {
                        dimensions {
                            routerAddress
                        }
                        sum {
                            bits
                        }
                    }
                    # Top source IPs
                    bySource: mnmFlowDataAdaptiveGroups(
                        filter: {
                            datetime_geq: $datetimeStart
                            datetime_leq: $datetimeEnd
                        }
                        limit: 10
                        orderBy: [sum_bits_DESC]
                    ) {
                        dimensions {
                            sourceAddress
                        }
                        sum {
                            bits
                        }
                    }
                    # Top destination
                    byDestination: mnmFlowDataAdaptiveGroups(
                        filter: {
                            datetime_geq: $datetimeStart
                            datetime_leq: $datetimeEnd
                        }
                        limit: 10
                        orderBy: [sum_bits_DESC]
                    ) {
                        dimensions {
                            destinationAddress
                        }
                        sum {
                            bits
                        }
                    }
                }
            }
        }
        """

        variables = {
            'accountTag': ACCOUNT_ID,
            'datetimeStart': start_time,
            'datetimeEnd': end_time
        }

        response = requests.post(
            'https://api.cloudflare.com/client/v4/graphql',
            headers=HEADERS,
            json={'query': query, 'variables': variables},
            timeout=30
        )

        if response.status_code != 200:
            return jsonify({"success": False, "error": f"API error: {response.status_code}"})

        data = response.json()
        if data.get('errors'):
            return jsonify({"success": False, "error": str(data['errors'])})

        accounts = data.get('data', {}).get('viewer', {}).get('accounts', [])
        if not accounts:
            return jsonify({"success": False, "error": "No account data"})

        account = accounts[0]

        # Get totals from aggregate query (no dimensions)
        total_data = account.get('total', [])
        total_bits = sum(g['sum']['bits'] or 0 for g in total_data)
        total_packets = sum(g['sum']['packets'] or 0 for g in total_data)

        # Calculate averages (bits/packets per second over 24h)
        seconds_in_period = 24 * 60 * 60  # 86400 seconds
        avg_bit_rate = total_bits / seconds_in_period if total_bits > 0 else 0
        avg_packet_rate = total_packets / seconds_in_period if total_packets > 0 else 0

        # Get top protocol (already sorted by bits DESC)
        by_protocol = account.get('byProtocol', [])
        top_protocol = by_protocol[0]['dimensions']['protocolString'] if by_protocol else '-'
        top_protocol_bits = by_protocol[0]['sum']['bits'] if by_protocol else 0

        # Get top router (already sorted by bits DESC)
        by_router = account.get('byRouter', [])
        top_router = by_router[0]['dimensions']['routerAddress'] if by_router else '-'
        top_router_bits = by_router[0]['sum']['bits'] if by_router else 0

        # Get top source (already sorted by bits DESC)
        by_source = account.get('bySource', [])
        top_source = by_source[0]['dimensions']['sourceAddress'] if by_source else '-'
        top_source_bits = by_source[0]['sum']['bits'] if by_source else 0

        # Get top destination (already sorted by bits DESC)
        by_destination = account.get('byDestination', [])
        top_destination = by_destination[0]['dimensions']['destinationAddress'] if by_destination else '-'
        top_destination_bits = by_destination[0]['sum']['bits'] if by_destination else 0

        # Resolve hostnames in parallel (with short timeout)
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(resolve_hostname, top_source): 'source',
                executor.submit(resolve_hostname, top_router): 'router',
                executor.submit(resolve_hostname, top_destination): 'destination'
            }
            hostnames = {'source': '', 'router': '', 'destination': ''}
            for future in as_completed(futures, timeout=2):
                key = futures[future]
                try:
                    hostnames[key] = future.result()
                except Exception:
                    hostnames[key] = ''

        return jsonify({
            "success": True,
            "network_flow": {
                "avg_bit_rate": avg_bit_rate,
                "avg_packet_rate": avg_packet_rate,
                "top_protocol": top_protocol,
                "top_protocol_bits": top_protocol_bits,
                "top_source": top_source,
                "top_source_bits": top_source_bits,
                "top_source_hostname": hostnames['source'],
                "top_router": top_router,
                "top_router_bits": top_router_bits,
                "top_router_hostname": hostnames['router'],
                "top_destination": top_destination,
                "top_destination_bits": top_destination_bits,
                "top_destination_hostname": hostnames['destination']
            },
            "period": "24h",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# =============================================================================
# PREFIX MANAGEMENT HELPERS
# =============================================================================

def check_15min_constraint(modified_at):
    """Check if 15-minute constraint is satisfied after last state change

    Returns:
        tuple: (can_proceed, remaining_seconds, available_time_str)
    """
    if not modified_at:
        return True, 0, None

    try:
        mod_time = datetime.fromisoformat(modified_at.replace('Z', '+00:00'))
        available_time = mod_time + timedelta(minutes=15)
        now = datetime.now(timezone.utc)

        if now >= available_time:
            return True, 0, None
        else:
            remaining = (available_time - now).total_seconds()
            # Format time in local timezone (UTC+1 for Switzerland)
            available_time_local = available_time + timedelta(hours=1)
            available_time_str = available_time_local.strftime('%H:%M:%S')
            return False, remaining, available_time_str
    except:
        return True, 0, None

def set_prefix_advertisement(prefix_id, bgp_prefix_id, advertise):
    """Set the advertisement state of a prefix via Cloudflare API"""
    url = f"{API_BASE}/addressing/prefixes/{prefix_id}/bgp/prefixes/{bgp_prefix_id}"
    data = {"on_demand": {"advertised": advertise}}

    try:
        response = requests.patch(url, headers=HEADERS, json=data, timeout=30)

        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                return {'success': True, 'result': result.get('result', {})}
            else:
                errors = result.get('errors', [])
                error_msg = errors[0].get('message', str(errors)) if errors else 'Unknown error'
                return {'success': False, 'error': error_msg}

        return {'success': False, 'error': f"HTTP {response.status_code}"}

    except Exception as e:
        return {'success': False, 'error': str(e)}

def log_prefix_action(event_type, prefix, description, action_taken):
    """Log prefix action to database"""
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO attack_events
            (event_type, alert_type, prefix, action_taken)
            VALUES (?, ?, ?, ?)
        """, (event_type, 'dashboard_manual', prefix, action_taken))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error logging to database: {e}")
        return False

def send_telegram_notification(message):
    """Send Telegram notification"""
    try:
        telegram_config = CONFIG.get('telegram', {})
        bot_token = telegram_config.get('bot_token', '')
        chat_id = telegram_config.get('chat_id', '')

        if not bot_token or not chat_id:
            print("Telegram not configured")
            return False

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }
        response = requests.post(url, json=data, timeout=10)
        return response.status_code == 200
    except Exception as e:
        print(f"Error sending Telegram: {e}")
        return False

def notify_prefix_action(action, prefix, description):
    """Send formatted Telegram notification for prefix action"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if action == 'advertise':
        emoji = "📡"
        status = "ADVERTISED"
        action_desc = "Manual Advertisement"
    else:
        emoji = "🔽"
        status = "WITHDRAWN"
        action_desc = "Manual Withdrawal"

    # Determine prefix type
    if ':' in prefix:
        prefix_type = "IPv6"
        prefix_icon = "🌐"
    else:
        prefix_type = "IPv4"
        prefix_icon = "📍"

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

{emoji} *BGP {status}*

🎯 *Action:* {action_desc}
📋 *Source:* Dashboard (Manual)

{prefix_icon} *PREFIX INFO*
📍 *CIDR:* `{prefix}`
📝 *Description:* {description}
🌍 *Type:* {prefix_type}

⏱️ *TIMING*
🕐 *Time:* {timestamp}
⏳ *Constraint:* 15 min before next change

━━━━━━━━━━━━━━━━━━
_GOLINE SOC - Magic Transit Dashboard_"""

    return send_telegram_notification(message)

# =============================================================================
# ROUTES - PREFIX MANAGEMENT
# =============================================================================

@app.route('/api/prefix/<path:cidr>/advertise', methods=['POST'])
@login_required
def api_prefix_advertise(cidr):
    """Advertise a BGP prefix"""
    try:
        # Load prefix configuration
        prefix_data = load_prefixes()
        prefixes = prefix_data.get('prefixes', prefix_data)

        if cidr not in prefixes:
            return jsonify({"success": False, "error": f"Prefix {cidr} not found"}), 404

        info = prefixes[cidr]
        prefix_id = info.get('prefix_id', info.get('id', ''))
        bgp_prefix_id = info.get('bgp_prefix_id', '')

        if not prefix_id or not bgp_prefix_id:
            return jsonify({"success": False, "error": "Missing prefix IDs in configuration"}), 400

        # Get current status to check constraint
        status_result = fetch_prefix_status(cidr, info)

        if status_result.get('status') == 'error':
            return jsonify({"success": False, "error": status_result.get('error', 'Failed to get status')}), 500

        # Already advertised?
        if status_result.get('advertised'):
            return jsonify({"success": False, "error": "Prefix is already advertised"}), 400

        # Check 15-minute constraint (can only re-advertise 15 min after withdrawal)
        modified_at = status_result.get('advertised_modified_at')
        can_proceed, remaining, available_time = check_15min_constraint(modified_at)

        if not can_proceed:
            minutes = int(remaining // 60)
            seconds = int(remaining % 60)
            return jsonify({
                "success": False,
                "error": f"Must wait {minutes}m {seconds}s before advertising (available at {available_time})",
                "remaining_seconds": remaining,
                "available_at": available_time
            }), 429

        # Perform advertisement
        result = set_prefix_advertisement(prefix_id, bgp_prefix_id, True)

        if result.get('success'):
            # Log to database
            description = info.get('description', '')
            log_prefix_action('ADVERTISE', cidr, description, 'advertised_manual')

            # Send Telegram notification
            notify_prefix_action('advertise', cidr, description)

            return jsonify({
                "success": True,
                "message": f"Prefix {cidr} advertised successfully",
                "cidr": cidr
            })
        else:
            return jsonify({"success": False, "error": result.get('error', 'Unknown error')}), 500

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/prefix/<path:cidr>/withdraw', methods=['POST'])
@login_required
def api_prefix_withdraw(cidr):
    """Withdraw a BGP prefix"""
    try:
        # Load prefix configuration
        prefix_data = load_prefixes()
        prefixes = prefix_data.get('prefixes', prefix_data)

        if cidr not in prefixes:
            return jsonify({"success": False, "error": f"Prefix {cidr} not found"}), 404

        info = prefixes[cidr]
        prefix_id = info.get('prefix_id', info.get('id', ''))
        bgp_prefix_id = info.get('bgp_prefix_id', '')

        if not prefix_id or not bgp_prefix_id:
            return jsonify({"success": False, "error": "Missing prefix IDs in configuration"}), 400

        # Get current status to check constraint
        status_result = fetch_prefix_status(cidr, info)

        if status_result.get('status') == 'error':
            return jsonify({"success": False, "error": status_result.get('error', 'Failed to get status')}), 500

        # Already withdrawn?
        if not status_result.get('advertised'):
            return jsonify({"success": False, "error": "Prefix is already withdrawn"}), 400

        # Check 15-minute constraint (can only withdraw 15 min after advertisement)
        modified_at = status_result.get('advertised_modified_at')
        can_proceed, remaining, available_time = check_15min_constraint(modified_at)

        if not can_proceed:
            minutes = int(remaining // 60)
            seconds = int(remaining % 60)
            return jsonify({
                "success": False,
                "error": f"Must wait {minutes}m {seconds}s before withdrawing (available at {available_time})",
                "remaining_seconds": remaining,
                "available_at": available_time
            }), 429

        # Perform withdrawal
        result = set_prefix_advertisement(prefix_id, bgp_prefix_id, False)

        if result.get('success'):
            # Log to database
            description = info.get('description', '')
            log_prefix_action('WITHDRAW', cidr, description, 'withdrawn_manual')

            # Send Telegram notification
            notify_prefix_action('withdraw', cidr, description)

            return jsonify({
                "success": True,
                "message": f"Prefix {cidr} withdrawn successfully",
                "cidr": cidr
            })
        else:
            return jsonify({"success": False, "error": result.get('error', 'Unknown error')}), 500

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# =============================================================================
# ROUTES - CONNECTORS (Tunnels & Interconnects)
# =============================================================================

@app.route('/connectors')
@login_required
def page_connectors():
    """Page to display Connectors (IPsec/GRE Tunnels & CNI Interconnects)"""
    return render_template('connectors.html', version=load_version())


def fetch_tunnel_health_stats():
    """Fetch tunnel health check statistics from GraphQL API (1 hour)"""
    try:
        now = datetime.now(timezone.utc)
        start_time = (now - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        end_time = now.strftime('%Y-%m-%dT%H:%M:%SZ')

        query = """
        query GetTunnelHealth($accountTag: String!, $since: Time!, $until: Time!) {
            viewer {
                accounts(filter: {accountTag: $accountTag}) {
                    magicTransitTunnelHealthChecksAdaptiveGroups(
                        limit: 1000,
                        filter: {
                            datetime_geq: $since,
                            datetime_lt: $until
                        }
                    ) {
                        count
                        avg {
                            tunnelState
                        }
                        dimensions {
                            tunnelName
                            edgeColoName
                        }
                    }
                }
            }
        }
        """

        variables = {
            'accountTag': ACCOUNT_ID,
            'since': start_time,
            'until': end_time
        }

        response = requests.post(
            'https://api.cloudflare.com/client/v4/graphql',
            headers=HEADERS,
            json={'query': query, 'variables': variables},
            timeout=30
        )

        if response.status_code != 200:
            return {}

        data = response.json()
        if data.get('errors'):
            return {}

        accounts = data.get('data', {}).get('viewer', {}).get('accounts', [])
        if not accounts:
            return {}

        health_groups = accounts[0].get('magicTransitTunnelHealthChecksAdaptiveGroups', [])

        # Aggregate by tunnel name
        tunnel_stats = {}
        for group in health_groups:
            tunnel_name = group.get('dimensions', {}).get('tunnelName')
            if not tunnel_name:
                continue

            count = group.get('count', 0)
            state = group.get('avg', {}).get('tunnelState', 0)

            if tunnel_name not in tunnel_stats:
                tunnel_stats[tunnel_name] = {
                    'total_checks': 0,
                    'weighted_state': 0,
                    'colos_count': 0
                }

            tunnel_stats[tunnel_name]['total_checks'] += count
            tunnel_stats[tunnel_name]['weighted_state'] += state * count
            tunnel_stats[tunnel_name]['colos_count'] += 1

        # Calculate pass rates
        result = {}
        for name, stats in tunnel_stats.items():
            total = stats['total_checks']
            if total > 0:
                avg_state = stats['weighted_state'] / total
                pass_rate = avg_state * 100  # Convert 0-1 to percentage

                # Determine status based on pass rate
                if pass_rate >= 80:
                    status = 'healthy'
                elif pass_rate >= 40:
                    status = 'degraded'
                else:
                    status = 'down'

                result[name] = {
                    'pass_rate': round(pass_rate, 2),
                    'total_checks': total,
                    'colos_count': stats['colos_count'],
                    'status': status
                }

        return result

    except Exception:
        return {}


@app.route('/api/connectors/tunnels')
@login_required
def api_connectors_tunnels():
    """Get GRE and IPsec tunnels from Cloudflare API with health stats"""
    try:
        tunnels = []
        gre_count = 0
        ipsec_count = 0

        # Fetch health stats from GraphQL (1 hour)
        health_stats = fetch_tunnel_health_stats()

        # Fetch GRE tunnels
        gre_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/magic/gre_tunnels"
        gre_response = requests.get(gre_url, headers=HEADERS, timeout=30)
        gre_data = gre_response.json()

        if gre_data.get('success'):
            gre_tunnels = gre_data.get('result', {}).get('gre_tunnels', [])
            gre_count = len(gre_tunnels)

            for tunnel in gre_tunnels:
                tunnel_name = tunnel.get('name')
                stats = health_stats.get(tunnel_name, {})

                # Use GraphQL health status if available, otherwise fallback
                if stats:
                    health_status = stats.get('status', 'unknown')
                elif tunnel.get('health_check', {}).get('enabled'):
                    health_status = 'healthy'
                else:
                    health_status = 'unknown'

                tunnels.append({
                    'id': tunnel.get('id'),
                    'name': tunnel_name,
                    'description': tunnel.get('description', ''),
                    'type': 'gre',
                    'cloudflare_endpoint': tunnel.get('cloudflare_gre_endpoint'),
                    'customer_endpoint': tunnel.get('customer_gre_endpoint'),
                    'interface_address': tunnel.get('interface_address'),
                    'mtu': tunnel.get('mtu'),
                    'ttl': tunnel.get('ttl'),
                    'health_status': health_status,
                    'health_check': tunnel.get('health_check'),
                    'bgp_status': tunnel.get('bgp_status'),
                    'created_on': tunnel.get('created_on'),
                    'modified_on': tunnel.get('modified_on'),
                    'pass_rate': stats.get('pass_rate'),
                    'total_checks': stats.get('total_checks'),
                    'colos_count': stats.get('colos_count')
                })

        # Fetch IPsec tunnels
        ipsec_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/magic/ipsec_tunnels"
        ipsec_response = requests.get(ipsec_url, headers=HEADERS, timeout=30)
        ipsec_data = ipsec_response.json()

        if ipsec_data.get('success'):
            ipsec_tunnels = ipsec_data.get('result', {}).get('ipsec_tunnels', [])
            ipsec_count = len(ipsec_tunnels)

            for tunnel in ipsec_tunnels:
                tunnel_name = tunnel.get('name')
                stats = health_stats.get(tunnel_name, {})

                if stats:
                    health_status = stats.get('status', 'unknown')
                elif tunnel.get('health_check', {}).get('enabled'):
                    health_status = 'healthy'
                else:
                    health_status = 'unknown'

                tunnels.append({
                    'id': tunnel.get('id'),
                    'name': tunnel_name,
                    'description': tunnel.get('description', ''),
                    'type': 'ipsec',
                    'cloudflare_endpoint': tunnel.get('cloudflare_endpoint'),
                    'customer_endpoint': tunnel.get('customer_endpoint'),
                    'interface_address': tunnel.get('interface_address'),
                    'mtu': None,
                    'health_status': health_status,
                    'health_check': tunnel.get('health_check'),
                    'bgp_status': None,
                    'created_on': tunnel.get('created_on'),
                    'modified_on': tunnel.get('modified_on'),
                    'replay_protection': tunnel.get('replay_protection'),
                    'allow_null_cipher': tunnel.get('allow_null_cipher'),
                    'pass_rate': stats.get('pass_rate'),
                    'total_checks': stats.get('total_checks'),
                    'colos_count': stats.get('colos_count')
                })

        return jsonify({
            'success': True,
            'tunnels': tunnels,
            'gre_count': gre_count,
            'ipsec_count': ipsec_count,
            'total': gre_count + ipsec_count,
            'health_stats': health_stats  # Include raw stats for CNI matching
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/connectors/interconnects')
@login_required
def api_connectors_interconnects():
    """Get CNI Interconnects from Cloudflare API with health stats"""
    try:
        interconnects = []
        interconnects_map = {}  # Map name -> interconnect data

        # Fetch health stats from GraphQL (includes CNI health)
        health_stats = fetch_tunnel_health_stats()

        # Fetch Interconnects (physical/virtual connections)
        interconnects_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/cni/interconnects"
        interconnects_response = requests.get(interconnects_url, headers=HEADERS, timeout=30)
        interconnects_data = interconnects_response.json()

        # CNI API returns items directly at top level (not wrapped in result)
        items = interconnects_data.get('items', [])

        for item in items:
            # facility can be a string or an object with 'name'
            facility = item.get('facility')
            if isinstance(facility, dict):
                facility_name = facility.get('name', '-')
            else:
                facility_name = facility or '-'

            interconnects_map[item.get('name')] = {
                'id': item.get('name'),  # interconnect ID is the name
                'name': item.get('name'),
                'description': '',
                'facility': facility_name,
                'speed': item.get('speed', '-'),
                'status': 'active',  # Interconnects don't have status field, assume active if present
                'type': item.get('type', '-'),
                'site': item.get('site', '-'),
                'slot_id': item.get('slot_id')
            }

        # Fetch CNIs (logical connections on interconnects)
        cnis_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/cni/cnis"
        cnis_response = requests.get(cnis_url, headers=HEADERS, timeout=30)
        cnis_data = cnis_response.json()

        cnis = []
        # CNI API returns items directly at top level
        cni_items = cnis_data.get('items', [])

        for item in cni_items:
            magic_config = item.get('magic', {})

            # p2p_ip and cust_ip are objects with 'ip' and 'cidr' fields
            p2p_ip_obj = item.get('p2p_ip', {})
            cust_ip_obj = item.get('cust_ip', {})

            p2p_cloudflare = f"{p2p_ip_obj.get('ip', '-')}/{p2p_ip_obj.get('cidr', '')}" if p2p_ip_obj.get('ip') else '-'
            p2p_customer = f"{cust_ip_obj.get('ip', '-')}/{cust_ip_obj.get('cidr', '')}" if cust_ip_obj.get('ip') else '-'

            cnis.append({
                'id': item.get('id'),
                'interconnect_id': item.get('interconnect'),
                'p2p_cloudflare': p2p_cloudflare,
                'p2p_customer': p2p_customer,
                'conduit_name': magic_config.get('conduit_name'),
                'description': magic_config.get('description', ''),
                'mtu': magic_config.get('mtu'),
                'bgp': item.get('bgp')
            })

        # Build final interconnects list combining physical interconnects with CNI data
        final_interconnects = []

        for cni in cnis:
            interconnect_id = cni.get('interconnect_id')
            base_data = interconnects_map.get(interconnect_id, {})
            cni_name = cni.get('conduit_name') or base_data.get('name', f"CNI-{cni.get('id', '')[:8]}")

            # Get health stats for this CNI
            stats = health_stats.get(cni_name, {})
            health_status = stats.get('status', 'active') if stats else 'active'

            final_interconnects.append({
                'id': cni.get('id'),
                'name': cni_name,
                'description': cni.get('description', ''),
                'facility': base_data.get('facility', '-'),
                'speed': base_data.get('speed', '-'),
                'status': health_status,
                'site': base_data.get('site', '-'),
                'type': base_data.get('type', 'cni'),
                'p2p_cloudflare': cni.get('p2p_cloudflare'),
                'p2p_customer': cni.get('p2p_customer'),
                'mtu': cni.get('mtu'),
                'pass_rate': stats.get('pass_rate'),
                'total_checks': stats.get('total_checks'),
                'colos_count': stats.get('colos_count')
            })

        # If no CNIs but have interconnects, show interconnects without P2P info
        if not final_interconnects and interconnects_map:
            for name, data in interconnects_map.items():
                final_interconnects.append({
                    'id': data.get('slot_id', name),
                    'name': name,
                    'description': '',
                    'facility': data.get('facility', '-'),
                    'speed': data.get('speed', '-'),
                    'status': 'active',
                    'site': data.get('site', '-'),
                    'type': data.get('type', '-'),
                    'p2p_cloudflare': '-',
                    'p2p_customer': '-'
                })

        return jsonify({
            'success': True,
            'interconnects': final_interconnects,
            'cnis': cnis,
            'total': len(final_interconnects)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/connectors/tunnel/<tunnel_id>')
@login_required
def api_connectors_tunnel_detail(tunnel_id):
    """Get single tunnel details"""
    try:
        # Try GRE first
        gre_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/magic/gre_tunnels/{tunnel_id}"
        gre_response = requests.get(gre_url, headers=HEADERS, timeout=30)
        gre_data = gre_response.json()

        if gre_data.get('success') and gre_data.get('result', {}).get('gre_tunnel'):
            tunnel = gre_data['result']['gre_tunnel']
            tunnel['type'] = 'gre'
            return jsonify({'success': True, 'tunnel': tunnel})

        # Try IPsec
        ipsec_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/magic/ipsec_tunnels/{tunnel_id}"
        ipsec_response = requests.get(ipsec_url, headers=HEADERS, timeout=30)
        ipsec_data = ipsec_response.json()

        if ipsec_data.get('success') and ipsec_data.get('result', {}).get('ipsec_tunnel'):
            tunnel = ipsec_data['result']['ipsec_tunnel']
            tunnel['type'] = 'ipsec'
            return jsonify({'success': True, 'tunnel': tunnel})

        return jsonify({'success': False, 'error': 'Tunnel not found'}), 404

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/connectors/tunnel/<tunnel_id>/update', methods=['POST'])
@login_required
def api_connectors_tunnel_update(tunnel_id):
    """Update tunnel fields - auto-detects GRE or IPsec"""
    try:
        data = request.get_json()
        new_description = data.get('description', '')
        new_customer_endpoint = data.get('customer_endpoint')
        new_mtu = data.get('mtu')
        new_health_check = data.get('health_check')

        # Try GRE tunnel first
        get_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/magic/gre_tunnels/{tunnel_id}"
        get_response = requests.get(get_url, headers=HEADERS, timeout=30)
        get_data = get_response.json()

        if get_data.get('success') and get_data.get('result', {}).get('gre_tunnel'):
            # It's a GRE tunnel
            current = get_data['result']['gre_tunnel']
            current_health = current.get('health_check', {})

            update_data = {
                'name': current['name'],
                'cloudflare_gre_endpoint': current['cloudflare_gre_endpoint'],
                'customer_gre_endpoint': new_customer_endpoint or current['customer_gre_endpoint'],
                'interface_address': current['interface_address'],
                'description': new_description,
                'ttl': current.get('ttl', 64),
                'mtu': new_mtu if new_mtu else current.get('mtu', 1476)
            }

            # Build health_check object
            if new_health_check:
                update_data['health_check'] = {
                    'enabled': new_health_check.get('enabled', current_health.get('enabled', True)),
                    'target': current_health.get('target', new_customer_endpoint or current['customer_gre_endpoint']),
                    'type': current_health.get('type', 'reply'),
                    'rate': new_health_check.get('rate', current_health.get('rate', 'mid')),
                    'direction': current_health.get('direction', 'unidirectional')
                }
            elif current_health:
                update_data['health_check'] = current_health

            update_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/magic/gre_tunnels/{tunnel_id}"
            response = requests.put(update_url, headers=HEADERS, json=update_data, timeout=30)
            result = response.json()

            if result.get('success'):
                return jsonify({'success': True, 'message': 'GRE tunnel updated successfully'})
            else:
                return jsonify({'success': False, 'error': str(result.get('errors', 'Unknown error'))}), 400

        # Not GRE, try IPsec
        get_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/magic/ipsec_tunnels/{tunnel_id}"
        get_response = requests.get(get_url, headers=HEADERS, timeout=30)
        get_data = get_response.json()

        if get_data.get('success') and get_data.get('result', {}).get('ipsec_tunnel'):
            # It's an IPsec tunnel
            current = get_data['result']['ipsec_tunnel']
            current_health = current.get('health_check', {})

            update_data = {
                'name': current['name'],
                'cloudflare_endpoint': current['cloudflare_endpoint'],
                'customer_endpoint': new_customer_endpoint or current['customer_endpoint'],
                'interface_address': current['interface_address'],
                'description': new_description
            }

            # Build health_check object for IPsec
            if new_health_check:
                update_data['health_check'] = {
                    'enabled': new_health_check.get('enabled', current_health.get('enabled', True)),
                    'target': current_health.get('target', new_customer_endpoint or current['customer_endpoint']),
                    'type': current_health.get('type', 'reply'),
                    'rate': new_health_check.get('rate', current_health.get('rate', 'mid')),
                    'direction': current_health.get('direction', 'unidirectional')
                }
            elif current_health:
                update_data['health_check'] = current_health

            update_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/magic/ipsec_tunnels/{tunnel_id}"
            response = requests.put(update_url, headers=HEADERS, json=update_data, timeout=30)
            result = response.json()

            if result.get('success'):
                return jsonify({'success': True, 'message': 'IPsec tunnel updated successfully'})
            else:
                return jsonify({'success': False, 'error': str(result.get('errors', 'Unknown error'))}), 400

        return jsonify({'success': False, 'error': 'Tunnel not found'}), 404

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/connectors/cni/<cni_id>')
@login_required
def api_connectors_cni_detail(cni_id):
    """Get single CNI details"""
    try:
        cni_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/cni/cnis/{cni_id}"
        response = requests.get(cni_url, headers=HEADERS, timeout=30)
        data = response.json()

        # CNI API structure is different
        if 'id' in data:
            return jsonify({'success': True, 'cni': data})
        elif data.get('items'):
            return jsonify({'success': True, 'cni': data['items'][0] if data['items'] else None})

        return jsonify({'success': False, 'error': 'CNI not found'}), 404

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/connectors/cni/<cni_id>/update', methods=['POST'])
@login_required
def api_connectors_cni_update(cni_id):
    """Update CNI description"""
    try:
        data = request.get_json()
        new_description = data.get('description', '')

        # Get current CNI data
        get_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/cni/cnis/{cni_id}"
        get_response = requests.get(get_url, headers=HEADERS, timeout=30)
        current = get_response.json()

        if not current.get('id'):
            return jsonify({'success': False, 'error': 'CNI not found'}), 404

        # Update the magic.description field
        update_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/cni/cnis/{cni_id}"
        magic_config = current.get('magic', {})
        magic_config['description'] = new_description

        update_data = {
            'magic': magic_config
        }

        response = requests.patch(update_url, headers=HEADERS, json=update_data, timeout=30)
        result = response.json()

        # CNI API returns the updated object on success
        if result.get('id') or result.get('success'):
            return jsonify({'success': True, 'message': 'CNI updated successfully'})
        else:
            return jsonify({'success': False, 'error': str(result.get('errors', result))}), 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/connectors/tunnel-health')
@login_required
def api_connectors_tunnel_health():
    """Get tunnel health check results from GraphQL API"""
    try:
        # GraphQL query for tunnel health
        now = datetime.now(timezone.utc)
        start_time = (now - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        end_time = now.strftime('%Y-%m-%dT%H:%M:%SZ')

        query = """
        query GetTunnelHealth($accountTag: String!, $since: Time!, $until: Time!) {
            viewer {
                accounts(filter: {accountTag: $accountTag}) {
                    magicTransitTunnelHealthChecksAdaptiveGroups(
                        limit: 100,
                        filter: {
                            datetime_geq: $since,
                            datetime_lt: $until
                        }
                    ) {
                        avg {
                            tunnelState
                        }
                        dimensions {
                            tunnelName
                            edgeColoName
                        }
                    }
                }
            }
        }
        """

        variables = {
            'accountTag': ACCOUNT_ID,
            'since': start_time,
            'until': end_time
        }

        response = requests.post(
            'https://api.cloudflare.com/client/v4/graphql',
            headers=HEADERS,
            json={'query': query, 'variables': variables},
            timeout=30
        )

        if response.status_code != 200:
            return jsonify({'success': False, 'error': f'GraphQL error: {response.status_code}'})

        data = response.json()
        if data.get('errors'):
            return jsonify({'success': False, 'error': str(data['errors'])})

        accounts = data.get('data', {}).get('viewer', {}).get('accounts', [])
        if not accounts:
            return jsonify({'success': True, 'health_checks': [], 'message': 'No health check data available'})

        health_groups = accounts[0].get('magicTransitTunnelHealthChecksAdaptiveGroups', [])

        # Aggregate health by tunnel
        tunnel_health = {}
        for group in health_groups:
            tunnel_name = group.get('dimensions', {}).get('tunnelName')
            colo = group.get('dimensions', {}).get('edgeColoName')
            state = group.get('avg', {}).get('tunnelState', 0)

            if tunnel_name not in tunnel_health:
                tunnel_health[tunnel_name] = {
                    'name': tunnel_name,
                    'colos': [],
                    'avg_state': 0,
                    'state_sum': 0,
                    'state_count': 0
                }

            tunnel_health[tunnel_name]['colos'].append({
                'colo': colo,
                'state': state
            })
            tunnel_health[tunnel_name]['state_sum'] += state
            tunnel_health[tunnel_name]['state_count'] += 1

        # Calculate average state per tunnel
        results = []
        for name, data in tunnel_health.items():
            avg_state = data['state_sum'] / data['state_count'] if data['state_count'] > 0 else 0

            # Map state to status: 0 = down, 0.5 = degraded, 1 = healthy
            if avg_state >= 0.8:
                status = 'healthy'
            elif avg_state >= 0.4:
                status = 'degraded'
            else:
                status = 'down'

            results.append({
                'name': name,
                'avg_state': round(avg_state, 2),
                'status': status,
                'colos_checked': len(data['colos'])
            })

        return jsonify({
            'success': True,
            'health_checks': results,
            'period': '1h',
            'timestamp': datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/connectors/health-summary')
@login_required
def api_connectors_health_summary():
    """Get connector health summary for dashboard header indicator"""
    try:
        healthy = 0
        degraded = 0
        down = 0
        total = 0

        # Get health stats from GraphQL
        health_stats = fetch_tunnel_health_stats()

        # Count GRE tunnels
        gre_response = requests.get(
            f'{CF_API_BASE}/accounts/{ACCOUNT_ID}/magic/gre_tunnels',
            headers=HEADERS,
            timeout=10
        )
        if gre_response.status_code == 200:
            gre_tunnels = gre_response.json().get('result', [])
            for tunnel in gre_tunnels:
                total += 1
                tunnel_name = tunnel.get('name', '')
                stats = health_stats.get(tunnel_name, {})
                if stats:
                    status = stats.get('status', 'unknown')
                else:
                    status = 'healthy' if tunnel.get('health_check', {}).get('enabled') else 'unknown'

                if status == 'healthy':
                    healthy += 1
                elif status == 'degraded':
                    degraded += 1
                elif status == 'down':
                    down += 1

        # Count IPsec tunnels
        ipsec_response = requests.get(
            f'{CF_API_BASE}/accounts/{ACCOUNT_ID}/magic/ipsec_tunnels',
            headers=HEADERS,
            timeout=10
        )
        if ipsec_response.status_code == 200:
            ipsec_tunnels = ipsec_response.json().get('result', [])
            for tunnel in ipsec_tunnels:
                total += 1
                tunnel_name = tunnel.get('name', '')
                stats = health_stats.get(tunnel_name, {})
                if stats:
                    status = stats.get('status', 'unknown')
                else:
                    status = 'healthy' if tunnel.get('health_check', {}).get('enabled') else 'unknown'

                if status == 'healthy':
                    healthy += 1
                elif status == 'degraded':
                    degraded += 1
                elif status == 'down':
                    down += 1

        # Determine overall status
        if down > 0:
            overall_status = 'down'
        elif degraded > 0:
            overall_status = 'degraded'
        elif healthy > 0:
            overall_status = 'healthy'
        else:
            overall_status = 'unknown'

        return jsonify({
            'success': True,
            'overall_status': overall_status,
            'total': total,
            'healthy': healthy,
            'degraded': degraded,
            'down': down
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'overall_status': 'unknown',
            'error': str(e)
        }), 500


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8081, debug=False)
