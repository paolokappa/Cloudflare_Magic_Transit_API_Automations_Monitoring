#!/usr/bin/env python3
"""
Cloudflare Network Analytics Monitor
Monitors DDoS mitigation events from Network Analytics and sends Telegram notifications.

This script queries the GraphQL API for dropped traffic events that may not trigger
standard webhook notifications, ensuring all mitigation events are tracked.

Version: 1.4.1
Author: GOLINE SOC

Changelog:
  v1.4.1 (2026-02-06): Added Telegram retry mechanism (3 attempts with exponential backoff) - fixes missed notifications due to API timeouts
  v1.4.0 (2026-02-02): "My prefixes only" toggle now controls Telegram notifications - reads preference from dashboard_prefs.json
  v1.3.10 (2026-02-02): Added Cloudflare anycast prefixes (162.159.0.0/16, 172.64.0.0/13, 104.16.0.0/13) to show Magic Transit pass-through traffic
  v1.3.9 (2026-01-22): Changed "no events" log from DEBUG to INFO for better polling visibility
  v1.3.8 (2026-01-21): Enhanced startup message with BGP status, attack history, services health
  v1.3.7 (2026-01-21): European date format DD/MM/YYYY throughout, shutdown message with stats
  v1.3.6 (2026-01-21): Added source ASN/Country to GraphQL query and DB - sourceAsn, sourceAsnName, sourceCountry
  v1.3.5 (2026-01-21): Enhanced startup message - system info, BGP status, services health, last attack
  v1.3.4 (2026-01-21): Show GeoIP DB type and update date in startup message (log + Telegram)
  v1.3.3 (2026-01-21): Show GeoIP DB type (Commercial/Free) in Telegram notifications footer
  v1.3.2 (2026-01-21): GeoIP fallback - supports both commercial (GeoIP2) and free (GeoLite2) databases
  v1.3.1 (2026-01-19): GeoIP in aggregated notifications - top source IPs show country/ASN
  v1.3.0 (2026-01-19): GeoIP2 integration - source IP geolocation and ASN info
  v1.2.0 (2026-01-19): Enhanced notifications - spoofed IP detection, hide Unknown fields, edge locations
  v1.1.3 (2026-01-19): Added GOLINE prefix filter - only notify for traffic to 185.54.80.0/22
  v1.1.2 (2026-01-19): Increased lookback window to 15 minutes
  v1.1.1 (2026-01-19): Removed WatchdogSec (no sd_notify support)
  v1.0.0 (2026-01-19): Initial release
"""

import requests
import happy_eyeballs
import json
import sqlite3
import hashlib
import time
import sys
import os
import signal
import logging
import ipaddress
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# GeoIP2 for source IP enrichment
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# Global variables for shutdown handling
_config = None
_shutdown_requested = False

# ============================================================
# CONFIGURATION
# ============================================================

# Paths
PROJECT_DIR = Path("/root/Cloudflare_MT_Integration")
CONFIG_FILE = PROJECT_DIR / "config/settings.json"
DASHBOARD_PREFS_FILE = PROJECT_DIR / "config/dashboard_prefs.json"
DB_PATH = PROJECT_DIR / "db/magic_transit.db"
LOG_DIR = PROJECT_DIR / "logs"
LOG_FILE = LOG_DIR / "network-analytics-monitor.log"

# Polling interval (seconds)
POLL_INTERVAL = 300  # 5 minutes

# Lookback window for queries (minutes)
# Set to 15 to ensure coverage during service restarts (poll interval is 5 min)
LOOKBACK_MINUTES = 15

# Minimum packets to consider an event significant
MIN_PACKETS_THRESHOLD = 1

# Prefix filters for notifications
# MY_PREFIXES: Only user's own prefixes (when "My prefixes only" toggle is ON)
MY_PREFIXES = [
    ipaddress.ip_network('185.54.80.0/22'),   # All GOLINE IPv4 (80, 81, 82, 83)
    ipaddress.ip_network('2a02:4460::/32'),   # GOLINE IPv6
]

# ALL_PREFIXES: User's prefixes + Cloudflare anycast (when toggle is OFF)
ALL_PREFIXES = MY_PREFIXES + [
    ipaddress.ip_network('162.159.0.0/16'),   # Cloudflare anycast
    ipaddress.ip_network('172.64.0.0/13'),    # Cloudflare anycast
    ipaddress.ip_network('104.16.0.0/13'),    # Cloudflare anycast
]

def load_dashboard_prefs() -> dict:
    """Load dashboard preferences to check notification filter setting."""
    default_prefs = {"my_prefixes_only": True}
    try:
        if DASHBOARD_PREFS_FILE.exists():
            with open(DASHBOARD_PREFS_FILE, 'r') as f:
                prefs = json.load(f)
                return prefs
        return default_prefs
    except Exception:
        return default_prefs

def get_notification_prefixes() -> list:
    """Get the list of prefixes to notify for based on dashboard preference."""
    prefs = load_dashboard_prefs()
    # Check for the toggle setting (default: my prefixes only)
    if prefs.get('my_prefixes_only', True):
        return MY_PREFIXES
    return ALL_PREFIXES

def is_notifiable_ip(ip_str: str) -> bool:
    """Check if an IP address should trigger a notification based on current preference."""
    try:
        ip = ipaddress.ip_address(ip_str)
        prefixes = get_notification_prefixes()
        for prefix in prefixes:
            if ip in prefix:
                return True
        return False
    except ValueError:
        # Invalid IP address
        return False

# Legacy function for compatibility
def is_goline_ip(ip_str: str) -> bool:
    """Check if an IP address belongs to any monitored prefixes."""
    return is_notifiable_ip(ip_str)

# GeoIP2 database paths (commercial first, then free/lite fallback)
GEOIP_CITY_DB_PATHS = [
    "/usr/share/GeoIP/GeoIP2-City.mmdb",      # Commercial (more accurate)
    "/usr/share/GeoIP/GeoLite2-City.mmdb",    # Free (fallback)
    "/var/lib/GeoIP/GeoIP2-City.mmdb",        # Alternative location
    "/var/lib/GeoIP/GeoLite2-City.mmdb",      # Alternative location
]
GEOIP_ASN_DB_PATHS = [
    "/usr/share/GeoIP/GeoIP2-ASN.mmdb",       # Commercial
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",     # Free (fallback)
    "/var/lib/GeoIP/GeoIP2-ASN.mmdb",         # Alternative location
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",       # Alternative location
]

# Global GeoIP readers (initialized lazily)
_geoip_city_reader = None
_geoip_asn_reader = None
_geoip_db_type = None  # "Commercial" or "Free"
_geoip_city_db_path = None  # Path to the loaded City database


def get_geoip_readers():
    """Get or initialize GeoIP readers with fallback to free databases."""
    global _geoip_city_reader, _geoip_asn_reader, _geoip_db_type, _geoip_city_db_path

    if not GEOIP_AVAILABLE:
        return None, None

    if _geoip_city_reader is None:
        for db_path in GEOIP_CITY_DB_PATHS:
            if os.path.exists(db_path):
                try:
                    _geoip_city_reader = geoip2.database.Reader(db_path)
                    _geoip_city_db_path = db_path
                    # Determine if commercial or free based on filename
                    if "GeoIP2-" in db_path:
                        _geoip_db_type = "Commercial"
                    else:
                        _geoip_db_type = "Free"
                    logging.info(f"Loaded GeoIP City DB ({_geoip_db_type}): {db_path}")
                    break
                except Exception as e:
                    logging.warning(f"Failed to open {db_path}: {e}")
        if _geoip_city_reader is None:
            logging.warning("No GeoIP City database found")

    if _geoip_asn_reader is None:
        for db_path in GEOIP_ASN_DB_PATHS:
            if os.path.exists(db_path):
                try:
                    _geoip_asn_reader = geoip2.database.Reader(db_path)
                    logging.info(f"Loaded GeoIP ASN DB: {db_path}")
                    break
                except Exception as e:
                    logging.warning(f"Failed to open {db_path}: {e}")
        if _geoip_asn_reader is None:
            logging.warning("No GeoIP ASN database found")

    return _geoip_city_reader, _geoip_asn_reader


def get_geoip_db_type() -> str:
    """Return the type of GeoIP database in use (Commercial/Free)."""
    global _geoip_db_type
    if _geoip_db_type is None:
        get_geoip_readers()  # Initialize if not done yet
    return _geoip_db_type or "N/A"


def get_geoip_db_info() -> Dict:
    """Return full GeoIP database info including type and modification date."""
    global _geoip_db_type, _geoip_city_db_path

    # Initialize if not done yet
    if _geoip_db_type is None:
        get_geoip_readers()

    info = {
        'available': GEOIP_AVAILABLE and _geoip_city_db_path is not None,
        'type': _geoip_db_type or "N/A",
        'path': _geoip_city_db_path,
        'updated': None
    }

    # Get file modification date
    if _geoip_city_db_path and os.path.exists(_geoip_city_db_path):
        try:
            mtime = os.path.getmtime(_geoip_city_db_path)
            info['updated'] = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime('%Y-%m-%d')
        except Exception:
            pass

    return info


def get_geo_info(ip_str: str) -> Dict:
    """Get geolocation and ASN info for an IP address."""
    result = {
        'country': None,
        'country_code': None,
        'city': None,
        'asn': None,
        'asn_org': None,
        'is_private': False
    }

    # Check if private IP
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_reserved or ip.is_loopback:
            result['is_private'] = True
            return result
    except ValueError:
        return result

    city_reader, asn_reader = get_geoip_readers()

    # Get city/country info
    if city_reader:
        try:
            city = city_reader.city(ip_str)
            result['country'] = city.country.name
            result['country_code'] = city.country.iso_code
            result['city'] = city.city.name
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception:
            pass

    # Get ASN info
    if asn_reader:
        try:
            asn = asn_reader.asn(ip_str)
            result['asn'] = asn.autonomous_system_number
            result['asn_org'] = asn.autonomous_system_organization
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception:
            pass

    return result


# Create log directory if not exists
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


# ============================================================
# DATABASE FUNCTIONS
# ============================================================

def init_analytics_table():
    """Initialize the network_analytics_events table."""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_analytics_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_hash TEXT UNIQUE NOT NULL,
            attack_id TEXT,
            event_datetime DATETIME,
            attack_vector TEXT,
            rule_name TEXT,
            rule_id TEXT,
            source_ip TEXT,
            source_port INTEGER,
            destination_ip TEXT,
            destination_port INTEGER,
            protocol TEXT,
            tcp_flags TEXT,
            colo_code TEXT,
            colo_country TEXT,
            packets INTEGER,
            bits INTEGER,
            outcome TEXT,
            mitigation_reason TEXT,
            notified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            raw_data JSON
        )
    ''')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_analytics_attack_id ON network_analytics_events(attack_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_analytics_datetime ON network_analytics_events(event_datetime)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_analytics_source_ip ON network_analytics_events(source_ip)')

    conn.commit()
    conn.close()
    logger.info("Database table initialized")


def generate_event_hash(event: Dict) -> str:
    """Generate unique hash for an event to prevent duplicates."""
    dims = event.get('dimensions', {})
    key = f"{dims.get('datetime')}|{dims.get('attackId')}|{dims.get('ipSourceAddress')}|{dims.get('ipDestinationAddress')}|{dims.get('destinationPort')}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def is_event_already_notified(event_hash: str) -> bool:
    """Check if an event was already notified."""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM network_analytics_events WHERE event_hash = ?', (event_hash,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists


def save_event(event: Dict, event_hash: str):
    """Save an event to the database."""
    dims = event.get('dimensions', {})
    sums = event.get('sum', {})

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO network_analytics_events
            (event_hash, attack_id, event_datetime, attack_vector, rule_name, rule_id,
             source_ip, source_port, source_asn, source_asn_name, source_country,
             destination_ip, destination_port, protocol,
             tcp_flags, colo_code, colo_country, packets, bits, outcome, mitigation_reason, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event_hash,
            dims.get('attackId'),
            dims.get('datetime'),
            dims.get('attackVector'),
            dims.get('ruleName'),
            dims.get('ruleId'),
            dims.get('ipSourceAddress'),
            dims.get('sourcePort'),
            dims.get('sourceAsn'),
            dims.get('sourceAsnName'),
            dims.get('sourceCountry'),
            dims.get('ipDestinationAddress'),
            dims.get('destinationPort'),
            dims.get('ipProtocolName'),
            dims.get('tcpFlagsString'),
            dims.get('coloCode'),
            dims.get('coloCountry'),
            sums.get('packets'),
            sums.get('bits'),
            dims.get('outcome'),
            dims.get('mitigationReason'),
            json.dumps(event)
        ))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Already exists
    finally:
        conn.close()


def get_recent_stats() -> Dict:
    """Get statistics for attacks and mitigations."""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    # Real attacks (webhook START events)
    cursor.execute('''
        SELECT COUNT(*) FROM attack_events WHERE event_type = 'START'
    ''')
    attacks_total = cursor.fetchone()[0]

    # Attacks this month
    cursor.execute('''
        SELECT COUNT(*) FROM attack_events
        WHERE event_type = 'START'
        AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
    ''')
    attacks_month = cursor.fetchone()[0]

    # Mitigations (Network Analytics dropped events) - total
    cursor.execute('SELECT COUNT(*) FROM network_analytics_events')
    mitigations_total = cursor.fetchone()[0]

    conn.close()

    return {
        'attacks_total': attacks_total,
        'attacks_month': attacks_month,
        'mitigations_total': mitigations_total
    }


def get_system_info() -> Dict:
    """Get system information for startup message."""
    info = {
        'hostname': socket.gethostname(),
        'uptime': 'N/A',
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    }

    # Get uptime
    try:
        result = subprocess.run(['uptime', '-p'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            info['uptime'] = result.stdout.strip().replace('up ', '')
    except Exception:
        pass

    return info


def get_bgp_status(config: Dict) -> Dict:
    """Get BGP prefix advertisement status."""
    status = {'advertised': 0, 'total': 0}

    try:
        account_id = config['cloudflare']['account_id']
        api_token = config['cloudflare']['api_token']

        response = requests.get(
            f"https://api.cloudflare.com/client/v4/accounts/{account_id}/addressing/prefixes",
            headers={'Authorization': f'Bearer {api_token}'},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            prefixes = data.get('result', [])
            status['total'] = len(prefixes)
            status['advertised'] = sum(1 for p in prefixes if p.get('advertised', False))
    except Exception as e:
        logging.warning(f"Failed to get BGP status: {e}")

    return status


def get_last_attack() -> Optional[Dict]:
    """Get the last attack event with details."""
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()

        # Get last webhook attack (real attack notification)
        cursor.execute('''
            SELECT created_at, attack_vector, target_ip, megabits_per_second
            FROM attack_events
            WHERE event_type = 'START'
            ORDER BY id DESC LIMIT 1
        ''')
        result = cursor.fetchone()
        conn.close()

        if result:
            # Convert from YYYY-MM-DD HH:MM to DD/MM/YYYY HH:MM (European format)
            raw_dt = result[0][:16].replace('T', ' ')  # "2026-01-19 21:51"
            parts = raw_dt.split(' ')
            date_parts = parts[0].split('-')  # ['2026', '01', '19']
            eu_date = f"{date_parts[2]}/{date_parts[1]}/{date_parts[0]} {parts[1]}"  # "19/01/2026 21:51"
            vector = result[1] or 'Unknown'
            target = result[2] or ''
            mbps = result[3] or '0'
            return {
                'datetime': eu_date,
                'vector': vector,
                'target': target.split('/')[0] if '/' in target else target,  # Remove CIDR
                'gbps': f"{float(mbps)/1000:.1f}" if mbps.isdigit() else mbps
            }
    except Exception:
        pass

    return None


def get_services_status() -> Dict:
    """Get status of related Cloudflare services."""
    services = {
        'webhook': '❓',
        'autowithdraw': '❓',
        'dashboard': '❓'
    }

    service_map = {
        'webhook': 'cloudflare-webhook',
        'autowithdraw': 'cloudflare-autowithdraw',
        'dashboard': 'cloudflare-dashboard'
    }

    for key, service_name in service_map.items():
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', service_name],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip() == 'active':
                services[key] = '✅'
            else:
                services[key] = '❌'
        except Exception:
            services[key] = '❓'

    return services


# ============================================================
# API FUNCTIONS
# ============================================================

def load_config() -> Dict:
    """Load configuration from settings.json."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        sys.exit(1)


def query_network_analytics(config: Dict, lookback_minutes: int = LOOKBACK_MINUTES) -> List[Dict]:
    """
    Query dosdNetworkAnalyticsAdaptiveGroups for dropped traffic events.
    """
    account_id = config['cloudflare']['account_id']
    api_token = config['cloudflare']['api_token']

    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json'
    }

    now = datetime.now(timezone.utc)
    start_time = (now - timedelta(minutes=lookback_minutes)).strftime('%Y-%m-%dT%H:%M:%SZ')
    end_time = now.strftime('%Y-%m-%dT%H:%M:%SZ')

    query = """
    query GetDroppedTraffic($accountTag: String!, $datetimeStart: Time!, $datetimeEnd: Time!) {
        viewer {
            accounts(filter: { accountTag: $accountTag }) {
                dosdNetworkAnalyticsAdaptiveGroups(
                    filter: {
                        datetime_gt: $datetimeStart
                        datetime_lt: $datetimeEnd
                        outcome: "drop"
                    }
                    limit: 100
                    orderBy: [datetime_DESC]
                ) {
                    dimensions {
                        datetime
                        attackId
                        attackVector
                        ruleName
                        ruleId
                        mitigationReason
                        outcome
                        verdict
                        ipSourceAddress
                        sourcePort
                        sourceAsn
                        sourceAsnName
                        sourceCountry
                        ipDestinationAddress
                        destinationPort
                        ipProtocolName
                        tcpFlagsString
                        coloCode
                        coloCountry
                        coloCity
                    }
                    sum {
                        packets
                        bits
                    }
                }
            }
        }
    }
    """

    variables = {
        'accountTag': account_id,
        'datetimeStart': start_time,
        'datetimeEnd': end_time
    }

    try:
        response = requests.post(
            'https://api.cloudflare.com/client/v4/graphql',
            headers=headers,
            json={'query': query, 'variables': variables},
            timeout=30
        )

        if response.status_code == 200:
            data = response.json()
            if data.get('errors'):
                logger.error(f"GraphQL errors: {data['errors']}")
                return []

            accounts = data.get('data', {}).get('viewer', {}).get('accounts', [])
            if accounts:
                events = accounts[0].get('dosdNetworkAnalyticsAdaptiveGroups', [])
                logger.debug(f"Retrieved {len(events)} events from API")
                return events
        else:
            logger.error(f"API error: HTTP {response.status_code}")

    except Exception as e:
        logger.error(f"API query failed: {e}")

    return []


# ============================================================
# TELEGRAM FUNCTIONS
# ============================================================

def send_telegram_notification(config: Dict, message: str, max_retries: int = 3) -> bool:
    """Send a Telegram notification with retry mechanism."""
    bot_token = config['telegram']['bot_token']
    chat_id = config['telegram']['chat_id']

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True
    }

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(url, json=payload, timeout=30)

            if response.status_code == 200:
                if attempt > 1:
                    logger.info(f"Telegram notification sent (attempt {attempt}/{max_retries})")
                else:
                    logger.debug("Telegram notification sent")
                return True
            else:
                logger.warning(f"Telegram error: {response.status_code} (attempt {attempt}/{max_retries})")

        except Exception as e:
            logger.error(f"Telegram send failed: {e} (attempt {attempt}/{max_retries})")

        # Wait before retry (exponential backoff: 5s, 10s, 20s)
        if attempt < max_retries:
            wait_time = 5 * (2 ** (attempt - 1))
            logger.info(f"Retrying Telegram in {wait_time}s...")
            time.sleep(wait_time)

    logger.error(f"Telegram notification failed after {max_retries} attempts")
    return False


def is_spoofed_ip(ip_str: str) -> bool:
    """Check if an IP address is likely spoofed (private/reserved ranges)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_reserved or ip.is_loopback
    except ValueError:
        return False


def format_source_ip(ip_str: str, port: int) -> str:
    """Format source IP with spoofing indicator."""
    if is_spoofed_ip(ip_str):
        return f"`{ip_str}:{port}` ⚠️ SPOOFED"
    return f"`{ip_str}:{port}`"


def format_event_notification(event: Dict) -> str:
    """Format an event for Telegram notification."""
    dims = event.get('dimensions', {})
    sums = event.get('sum', {})

    # Parse timestamp
    event_time = dims.get('datetime', 'Unknown')
    try:
        dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
        formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        formatted_time = event_time

    # Format bits
    bits = sums.get('bits', 0)
    if bits >= 1000000000:
        bits_str = f"{bits / 1000000000:.2f} Gbps"
    elif bits >= 1000000:
        bits_str = f"{bits / 1000000:.2f} Mbps"
    elif bits >= 1000:
        bits_str = f"{bits / 1000:.2f} Kbps"
    else:
        bits_str = f"{bits} bps"

    # Get values with smart defaults
    attack_vector = dims.get('attackVector', '')
    rule_name = dims.get('ruleName', '')
    rule_id = dims.get('ruleId', '')
    source_ip = dims.get('ipSourceAddress', 'N/A')
    source_port = dims.get('sourcePort', 'N/A')

    # Build attack info section - hide Unknown fields
    attack_info_lines = []
    if attack_vector and attack_vector != 'Unknown':
        attack_info_lines.append(f"💥 *Vector:* {attack_vector}")
    if rule_name and rule_name != 'Unknown':
        attack_info_lines.append(f"📋 *Rule:* {rule_name}")
    elif rule_id:
        # Show rule ID if name is unknown but ID exists
        attack_info_lines.append(f"📋 *Rule ID:* `{rule_id[:12]}...`")
    attack_info_lines.append(f"🛡️ *Action:* {dims.get('mitigationReason', 'BLOCKED')}")

    # If no vector/rule info, add a note
    if not attack_vector or attack_vector == 'Unknown':
        attack_info_lines.insert(0, "💥 *Vector:* Generic DDoS")

    attack_info = "\n".join(attack_info_lines)

    # Format source with spoofing detection
    source_formatted = format_source_ip(source_ip, source_port)

    # Get GeoIP info for source IP
    geo = get_geo_info(source_ip)

    # Build source info section
    if geo['is_private']:
        source_geo = "⚠️ *Spoofed IP* (private range)"
    elif geo['country']:
        city_str = f"{geo['city']}, " if geo['city'] else ""
        source_geo = f"🌍 *Origin:* {city_str}{geo['country']} ({geo['country_code']})"
        if geo['asn']:
            source_geo += f"\n🏢 *ASN:* AS{geo['asn']} - {geo['asn_org']}"
    else:
        source_geo = "🌍 *Origin:* Unknown"

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

🚨 *MITIGATION EVENT*

⏱️ *Time:* `{formatted_time}`
🆔 *Attack ID:* `{dims.get('attackId', 'N/A')}`

⚔️ *ATTACK INFO*
{attack_info}

🌐 *NETWORK*
📤 *Source:* {source_formatted}
{source_geo}
📥 *Target:* `{dims.get('ipDestinationAddress', 'N/A')}:{dims.get('destinationPort', 'N/A')}`
🔧 *Protocol:* {dims.get('ipProtocolName', 'N/A')}
🏷️ *TCP Flags:* {dims.get('tcpFlagsString', 'N/A')}

📊 *METRICS*
📦 *Packets:* {sums.get('packets', 0):,}
📈 *Data:* {bits_str}

📍 *CLOUDFLARE EDGE*
🌍 *Scrubbed at:* {dims.get('coloCity', 'N/A')}, {dims.get('coloCountry', 'N/A')} ({dims.get('coloCode', 'N/A')})

🏢 *GOLINE SOC* | _Network Analytics Monitor_ | _GeoIP: {get_geoip_db_type()}_"""

    return message


def format_aggregated_notification(events: List[Dict]) -> str:
    """Format multiple events into a single aggregated notification."""
    if len(events) == 1:
        return format_event_notification(events[0])

    # Aggregate stats
    total_packets = sum(e.get('sum', {}).get('packets', 0) for e in events)
    total_bits = sum(e.get('sum', {}).get('bits', 0) for e in events)

    # Get unique attack IDs
    attack_ids = set()
    vectors = set()
    source_ips = set()
    spoofed_ips = set()
    edge_locations = set()

    for e in events:
        dims = e.get('dimensions', {})
        if dims.get('attackId'):
            attack_ids.add(dims['attackId'])
        if dims.get('attackVector') and dims.get('attackVector') != 'Unknown':
            vectors.add(dims['attackVector'])
        if dims.get('ipSourceAddress'):
            ip = dims['ipSourceAddress']
            source_ips.add(ip)
            if is_spoofed_ip(ip):
                spoofed_ips.add(ip)
        # Collect edge locations
        colo = dims.get('coloCode', '')
        country = dims.get('coloCountry', '')
        if colo and country:
            edge_locations.add(f"{colo} ({country})")

    # Format time range
    times = [e.get('dimensions', {}).get('datetime', '') for e in events]
    times = [t for t in times if t]
    if times:
        first_time = min(times)
        last_time = max(times)
    else:
        first_time = last_time = 'Unknown'

    # Format bits
    if total_bits >= 1000000000:
        bits_str = f"{total_bits / 1000000000:.2f} Gb"
    elif total_bits >= 1000000:
        bits_str = f"{total_bits / 1000000:.2f} Mb"
    elif total_bits >= 1000:
        bits_str = f"{total_bits / 1000:.2f} Kb"
    else:
        bits_str = f"{total_bits} b"

    # Build vectors list (or show Generic if all Unknown)
    if vectors:
        vectors_str = chr(10).join(f'• {v}' for v in sorted(vectors))
    else:
        vectors_str = "• Generic DDoS"

    # Build source IPs list with GeoIP info
    source_lines = []
    for ip in sorted(source_ips)[:5]:
        if ip in spoofed_ips:
            source_lines.append(f"• `{ip}` ⚠️ _Spoofed_")
        else:
            geo = get_geo_info(ip)
            if geo['country_code']:
                asn_str = f" (AS{geo['asn']})" if geo['asn'] else ""
                source_lines.append(f"• `{ip}` 🌍 {geo['country_code']}{asn_str}")
            else:
                source_lines.append(f"• `{ip}`")
    source_ips_str = chr(10).join(source_lines)

    # Spoofed count warning
    spoofed_warning = ""
    if spoofed_ips:
        spoofed_warning = f"\n⚠️ *Spoofed IPs:* {len(spoofed_ips)}/{len(source_ips)}"

    # Edge locations (top 5)
    edge_str = ", ".join(sorted(edge_locations)[:5]) if edge_locations else "N/A"

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

🚨 *BULK MITIGATION EVENTS*

📊 *SUMMARY*
📦 *Events:* {len(events)}
🆔 *Attack IDs:* {len(attack_ids)}
📍 *Unique Sources:* {len(source_ips)}{spoofed_warning}

⏱️ *TIME RANGE*
🕐 *From:* `{first_time}`
🕑 *To:* `{last_time}`

⚔️ *ATTACK VECTORS*
{vectors_str}

📊 *TOTAL METRICS*
📦 *Packets Dropped:* {total_packets:,}
📈 *Data Blocked:* {bits_str}

📤 *TOP SOURCE IPs*
{source_ips_str}

🌍 *EDGE LOCATIONS*
{edge_str}

🏢 *GOLINE SOC* | _Network Analytics Monitor_ | _GeoIP: {get_geoip_db_type()}_"""

    return message


# ============================================================
# MAIN MONITOR LOOP
# ============================================================

def process_events(config: Dict, events: List[Dict]) -> int:
    """Process events and send notifications for new ones."""
    new_events = []
    filtered_count = 0

    for event in events:
        # Filter by minimum packets
        packets = event.get('sum', {}).get('packets', 0)
        if packets < MIN_PACKETS_THRESHOLD:
            continue

        # Filter by GOLINE prefixes - only notify for traffic to our IPs
        dest_ip = event.get('dimensions', {}).get('ipDestinationAddress', '')
        if not is_goline_ip(dest_ip):
            filtered_count += 1
            logger.debug(f"Filtered non-GOLINE event: {dest_ip}")
            continue

        event_hash = generate_event_hash(event)

        if not is_event_already_notified(event_hash):
            save_event(event, event_hash)
            new_events.append(event)

    if filtered_count > 0:
        logger.debug(f"Filtered {filtered_count} events (non-GOLINE destinations)")

    if not new_events:
        return 0

    logger.info(f"Found {len(new_events)} new GOLINE mitigation events")

    # Aggregate events by attack ID for notification
    events_by_attack = {}
    for event in new_events:
        attack_id = event.get('dimensions', {}).get('attackId', 'unknown')
        if attack_id not in events_by_attack:
            events_by_attack[attack_id] = []
        events_by_attack[attack_id].append(event)

    # Send notifications
    for attack_id, attack_events in events_by_attack.items():
        if len(attack_events) <= 3:
            # Send individual notifications
            for event in attack_events:
                message = format_event_notification(event)
                send_telegram_notification(config, message)
                time.sleep(0.5)  # Rate limiting
        else:
            # Send aggregated notification
            message = format_aggregated_notification(attack_events)
            send_telegram_notification(config, message)

    return len(new_events)


def send_shutdown_notification(signum=None, frame=None):
    """Send shutdown notification via Telegram."""
    global _config, _shutdown_requested

    if _shutdown_requested:
        return  # Already shutting down

    _shutdown_requested = True
    logger.info("Shutdown signal received, sending notification...")

    if _config:
        stats = get_recent_stats()
        now = datetime.now(timezone.utc)
        eu_datetime = now.strftime('%d/%m/%Y %H:%M:%S UTC')
        shutdown_msg = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

⏹️ *Network Analytics Monitor STOPPED*

📈 *Stats*
🎯 Attacks: {stats['attacks_total']} total ({stats['attacks_month']} this month)
📊 Mitigations: {stats['mitigations_total']:,} events

⏰ *Stopped at:* {eu_datetime}

🏢 *GOLINE SOC* | _Network Analytics_"""
        send_telegram_notification(_config, shutdown_msg)

    logger.info("Monitor stopped")
    sys.exit(0)


def run_monitor(single_run: bool = False):
    """Run the monitoring loop."""
    global _config

    logger.info("=" * 60)
    logger.info("CLOUDFLARE NETWORK ANALYTICS MONITOR")
    logger.info("=" * 60)

    # Initialize
    init_analytics_table()
    config = load_config()
    _config = config  # Store for shutdown handler

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, send_shutdown_notification)
    signal.signal(signal.SIGINT, send_shutdown_notification)

    logger.info(f"Account ID: {config['cloudflare']['account_id']}")
    logger.info(f"Poll interval: {POLL_INTERVAL} seconds")
    logger.info(f"Lookback window: {LOOKBACK_MINUTES} minutes")

    # Initialize and log GeoIP info
    geoip_info = get_geoip_db_info()
    if geoip_info['available']:
        logger.info(f"GeoIP Database: {geoip_info['type']} (updated: {geoip_info['updated']})")
    else:
        logger.info("GeoIP Database: Not available")
    logger.info("=" * 60)

    # Send startup notification
    if not single_run:
        # Gather all startup info
        stats = get_recent_stats()
        bgp_status = get_bgp_status(config)
        last_attack = get_last_attack()
        services = get_services_status()

        # Build GeoIP status line
        if geoip_info['available']:
            geoip_line = f"🌍 GeoIP: {geoip_info['type']} (updated: {geoip_info['updated']})"
        else:
            geoip_line = "🌍 GeoIP: Not available"

        # Build last attack lines with details (2 lines)
        if last_attack:
            last_attack_line = f"🚨 Last: `{last_attack['datetime']}`\n💥 Type: {last_attack['vector']}, {last_attack['gbps']} Gbps → {last_attack['target']}"
        else:
            last_attack_line = "🚨 Last: No attacks recorded"

        # Build BGP status line with color indicator
        if bgp_status['advertised'] > 0:
            bgp_line = f"📡 Prefixes: {bgp_status['advertised']}/{bgp_status['total']} ⚠️ ADVERTISED"
        else:
            bgp_line = f"📡 Prefixes: {bgp_status['advertised']}/{bgp_status['total']} ✅ All withdrawn"

        startup_msg = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

🚀 *Network Analytics Monitor STARTED*

📊 *Configuration*
📌 Version: 1.3.10
⏰ Poll: {POLL_INTERVAL}s | Lookback: {LOOKBACK_MINUTES} min
{geoip_line}

🌐 *BGP Status*
{bgp_line}

📈 *Attack History*
🎯 Attacks: {stats['attacks_total']} total ({stats['attacks_month']} this month)
📊 Mitigations: {stats['mitigations_total']:,} events logged
{last_attack_line}

⚙️ *Services*
{services['webhook']} Webhook | {services['autowithdraw']} Autowithdraw | {services['dashboard']} Dashboard

_Monitoring for DDoS mitigation events..._"""
        send_telegram_notification(config, startup_msg)

    while True:
        try:
            # Query API
            events = query_network_analytics(config, LOOKBACK_MINUTES)

            if events:
                new_count = process_events(config, events)
                if new_count > 0:
                    logger.info(f"Processed {new_count} new events")
            else:
                logger.info("Poll completed - no new events")

            if single_run:
                break

            # Wait for next poll
            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            # This is handled by signal handler, but keep as backup
            send_shutdown_notification()
            break
        except Exception as e:
            logger.error(f"Monitor error: {e}")
            if single_run:
                break
            time.sleep(60)  # Wait 1 minute on error


def main():
    """Main entry point."""
    global LOOKBACK_MINUTES
    import argparse

    parser = argparse.ArgumentParser(description='Cloudflare Network Analytics Monitor')
    parser.add_argument('--once', '-1', action='store_true', help='Run once and exit')
    parser.add_argument('--test', '-t', action='store_true', help='Test query and print results')
    parser.add_argument('--lookback', '-l', type=int, default=LOOKBACK_MINUTES, help='Lookback window in minutes')
    args = parser.parse_args()

    LOOKBACK_MINUTES = args.lookback

    if args.test:
        # Test mode - just query and print
        print(f"Testing query (lookback: {LOOKBACK_MINUTES} minutes)...")
        init_analytics_table()
        config = load_config()
        events = query_network_analytics(config, LOOKBACK_MINUTES)

        print(f"\nFound {len(events)} events:")
        for i, event in enumerate(events):
            dims = event.get('dimensions', {})
            sums = event.get('sum', {})
            print(f"\n[{i+1}] {dims.get('datetime')}")
            print(f"    Attack: {dims.get('attackVector')} | ID: {dims.get('attackId')}")
            print(f"    Src: {dims.get('ipSourceAddress')}:{dims.get('sourcePort')}")
            print(f"    Dst: {dims.get('ipDestinationAddress')}:{dims.get('destinationPort')}")
            print(f"    Colo: {dims.get('coloCode')} ({dims.get('coloCountry')})")
            print(f"    Dropped: {sums.get('packets')} pkts, {sums.get('bits')} bits")
    else:
        run_monitor(single_run=args.once)


if __name__ == "__main__":
    main()
