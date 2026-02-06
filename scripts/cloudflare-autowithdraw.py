#!/usr/bin/env python3
"""
Cloudflare Magic Transit - Auto Withdraw Manager v3.5
GOLINE SA - SOC Tools

Automatically withdraws prefixes after DDoS attacks end.
Uses Cloudflare GraphQL Analytics API to detect active attacks.

Run as a daemon: python3 cloudflare-autowithdraw.py daemon

Changelog:
  v3.5 (2026-02-06): Added Telegram retry mechanism (3 attempts with exponential backoff).
                     Fixes missed notifications due to Telegram API timeouts.
  v3.4 (2026-01-23): Peak Attack Statistics in Withdraw Notifications.
  v3.3 (2026-01-21): Fixed API endpoint for detecting advertised prefixes.
                     Now uses /bgp/prefixes/{bgp_prefix_id} with on_demand.advertised
                     instead of /bgp/status which always returned False.
  v3.2 (2026-01-21): Added prefix_calm_status table for dashboard integration.
  v3.1 (2026-01-19): Changed threshold logic from OR to AND.
  v3.0 (2026-01-19): Major refactoring with database logging.
"""

import requests
import json
import time
import sys
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta, timezone

# ============================================
# CONFIGURATION
# ============================================

ACCOUNT_ID = "YOUR_CLOUDFLARE_ACCOUNT_ID"
AUTH_EMAIL = "YOUR_EMAIL"
AUTH_KEY = "YOUR_CLOUDFLARE_API_KEY"

# Telegram notifications
TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"

# Auto-withdraw settings
CALM_PERIOD_MINUTES = 15      # Minutes without attacks before auto-withdraw
CHECK_INTERVAL_SECONDS = 60   # How often to check (seconds)
ATTACK_LOOKBACK_MINUTES = 5   # Look for attacks in last N minutes

# Thresholds for "attack in progress"
# Note: flowtrackd (Advanced TCP Protection) may drop some packets during normal operation
# Adjust these based on your baseline traffic patterns
MIN_DROPPED_PACKETS = 5000    # Minimum dropped packets to consider as attack
MIN_DROPPED_BITS = 10000000   # Minimum dropped bits (10 Mbps) to consider as attack

# API endpoints
API_BASE = "https://api.cloudflare.com/client/v4"
PREFIXES_URL = f"{API_BASE}/accounts/{ACCOUNT_ID}/addressing/prefixes"
GRAPHQL_URL = f"{API_BASE}/graphql"

HEADERS = {
    "X-Auth-Email": AUTH_EMAIL,
    "X-Auth-Key": AUTH_KEY,
    "Content-Type": "application/json"
}

# GOLINE Prefixes for filtering
GOLINE_PREFIXES = [
    "185.54.80.0/24",
    "185.54.81.0/24",
    "185.54.82.0/24",
    "185.54.83.0/24",
    "2a02:4460:1::/48"  # IPv6 DMZv6
]

# Track when each prefix became "calm" (no attacks)
calm_since = {}

# Track peak attack statistics for each prefix (to show in withdraw notification)
# Format: {cidr: {'dropped_packets': int, 'dropped_mbps': float, 'mitigation_systems': [], 'peak_time': datetime}}
attack_peak_stats = {}

# Database path for logging withdrawals
DB_PATH = Path("/root/Cloudflare_MT_Integration/db/magic_transit.db")

# Status file for dashboard integration
STATUS_FILE = Path("/root/Cloudflare_MT_Integration/db/autowithdraw_status.json")

# Prefix mapping file (contains prefix_id and bgp_prefix_id for each CIDR)
PREFIX_MAPPING_FILE = Path("/root/Cloudflare_MT_Integration/config/prefix_mapping.json")

def load_prefix_mapping():
    """Load prefix mapping from JSON file"""
    try:
        with open(PREFIX_MAPPING_FILE, 'r') as f:
            data = json.load(f)
            return data.get('prefixes', {})
    except Exception as e:
        log_error(f"Failed to load prefix mapping: {e}")
        return {}

# ============================================
# LOGGING
# ============================================

def log(message, level="INFO"):
    """Print timestamped log message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def log_error(message):
    log(message, "ERROR")

def log_warn(message):
    log(message, "WARN")

def log_debug(message):
    log(message, "DEBUG")

# ============================================
# DATABASE LOGGING
# ============================================

def log_withdraw_to_db(prefix, description, calm_minutes, details):
    """
    Log a successful withdrawal to the shared database.
    Records in both attack_events and withdrawal_history tables.
    """
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()

        now = datetime.now(timezone.utc)
        now_str = now.strftime('%Y-%m-%d %H:%M:%S')

        # Log to attack_events table
        cursor.execute('''
            INSERT INTO attack_events
            (event_type, alert_type, prefix, action_taken, raw_payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            'WITHDRAW',
            'autowithdraw_daemon',
            prefix,
            'withdrawn_auto',
            json.dumps({
                'description': description,
                'calm_minutes': calm_minutes,
                'dropped_packets': details.get('dropped_packets', 0),
                'dropped_mbps': details.get('dropped_mbps', 0),
                'mitigation_systems': details.get('mitigation_systems', [])
            }),
            now_str
        ))

        # Log to withdrawal_history table
        cursor.execute('''
            INSERT INTO withdrawal_history
            (prefix, withdrawn_at, protection_duration_seconds, withdraw_method, status, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            prefix,
            now_str,
            int(calm_minutes * 60),  # Convert to seconds
            'autowithdraw_daemon',
            'success',
            f"Auto-withdrawn after {calm_minutes:.1f} min calm. Dropped: {details.get('dropped_packets', 0)} pkts, {details.get('dropped_mbps', 0)} Mbps"
        ))

        conn.commit()
        conn.close()
        log(f"  📝 Withdraw logged to database for {prefix}")
        return True

    except Exception as e:
        log_error(f"Failed to log withdraw to database: {e}")
        return False

def update_prefix_calm_status(prefix_data):
    """
    Update the prefix_calm_status table with current state.
    Called after each check cycle to share state with dashboard.

    prefix_data: list of dicts with keys:
        - prefix: CIDR notation
        - advertised: bool
        - under_attack: bool
        - calm_since: datetime or None
        - dropped_packets: int
        - dropped_mbps: float
        - mitigation_systems: list
    """
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

        for p in prefix_data:
            calm_since_str = None
            if p.get('calm_since'):
                calm_since_str = p['calm_since'].strftime('%Y-%m-%d %H:%M:%S')

            systems_str = ','.join(p.get('mitigation_systems', [])) if p.get('mitigation_systems') else ''

            cursor.execute('''
                INSERT INTO prefix_calm_status
                (prefix, advertised, under_attack, calm_since, last_attack_packets, last_attack_mbps, mitigation_systems, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(prefix) DO UPDATE SET
                    advertised = excluded.advertised,
                    under_attack = excluded.under_attack,
                    calm_since = excluded.calm_since,
                    last_attack_packets = excluded.last_attack_packets,
                    last_attack_mbps = excluded.last_attack_mbps,
                    mitigation_systems = excluded.mitigation_systems,
                    updated_at = excluded.updated_at
            ''', (
                p['prefix'],
                1 if p.get('advertised') else 0,
                1 if p.get('under_attack') else 0,
                calm_since_str,
                p.get('dropped_packets', 0),
                p.get('dropped_mbps', 0),
                systems_str,
                now_str
            ))

        conn.commit()
        conn.close()
        log_debug(f"Updated prefix_calm_status for {len(prefix_data)} prefixes")
        return True
    except Exception as e:
        log_error(f"Failed to update prefix_calm_status: {e}")
        return False

# ============================================
# TELEGRAM NOTIFICATIONS
# ============================================

def send_telegram(message, max_retries=3):
    """Send Telegram notification with retry mechanism"""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(url, json=data, timeout=30)
            if response.ok:
                if attempt > 1:
                    log(f"  ✅ Telegram notification sent (attempt {attempt}/{max_retries})")
                return True
            else:
                log_error(f"Telegram API error: {response.status_code} (attempt {attempt}/{max_retries})")
        except Exception as e:
            log_error(f"Telegram error: {e} (attempt {attempt}/{max_retries})")

        # Wait before retry (exponential backoff: 5s, 10s, 20s)
        if attempt < max_retries:
            wait_time = 5 * (2 ** (attempt - 1))
            log(f"  ⏳ Retrying Telegram in {wait_time}s...")
            time.sleep(wait_time)

    log_error(f"❌ Telegram notification failed after {max_retries} attempts")
    return False

# ============================================
# CLOUDFLARE API FUNCTIONS
# ============================================

def api_get(url):
    """GET request to Cloudflare API"""
    try:
        response = requests.get(url, headers=HEADERS, timeout=30)
        return response.json()
    except Exception as e:
        log_error(f"API GET error: {e}")
        return {"success": False, "errors": [{"message": str(e)}]}

def api_patch(url, data):
    """PATCH request to Cloudflare API"""
    try:
        response = requests.patch(url, headers=HEADERS, json=data, timeout=30)
        return response.json()
    except Exception as e:
        log_error(f"API PATCH error: {e}")
        return {"success": False, "errors": [{"message": str(e)}]}

def graphql_query(query, variables=None):
    """Execute GraphQL query against Cloudflare Analytics API"""
    try:
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        
        response = requests.post(GRAPHQL_URL, headers=HEADERS, json=payload, timeout=30)
        result = response.json()
        
        if "errors" in result and result["errors"]:
            log_error(f"GraphQL errors: {result['errors']}")
            return None
        
        return result.get("data")
    except Exception as e:
        log_error(f"GraphQL error: {e}")
        return None

# ============================================
# ATTACK DETECTION VIA GRAPHQL
# ============================================

def get_mitigated_traffic_all(minutes=ATTACK_LOOKBACK_MINUTES):
    """
    Get mitigated (dropped) traffic statistics for all prefixes.
    Uses magicTransitNetworkAnalyticsAdaptiveGroups with outcome=drop.
    Groups by ipDestinationSubnet to see per-prefix stats.
    """
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(minutes=minutes)
    
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    query = """
    query GetMitigatedTraffic($accountTag: string!, $start: Time!, $end: Time!) {
        viewer {
            accounts(filter: {accountTag: $accountTag}) {
                magicTransitNetworkAnalyticsAdaptiveGroups(
                    filter: {
                        datetime_geq: $start,
                        datetime_leq: $end,
                        outcome: "drop"
                    },
                    limit: 100,
                    orderBy: [sum_packets_DESC]
                ) {
                    sum {
                        packets
                        bits
                    }
                    dimensions {
                        ipDestinationSubnet
                        mitigationSystem
                    }
                }
            }
        }
    }
    """
    
    variables = {
        "accountTag": ACCOUNT_ID,
        "start": start_str,
        "end": end_str
    }
    
    data = graphql_query(query, variables)
    
    if not data:
        return {}
    
    try:
        groups = data["viewer"]["accounts"][0]["magicTransitNetworkAnalyticsAdaptiveGroups"]
        
        # Aggregate by destination subnet
        result = {}
        for group in groups or []:
            subnet = group.get("dimensions", {}).get("ipDestinationSubnet", "unknown")
            if subnet not in result:
                result[subnet] = {"packets": 0, "bits": 0, "systems": set()}
            
            result[subnet]["packets"] += group.get("sum", {}).get("packets", 0) or 0
            result[subnet]["bits"] += group.get("sum", {}).get("bits", 0) or 0
            
            system = group.get("dimensions", {}).get("mitigationSystem", "")
            if system:
                result[subnet]["systems"].add(system)
        
        # Convert sets to lists for JSON serialization
        for subnet in result:
            result[subnet]["systems"] = list(result[subnet]["systems"])
        
        return result
    except (KeyError, IndexError, TypeError) as e:
        log_debug(f"No mitigated traffic data: {e}")
        return {}

def get_active_attacks_all(minutes=ATTACK_LOOKBACK_MINUTES):
    """
    Get active DDoS attacks.
    
    Note: dosdAttackAnalyticsGroups has a different schema that varies by account.
    We rely primarily on magicTransitNetworkAnalyticsAdaptiveGroups (mitigated traffic)
    which is more reliable for detecting active attacks.
    
    Returns empty list - attack detection is handled by mitigated traffic query.
    """
    # Disabled - the mitigated traffic query is sufficient for attack detection
    return []

def prefix_to_subnet(prefix):
    """
    Convert prefix notation to subnet format used by Cloudflare.
    185.54.81.0/24 -> 185.54.81.0/24 (same for /24)
    """
    return prefix

def is_under_attack(prefix):
    """
    Determine if a prefix is currently under attack.
    
    Checks:
    1. Dropped traffic from mitigated traffic query
    2. Uses subnet matching to find relevant traffic
    
    Returns: (bool, dict) - (is_under_attack, details)
    """
    details = {
        "active_attacks": 0,
        "attack_types": [],
        "dropped_packets": 0,
        "dropped_bits": 0,
        "dropped_mbps": 0,
        "mitigation_systems": []
    }
    
    # Get all mitigated traffic
    mitigated = get_mitigated_traffic_all(ATTACK_LOOKBACK_MINUTES)

    # Detect if this is an IPv6 prefix
    is_ipv6 = ":" in prefix

    if is_ipv6:
        # IPv6 handling - e.g., "2a02:4460:1::/48"
        prefix_base = prefix.split("/")[0]  # e.g., "2a02:4460:1::"
        # Remove trailing colons for matching
        prefix_match = prefix_base.rstrip(":")  # e.g., "2a02:4460:1"

        for subnet, data in mitigated.items():
            # Check if this subnet matches our IPv6 prefix
            if prefix in subnet or prefix_base in subnet or prefix_match in subnet:
                details["dropped_packets"] += data["packets"]
                details["dropped_bits"] += data["bits"]
                details["mitigation_systems"].extend(data["systems"])
    else:
        # IPv4 handling - e.g., "185.54.81.0/24"
        prefix_base = prefix.replace("/24", "")  # e.g., "185.54.81.0"
        prefix_network = prefix.split(".")[0:3]  # e.g., ["185", "54", "81"]

        for subnet, data in mitigated.items():
            # Check if this subnet matches our prefix
            if prefix in subnet or prefix_base in subnet:
                details["dropped_packets"] += data["packets"]
                details["dropped_bits"] += data["bits"]
                details["mitigation_systems"].extend(data["systems"])

        # Also check subnet format like "185.54.81"
        for subnet, data in mitigated.items():
            subnet_parts = subnet.split(".")
            if len(subnet_parts) >= 3:
                if subnet_parts[0:3] == prefix_network:
                    if data["packets"] not in [details["dropped_packets"]]:  # Avoid double counting
                        details["dropped_packets"] += data["packets"]
                        details["dropped_bits"] += data["bits"]
    
    # Calculate Mbps
    if ATTACK_LOOKBACK_MINUTES > 0:
        details["dropped_mbps"] = round(details["dropped_bits"] / ATTACK_LOOKBACK_MINUTES / 60 / 1_000_000, 2)
    
    # Remove duplicates from mitigation systems
    details["mitigation_systems"] = list(set(details["mitigation_systems"]))
    
    # Check if significant mitigated traffic (BOTH thresholds must be exceeded)
    if details["dropped_packets"] > MIN_DROPPED_PACKETS and details["dropped_bits"] > MIN_DROPPED_BITS:
        log(f"  📊 Mitigated traffic: {details['dropped_packets']} pkts, {details['dropped_mbps']} Mbps")
        log(f"     Systems: {', '.join(details['mitigation_systems']) if details['mitigation_systems'] else 'N/A'}")
        return True, details
    
    # Also check global attacks (they might not be subnet-specific)
    attacks = get_active_attacks_all(ATTACK_LOOKBACK_MINUTES)
    if attacks:
        details["active_attacks"] = len(attacks)
        attack_types = set()
        for attack in attacks:
            if attack.get("dimensions", {}).get("attackType"):
                attack_types.add(attack["dimensions"]["attackType"])
        details["attack_types"] = list(attack_types)
        
        # If there are global attacks, consider under attack
        # (We can't easily filter by destination in dosd, so we're conservative)
        total_attack_packets = sum(a.get("sum", {}).get("packets", 0) or 0 for a in attacks)
        if total_attack_packets > MIN_DROPPED_PACKETS:
            log(f"  📊 Active attacks: {len(attacks)}, types: {details['attack_types']}")
            return True, details
    
    log(f"  ✅ No significant attacks (dropped: {details['dropped_packets']} pkts, {details['dropped_mbps']} Mbps)")
    return False, details

# ============================================
# PREFIX MANAGEMENT
# ============================================

def get_advertised_prefixes():
    """
    Get list of currently advertised prefixes.

    Uses the BGP prefix endpoint which returns the correct on_demand.advertised state.
    The base /addressing/prefixes endpoint does NOT reflect actual BGP advertisement state.
    """
    prefix_mapping = load_prefix_mapping()

    if not prefix_mapping:
        log_error("No prefix mapping available")
        return []

    advertised = []
    for cidr, mapping in prefix_mapping.items():
        prefix_id = mapping.get('prefix_id')
        bgp_prefix_id = mapping.get('bgp_prefix_id')

        if not prefix_id or not bgp_prefix_id:
            log_warn(f"Missing IDs for {cidr}")
            continue

        # Use the correct BGP prefix endpoint
        url = f"{PREFIXES_URL}/{prefix_id}/bgp/prefixes/{bgp_prefix_id}"
        result = api_get(url)

        if not result.get("success"):
            log_warn(f"Failed to get status for {cidr}: {result.get('errors')}")
            continue

        prefix_data = result.get("result", {})
        on_demand = prefix_data.get("on_demand", {})

        if on_demand.get("advertised"):
            advertised.append({
                "id": prefix_id,
                "bgp_prefix_id": bgp_prefix_id,
                "cidr": cidr,
                "description": mapping.get("description", ""),
                "advertised_at": on_demand.get("advertised_modified_at", "")
            })

    return advertised

def get_all_prefixes():
    """Get all prefixes with their current on_demand.advertised status"""
    prefix_mapping = load_prefix_mapping()

    if not prefix_mapping:
        log_error("No prefix mapping available")
        return []

    all_prefixes = []
    for cidr, mapping in prefix_mapping.items():
        prefix_id = mapping.get('prefix_id')
        bgp_prefix_id = mapping.get('bgp_prefix_id')

        if not prefix_id or not bgp_prefix_id:
            continue

        url = f"{PREFIXES_URL}/{prefix_id}/bgp/prefixes/{bgp_prefix_id}"
        result = api_get(url)

        if result.get("success"):
            prefix_data = result.get("result", {})
            on_demand = prefix_data.get("on_demand", {})
            all_prefixes.append({
                "id": prefix_id,
                "bgp_prefix_id": bgp_prefix_id,
                "cidr": cidr,
                "description": mapping.get("description", ""),
                "advertised": on_demand.get("advertised", False),
                "modified_at": on_demand.get("advertised_modified_at", "")
            })

    return all_prefixes

def withdraw_prefix(prefix_id, cidr):
    """Withdraw a prefix (disable Magic Transit)"""
    # Get bgp_prefix_id from mapping
    prefix_mapping = load_prefix_mapping()
    mapping = prefix_mapping.get(cidr, {})
    bgp_prefix_id = mapping.get('bgp_prefix_id')

    if not bgp_prefix_id:
        log_error(f"No bgp_prefix_id found for {cidr}")
        return False

    url = f"{PREFIXES_URL}/{prefix_id}/bgp/prefixes/{bgp_prefix_id}"
    result = api_patch(url, {"on_demand": {"advertised": False}})

    if result.get("success"):
        log(f"✓ Successfully withdrawn: {cidr}")
        return True
    else:
        error = result.get("errors", [{}])[0].get("message", "Unknown error")
        log_error(f"Failed to withdraw {cidr}: {error}")
        return False

def advertise_prefix(prefix_id, cidr):
    """Advertise a prefix (enable Magic Transit)"""
    # Get bgp_prefix_id from mapping
    prefix_mapping = load_prefix_mapping()
    mapping = prefix_mapping.get(cidr, {})
    bgp_prefix_id = mapping.get('bgp_prefix_id')

    if not bgp_prefix_id:
        log_error(f"No bgp_prefix_id found for {cidr}")
        return False

    url = f"{PREFIXES_URL}/{prefix_id}/bgp/prefixes/{bgp_prefix_id}"
    result = api_patch(url, {"on_demand": {"advertised": True}})

    if result.get("success"):
        log(f"✓ Successfully advertised: {cidr}")
        return True
    else:
        error = result.get("errors", [{}])[0].get("message", "Unknown error")
        log_error(f"Failed to advertise {cidr}: {error}")
        return False

def check_advertise_constraint(modified_at):
    """Check if the 15-minute constraint is satisfied for RE-ADVERTISE after withdrawal

    Cloudflare enforces a 15-minute cooldown after withdrawing a prefix before
    it can be re-advertised.

    Args:
        modified_at: The advertised_modified_at timestamp from API

    Returns:
        tuple: (can_advertise, remaining_seconds, advertise_time_str)
    """
    if not modified_at:
        return True, 0, None

    try:
        mod_time = datetime.fromisoformat(modified_at.replace('Z', '+00:00'))
        advertise_time = mod_time + timedelta(minutes=15)
        now = datetime.now(timezone.utc)

        if now >= advertise_time:
            return True, 0, None
        else:
            remaining = (advertise_time - now).total_seconds()
            # Format advertise time in local timezone (UTC+1 for Switzerland)
            advertise_time_local = advertise_time + timedelta(hours=1)
            advertise_time_str = advertise_time_local.strftime('%H:%M:%S')
            return False, remaining, advertise_time_str
    except:
        return True, 0, None

# ============================================
# AUTO-WITHDRAW LOGIC
# ============================================

def process_advertised_prefix(prefix):
    """
    Process a single advertised prefix.
    
    Logic:
    1. Check if under attack via GraphQL
    2. If under attack, reset calm timer
    3. If not under attack, start/continue calm timer
    4. If calm for CALM_PERIOD_MINUTES, withdraw
    """
    cidr = prefix["cidr"]
    prefix_id = prefix["id"]
    description = prefix["description"]
    
    log(f"🔍 Checking {cidr} ({description})...")
    
    # Check attack status via GraphQL
    under_attack, details = is_under_attack(cidr)
    
    if under_attack:
        # Reset calm timer
        if cidr in calm_since:
            log(f"  ⚠️ Attack detected! Resetting calm timer for {cidr}")
            calm_since.pop(cidr)
        else:
            log(f"  ⚠️ Attack in progress for {cidr}")

        # Track peak attack statistics
        current_packets = details.get('dropped_packets', 0)
        current_mbps = details.get('dropped_mbps', 0)

        if cidr not in attack_peak_stats:
            attack_peak_stats[cidr] = {
                'dropped_packets': current_packets,
                'dropped_mbps': current_mbps,
                'mitigation_systems': details.get('mitigation_systems', []),
                'peak_time': datetime.now(timezone.utc)
            }
        else:
            # Update if current values are higher
            if current_packets > attack_peak_stats[cidr]['dropped_packets']:
                attack_peak_stats[cidr]['dropped_packets'] = current_packets
            if current_mbps > attack_peak_stats[cidr]['dropped_mbps']:
                attack_peak_stats[cidr]['dropped_mbps'] = current_mbps
            # Merge mitigation systems
            existing_systems = set(attack_peak_stats[cidr].get('mitigation_systems', []))
            new_systems = set(details.get('mitigation_systems', []))
            attack_peak_stats[cidr]['mitigation_systems'] = list(existing_systems | new_systems)
            attack_peak_stats[cidr]['peak_time'] = datetime.now(timezone.utc)

        return False  # Not ready to withdraw
    
    # Not under attack - start or continue calm period
    if cidr not in calm_since:
        calm_since[cidr] = datetime.now(timezone.utc)
        log(f"  📊 Starting calm period tracking for {cidr}")
        return False
    
    # Check if calm period has elapsed
    elapsed = datetime.now(timezone.utc) - calm_since[cidr]
    elapsed_minutes = elapsed.total_seconds() / 60
    
    if elapsed_minutes >= CALM_PERIOD_MINUTES:
        log(f"  ✅ {cidr} calm for {elapsed_minutes:.1f} minutes - WAITING FOR AUTO-WITHDRAW")
        
        # Withdraw the prefix
        success = withdraw_prefix(prefix_id, cidr)
        
        if success:
            # Get peak attack statistics (from the attack before calm period)
            peak_stats = attack_peak_stats.get(cidr, {})
            peak_packets = peak_stats.get('dropped_packets', 0)
            peak_mbps = peak_stats.get('dropped_mbps', 0)
            peak_systems = peak_stats.get('mitigation_systems', [])

            # Clear tracking
            calm_since.pop(cidr, None)
            attack_peak_stats.pop(cidr, None)  # Clear peak stats after withdraw

            # Send notification with PEAK stats (not current which is 0)
            now = datetime.now()
            message = f"""🛡️ <b>CLOUDFLARE DDoS PROTECTION</b>
✅ <b>PREFIX AUTO-WITHDRAWN</b>

🔖 <b>Event ID:</b> {now.strftime("%Y%m%d%H%M%S")}-withdraw

⚔️ <b>PREFIX INFO</b>
🌐 <b>Prefix:</b> {cidr}
📝 <b>Description:</b> {description}

📊 <b>ATTACK PEAK STATS</b>
⏱️ <b>Calm Duration:</b> {elapsed_minutes:.1f} minutes
📦 <b>Peak Dropped Packets:</b> {peak_packets:,} pkts
📈 <b>Peak Dropped Traffic:</b> {peak_mbps} Mbps
🔧 <b>Systems:</b> {', '.join(peak_systems) if peak_systems else 'None'}
ℹ️ <i>Withdrawn after {CALM_PERIOD_MINUTES} min of calm (no traffic above thresholds)</i>

🔄 <b>BGP STATUS</b>
📤 <b>Action:</b> Withdrawn
🌐 <b>Routing:</b> Direct (Magic Transit OFF)

⏰ <b>Timestamp:</b> {now.strftime("%Y-%m-%dT%H:%M:%SZ")}

🏢 <b>GOLINE SOC</b> | Cloudflare Magic Transit"""

            send_telegram(message)

            # Log to shared database with peak stats
            peak_details = {
                'dropped_packets': peak_packets,
                'dropped_mbps': peak_mbps,
                'mitigation_systems': peak_systems
            }
            log_withdraw_to_db(cidr, description, elapsed_minutes, peak_details)

            return True
    else:
        remaining = CALM_PERIOD_MINUTES - elapsed_minutes
        log(f"  ⏳ Calm for {elapsed_minutes:.1f} min, {remaining:.1f} min remaining before withdraw")
    
    return False

def run_check_cycle():
    """Run a single check cycle for all advertised prefixes"""
    log("=" * 60)
    log("Starting check cycle...")

    # Get all prefixes for status tracking
    all_prefixes = get_all_prefixes()
    advertised = [p for p in all_prefixes if p.get('advertised')]

    if not advertised:
        log("✅ No prefixes currently advertised - nothing to check")
        # Still update status for withdrawn prefixes
        _update_all_prefix_status(all_prefixes)
        return

    log(f"Found {len(advertised)} advertised prefix(es)")

    for prefix in advertised:
        try:
            process_advertised_prefix(prefix)
        except Exception as e:
            log_error(f"Error processing {prefix['cidr']}: {e}")

    # Update prefix status for dashboard
    _update_all_prefix_status(all_prefixes)

    log("Check cycle complete")

def _update_all_prefix_status(all_prefixes):
    """Collect and update status for all prefixes (for dashboard integration)"""
    prefix_data = []

    for prefix in all_prefixes:
        cidr = prefix['cidr']
        is_advertised = prefix.get('advertised', False)

        # Check attack status for advertised prefixes
        under_attack = False
        details = {'dropped_packets': 0, 'dropped_mbps': 0, 'mitigation_systems': []}

        if is_advertised:
            under_attack, details = is_under_attack(cidr)

        # Get calm_since from in-memory tracking
        calm_since_time = calm_since.get(cidr)

        prefix_data.append({
            'prefix': cidr,
            'advertised': is_advertised,
            'under_attack': under_attack,
            'calm_since': calm_since_time,
            'dropped_packets': details.get('dropped_packets', 0),
            'dropped_mbps': details.get('dropped_mbps', 0),
            'mitigation_systems': details.get('mitigation_systems', [])
        })

    update_prefix_calm_status(prefix_data)

# ============================================
# DAEMON MODE
# ============================================

def run_daemon():
    """Run continuously as a daemon"""
    log("=" * 60)
    log("Cloudflare Magic Transit - Auto Withdraw Manager v3")
    log("GOLINE SA - SOC Tools")
    log("=" * 60)
    log(f"Configuration:")
    log(f"  Calm period: {CALM_PERIOD_MINUTES} minutes")
    log(f"  Check interval: {CHECK_INTERVAL_SECONDS} seconds")
    log(f"  Attack lookback: {ATTACK_LOOKBACK_MINUTES} minutes")
    log(f"  Min dropped packets: {MIN_DROPPED_PACKETS}")
    log(f"  Min dropped bits: {MIN_DROPPED_BITS} ({MIN_DROPPED_BITS/1_000_000} Mbps)")
    log("=" * 60)
    
    # Send startup notification
    now = datetime.now()
    send_telegram(f"""🛡️ <b>CLOUDFLARE DDoS PROTECTION</b>
🚀 <b>AUTO-WITHDRAW SERVICE STARTED</b>

🔖 <b>Event ID:</b> {now.strftime("%Y%m%d%H%M%S")}-startup

⚙️ <b>CONFIGURATION</b>
⏱️ <b>Calm Period:</b> {CALM_PERIOD_MINUTES} minutes
🔄 <b>Check Interval:</b> {CHECK_INTERVAL_SECONDS} seconds
📊 <b>Lookback Window:</b> {ATTACK_LOOKBACK_MINUTES} minutes
📦 <b>Packet Threshold:</b> {MIN_DROPPED_PACKETS} pkts
📈 <b>Bits Threshold:</b> {MIN_DROPPED_BITS/1_000_000:.0f} Mbps

🔧 <b>DETECTION METHOD</b>
📡 <b>API:</b> Cloudflare GraphQL Analytics
📊 <b>Node:</b> magicTransitNetworkAnalyticsAdaptiveGroups

⏰ <b>Timestamp:</b> {now.strftime("%Y-%m-%dT%H:%M:%SZ")}

🏢 <b>GOLINE SOC</b> | Cloudflare Magic Transit""")
    
    while True:
        try:
            run_check_cycle()
        except Exception as e:
            log_error(f"Check cycle error: {e}")
        
        log(f"Sleeping {CHECK_INTERVAL_SECONDS} seconds...")
        time.sleep(CHECK_INTERVAL_SECONDS)

# ============================================
# MANUAL COMMANDS
# ============================================

def cmd_status():
    """Show current status of all prefixes"""
    print("\n" + "=" * 60)
    print(" MAGIC TRANSIT PREFIX STATUS")
    print("=" * 60 + "\n")
    
    prefixes = get_all_prefixes()
    
    if not prefixes:
        print("No prefixes found or error fetching data.")
        return
    
    for prefix in prefixes:
        cidr = prefix["cidr"]
        status = "🟢 ADVERTISED" if prefix.get("advertised") else "⚪ Withdrawn"
        desc = prefix.get("description", "")
        
        print(f"{status} | {cidr} | {desc}")
        
        if prefix.get("advertised"):
            # Check attack status
            under_attack, details = is_under_attack(cidr)
            
            if under_attack:
                print(f"  └─ ⚠️  UNDER ATTACK: {details['dropped_packets']} pkts dropped, {details['dropped_mbps']} Mbps mitigated")
            else:
                print(f"  └─ ✅ No active attacks")
            
            if cidr in calm_since:
                elapsed = (datetime.now(timezone.utc) - calm_since[cidr]).total_seconds() / 60
                print(f"  └─ ⏳ Calm for {elapsed:.1f} minutes")
    
    print()

def cmd_check():
    """Run a single check cycle"""
    run_check_cycle()

def cmd_withdraw(cidr=None):
    """Manually withdraw prefix(es)"""
    prefixes = get_all_prefixes()
    advertised = [p for p in prefixes if p.get("advertised")]
    
    if not advertised:
        print("No prefixes currently advertised.")
        return
    
    if cidr:
        # Withdraw specific prefix
        for prefix in advertised:
            if prefix["cidr"] == cidr:
                success = withdraw_prefix(prefix["id"], cidr)
                if success:
                    now = datetime.now()
                    send_telegram(f"""🛡️ <b>CLOUDFLARE DDoS PROTECTION</b>
🔧 <b>MANUAL PREFIX WITHDRAWAL</b>

🔖 <b>Event ID:</b> {now.strftime("%Y%m%d%H%M%S")}-manual

⚔️ <b>PREFIX INFO</b>
🌐 <b>Prefix:</b> {cidr}
📝 <b>Description:</b> {prefix.get('description', 'N/A')}

🔄 <b>BGP STATUS</b>
📤 <b>Action:</b> Withdrawn (Manual)
🌐 <b>Routing:</b> Direct (Magic Transit OFF)

⏰ <b>Timestamp:</b> {now.strftime("%Y-%m-%dT%H:%M:%SZ")}

🏢 <b>GOLINE SOC</b> | Cloudflare Magic Transit""")
                    # Log to database
                    log_withdraw_to_db(cidr, prefix.get('description', 'N/A'), 0, {'dropped_packets': 0, 'dropped_mbps': 0, 'mitigation_systems': []})
                return
        print(f"Prefix {cidr} not found or not advertised.")
    else:
        # Withdraw all
        print(f"Withdrawing {len(advertised)} prefix(es)...")
        withdrawn_list = []
        for prefix in advertised:
            if withdraw_prefix(prefix["id"], prefix["cidr"]):
                withdrawn_list.append(prefix["cidr"])
        
        if withdrawn_list:
            now = datetime.now()
            send_telegram(f"""🛡️ <b>CLOUDFLARE DDoS PROTECTION</b>
🔧 <b>BULK PREFIX WITHDRAWAL</b>

🔖 <b>Event ID:</b> {now.strftime("%Y%m%d%H%M%S")}-bulk

⚔️ <b>PREFIXES WITHDRAWN</b>
{chr(10).join([f'🌐 {p}' for p in withdrawn_list])}

📊 <b>SUMMARY</b>
📦 <b>Total:</b> {len(withdrawn_list)} prefix(es)
📤 <b>Action:</b> Withdrawn (Manual Bulk)
🌐 <b>Routing:</b> Direct (Magic Transit OFF)

⏰ <b>Timestamp:</b> {now.strftime("%Y-%m-%dT%H:%M:%SZ")}

🏢 <b>GOLINE SOC</b> | Cloudflare Magic Transit""")
            # Log each to database
            for p in withdrawn_list:
                log_withdraw_to_db(p, 'bulk_manual', 0, {'dropped_packets': 0, 'dropped_mbps': 0, 'mitigation_systems': []})

def cmd_advertise(cidr):
    """Manually advertise a prefix"""
    prefixes = get_all_prefixes()

    for prefix in prefixes:
        if prefix["cidr"] == cidr:
            if prefix.get("advertised"):
                print(f"{cidr} is already advertised.")
                return

            # Check 15-minute constraint for re-advertise after withdrawal
            modified_at = prefix.get("modified_at")
            can_advertise, remaining, advertise_time = check_advertise_constraint(modified_at)

            if not can_advertise:
                mins = int(remaining // 60)
                secs = int(remaining % 60)
                print(f"ERROR: Cannot advertise {cidr} - 15-minute constraint not satisfied")
                print(f"       Cloudflare requires 15 minutes between withdrawal and re-advertisement")
                print(f"       Advertise available at {advertise_time} (in {mins}m {secs}s)")
                return

            success = advertise_prefix(prefix["id"], cidr)
            if success:
                now = datetime.now()
                send_telegram(f"""🛡️ <b>CLOUDFLARE DDoS PROTECTION</b>
🚨 <b>MANUAL PREFIX ADVERTISEMENT</b>

🔖 <b>Event ID:</b> {now.strftime("%Y%m%d%H%M%S")}-emergency

⚔️ <b>PREFIX INFO</b>
🌐 <b>Prefix:</b> {cidr}
📝 <b>Description:</b> {prefix.get('description', 'N/A')}

🔄 <b>BGP STATUS</b>
📥 <b>Action:</b> Advertised (Manual/Emergency)
🌐 <b>Routing:</b> Via Cloudflare (Magic Transit ON)

⚠️ <b>WARNING</b>
This prefix will remain advertised until manually withdrawn or auto-withdraw triggers after {CALM_PERIOD_MINUTES} minutes of calm.

⏰ <b>Timestamp:</b> {now.strftime("%Y-%m-%dT%H:%M:%SZ")}

🏢 <b>GOLINE SOC</b> | Cloudflare Magic Transit""")
            return
    
    print(f"Prefix {cidr} not found.")

def cmd_test_graphql():
    """Test GraphQL API connection and queries"""
    print("\n" + "=" * 60)
    print(" GRAPHQL API TEST")
    print("=" * 60 + "\n")
    
    print("Testing connection to Cloudflare GraphQL API...")
    
    # Test basic query
    query = """
    query Test($accountTag: string!) {
        viewer {
            accounts(filter: {accountTag: $accountTag}) {
                accountTag
            }
        }
    }
    """
    
    data = graphql_query(query, {"accountTag": ACCOUNT_ID})
    
    if data:
        print("✅ GraphQL API connection successful!")
        print(f"   Account: {data['viewer']['accounts'][0]['accountTag']}")
    else:
        print("❌ GraphQL API connection failed!")
        return
    
    print("\n" + "-" * 60)
    print("Testing mitigated traffic query...")
    
    mitigated = get_mitigated_traffic_all(60)  # Last hour
    
    if mitigated:
        print(f"✅ Found mitigated traffic data for {len(mitigated)} subnet(s):")
        for subnet, data in mitigated.items():
            mbps = data["bits"] / 60 / 60 / 1_000_000
            print(f"   {subnet}: {data['packets']} pkts, {mbps:.2f} Mbps avg")
            print(f"      Systems: {', '.join(data['systems']) if data['systems'] else 'N/A'}")
    else:
        print("ℹ️  No mitigated traffic in last hour (this is good!)")
    
    print("\n" + "-" * 60)
    print("Testing attack analytics query...")
    
    attacks = get_active_attacks_all(60)  # Last hour
    
    if attacks:
        print(f"✅ Found {len(attacks)} attack records in last hour:")
        for attack in attacks[:5]:  # Show first 5
            attack_type = attack.get("dimensions", {}).get("attackType", "unknown")
            packets = attack.get("sum", {}).get("packets", 0)
            print(f"   Type: {attack_type}, Packets: {packets}")
    else:
        print("ℹ️  No attacks in last hour (this is good!)")
    
    print("\n" + "-" * 60)
    print("Testing prefix attack detection...")
    
    for prefix in GOLINE_PREFIXES:
        print(f"\n  Checking {prefix}...")
        under_attack, details = is_under_attack(prefix)
        
        if under_attack:
            print(f"    ⚠️  ATTACK DETECTED")
            print(f"       Dropped: {details['dropped_packets']} pkts, {details['dropped_mbps']} Mbps")
        else:
            print(f"    ✅ No active attacks")
            print(f"       Dropped: {details['dropped_packets']} pkts, {details['dropped_mbps']} Mbps")
    
    print()

def show_help():
    """Show help message"""
    print(f"""
Cloudflare Magic Transit - Auto Withdraw Manager v3
GOLINE SA - SOC Tools

Usage:
  python3 cf_auto_withdraw_v3.py [command] [arguments]

Commands:
  daemon              Run as continuous daemon (default)
  status              Show current prefix status with attack info
  check               Run a single check cycle
  withdraw            Withdraw all advertised prefixes
  withdraw <cidr>     Withdraw specific prefix
  advertise <cidr>    Advertise specific prefix
  test                Test GraphQL API connection
  help                Show this help

Configuration (edit in script):
  CALM_PERIOD_MINUTES     = {CALM_PERIOD_MINUTES}    # Minutes without attacks before withdraw
  CHECK_INTERVAL_SECONDS  = {CHECK_INTERVAL_SECONDS}   # How often to check
  ATTACK_LOOKBACK_MINUTES = {ATTACK_LOOKBACK_MINUTES}     # Look for attacks in last N minutes
  MIN_DROPPED_PACKETS     = {MIN_DROPPED_PACKETS}   # Minimum packets to consider attack
  MIN_DROPPED_BITS        = {MIN_DROPPED_BITS}  # Minimum bits to consider attack

Examples:
  python3 cf_auto_withdraw_v3.py daemon
  python3 cf_auto_withdraw_v3.py status
  python3 cf_auto_withdraw_v3.py withdraw 185.54.81.0/24
  python3 cf_auto_withdraw_v3.py advertise 185.54.81.0/24
  python3 cf_auto_withdraw_v3.py test

How it works:
  1. Daemon monitors all advertised prefixes every {CHECK_INTERVAL_SECONDS} seconds
  2. For each prefix, queries Cloudflare GraphQL API for:
     - Mitigated/dropped traffic (magicTransitNetworkAnalyticsAdaptiveGroups)
     - Active DDoS attacks (dosdAttackAnalyticsGroups)
  3. If significant dropped traffic detected, resets calm timer
  4. If no attacks for {CALM_PERIOD_MINUTES} minutes, automatically withdraws prefix
  5. Sends Telegram notification on withdraw

Run as systemd service for production use.
""")

# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        run_daemon()
    elif sys.argv[1] == "daemon":
        run_daemon()
    elif sys.argv[1] == "status":
        cmd_status()
    elif sys.argv[1] == "check":
        cmd_check()
    elif sys.argv[1] == "withdraw":
        if len(sys.argv) > 2:
            cmd_withdraw(sys.argv[2])
        else:
            cmd_withdraw()
    elif sys.argv[1] == "advertise":
        if len(sys.argv) > 2:
            cmd_advertise(sys.argv[2])
        else:
            print("Usage: cf_auto_withdraw_v3.py advertise <cidr>")
    elif sys.argv[1] == "test":
        cmd_test_graphql()
    elif sys.argv[1] == "help" or sys.argv[1] == "-h" or sys.argv[1] == "--help":
        show_help()
    else:
        print(f"Unknown command: {sys.argv[1]}")
        show_help()
