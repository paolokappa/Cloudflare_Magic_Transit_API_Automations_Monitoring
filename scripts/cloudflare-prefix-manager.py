#!/usr/bin/env python3
"""
Cloudflare BGP Prefix Manager
=============================
Complete management of BGP prefixes for Magic Transit On-Demand.

Commands:
  status                    Show status of all prefixes
  status <prefix>           Show detailed status of a prefix
  advertise <prefix>        Advertise a specific prefix
  advertise --all           Advertise all prefixes
  withdraw <prefix>         Withdraw a specific prefix
  withdraw --all            Withdraw all prefixes
  list                      List configured prefixes
  help                      Show this help

Examples:
  cloudflare-prefix-manager.py status
  cloudflare-prefix-manager.py advertise 185.54.82.0/24
  cloudflare-prefix-manager.py withdraw --all
  cloudflare-prefix-manager.py status 2a02:4460:1::/48

Version: 1.4.1

Changelog:
  v1.4.1 (2026-02-06): Added Telegram retry mechanism (3 attempts with exponential backoff)
  v1.4.0 (2026-01-21): Added database logging for ADVERTISE/WITHDRAW operations.
                       Manual operations now appear in dashboard's Recent Attacks.
"""

import requests
import happy_eyeballs
import json
import sys
import argparse
import random
import string
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Configuration
CONFIG_PATH = Path("/root/Cloudflare_MT_Integration/config/settings.json")
PREFIX_MAP_PATH = Path("/root/Cloudflare_MT_Integration/config/prefix_mapping.json")
DB_PATH = Path("/root/Cloudflare_MT_Integration/db/magic_transit.db")

# Load configuration
def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)

def load_prefix_mapping():
    with open(PREFIX_MAP_PATH) as f:
        return json.load(f)['prefixes']

def log_event_to_db(event_type, prefix, action_taken, description=None, operation_id=None):
    """
    Log ADVERTISE or WITHDRAW event to the attack_events database.
    This allows manual operations to appear in the dashboard's Recent Attacks section.

    Args:
        event_type: 'ADVERTISE' or 'WITHDRAW'
        prefix: The BGP prefix (e.g., '185.54.82.0/24')
        action_taken: 'advertised_manual' or 'withdrawn_manual'
        description: Optional description of the prefix
        operation_id: Unique operation ID for tracking
    """
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()

        now = datetime.now(timezone.utc)
        now_str = now.strftime('%Y-%m-%d %H:%M:%S')

        # Build raw_payload with details
        payload = {
            'source': 'prefix_manager_cli',
            'operation_id': operation_id,
            'description': description,
            'timestamp': now_str
        }

        cursor.execute('''
            INSERT INTO attack_events
            (event_type, alert_type, prefix, action_taken, raw_payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            event_type,
            'prefix_manager_manual',
            prefix,
            action_taken,
            json.dumps(payload),
            now_str
        ))

        conn.commit()
        conn.close()
        return True

    except Exception as e:
        # Silent fail - don't interrupt the main operation
        return False

config = load_config()
ACCOUNT_ID = config['cloudflare']['account_id']
API_TOKEN = config['cloudflare']['api_token']
TELEGRAM_TOKEN = config['telegram']['bot_token']
TELEGRAM_CHAT_ID = config['telegram']['chat_id']

BASE_URL = "https://api.cloudflare.com/client/v4"

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

# ANSI colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def c(text, color):
    """Apply color to text"""
    return f"{color}{text}{Colors.END}"

def generate_operation_id():
    """Generate a unique operation ID"""
    return datetime.now().strftime("%Y%m%d%H%M%S") + '-' + ''.join(random.choices(string.hexdigits[:16], k=6))

# ============================================================
# API FUNCTIONS
# ============================================================

def get_prefix_status(prefix_id, bgp_prefix_id):
    """Get the status of a BGP prefix"""
    url = f"{BASE_URL}/accounts/{ACCOUNT_ID}/addressing/prefixes/{prefix_id}/bgp/prefixes/{bgp_prefix_id}"

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                result = data.get('result', {})
                on_demand = result.get('on_demand', {})
                return {
                    'success': True,
                    'advertised': on_demand.get('advertised', False),
                    'locked': on_demand.get('locked', False),
                    'enabled': on_demand.get('enabled', False),
                    'modified_at': on_demand.get('advertised_modified_at'),
                    'cidr': result.get('cidr'),
                    'asn': result.get('asn'),
                    'full_data': result
                }

        return {'success': False, 'error': f"HTTP {response.status_code}: {response.text[:200]}"}

    except Exception as e:
        return {'success': False, 'error': str(e)}

def set_prefix_advertisement(prefix_id, bgp_prefix_id, advertise):
    """Set the advertisement state of a prefix"""
    url = f"{BASE_URL}/accounts/{ACCOUNT_ID}/addressing/prefixes/{prefix_id}/bgp/prefixes/{bgp_prefix_id}"
    data = {"on_demand": {"advertised": advertise}}

    try:
        response = requests.patch(url, headers=headers, json=data, timeout=30)

        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                return {'success': True, 'result': result.get('result', {})}
            else:
                errors = result.get('errors', [])
                return {'success': False, 'error': str(errors)}

        return {'success': False, 'error': f"HTTP {response.status_code}: {response.text[:200]}"}

    except Exception as e:
        return {'success': False, 'error': str(e)}

def check_withdraw_constraint(modified_at):
    """Check if the 15-minute constraint is satisfied for WITHDRAW

    Returns:
        tuple: (can_withdraw, remaining_seconds, withdraw_time_str)
    """
    if not modified_at:
        return True, 0, None

    try:
        mod_time = datetime.fromisoformat(modified_at.replace('Z', '+00:00'))
        withdraw_time = mod_time + timedelta(minutes=15)
        now = datetime.now(timezone.utc)

        if now >= withdraw_time:
            return True, 0, None
        else:
            remaining = (withdraw_time - now).total_seconds()
            # Format withdraw time in local timezone (UTC+1 for Switzerland)
            withdraw_time_local = withdraw_time + timedelta(hours=1)
            withdraw_time_str = withdraw_time_local.strftime('%H:%M:%S')
            return False, remaining, withdraw_time_str
    except:
        return True, 0, None

def check_advertise_constraint(modified_at):
    """Check if the 15-minute constraint is satisfied for RE-ADVERTISE after withdrawal

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

def send_telegram_notification(message, max_retries=3):
    """Send Telegram notification with retry mechanism"""
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True
    }

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(url, json=data, timeout=30)
            if response.ok:
                return True
        except:
            pass

        # Wait before retry (exponential backoff: 5s, 10s)
        if attempt < max_retries:
            import time
            time.sleep(5 * (2 ** (attempt - 1)))

    return False

# ============================================================
# TELEGRAM NOTIFICATION BUILDERS
# ============================================================

def notify_prefix_advertised(prefix, prefix_info, operation_id):
    """Send enriched Telegram notification for prefix advertisement"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    description = prefix_info.get('description', 'N/A')
    asn = prefix_info.get('asn', '202032')

    # Determine prefix type
    if ':' in prefix:
        prefix_type = "IPv6"
        prefix_icon = "🌐"
    else:
        prefix_type = "IPv4"
        prefix_icon = "📡"

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

📡 *BGP ADVERTISEMENT*

🔖 *Operation ID:* `{operation_id}`
✅ *Status:* PREFIX ADVERTISED
🎯 *Action:* Manual Advertisement

{prefix_icon} *PREFIX INFO*
📍 *CIDR:* `{prefix}`
📝 *Description:* {description}
🔢 *ASN:* {asn}
🌍 *Type:* {prefix_type}

⏱️ *TIMING*
🕐 *Advertised at:* {timestamp}
⏳ *BGP Propagation:* 2-7 minutes
🔒 *Min. Hold Time:* 15 minutes

🔄 *BGP STATUS*
✅ Prefix now advertised via Cloudflare
🛡️ Traffic will be scrubbed through Magic Transit
📊 DDoS protection active

👤 *Operator:* CLI (Manual)

🏢 *GOLINE SOC* | _Magic Transit On-Demand_"""

    send_telegram_notification(message)

def notify_prefix_withdrawn(prefix, prefix_info, operation_id, advertised_duration=None):
    """Send enriched Telegram notification for prefix withdrawal"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    description = prefix_info.get('description', 'N/A')
    asn = prefix_info.get('asn', '202032')

    # Determine prefix type
    if ':' in prefix:
        prefix_type = "IPv6"
        prefix_icon = "🌐"
    else:
        prefix_type = "IPv4"
        prefix_icon = "📡"

    # Duration info
    duration_str = ""
    if advertised_duration:
        mins = int(advertised_duration // 60)
        if mins > 0:
            duration_str = f"\n⏱️ *Was advertised for:* {mins} minutes"

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

🔚 *BGP WITHDRAWAL*

🔖 *Operation ID:* `{operation_id}`
✅ *Status:* PREFIX WITHDRAWN
🎯 *Action:* Manual Withdrawal

{prefix_icon} *PREFIX INFO*
📍 *CIDR:* `{prefix}`
📝 *Description:* {description}
🔢 *ASN:* {asn}
🌍 *Type:* {prefix_type}

⏱️ *TIMING*
🕐 *Withdrawn at:* {timestamp}
⏳ *BGP Withdrawal:* ~15 minutes{duration_str}

🔄 *BGP STATUS*
🔙 Traffic returning to origin path
⚠️ Direct routing resumed
📊 Magic Transit protection disabled for this prefix

👤 *Operator:* CLI (Manual)

🏢 *GOLINE SOC* | _Magic Transit On-Demand_"""

    send_telegram_notification(message)

def notify_bulk_operation(operation, prefixes_success, prefixes_failed, prefixes_skipped, operation_id):
    """Send notification for bulk operations"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

    if operation == "advertise":
        emoji = "📡"
        title = "BULK BGP ADVERTISEMENT"
        status_msg = "advertised"
    else:
        emoji = "🔚"
        title = "BULK BGP WITHDRAWAL"
        status_msg = "withdrawn"

    total = len(prefixes_success) + len(prefixes_failed) + len(prefixes_skipped)

    # Build prefix lists
    success_list = ""
    if prefixes_success:
        success_list = "\n✅ *Successful:*\n" + "\n".join([f"  • `{p}`" for p in prefixes_success])

    failed_list = ""
    if prefixes_failed:
        failed_list = "\n❌ *Failed:*\n" + "\n".join([f"  • `{p}`" for p in prefixes_failed])

    skipped_list = ""
    if prefixes_skipped:
        skipped_list = "\n⏭️ *Skipped:*\n" + "\n".join([f"  • `{p[0]}` ({p[1]})" for p in prefixes_skipped])

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

{emoji} *{title}*

🔖 *Operation ID:* `{operation_id}`
🎯 *Action:* Bulk {operation.capitalize()}

📊 *SUMMARY*
📦 *Total Prefixes:* {total}
✅ *{status_msg.capitalize()}:* {len(prefixes_success)}
❌ *Failed:* {len(prefixes_failed)}
⏭️ *Skipped:* {len(prefixes_skipped)}
{success_list}{failed_list}{skipped_list}

⏱️ *Completed at:* {timestamp}

👤 *Operator:* CLI (Manual)

🏢 *GOLINE SOC* | _Magic Transit On-Demand_"""

    send_telegram_notification(message)

# ============================================================
# COMMANDS
# ============================================================

def cmd_list():
    """List all configured prefixes"""
    prefix_map = load_prefix_mapping()

    print(f"\n{c('CONFIGURED PREFIXES', Colors.BOLD)}")
    print("=" * 70)
    print(f"{'Prefix':<20} {'Description':<15} {'ASN':<10} {'Notes'}")
    print("-" * 70)

    for prefix, info in prefix_map.items():
        desc = info.get('description', 'N/A')
        asn = info.get('asn', 'N/A')
        note = info.get('note', '')

        if 'locked' in note.lower():
            note_str = c('[LOCKED]', Colors.YELLOW)
        elif ':' in prefix:
            note_str = c('[IPv6]', Colors.CYAN)
        else:
            note_str = ''

        print(f"{prefix:<20} {desc:<15} {asn:<10} {note_str}")

    print("=" * 70)
    print(f"Total: {len(prefix_map)} prefixes")

def cmd_status(prefix=None):
    """Show prefix status"""
    prefix_map = load_prefix_mapping()

    if prefix:
        # Status of a single prefix
        if prefix not in prefix_map:
            print(f"\n{c('ERROR', Colors.RED)}: Prefix '{prefix}' not found.")
            print("Use 'list' to see available prefixes.")
            return False

        info = prefix_map[prefix]
        prefix_id = info['prefix_id']
        bgp_prefix_id = info.get('bgp_prefix_id')

        print(f"\n{c('DETAILED STATUS', Colors.BOLD)}: {prefix}")
        print("=" * 60)
        print(f"Description: {info.get('description', 'N/A')}")
        print(f"ASN: {info.get('asn', 'N/A')}")
        print(f"Prefix ID: {prefix_id}")
        print(f"BGP Prefix ID: {bgp_prefix_id or 'N/A'}")

        if info.get('note'):
            print(f"Notes: {info.get('note')}")

        if not bgp_prefix_id:
            print(f"\n{c('ERROR', Colors.RED)}: No BGP Prefix ID configured")
            return False

        status = get_prefix_status(prefix_id, bgp_prefix_id)

        if not status['success']:
            print(f"\n{c('API ERROR', Colors.RED)}: {status.get('error')}")
            return False

        print("-" * 60)

        if status['locked']:
            print(f"Status: {c('LOCKED', Colors.YELLOW)} (on_demand_locked)")
        elif status['advertised']:
            print(f"Status: {c('ADVERTISED', Colors.GREEN)}")
        else:
            print(f"Status: {c('NOT ADVERTISED', Colors.BLUE)}")

        print(f"On-Demand Enabled: {'Yes' if status['enabled'] else 'No'}")
        print(f"Locked: {'Yes' if status['locked'] else 'No'}")

        if status['modified_at']:
            print(f"Last Modified: {status['modified_at']}")

            if status['advertised']:
                can_withdraw, remaining, withdraw_time = check_withdraw_constraint(status['modified_at'])
                if can_withdraw:
                    print(f"Withdraw: {c('AVAILABLE NOW', Colors.GREEN)}")
                else:
                    mins = int(remaining // 60)
                    secs = int(remaining % 60)
                    print(f"Withdraw: {c(f'Wait {mins}m {secs}s (available at {withdraw_time})', Colors.YELLOW)}")

        print("-" * 60)
        print("\nRAW API Data:")
        print(json.dumps(status['full_data'], indent=2))

        return True

    else:
        # Status of all prefixes
        print(f"\n{c('BGP PREFIX STATUS', Colors.BOLD)}")
        print("=" * 75)
        print(f"{'Prefix':<20} {'Status':<15} {'Description':<15} {'Withdraw'}")
        print("-" * 75)

        advertised_count = 0
        locked_count = 0

        for pfx, info in prefix_map.items():
            prefix_id = info['prefix_id']
            bgp_prefix_id = info.get('bgp_prefix_id')
            desc = info.get('description', 'N/A')

            if not bgp_prefix_id:
                print(f"{pfx:<20} {c('NO BGP ID', Colors.RED):<25} {desc:<15}")
                continue

            status = get_prefix_status(prefix_id, bgp_prefix_id)

            if not status['success']:
                print(f"{pfx:<20} {c('API ERROR', Colors.RED):<25} {desc:<15}")
                continue

            if status['locked']:
                locked_count += 1
                status_str = c('LOCKED', Colors.YELLOW)
                withdraw_str = c('N/A', Colors.YELLOW)
            elif status['advertised']:
                advertised_count += 1
                status_str = c('ADVERTISED', Colors.GREEN)

                can_withdraw, remaining, withdraw_time = check_withdraw_constraint(status['modified_at'])
                if can_withdraw:
                    withdraw_str = c('Now', Colors.GREEN)
                else:
                    mins = int(remaining // 60)
                    withdraw_str = c(f'{mins}m ({withdraw_time})', Colors.YELLOW)
            else:
                status_str = c('NOT ADVERT.', Colors.BLUE)
                withdraw_str = '-'

            # Manual padding for ANSI colors
            print(f"{pfx:<20} {status_str:<25} {desc:<15} {withdraw_str}")

        print("=" * 75)
        print(f"Total: {advertised_count} advertised, {locked_count} locked, {len(prefix_map) - advertised_count - locked_count} not advertised")

        if advertised_count > 0:
            print(f"\n{c('WARNING', Colors.YELLOW)}: {advertised_count} prefixes currently advertised")

        return True

def cmd_advertise(prefix=None, all_prefixes=False, force=False):
    """Advertise one or all prefixes"""
    prefix_map = load_prefix_mapping()
    operation_id = generate_operation_id()

    if all_prefixes:
        prefixes_to_advertise = list(prefix_map.keys())
        action_desc = "ALL PREFIXES"
    elif prefix:
        if prefix not in prefix_map:
            print(f"\n{c('ERROR', Colors.RED)}: Prefix '{prefix}' not found.")
            return False
        prefixes_to_advertise = [prefix]
        action_desc = prefix
    else:
        print(f"\n{c('ERROR', Colors.RED)}: Specify a prefix or use --all")
        return False

    print(f"\n{c('BGP ADVERTISEMENT', Colors.BOLD)}: {action_desc}")
    print(f"Operation ID: {operation_id}")
    print("=" * 60)

    if not force and all_prefixes:
        confirm = input(f"{c('WARNING', Colors.YELLOW)}: Advertise all prefixes? (y/N): ").lower()
        if confirm != 'y':
            print("Operation cancelled.")
            return False

    success_list = []
    failed_list = []
    skipped_list = []
    blocked_count = 0

    for pfx in prefixes_to_advertise:
        info = prefix_map[pfx]
        prefix_id = info['prefix_id']
        bgp_prefix_id = info.get('bgp_prefix_id')

        if not bgp_prefix_id:
            print(f"  {c('SKIP', Colors.YELLOW)} {pfx} - No BGP Prefix ID")
            skipped_list.append((pfx, "No BGP ID"))
            continue

        # Check current status
        status = get_prefix_status(prefix_id, bgp_prefix_id)

        if status['success'] and status['locked']:
            print(f"  {c('SKIP', Colors.YELLOW)} {pfx} - Prefix LOCKED")
            skipped_list.append((pfx, "Locked"))
            continue

        if status['success'] and status['advertised']:
            print(f"  {c('SKIP', Colors.BLUE)} {pfx} - Already advertised")
            skipped_list.append((pfx, "Already advertised"))
            continue

        # Check 15-minute constraint for re-advertise after withdrawal
        if status['success'] and not status['advertised']:
            can_advertise, remaining, advertise_time = check_advertise_constraint(status['modified_at'])

            if not can_advertise:
                mins = int(remaining // 60)
                secs = int(remaining % 60)
                print(f"  {c('BLOCKED', Colors.RED)} {pfx} - 15min constraint not satisfied")
                print(f"           Advertise available at {c(advertise_time, Colors.CYAN)} (in {mins}m {secs}s)")
                skipped_list.append((pfx, f"Wait until {advertise_time}"))
                blocked_count += 1
                continue

        # Advertise
        result = set_prefix_advertisement(prefix_id, bgp_prefix_id, True)

        if result['success']:
            print(f"  {c('OK', Colors.GREEN)} {pfx} - Advertised")
            success_list.append(pfx)

            # Log to database for dashboard visibility
            log_event_to_db('ADVERTISE', pfx, 'advertised_manual', info.get('description'), operation_id)

            # Send individual notification only if single prefix
            if not all_prefixes:
                notify_prefix_advertised(pfx, info, operation_id)
        else:
            print(f"  {c('FAIL', Colors.RED)} {pfx} - {result.get('error', 'Unknown error')}")
            failed_list.append(pfx)

    print("-" * 60)
    print(f"Completed: {len(success_list)} successful, {len(failed_list)} failed, {len(skipped_list)} skipped")

    if blocked_count > 0:
        print(f"\n{c('INFO', Colors.CYAN)}: {blocked_count} prefix(es) blocked by 15-minute Cloudflare constraint.")
        print("This is a mandatory limit - prefixes can only be re-advertised 15 minutes after withdrawal.")
        print("Run 'cloudflare-prefix-manager status' to check when advertisement will be available.")

    if success_list:
        print(f"\n{c('INFO', Colors.CYAN)}: BGP propagation takes 2-7 minutes")

        # Send bulk notification if multiple prefixes
        if all_prefixes and (success_list or failed_list):
            notify_bulk_operation("advertise", success_list, failed_list, skipped_list, operation_id)

    return len(failed_list) == 0 and blocked_count == 0

def cmd_withdraw(prefix=None, all_prefixes=False):
    """Withdraw one or all prefixes"""
    prefix_map = load_prefix_mapping()
    operation_id = generate_operation_id()

    if all_prefixes:
        prefixes_to_withdraw = list(prefix_map.keys())
        action_desc = "ALL PREFIXES"
    elif prefix:
        if prefix not in prefix_map:
            print(f"\n{c('ERROR', Colors.RED)}: Prefix '{prefix}' not found.")
            return False
        prefixes_to_withdraw = [prefix]
        action_desc = prefix
    else:
        print(f"\n{c('ERROR', Colors.RED)}: Specify a prefix or use --all")
        return False

    print(f"\n{c('BGP WITHDRAWAL', Colors.BOLD)}: {action_desc}")
    print(f"Operation ID: {operation_id}")
    print("=" * 60)

    if all_prefixes:
        confirm = input(f"{c('WARNING', Colors.YELLOW)}: Withdraw all prefixes? (y/N): ").lower()
        if confirm != 'y':
            print("Operation cancelled.")
            return False

    success_list = []
    failed_list = []
    skipped_list = []
    blocked_count = 0

    for pfx in prefixes_to_withdraw:
        info = prefix_map[pfx]
        prefix_id = info['prefix_id']
        bgp_prefix_id = info.get('bgp_prefix_id')

        if not bgp_prefix_id:
            print(f"  {c('SKIP', Colors.YELLOW)} {pfx} - No BGP Prefix ID")
            skipped_list.append((pfx, "No BGP ID"))
            continue

        # Check current status
        status = get_prefix_status(prefix_id, bgp_prefix_id)

        if status['success'] and status['locked']:
            print(f"  {c('SKIP', Colors.YELLOW)} {pfx} - Prefix LOCKED")
            skipped_list.append((pfx, "Locked"))
            continue

        if status['success'] and not status['advertised']:
            print(f"  {c('SKIP', Colors.BLUE)} {pfx} - Already not advertised")
            skipped_list.append((pfx, "Not advertised"))
            continue

        # Check 15-minute constraint - MANDATORY, no bypass
        advertised_duration = None
        if status['success'] and status['advertised']:
            can_withdraw, remaining, withdraw_time = check_withdraw_constraint(status['modified_at'])

            # Calculate how long it was advertised
            if status['modified_at']:
                try:
                    mod_time = datetime.fromisoformat(status['modified_at'].replace('Z', '+00:00'))
                    advertised_duration = (datetime.now(timezone.utc) - mod_time).total_seconds()
                except:
                    pass

            if not can_withdraw:
                mins = int(remaining // 60)
                secs = int(remaining % 60)
                print(f"  {c('BLOCKED', Colors.RED)} {pfx} - 15min constraint not satisfied")
                print(f"           Withdraw available at {c(withdraw_time, Colors.CYAN)} (in {mins}m {secs}s)")
                skipped_list.append((pfx, f"Wait until {withdraw_time}"))
                blocked_count += 1
                continue

        # Withdraw
        result = set_prefix_advertisement(prefix_id, bgp_prefix_id, False)

        if result['success']:
            print(f"  {c('OK', Colors.GREEN)} {pfx} - Withdrawn")
            success_list.append(pfx)

            # Log to database for dashboard visibility
            log_event_to_db('WITHDRAW', pfx, 'withdrawn_manual', info.get('description'), operation_id)

            # Send individual notification only if single prefix
            if not all_prefixes:
                notify_prefix_withdrawn(pfx, info, operation_id, advertised_duration)
        else:
            print(f"  {c('FAIL', Colors.RED)} {pfx} - {result.get('error', 'Unknown error')}")
            failed_list.append(pfx)

    print("-" * 60)
    print(f"Completed: {len(success_list)} successful, {len(failed_list)} failed, {len(skipped_list)} skipped")

    if blocked_count > 0:
        print(f"\n{c('INFO', Colors.CYAN)}: {blocked_count} prefix(es) blocked by 15-minute Cloudflare constraint.")
        print("This is a mandatory limit - prefixes can only be withdrawn 15 minutes after advertisement.")
        print("Run 'cloudflare-prefix-manager status' to check when withdrawal will be available.")

    # Send bulk notification if multiple prefixes
    if all_prefixes and (success_list or failed_list):
        notify_bulk_operation("withdraw", success_list, failed_list, skipped_list, operation_id)

    return len(failed_list) == 0 and blocked_count == 0

def cmd_interactive():
    """Interactive menu"""
    while True:
        print(f"\n{'=' * 60}")
        print(f"{c('CLOUDFLARE BGP PREFIX MANAGER', Colors.BOLD)}")
        print(f"{'=' * 60}")
        print("1. Show status of all prefixes")
        print("2. Show status of specific prefix")
        print("3. Advertise prefix")
        print("4. Withdraw prefix")
        print("5. Advertise ALL prefixes")
        print("6. Withdraw ALL prefixes")
        print("7. List configured prefixes")
        print("0. Exit")
        print("-" * 60)

        choice = input("Select: ").strip()

        if choice == "1":
            cmd_status()

        elif choice == "2":
            prefix = input("Enter prefix (e.g. 185.54.82.0/24): ").strip()
            cmd_status(prefix)

        elif choice == "3":
            prefix = input("Enter prefix to advertise: ").strip()
            cmd_advertise(prefix)

        elif choice == "4":
            prefix = input("Enter prefix to withdraw: ").strip()
            cmd_withdraw(prefix)

        elif choice == "5":
            cmd_advertise(all_prefixes=True)

        elif choice == "6":
            cmd_withdraw(all_prefixes=True)

        elif choice == "7":
            cmd_list()

        elif choice == "0":
            print("\nExiting...")
            break

        else:
            print(f"\n{c('Invalid option', Colors.RED)}")

# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Cloudflare BGP Prefix Manager - Magic Transit prefix management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s status                    # Status of all prefixes
  %(prog)s status 185.54.82.0/24     # Detailed status
  %(prog)s advertise 185.54.82.0/24  # Advertise prefix
  %(prog)s advertise --all           # Advertise all
  %(prog)s withdraw 185.54.82.0/24   # Withdraw prefix (15min constraint)
  %(prog)s withdraw --all            # Withdraw all (15min constraint)
  %(prog)s list                      # List prefixes
  %(prog)s                           # Interactive menu

Note: Withdrawal is blocked until 15 minutes after advertisement (Cloudflare constraint).
"""
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # status
    status_parser = subparsers.add_parser('status', help='Show prefix status')
    status_parser.add_argument('prefix', nargs='?', help='Specific prefix (optional)')

    # advertise
    adv_parser = subparsers.add_parser('advertise', help='Advertise prefix')
    adv_parser.add_argument('prefix', nargs='?', help='Prefix to advertise')
    adv_parser.add_argument('--all', '-a', action='store_true', help='Advertise all prefixes')
    adv_parser.add_argument('--force', '-f', action='store_true', help='Skip confirmation')

    # withdraw
    with_parser = subparsers.add_parser('withdraw', help='Withdraw prefix')
    with_parser.add_argument('prefix', nargs='?', help='Prefix to withdraw')
    with_parser.add_argument('--all', '-a', action='store_true', help='Withdraw all prefixes')

    # list
    subparsers.add_parser('list', help='List configured prefixes')

    args = parser.parse_args()

    if args.command == 'status':
        cmd_status(args.prefix)

    elif args.command == 'advertise':
        if not args.prefix and not args.all:
            print(f"\n{c('ERROR', Colors.RED)}: Specify a prefix or use --all")
            sys.exit(1)
        success = cmd_advertise(args.prefix, args.all, args.force)
        sys.exit(0 if success else 1)

    elif args.command == 'withdraw':
        if not args.prefix and not args.all:
            print(f"\n{c('ERROR', Colors.RED)}: Specify a prefix or use --all")
            sys.exit(1)
        success = cmd_withdraw(args.prefix, args.all)
        sys.exit(0 if success else 1)

    elif args.command == 'list':
        cmd_list()

    else:
        cmd_interactive()

if __name__ == "__main__":
    main()
