#!/usr/bin/env python3
"""
Webhook Receiver per Cloudflare DDoS Protection
Riceve notifiche real-time da Cloudflare per:
- DDoS attacks (L3/L4/L7)
- Magic Network Monitoring alerts
- Tunnel health checks
- Auto BGP advertisement

Version: 1.9.1
Changelog:
- 1.9.1: Added Telegram retry mechanism (3 attempts with exponential backoff)
         Fixes missed notifications due to Telegram API timeouts
- 1.9.0: Added database logging for all webhook handlers (L7, tunnel, incident, health, BGP hijack)
- 1.8.0: Added database logging for auto-advertisement events (fbm_auto_advertisement)
         DDoS L4 attacks now show action_taken='mitigating' instead of 'notified'
- 1.7.0: Added database logging for MNM alerts (fbm_dosd_attack, fbm_volumetric_attack)
         These events now appear in dashboard "Recent Attacks" section
- 1.6.0: Added precise prefix matching with ipaddress module,
         improved immediate withdrawal failure handling
- 1.5.0: Added webhook logging to database
- 1.0.0: Initial version
"""

import json
import logging
import hashlib
import hmac
import time
import random
import string
import ipaddress
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
import requests
from pathlib import Path
import sys

# Aggiungi il percorso per importare i moduli esistenti
sys.path.append(str(Path(__file__).parent))

# Import database manager
from db_manager import (
    init_database, log_attack_event, mark_withdrawn,
    log_webhook_event
)

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/root/Cloudflare_MT_Integration/logs/webhook.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__)

# Carica configurazione
CONFIG_PATH = Path("/root/Cloudflare_MT_Integration/config/settings.json")
PREFIX_MAP_PATH = Path("/root/Cloudflare_MT_Integration/config/prefix_mapping.json")

def load_config():
    """Carica la configurazione"""
    with open(CONFIG_PATH) as f:
        return json.load(f)

def load_prefix_mapping():
    """Carica mapping dei prefissi"""
    with open(PREFIX_MAP_PATH) as f:
        return json.load(f)

# Carica configurazioni
config = load_config()
prefix_mapping = load_prefix_mapping()

# Initialize database
init_database()
logger.info("Database initialized")

# Configurazione webhook
WEBHOOK_SECRET = config.get('cloudflare', {}).get('webhook_secret', '')
TELEGRAM_BOT_TOKEN = config['telegram']['bot_token']
TELEGRAM_CHAT_ID = config['telegram']['chat_id']

def verify_webhook_signature(payload, signature):
    """Verifica la firma del webhook Cloudflare."""
    if not WEBHOOK_SECRET:
        logger.warning("Webhook secret not configured - signature not verified")
        return True
    return hmac.compare_digest(signature, WEBHOOK_SECRET)

def send_telegram_notification(message, max_retries=3):
    """Invia notifica Telegram (Markdown format) con retry mechanism"""
    import time as time_module
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True
    }

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(url, json=data, timeout=30)
            if response.status_code == 200:
                if attempt > 1:
                    logger.info(f"Telegram notification sent (attempt {attempt}/{max_retries})")
                else:
                    logger.info("Telegram notification sent")
                return True
            else:
                logger.error(f"Telegram error: {response.text} (attempt {attempt}/{max_retries})")
        except Exception as e:
            logger.error(f"Telegram error: {e} (attempt {attempt}/{max_retries})")

        # Wait before retry (exponential backoff: 5s, 10s, 20s)
        if attempt < max_retries:
            wait_time = 5 * (2 ** (attempt - 1))
            logger.info(f"Retrying Telegram in {wait_time}s...")
            time_module.sleep(wait_time)

    logger.error(f"Telegram notification failed after {max_retries} attempts")
    return False

def generate_alert_id():
    """Genera un ID univoco per l'alert"""
    return datetime.now().strftime("%Y%m%d%H%M%S") + '-' + ''.join(random.choices(string.hexdigits[:16], k=6))

def format_rate(value, unit="pps"):
    """Formatta i valori di rate in modo leggibile"""
    try:
        num = float(str(value).replace(',', '').replace(' pps', '').replace(' rps', ''))
        if num >= 1_000_000:
            return f"{num/1_000_000:.2f}M {unit}"
        elif num >= 1_000:
            return f"{num/1_000:.2f}K {unit}"
        return f"{num:.0f} {unit}"
    except:
        return str(value)

def format_bandwidth(mbps):
    """Formatta la banda in modo leggibile"""
    try:
        num = float(mbps)
        if num >= 1000:
            return f"{num/1000:.2f} Gbps"
        return f"{num:.2f} Mbps"
    except:
        return str(mbps)

def get_prefix_from_ip(target_ip):
    """
    Identifica il prefisso BGP dall'IP target usando matching CIDR preciso.
    Uses Python's ipaddress module for accurate network containment check.
    """
    if not target_ip or target_ip == 'N/A':
        return None

    try:
        # Strip CIDR suffix if present (e.g., "185.54.82.4/32" -> "185.54.82.4")
        if '/' in target_ip:
            target_ip = target_ip.split('/')[0]

        ip = ipaddress.ip_address(target_ip)

        # Find the most specific (longest) matching prefix
        best_match = None
        best_prefix_len = -1

        for prefix in prefix_mapping['prefixes'].keys():
            try:
                network = ipaddress.ip_network(prefix, strict=False)
                if ip in network:
                    # Keep the most specific match (longest prefix)
                    if network.prefixlen > best_prefix_len:
                        best_match = prefix
                        best_prefix_len = network.prefixlen
            except ValueError:
                # Invalid prefix format, skip
                continue

        return best_match

    except ValueError:
        # Invalid IP address
        logger.warning(f"Invalid IP address format: {target_ip}")
        return None

def manage_prefix_advertisement(prefix, advertise=True):
    """Gestisce l'annuncio/ritiro di un prefisso"""
    try:
        if prefix not in prefix_mapping['prefixes']:
            logger.warning(f"Prefix {prefix} not found in mapping")
            return False

        prefix_info = prefix_mapping['prefixes'][prefix]

        if not prefix_info.get('bgp_prefix_id'):
            logger.warning(f"Prefix {prefix} has no BGP prefix configured")
            return False

        url = (f"https://api.cloudflare.com/client/v4/accounts/"
               f"{config['cloudflare']['account_id']}/addressing/prefixes/"
               f"{prefix_info['prefix_id']}/bgp/prefixes/{prefix_info['bgp_prefix_id']}")

        headers = {
            "Authorization": f"Bearer {config['cloudflare']['api_token']}",
            "Content-Type": "application/json"
        }

        data = {"on_demand": {"advertised": advertise}}
        response = requests.patch(url, headers=headers, json=data, timeout=30)

        if response.status_code == 200:
            action = "advertised" if advertise else "withdrawn"
            logger.info(f"Prefix {prefix} {action} successfully")
            return True
        else:
            logger.error(f"Error managing prefix {prefix}: {response.text}")
            return False

    except Exception as e:
        logger.error(f"Error managing prefix {prefix}: {e}")
        return False

def get_prefix_withdraw_status(prefix):
    """Verifica se un prefisso può essere ritirato (15 min constraint)"""
    if prefix not in prefix_mapping['prefixes']:
        return False, 0, None

    prefix_info = prefix_mapping['prefixes'][prefix]
    if not prefix_info.get('bgp_prefix_id'):
        return False, 0, None

    url = (f"https://api.cloudflare.com/client/v4/accounts/"
           f"{config['cloudflare']['account_id']}/addressing/prefixes/"
           f"{prefix_info['prefix_id']}/bgp/prefixes/{prefix_info['bgp_prefix_id']}")

    headers = {
        "Authorization": f"Bearer {config['cloudflare']['api_token']}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            result = response.json().get('result', {})
            on_demand = result.get('on_demand', {})

            if not on_demand.get('advertised'):
                return True, 0, None

            modified_at = on_demand.get('advertised_modified_at')
            if modified_at:
                mod_time = datetime.fromisoformat(modified_at.replace('Z', '+00:00'))
                withdraw_time = mod_time + timedelta(minutes=15)
                now = datetime.now(timezone.utc)

                if now >= withdraw_time:
                    return True, 0, modified_at
                else:
                    remaining = (withdraw_time - now).total_seconds()
                    return False, remaining, modified_at
    except Exception as e:
        logger.error(f"Error checking prefix status {prefix}: {e}")

    return False, 0, None


# ============================================================
# ALERT HANDLERS
# ============================================================

def handle_ddos_l4_attack(payload, is_advanced=True):
    """
    Handle Layer 3/4 DDoS Attack alerts
    alert_type: advanced_ddos_attack_l4_alert, dos_attack_l4
    """
    data = payload.get('data', {})
    alert_id = generate_alert_id()

    # Extract fields
    attack_id = data.get('attack_id', 'N/A')
    attack_vector = data.get('attack_vector', 'Unknown')
    target_ip = data.get('target_ip', 'N/A')
    target_port = data.get('target_port', 'N/A')
    protocol = data.get('protocol', 'N/A')
    pps = data.get('packets_per_second', data.get('max_rate', '0'))
    mbps = data.get('megabits_per_second', '0')
    action = data.get('action', 'N/A')
    mitigation = data.get('mitigation', 'N/A')
    rule_name = data.get('rule_name', 'N/A')
    start_time = data.get('start_time', 'N/A')
    dashboard_link = data.get('dashboard_link', '')
    severity = data.get('severity', 'INFO')

    # Identify prefix
    target_prefix = get_prefix_from_ip(target_ip)

    # Build message
    alert_type_str = "Advanced L3/L4" if is_advanced else "L3/L4"

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

🚨 *{alert_type_str} DDoS ATTACK*

🔖 *Alert ID:* `{alert_id}`
⚠️ *Severity:* {severity}

⚔️ *ATTACK INFO*
🆔 *Attack ID:* `{attack_id}`
💥 *Vector:* {attack_vector}
🔧 *Protocol:* {protocol}
🛡️ *Action:* {action}
🔒 *Mitigation:* {mitigation}

📊 *TRAFFIC METRICS*
📦 *Packets:* {format_rate(pps, 'pps')}
📈 *Bandwidth:* {format_bandwidth(mbps)}
⏱️ *Start:* {start_time}

🎯 *TARGET*
🌐 *IP:* `{target_ip}`
🔌 *Port:* {target_port}"""

    if target_prefix:
        message += f"""
📡 *Prefix:* `{target_prefix}`

🔄 *BGP STATUS*
✅ Auto-advertised by Cloudflare
🛡️ Traffic scrubbing active"""

    if rule_name != 'N/A':
        message += f"""

📋 *RULE:* {rule_name}"""

    message += f"""

🏢 *GOLINE SOC* | _Cloudflare Magic Transit_"""

    send_telegram_notification(message)
    logger.info(f"L4 DDoS Alert: {attack_id} - {target_ip} - {format_bandwidth(mbps)}")

    # Log attack START event to database
    # DDoS L4 attacks trigger automatic BGP advertisement and mitigation by Cloudflare
    log_attack_event('START', payload, prefix=target_prefix, action_taken='mitigating')


def handle_ddos_l7_attack(payload):
    """
    Handle Layer 7 HTTP DDoS Attack alerts
    alert_type: dos_attack_l7
    """
    data = payload.get('data', {})
    alert_id = generate_alert_id()

    # Extract fields
    attack_id = data.get('attack_id', 'N/A')
    attack_type = data.get('attack_type', 'Unknown')
    target_hostname = data.get('target_hostname', data.get('target_zone_name', 'N/A'))
    rps = data.get('requests_per_second', data.get('max_rate', '0'))
    action = data.get('action', 'N/A')
    mitigation = data.get('mitigation', 'N/A')
    rule_desc = data.get('rule_description', 'N/A')
    start_time = data.get('start_time', 'N/A')
    severity = data.get('severity', 'INFO')

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

🚨 *HTTP DDoS ATTACK (Layer 7)*

🔖 *Alert ID:* `{alert_id}`
⚠️ *Severity:* {severity}

⚔️ *ATTACK INFO*
🆔 *Attack ID:* `{attack_id}`
💥 *Attack Type:* {attack_type}
🛡️ *Action:* {action}
🔒 *Mitigation:* {mitigation}

📊 *TRAFFIC METRICS*
🌐 *Requests:* {format_rate(rps, 'rps')}
⏱️ *Start:* {start_time}

🎯 *TARGET*
🌍 *Hostname:* `{target_hostname}`

📋 *RULE:* {rule_desc}

🏢 *GOLINE SOC* | _Cloudflare Magic Transit_"""

    send_telegram_notification(message)
    logger.info(f"L7 DDoS Alert: {attack_id} - {target_hostname} - {format_rate(rps, 'rps')}")

    # Log to database
    log_attack_event('START', payload, action_taken='mitigating')


def handle_mnm_ddos_attack(payload):
    """
    Handle Magic Network Monitoring DDoS Attack alerts
    alert_type: fbm_dosd_attack
    """
    data = payload.get('data', {})
    alert_id = generate_alert_id()

    # Extract fields
    target_ip = data.get('target_ip', 'N/A')
    target_port = data.get('target_port', 'N/A')
    attack_type = data.get('attack_type', 'Unknown')
    protocol = data.get('protocol', 'N/A')
    pps = data.get('packets_per_second', '0')
    mbps = data.get('megabits_per_second', '0')
    max_rate = data.get('max_rate', 'N/A')
    rule_name = data.get('rule_name', 'N/A')
    start_time = data.get('start_time', 'N/A')
    auto_advertised = data.get('auto_advertised', False)
    advertise_status = data.get('advertise_status', [])
    severity = data.get('severity', 'INFO')

    target_prefix = get_prefix_from_ip(target_ip)

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

🚨 *DDoS ATTACK (Magic Network Monitoring)*

🔖 *Alert ID:* `{alert_id}`
⚠️ *Severity:* {severity}

⚔️ *ATTACK INFO*
💥 *Attack Type:* {attack_type}
🔧 *Protocol:* {protocol}
📋 *Rule:* {rule_name}

📊 *TRAFFIC METRICS*
📦 *Packets:* {format_rate(pps, 'pps')}
📈 *Bandwidth:* {format_bandwidth(mbps)}
📊 *Max Rate:* {max_rate}
⏱️ *Start:* {start_time}

🎯 *TARGET*
🌐 *IP:* `{target_ip}`
🔌 *Port:* {target_port}"""

    if target_prefix:
        message += f"""
📡 *Prefix:* `{target_prefix}`"""

    message += f"""

🔄 *BGP ADVERTISEMENT*
🤖 *Auto-advertise:* {'Enabled' if auto_advertised else 'Disabled'}"""

    for adv in advertise_status:
        status_icon = "✅" if adv.get('status') == 'advertised' else "⏳"
        message += f"""
{status_icon} `{adv.get('prefix', 'N/A')}`: {adv.get('status', 'N/A')}"""

    message += f"""

🏢 *GOLINE SOC* | _Cloudflare Magic Transit_"""

    send_telegram_notification(message)
    logger.info(f"MNM DDoS Alert: {target_ip} - {attack_type} - {format_bandwidth(mbps)}")

    # Log attack START event to database (v1.7.0)
    log_attack_event('START', payload, prefix=target_prefix, action_taken='notified')


def handle_volumetric_attack(payload):
    """
    Handle Magic Network Monitoring Volumetric Attack alerts
    alert_type: fbm_volumetric_attack
    """
    data = payload.get('data', {})
    alert_id = generate_alert_id()

    # Extract fields
    rule_name = data.get('rule_name', 'N/A')
    rule_threshold = data.get('rule_threshold', 'N/A')
    rule_duration = data.get('rule_duration', 'N/A')
    rule_sensitivity = data.get('rule_zscore_sensitivity', '')
    pps = data.get('packets_per_second', '0')
    pps_string = data.get('packets_per_second_string', format_rate(pps, 'pps'))
    # Use bits_per_second (pre-formatted like "6.4Gb/s") if available, else format megabits_per_second
    bps_string = data.get('bits_per_second', '')
    if bps_string:
        bandwidth_str = bps_string
    else:
        mbps = data.get('megabits_per_second', '0')
        bandwidth_str = format_bandwidth(mbps)
    start_time = data.get('start_time', 'N/A')
    auto_advertised = data.get('auto_advertised', False)
    severity = data.get('severity', 'INFO')

    # Extract prefix for database logging (v1.7.0)
    target_prefix = data.get('prefix') or None
    if not target_prefix:
        target_ip = data.get('target_ip')
        if target_ip:
            target_prefix = get_prefix_from_ip(target_ip)

    # Build sensitivity line only if present (only for ZScore rules)
    sensitivity_line = f"\n🎚️ *Sensitivity:* {rule_sensitivity}" if rule_sensitivity else ""

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

⚠️ *VOLUMETRIC ALERT*

🔖 *Alert ID:* `{alert_id}`
⚠️ *Severity:* {severity}

📋 *RULE TRIGGERED*
📛 *Rule Name:* {rule_name}
📊 *Threshold:* {rule_threshold}
⏱️ *Duration:* {rule_duration}{sensitivity_line}

📊 *CURRENT TRAFFIC*
📦 *Packets:* {pps_string}
📈 *Bandwidth:* {bandwidth_str}
⏱️ *Time:* {start_time}

🔄 *BGP STATUS*
🤖 *Auto-advertise:* {'Enabled' if auto_advertised else 'Disabled'}

🏢 *GOLINE SOC* | _Cloudflare Magic Transit_"""

    send_telegram_notification(message)
    logger.info(f"Volumetric Alert: {rule_name} - {pps_string}")

    # Log attack START event to database (v1.7.0)
    log_attack_event('START', payload, prefix=target_prefix, action_taken='notified')


def handle_auto_advertisement(payload):
    """
    Handle Auto BGP Advertisement notifications
    alert_type: fbm_auto_advertisement
    """
    data = payload.get('data', {})
    alert_id = generate_alert_id()

    # Extract fields
    rule_name = data.get('rule_name', 'N/A')
    advertise_status = data.get('advertise_status', [])
    attack_type = data.get('attack_type', '')
    start_time = data.get('start_time')

    # Get timestamp from payload if start_time not available
    ts = payload.get('ts')
    if start_time:
        time_str = start_time
    elif ts:
        from datetime import datetime
        time_str = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')
    else:
        time_str = 'N/A'

    # Build optional attack type line
    attack_line = f"\n💥 *Attack Type:* {attack_type}" if attack_type else ""

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

📡 *AUTO BGP ADVERTISEMENT*

🔖 *Alert ID:* `{alert_id}`

📋 *TRIGGER*{attack_line}
📋 *Rule:* {rule_name}
⏱️ *Time:* {time_str}

📡 *PREFIX ADVERTISEMENT STATUS*"""

    for adv in advertise_status:
        prefix = adv.get('prefix', 'N/A')
        status = adv.get('status', 'N/A')
        if status.lower() in ['advertised', 'success', 'active']:
            status_icon = "✅"
        elif status.lower() in ['pending', 'in_progress']:
            status_icon = "⏳"
        else:
            status_icon = "❌"
        message += f"""
{status_icon} `{prefix}`: {status}"""

    message += f"""

🏢 *GOLINE SOC* | _Cloudflare Magic Transit_"""

    send_telegram_notification(message)
    logger.info(f"Auto Advertisement: {len(advertise_status)} prefixes")

    # Log each prefix advertisement to database (v1.8.0)
    for adv in advertise_status:
        prefix = adv.get('prefix')
        status = adv.get('status', '').lower()
        if prefix and status in ['advertised', 'success', 'active', 'already advertised']:
            # Create a modified payload for logging
            adv_payload = payload.copy()
            adv_payload['data'] = adv_payload.get('data', {}).copy()
            adv_payload['data']['prefix'] = prefix
            log_attack_event('ADVERTISE', adv_payload, prefix=prefix, action_taken='auto_advertised')


def handle_tunnel_health(payload):
    """
    Handle Magic Tunnel Health Check events
    alert_type: magic_tunnel_health_check_event
    """
    data = payload.get('data', {})
    alert_id = generate_alert_id()
    alert_event = payload.get('alert_event', '')

    # Extract fields
    tunnel_name = data.get('tunnel_name', 'N/A')
    tunnel_id = data.get('tunnel_id', 'N/A')
    new_status = data.get('new_status', 'N/A')
    previous_status = data.get('previous_status', 'N/A')
    pop_names = data.get('pop_names', 'N/A')
    slo = data.get('slo', 'N/A')
    observed_slo = data.get('observed_slo', 'N/A')
    site_name = data.get('mwan_site_name', 'N/A')
    event_ts = data.get('event_ts', 'N/A')
    severity = data.get('severity', 'INFO')

    # Determine status icons
    is_down = 'DOWN' in str(new_status).upper()
    status_icon = "🔴" if is_down else "🟢"
    status_text = "DOWN" if is_down else "UP"
    alert_emoji = "🚨🚨🚨" if is_down else "✅✅✅"
    alert_title = "TUNNEL DOWN" if is_down else "TUNNEL RECOVERED"

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

{alert_emoji} *{alert_title}*

🔖 *Alert ID:* `{alert_id}`
⚠️ *Severity:* {severity}

🔗 *TUNNEL INFO*
📛 *Name:* {tunnel_name}
🆔 *ID:* `{tunnel_id}`
🏢 *Site:* {site_name}

📊 *STATUS*
{status_icon} *Current:* {status_text}
🔄 *Previous:* {previous_status.replace('MAGIC_TUNNEL_STATUS_', '')}
🌍 *PoPs:* {pop_names}

📈 *SLO METRICS*
🎯 *Target SLO:* {slo}%
📊 *Current SLI:* {observed_slo}%
⏱️ *Time:* {event_ts}

🏢 *GOLINE SOC* | _Cloudflare Magic Transit_"""

    send_telegram_notification(message)
    logger.info(f"Tunnel Health: {tunnel_name} - {status_text}")

    # Log to database
    log_attack_event('START', payload, action_taken='notified')


def handle_attack_end(payload):
    """
    Handle attack end events - notification only.
    BGP withdraw is handled by cloudflare-autowithdraw.service.

    Note: This function no longer performs withdraw or scheduling.
    The autowithdraw daemon monitors for calm periods and handles
    all BGP withdrawals automatically.
    """
    data = payload.get('data', {})
    alert_id = generate_alert_id()

    attack_id = data.get('attack_id', 'N/A')
    target_ip = data.get('target_ip', 'N/A')

    ts = payload.get('ts', 0)
    end_time = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else datetime.now(timezone.utc)
    end_str = end_time.strftime('%Y-%m-%d %H:%M:%S UTC')

    target_prefix = get_prefix_from_ip(target_ip)

    # Log attack END event to database
    log_attack_event('END', payload, prefix=target_prefix, action_taken='notified_autowithdraw_handles')

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

✅ *ATTACK MITIGATED*

🔖 *Alert ID:* `{alert_id}`
✅ *Status:* 🟢 ATTACK ENDED

📋 *ATTACK SUMMARY*
🆔 *Attack ID:* `{attack_id}`
🌐 *Target IP:* `{target_ip}`
⏱️ *End Time:* {end_str}"""

    if target_prefix:
        message += f"""

📡 *BGP PREFIX STATUS*
🌐 *Prefix:* `{target_prefix}`
🤖 *Action:* Auto-withdraw pending
⏳ *Method:* Autowithdraw daemon (15 min calm period)
ℹ️ Prefix will be withdrawn automatically when no attacks detected for 15 minutes"""
    else:
        message += f"""

⚠️ Prefix not identified for IP `{target_ip}`"""

    message += f"""

🏢 *GOLINE SOC* | _Cloudflare Magic Transit_"""

    send_telegram_notification(message)
    logger.info(f"Attack ended: {attack_id} - withdraw delegated to autowithdraw service")


def handle_incident_alert(payload):
    """
    Handle Cloudflare Status Page Incident alerts
    alert_type: incident_alert
    """
    data = payload.get('data', {})
    alert_id = generate_alert_id()

    # Extract fields
    incident_name = data.get('incident_name', 'N/A')
    incident_id = data.get('incident_id', 'N/A')
    incident_status = data.get('incident_status', 'N/A').replace('INCIDENT_STATUS_', '')
    incident_impact = data.get('incident_impact', 'N/A').replace('INCIDENT_IMPACT_', '')
    message_text = data.get('message', 'N/A')
    created_at = data.get('created_at', 'N/A')
    affected_components = data.get('affected_components', [])
    severity = data.get('severity', 'INFO')

    # Determine emoji based on impact
    if incident_impact == 'CRITICAL':
        impact_emoji = "🔴"
    elif incident_impact == 'MAJOR':
        impact_emoji = "🟠"
    elif incident_impact == 'MINOR':
        impact_emoji = "🟡"
    else:
        impact_emoji = "🟢"

    # Status emoji
    if incident_status == 'RESOLVED':
        status_emoji = "✅"
    elif incident_status == 'MONITORING':
        status_emoji = "👀"
    elif incident_status == 'INVESTIGATING':
        status_emoji = "🔍"
    else:
        status_emoji = "⚠️"

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

🌐 *CLOUDFLARE INCIDENT*

🔖 *Alert ID:* `{alert_id}`
{impact_emoji} *Impact:* {incident_impact}
{status_emoji} *Status:* {incident_status}

📋 *INCIDENT DETAILS*
📛 *Name:* {incident_name}
🆔 *ID:* `{incident_id}`
⏱️ *Created:* {created_at}

💬 *Message:*
{message_text}

🔧 *AFFECTED COMPONENTS*"""

    for comp in affected_components:
        message += f"""
• {comp.get('name', 'N/A')}"""

    if not affected_components:
        message += """
• None specified"""

    message += f"""

🔗 [View on Status Page](https://www.cloudflarestatus.com/incidents/{incident_id})

🏢 *GOLINE SOC* | _Cloudflare Status_"""

    send_telegram_notification(message)
    logger.info(f"Incident Alert: {incident_id} - {incident_status} - {incident_impact}")

    # Log to database
    log_attack_event('START', payload, action_taken='notified')


def handle_health_check_alert(payload):
    """
    Handle Origin Health Check Status notifications
    alert_type: health_check_status_notification
    """
    data = payload.get('data', {})
    alert_id = generate_alert_id()

    # Extract fields
    name = data.get('name', 'N/A')
    health_check_id = data.get('health_check_id', 'N/A')
    status = data.get('status', 'N/A')
    reason = data.get('reason', 'N/A')
    expected_codes = data.get('expected_codes', 'N/A')
    actual_code = data.get('actual_code', 'N/A')
    check_time = data.get('time', 'N/A')
    is_preview = data.get('preview', False)
    severity = data.get('severity', 'INFO')

    # Status emoji
    if status.lower() == 'healthy':
        status_emoji = "🟢"
        alert_emoji = "✅"
    elif status.lower() == 'unhealthy':
        status_emoji = "🔴"
        alert_emoji = "🚨"
    else:
        status_emoji = "🟡"
        alert_emoji = "⚠️"

    preview_tag = " \\[PREVIEW]" if is_preview else ""

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

{alert_emoji} *HEALTH CHECK{preview_tag}*

🔖 *Alert ID:* `{alert_id}`
{status_emoji} *Status:* {status}

🔍 *CHECK DETAILS*
📛 *Name:* {name}
🆔 *ID:* `{health_check_id}`
⏱️ *Time:* {check_time}

📊 *RESPONSE*
✅ *Expected:* {expected_codes}
📥 *Received:* {actual_code}
💬 *Reason:* {reason}

🏢 *GOLINE SOC* | _Cloudflare Health Checks_"""

    send_telegram_notification(message)
    logger.info(f"Health Check: {name} - {status} - Code {actual_code}")

    # Log to database
    log_attack_event('START', payload, action_taken='notified')


def handle_bgp_hijack_alert(payload):
    """
    Handle BGP Hijack / Route Leak Detection alerts
    alert_type: bgp_hijack_notification
    THIS IS CRITICAL - BGP hijacks are serious security events!
    """
    data = payload.get('data', {})
    alert_id = generate_alert_id()

    # Extract fields
    alert_title = data.get('alert_title', 'N/A')
    priority_level = data.get('alert_priority_level', 'N/A')
    prefix_configured = data.get('prefix_configured', 'N/A')
    prefix_hijacked = data.get('prefix_hijacked', 'N/A')
    hijack_as = data.get('hijack_as', 'N/A')
    asns_seen = data.get('ASNs_seen', [])
    start_time = data.get('alert_start_time', 'N/A')
    additional_info = data.get('additional_info', 'N/A')
    dashboard_link = data.get('dashboard_link', '')
    account_name = data.get('account_name', 'N/A')
    severity = data.get('severity', 'INFO')

    # Priority emoji
    if priority_level == 'CRITICAL':
        priority_emoji = "🔴"
        alert_header = "🚨🚨🚨 *CRITICAL: BGP HIJACK DETECTED* 🚨🚨🚨"
    elif priority_level == 'HIGH':
        priority_emoji = "🟠"
        alert_header = "🚨 *HIGH: BGP HIJACK DETECTED*"
    else:
        priority_emoji = "🟡"
        alert_header = "⚠️ *BGP HIJACK DETECTED*"

    asns_list = ", ".join(asns_seen) if asns_seen else "N/A"

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

{alert_header}

🔖 *Alert ID:* `{alert_id}`
{priority_emoji} *Priority:* {priority_level}
🏢 *Account:* {account_name}

📋 *HIJACK DETAILS*
📛 *Title:* {alert_title}
⏱️ *Detected:* {start_time}

🌐 *PREFIX INFO*
✅ *Configured:* `{prefix_configured}`
❌ *Hijacked:* `{prefix_hijacked}`

🏴‍☠️ *HIJACKER*
🔢 *Hijack AS:* `{hijack_as}`
📡 *ASNs Advertising:* {asns_list}

ℹ️ *Additional Info:*
{additional_info}

🔗 [View Dashboard](https://{dashboard_link})

🏢 *GOLINE SOC* | _Cloudflare Route Leak Detection_"""

    send_telegram_notification(message)
    logger.info(f"BGP HIJACK ALERT: {prefix_hijacked} - AS {hijack_as} - {priority_level}")

    # Log to database - BGP hijacks are critical security events
    log_attack_event('START', payload, prefix=prefix_hijacked, action_taken='notified')


def handle_unknown_alert(payload):
    """Handle unknown/unrecognized alert types"""
    alert_type = payload.get('alert_type', 'unknown')
    policy_name = payload.get('policy_name', 'N/A')
    alert_event = payload.get('alert_event', 'N/A')
    name = payload.get('name', 'N/A')

    message = f"""🛡️ *CLOUDFLARE DDoS PROTECTION*

ℹ️ *CLOUDFLARE NOTIFICATION*

📋 *WEBHOOK RECEIVED*
📛 *Name:* {name}
🏷️ *Policy:* {policy_name}
🔔 *Type:* `{alert_type}`
📌 *Event:* `{alert_event}`

🏢 *GOLINE SOC* | _Cloudflare Magic Transit_"""

    send_telegram_notification(message)
    logger.info(f"Unknown alert: {alert_type} - {policy_name}")


# ============================================================
# FLASK ROUTES
# ============================================================

@app.route('/webhook/cloudflare', methods=['POST'])
def cloudflare_webhook():
    """Main webhook endpoint for Cloudflare notifications"""
    try:
        # Verify signature
        signature = request.headers.get('cf-webhook-auth', '')
        if WEBHOOK_SECRET and not verify_webhook_signature(request.data, signature):
            logger.warning("Invalid webhook signature")
            return jsonify({"error": "Invalid signature"}), 403

        # Parse payload
        payload = request.json
        alert_type = payload.get('alert_type', '')
        alert_event = payload.get('alert_event', '')
        policy_name = payload.get('policy_name', 'Unknown')

        # Get source IP for logging
        source_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if source_ip and ',' in source_ip:
            source_ip = source_ip.split(',')[0].strip()

        logger.info(f"Webhook received: {policy_name} - Type: {alert_type} - Event: {alert_event}")

        # Save raw webhook for debugging (JSON files)
        webhook_log_path = Path("/root/Cloudflare_MT_Integration/logs/webhooks")
        webhook_log_path.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        with open(webhook_log_path / f"webhook_{timestamp}.json", 'w') as f:
            json.dump(payload, f, indent=2)

        # Identify target prefix for logging
        data = payload.get('data', {})
        target_ip = data.get('target_ip')
        target_prefix = get_prefix_from_ip(target_ip) if target_ip else None

        # Log webhook to database (before processing)
        webhook_db_id = log_webhook_event(
            payload=payload,
            source_ip=source_ip,
            action_taken='received',
            target_prefix=target_prefix
        )
        if webhook_db_id:
            logger.info(f"Webhook logged to DB: ID {webhook_db_id}")

        # Route to appropriate handler based on alert_type

        # Check for END events first (for any attack type)
        if alert_event == 'ALERT_STATE_EVENT_END':
            if alert_type in ['advanced_ddos_attack_l4_alert', 'dos_attack_l4', 'dos_attack_l7', 'fbm_dosd_attack']:
                handle_attack_end(payload)
                return jsonify({"status": "ok"}), 200

        # L3/L4 DDoS Attacks
        if alert_type == 'advanced_ddos_attack_l4_alert':
            handle_ddos_l4_attack(payload, is_advanced=True)

        elif alert_type == 'dos_attack_l4':
            handle_ddos_l4_attack(payload, is_advanced=False)

        # L7 HTTP DDoS Attack
        elif alert_type == 'dos_attack_l7':
            handle_ddos_l7_attack(payload)

        # Magic Network Monitoring DDoS
        elif alert_type == 'fbm_dosd_attack':
            handle_mnm_ddos_attack(payload)

        # Volumetric Attack
        elif alert_type == 'fbm_volumetric_attack':
            handle_volumetric_attack(payload)

        # Auto BGP Advertisement
        elif alert_type == 'fbm_auto_advertisement':
            handle_auto_advertisement(payload)

        # Tunnel Health Check
        elif alert_type == 'magic_tunnel_health_check_event':
            handle_tunnel_health(payload)

        # Cloudflare Incident (Status Page)
        elif alert_type == 'incident_alert':
            handle_incident_alert(payload)

        # Origin Health Check
        elif alert_type == 'health_check_status_notification':
            handle_health_check_alert(payload)

        # BGP Hijack / Route Leak (CRITICAL)
        elif alert_type == 'bgp_hijack_notification':
            handle_bgp_hijack_alert(payload)

        # Unknown alert type
        else:
            handle_unknown_alert(payload)

        return jsonify({"status": "ok"}), 200

    except Exception as e:
        logger.error(f"Error processing webhook: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "Cloudflare MT Webhook Receiver",
        "version": "1.6.0"
    }), 200


@app.route('/test/attack', methods=['POST'])
def test_attack():
    """Test endpoint to simulate attacks"""
    try:
        event = request.json.get('event', 'ALERT_STATE_EVENT_START')
        attack_type = request.json.get('type', 'advanced_ddos_attack_l4_alert')

        test_payload = {
            "name": "TEST Alert",
            "policy_name": "Test Policy",
            "alert_type": attack_type,
            "alert_event": event,
            "data": {
                "attack_id": f"test-{generate_alert_id()}",
                "attack_vector": "Test Vector",
                "target_ip": "185.54.82.1",
                "target_port": 80,
                "protocol": "TCP",
                "packets_per_second": "100000",
                "megabits_per_second": "500",
                "action": "block",
                "mitigation": "managed-challenge",
                "rule_name": "Test Rule",
                "start_time": datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
                "severity": "INFO"
            },
            "ts": int(time.time())
        }

        # Route based on type
        if attack_type == 'advanced_ddos_attack_l4_alert':
            if event == 'ALERT_STATE_EVENT_END':
                handle_attack_end(test_payload)
            else:
                handle_ddos_l4_attack(test_payload)

        return jsonify({"status": "test processed", "type": attack_type, "event": event}), 200

    except Exception as e:
        logger.error(f"Test error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    logger.info("Starting Cloudflare Webhook Receiver v1.6.0")
    logger.info(f"Endpoint: http://0.0.0.0:8080/webhook/cloudflare")
    logger.info(f"Health check: http://0.0.0.0:8080/health")
    logger.info(f"Test endpoint: http://0.0.0.0:8080/test/attack")

    app.run(
        host='0.0.0.0',
        port=8080,
        debug=False
    )
