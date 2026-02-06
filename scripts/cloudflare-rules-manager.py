#!/usr/bin/env python3
"""
Cloudflare Magic Network Monitoring - Rules Manager
GOLINE SA - SOC Tools

Interactive management of MNM rules for Magic Transit On-Demand
"""

import requests
import happy_eyeballs
import json
import sys
from datetime import datetime

# ============================================
# CONFIGURATION
# ============================================
ACCOUNT_ID = "YOUR_ACCOUNT_ID"
AUTH_EMAIL = "YOUR_EMAIL"
AUTH_KEY = "YOUR_API_KEY"

API_BASE = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/mnm/rules"

HEADERS = {
    "X-Auth-Email": AUTH_EMAIL,
    "X-Auth-Key": AUTH_KEY,
    "Content-Type": "application/json"
}

# GOLINE Prefixes
GOLINE_PREFIXES = [
    "185.54.80.0/24",
    "185.54.81.0/24",
    "185.54.82.0/24",
    "185.54.83.0/24",
    "2a02:4460:1::/48"  # IPv6 DMZv6
]

# DDoS Managed Rulesets
DDOS_L4_RULESET_ID = "3b64149bfa6e4220bbbc2bd6db589552"  # Cloudflare L3/4 DDoS Ruleset
DDOS_L4_ROOT_ID = "108b5719d12e4169a0ac2e4f499d8bae"     # Account root ruleset for overrides
RULESETS_API = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/rulesets"

# Action descriptions
ACTION_DESCRIPTIONS = {
    "block": "Block traffic immediately",
    "log": "Log only (monitor mode)",
    "ddos_dynamic": "Dynamic sensitivity (auto-adjust)"
}

# ============================================
# API FUNCTIONS
# ============================================

def api_get(endpoint=""):
    """GET request to API"""
    try:
        response = requests.get(f"{API_BASE}{endpoint}", headers=HEADERS)
        return response.json()
    except Exception as e:
        return {"success": False, "errors": [{"message": str(e)}]}

def api_post(data):
    """POST request to API"""
    try:
        response = requests.post(API_BASE, headers=HEADERS, json=data)
        return response.json()
    except Exception as e:
        return {"success": False, "errors": [{"message": str(e)}]}

def api_delete(rule_id):
    """DELETE request to API"""
    try:
        response = requests.delete(f"{API_BASE}/{rule_id}", headers=HEADERS)
        return response.json()
    except Exception as e:
        return {"success": False, "errors": [{"message": str(e)}]}

def ddos_api_get(ruleset_id=None):
    """GET request to rulesets API"""
    try:
        url = f"{RULESETS_API}/{ruleset_id}" if ruleset_id else RULESETS_API
        response = requests.get(url, headers=HEADERS)
        return response.json()
    except Exception as e:
        return {"success": False, "errors": [{"message": str(e)}]}

def ddos_api_get_managed_rules():
    """Get L3/4 DDoS managed ruleset rules"""
    return ddos_api_get(DDOS_L4_RULESET_ID)

def ddos_api_get_overrides():
    """Get account root ruleset with overrides"""
    return ddos_api_get(DDOS_L4_ROOT_ID)

def ddos_api_update_override(rule_id, action, sensitivity=None):
    """Update or create an override for a DDoS rule, preserving existing overrides"""
    try:
        # First get current root ruleset with existing overrides
        current = ddos_api_get(DDOS_L4_ROOT_ID)
        if not current.get('success'):
            return current

        # Get existing rules from root ruleset
        existing_rules = current.get('result', {}).get('rules', [])

        # Find the execute rule that targets our DDoS ruleset
        execute_rule = None
        execute_rule_index = None
        for i, rule in enumerate(existing_rules):
            if (rule.get('action') == 'execute' and
                rule.get('action_parameters', {}).get('id') == DDOS_L4_RULESET_ID):
                execute_rule = rule
                execute_rule_index = i
                break

        # Build the new override entry
        new_override = {
            "id": rule_id,
            "action": action
        }
        if sensitivity:
            new_override["sensitivity_level"] = sensitivity

        if execute_rule:
            # Update existing execute rule - merge overrides
            existing_overrides = execute_rule.get('action_parameters', {}).get('overrides', {}).get('rules', [])

            # Remove any existing override for this rule_id (we'll add the new one)
            updated_overrides = [o for o in existing_overrides if o.get('id') != rule_id]

            # Add the new/updated override
            updated_overrides.append(new_override)

            # Update the execute rule with merged overrides
            execute_rule['action_parameters']['overrides']['rules'] = updated_overrides
            existing_rules[execute_rule_index] = execute_rule
        else:
            # No existing execute rule - create new one
            new_execute_rule = {
                "action": "execute",
                "action_parameters": {
                    "id": DDOS_L4_RULESET_ID,
                    "overrides": {
                        "rules": [new_override]
                    }
                },
                "expression": "true",
                "enabled": True
            }
            existing_rules.append(new_execute_rule)

        # Update the root ruleset with ALL rules preserved
        response = requests.put(
            f"{RULESETS_API}/{DDOS_L4_ROOT_ID}",
            headers=HEADERS,
            json={
                "rules": existing_rules
            }
        )
        return response.json()
    except Exception as e:
        return {"success": False, "errors": [{"message": str(e)}]}

# ============================================
# DISPLAY FUNCTIONS
# ============================================

def format_threshold(rule):
    """Format rule threshold"""
    if rule.get('type') == 'advanced_ddos':
        prefix_match = rule.get('prefix_match', 'exact')
        return f"Fingerprint-based ({prefix_match} match)"
    elif rule.get('type') == 'zscore':
        sens = rule.get('zscore_sensitivity', 'N/A')
        target = rule.get('zscore_target', 'N/A')
        return f"Dynamic ({sens} sensitivity, {target})"
    elif 'bandwidth_threshold' in rule:
        bw = rule['bandwidth_threshold']
        if bw >= 1_000_000_000:
            return f"{bw/1_000_000_000:.1f} Gbps"
        elif bw >= 1_000_000:
            return f"{bw/1_000_000:.1f} Mbps"
        else:
            return f"{bw/1_000:.1f} Kbps"
    elif 'packet_threshold' in rule:
        pkt = rule['packet_threshold']
        if pkt >= 1_000_000:
            return f"{pkt/1_000_000:.1f}M pps"
        elif pkt >= 1_000:
            return f"{pkt/1_000:.1f}k pps"
        else:
            return f"{pkt} pps"
    return "N/A"

def print_rule(rule, index=None):
    """Print formatted rule"""
    prefix = f"[{index}] " if index is not None else ""
    auto_adv = "✓" if rule.get('automatic_advertisement') else "✗"
    rule_type = rule.get('type', 'threshold')
    
    type_icon = {
        'threshold': '📊',
        'zscore': '📈',
        'advanced_ddos': '🛡️'
    }.get(rule_type, '❓')
    
    print(f"{prefix}{type_icon} {rule['name']}")
    print(f"    ID: {rule['id'][:16]}...")
    print(f"    Prefixes: {', '.join(rule.get('prefixes', []))}")
    print(f"    Type: {rule_type}")
    print(f"    Threshold: {format_threshold(rule)}")
    print(f"    Duration: {rule.get('duration', 'N/A')}")
    print(f"    Auto-Advertisement: {auto_adv}")
    print()

def print_header(title):
    """Print header"""
    print()
    print("=" * 60)
    print(f" {title}")
    print("=" * 60)
    print()

def print_success(msg):
    print(f"\033[92m✓ {msg}\033[0m")

def print_error(msg):
    print(f"\033[91m✗ {msg}\033[0m")

def print_warning(msg):
    print(f"\033[93m⚠ {msg}\033[0m")

# ============================================
# COMMANDS
# ============================================

def cmd_list_all():
    """List all rules"""
    print_header("ALL RULES")
    
    result = api_get()
    if not result.get('success'):
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")
        return
    
    rules = result.get('result', [])
    if not rules:
        print("No rules found.")
        return
    
    print(f"Found {len(rules)} rules:\n")
    for i, rule in enumerate(rules, 1):
        print_rule(rule, i)

def cmd_list_dynamic():
    """List only dynamic rules (zscore)"""
    print_header("DYNAMIC RULES (ZSCORE)")
    
    result = api_get()
    if not result.get('success'):
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")
        return
    
    rules = [r for r in result.get('result', []) if r.get('type') == 'zscore']
    if not rules:
        print("No dynamic rules found.")
        return
    
    print(f"Found {len(rules)} dynamic rules:\n")
    for i, rule in enumerate(rules, 1):
        print_rule(rule, i)

def cmd_list_threshold():
    """List only threshold rules"""
    print_header("THRESHOLD RULES (STATIC)")
    
    result = api_get()
    if not result.get('success'):
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")
        return
    
    rules = [r for r in result.get('result', []) if r.get('type') == 'threshold']
    if not rules:
        print("No threshold rules found.")
        return
    
    # Separate BPS and PPS
    bps_rules = [r for r in rules if 'bandwidth_threshold' in r]
    pps_rules = [r for r in rules if 'packet_threshold' in r]
    
    if bps_rules:
        print(f"=== BPS (Bandwidth) - {len(bps_rules)} rules ===\n")
        for i, rule in enumerate(bps_rules, 1):
            print_rule(rule, i)
    
    if pps_rules:
        print(f"=== PPS (Packets) - {len(pps_rules)} rules ===\n")
        for i, rule in enumerate(pps_rules, 1):
            print_rule(rule, i)

def cmd_list_advanced_ddos():
    """List only advanced_ddos rules (sFlow fingerprint-based)"""
    print_header("ADVANCED DDOS RULES (sFlow Fingerprint)")

    result = api_get()
    if not result.get('success'):
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")
        return

    rules = [r for r in result.get('result', []) if r.get('type') == 'advanced_ddos']
    if not rules:
        print("No advanced DDoS rules found.")
        return

    print(f"Found {len(rules)} advanced DDoS rules:\n")
    for i, rule in enumerate(rules, 1):
        print_rule(rule, i)

def cmd_add_advanced_ddos():
    """Add an advanced_ddos rule (sFlow fingerprint-based)"""
    print_header("ADD ADVANCED DDOS RULE (sFlow Fingerprint)")

    print("This creates a fingerprint-based DDoS detection rule using sFlow.")
    print("These rules detect attack patterns regardless of traffic volume.\n")

    print("Available prefixes:")
    for i, prefix in enumerate(GOLINE_PREFIXES, 1):
        print(f"  [{i}] {prefix}")
    print(f"  [6] All IPv4 prefixes (4 rules)")
    print(f"  [7] All prefixes including IPv6 (5 rules)")
    print(f"  [8] Enter manually")
    print()

    choice = input("Select prefix [1-8]: ").strip()

    if choice == '6':
        # All IPv4 prefixes (first 4)
        prefixes_to_add = GOLINE_PREFIXES[:4]
    elif choice == '7':
        # All prefixes including IPv6
        prefixes_to_add = GOLINE_PREFIXES
    elif choice in ['1', '2', '3', '4', '5']:
        prefixes_to_add = [GOLINE_PREFIXES[int(choice) - 1]]
    elif choice == '8':
        prefix = input("Enter prefix (e.g. 192.168.1.0/24): ").strip()
        prefixes_to_add = [prefix]
    else:
        print_error("Invalid choice")
        return

    print("\nPrefix match mode:")
    print("  [1] subnet - Matches traffic to any IP in the prefix (recommended)")
    print("  [2] exact - Matches only traffic to the exact prefix")

    match_choice = input("Select [1-2, default: 1]: ").strip() or "1"
    prefix_match = {'1': 'subnet', '2': 'exact'}.get(match_choice, 'subnet')

    duration = input("Duration in minutes [default: 1]: ").strip() or "1"
    auto_adv = input("Auto-advertisement? [Y/n]: ").strip().lower() != 'n'

    print(f"\nCreating {len(prefixes_to_add)} advanced DDoS rules:")
    print(f"  Type: advanced_ddos (sFlow fingerprint)")
    print(f"  Prefix match: {prefix_match}")
    print(f"  Duration: {duration} min")
    print(f"  Auto-Adv: {auto_adv}")
    print("\nPrefixes:")
    for p in prefixes_to_add:
        print(f"  - {p}")

    confirm = input("\nConfirm? [Y/n]: ").strip().lower()
    if confirm == 'n':
        print("Cancelled.")
        return

    created = 0
    for prefix in prefixes_to_add:
        # Determine if IPv4 or IPv6
        if ':' in prefix:
            name = f"sFlow-DDoS-Attack-IPv6"
        else:
            name = f"sFlow-DDoS-Attack-{prefix.replace('/', '-')}"

        data = {
            "name": name,
            "prefixes": [prefix],
            "type": "advanced_ddos",
            "prefix_match": prefix_match,
            "automatic_advertisement": auto_adv,
            "duration": f"{duration}m0s"
        }

        result = api_post(data)
        if result.get('success'):
            print_success(f"Created: {name} (ID: {result['result']['id'][:16]}...)")
            created += 1
        else:
            print_error(f"Error {prefix}: {result.get('errors', [{}])[0].get('message', 'Unknown')}")

    print(f"\nCreated {created}/{len(prefixes_to_add)} advanced DDoS rules.")

def cmd_add_bps():
    """Add a BPS rule"""
    print_header("ADD BPS RULE (Bandwidth)")
    
    print("Available prefixes:")
    for i, prefix in enumerate(GOLINE_PREFIXES, 1):
        print(f"  [{i}] {prefix}")
    print(f"  [5] Enter manually")
    print()
    
    choice = input("Select prefix [1-5]: ").strip()
    
    if choice in ['1', '2', '3', '4']:
        prefix = GOLINE_PREFIXES[int(choice) - 1]
    elif choice == '5':
        prefix = input("Enter prefix (e.g. 192.168.1.0/24): ").strip()
    else:
        print_error("Invalid choice")
        return
    
    threshold = input("Threshold in Gbps [default: 2]: ").strip() or "2"
    try:
        threshold_bps = int(float(threshold) * 1_000_000_000)
    except:
        print_error("Invalid value")
        return
    
    duration = input("Duration in minutes [default: 1]: ").strip() or "1"
    auto_adv = input("Auto-advertisement? [Y/n]: ").strip().lower() != 'n'
    
    # Create name without slash
    name = f"DDoS Protection BPS {prefix.replace('/', '-')}"
    
    data = {
        "name": name,
        "prefixes": [prefix],
        "bandwidth_threshold": threshold_bps,
        "automatic_advertisement": auto_adv,
        "duration": f"{duration}m0s"
    }
    
    print(f"\nCreating rule: {name}")
    print(f"  Threshold: {threshold} Gbps")
    print(f"  Duration: {duration} min")
    print(f"  Auto-Adv: {auto_adv}")
    
    confirm = input("\nConfirm? [Y/n]: ").strip().lower()
    if confirm == 'n':
        print("Cancelled.")
        return
    
    result = api_post(data)
    if result.get('success'):
        print_success(f"Rule created! ID: {result['result']['id']}")
    else:
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")

def cmd_add_pps():
    """Add a PPS rule"""
    print_header("ADD PPS RULE (Packets)")
    
    print("Available prefixes:")
    for i, prefix in enumerate(GOLINE_PREFIXES, 1):
        print(f"  [{i}] {prefix}")
    print(f"  [5] Enter manually")
    print()
    
    choice = input("Select prefix [1-5]: ").strip()
    
    if choice in ['1', '2', '3', '4']:
        prefix = GOLINE_PREFIXES[int(choice) - 1]
    elif choice == '5':
        prefix = input("Enter prefix (e.g. 192.168.1.0/24): ").strip()
    else:
        print_error("Invalid choice")
        return
    
    threshold = input("Threshold in kpps [default: 500]: ").strip() or "500"
    try:
        threshold_pps = int(float(threshold) * 1_000)
    except:
        print_error("Invalid value")
        return
    
    duration = input("Duration in minutes [default: 1]: ").strip() or "1"
    auto_adv = input("Auto-advertisement? [Y/n]: ").strip().lower() != 'n'
    
    name = f"DDoS Protection PPS {prefix.replace('/', '-')}"
    
    data = {
        "name": name,
        "prefixes": [prefix],
        "packet_threshold": threshold_pps,
        "automatic_advertisement": auto_adv,
        "duration": f"{duration}m0s"
    }
    
    print(f"\nCreating rule: {name}")
    print(f"  Threshold: {threshold} kpps")
    print(f"  Duration: {duration} min")
    print(f"  Auto-Adv: {auto_adv}")
    
    confirm = input("\nConfirm? [Y/n]: ").strip().lower()
    if confirm == 'n':
        print("Cancelled.")
        return
    
    result = api_post(data)
    if result.get('success'):
        print_success(f"Rule created! ID: {result['result']['id']}")
    else:
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")

def cmd_add_dynamic():
    """Add a dynamic rule (zscore)"""
    print_header("ADD DYNAMIC RULE (ZScore)")
    
    print("Available prefixes:")
    for i, prefix in enumerate(GOLINE_PREFIXES, 1):
        print(f"  [{i}] {prefix}")
    print(f"  [5] Enter manually")
    print(f"  [6] All GOLINE prefixes (4 rules)")
    print()
    
    choice = input("Select prefix [1-6]: ").strip()
    
    if choice == '6':
        prefixes_to_add = GOLINE_PREFIXES
    elif choice in ['1', '2', '3', '4']:
        prefixes_to_add = [GOLINE_PREFIXES[int(choice) - 1]]
    elif choice == '5':
        prefixes_to_add = [input("Enter prefix (e.g. 192.168.1.0/24): ").strip()]
    else:
        print_error("Invalid choice")
        return
    
    print("\nSensitivity:")
    print("  [1] low - less sensitive, fewer false positives")
    print("  [2] medium - balanced (recommended)")
    print("  [3] high - more sensitive, more false positives")
    
    sens_choice = input("Select [1-3, default: 2]: ").strip() or "2"
    sensitivity = {'1': 'low', '2': 'medium', '3': 'high'}.get(sens_choice, 'medium')
    
    print("\nTarget:")
    print("  [1] bits - monitor bandwidth")
    print("  [2] packets - monitor packet rate")
    
    target_choice = input("Select [1-2, default: 1]: ").strip() or "1"
    target = {'1': 'bits', '2': 'packets'}.get(target_choice, 'bits')
    
    auto_adv = input("Auto-advertisement? [Y/n]: ").strip().lower() != 'n'
    
    print(f"\nCreating {len(prefixes_to_add)} dynamic rules:")
    print(f"  Sensitivity: {sensitivity}")
    print(f"  Target: {target}")
    print(f"  Auto-Adv: {auto_adv}")
    
    confirm = input("\nConfirm? [Y/n]: ").strip().lower()
    if confirm == 'n':
        print("Cancelled.")
        return
    
    for prefix in prefixes_to_add:
        name = f"Dynamic DDoS Detection {prefix.replace('/', '-')}"
        
        data = {
            "name": name,
            "prefixes": [prefix],
            "automatic_advertisement": auto_adv,
            "type": "zscore",
            "zscore_sensitivity": sensitivity,
            "zscore_target": target,
            "duration": "1m"
        }
        
        result = api_post(data)
        if result.get('success'):
            print_success(f"Created: {name}")
        else:
            print_error(f"Error {prefix}: {result.get('errors', [{}])[0].get('message', 'Unknown')}")

def cmd_delete():
    """Delete a rule"""
    print_header("DELETE RULE")
    
    result = api_get()
    if not result.get('success'):
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")
        return
    
    rules = result.get('result', [])
    if not rules:
        print("No rules found.")
        return
    
    print("Available rules:\n")
    for i, rule in enumerate(rules, 1):
        auto_adv = "✓" if rule.get('automatic_advertisement') else "✗"
        print(f"  [{i}] {rule['name']} [{auto_adv}]")
    
    print()
    choice = input(f"Select rule to delete [1-{len(rules)}] or 'q' to cancel: ").strip()
    
    if choice.lower() == 'q':
        print("Cancelled.")
        return
    
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(rules):
            raise ValueError()
        rule = rules[idx]
    except:
        print_error("Invalid choice")
        return
    
    print(f"\nYou are about to delete: {rule['name']}")
    print(f"  ID: {rule['id']}")
    print(f"  Prefixes: {', '.join(rule.get('prefixes', []))}")
    
    confirm = input("\nAre you sure? Type 'DELETE' to confirm: ").strip()
    if confirm != 'DELETE':
        print("Cancelled.")
        return
    
    result = api_delete(rule['id'])
    if result.get('success'):
        print_success(f"Rule deleted!")
    else:
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")

def cmd_delete_all_type():
    """Delete all rules of a type"""
    print_header("DELETE RULES BY TYPE")

    result = api_get()
    if not result.get('success'):
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")
        return

    rules = result.get('result', [])

    # Count by type
    threshold_bps = [r for r in rules if r.get('type') == 'threshold' and 'bandwidth_threshold' in r]
    threshold_pps = [r for r in rules if r.get('type') == 'threshold' and 'packet_threshold' in r]
    zscore_rules = [r for r in rules if r.get('type') == 'zscore']
    advanced_ddos_rules = [r for r in rules if r.get('type') == 'advanced_ddos']

    print("Select type of rules to delete:\n")
    print(f"  [1] Threshold BPS ({len(threshold_bps)} rules)")
    print(f"  [2] Threshold PPS ({len(threshold_pps)} rules)")
    print(f"  [3] Dynamic/ZScore ({len(zscore_rules)} rules)")
    print(f"  [4] Advanced DDoS/sFlow ({len(advanced_ddos_rules)} rules)")
    print(f"  [5] ALL ({len(rules)} rules)")
    print()

    choice = input("Select [1-5] or 'q' to cancel: ").strip()

    if choice.lower() == 'q':
        print("Cancelled.")
        return

    rules_to_delete = {
        '1': threshold_bps,
        '2': threshold_pps,
        '3': zscore_rules,
        '4': advanced_ddos_rules,
        '5': rules
    }.get(choice, [])
    
    if not rules_to_delete:
        print("No rules to delete.")
        return
    
    print(f"\nYou are about to delete {len(rules_to_delete)} rules:")
    for r in rules_to_delete:
        print(f"  - {r['name']}")
    
    confirm = input(f"\nAre you sure? Type 'DELETE ALL' to confirm: ").strip()
    if confirm != 'DELETE ALL':
        print("Cancelled.")
        return
    
    deleted = 0
    for rule in rules_to_delete:
        result = api_delete(rule['id'])
        if result.get('success'):
            print_success(f"Deleted: {rule['name']}")
            deleted += 1
        else:
            print_error(f"Error {rule['name']}: {result.get('errors', [{}])[0].get('message', 'Unknown')}")
    
    print(f"\nDeleted {deleted}/{len(rules_to_delete)} rules.")

def cmd_status():
    """Show general status"""
    print_header("MAGIC NETWORK MONITORING STATUS")

    result = api_get()
    if not result.get('success'):
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")
        return

    rules = result.get('result', [])

    # Count by type
    threshold_bps = len([r for r in rules if r.get('type') == 'threshold' and 'bandwidth_threshold' in r])
    threshold_pps = len([r for r in rules if r.get('type') == 'threshold' and 'packet_threshold' in r])
    zscore_rules = len([r for r in rules if r.get('type') == 'zscore'])
    advanced_ddos_rules = len([r for r in rules if r.get('type') == 'advanced_ddos'])
    auto_adv = len([r for r in rules if r.get('automatic_advertisement')])

    # Covered prefixes
    all_prefixes = set()
    for r in rules:
        all_prefixes.update(r.get('prefixes', []))

    print(f"📊 Total rules: {len(rules)}")
    print(f"   ├─ Threshold BPS: {threshold_bps}")
    print(f"   ├─ Threshold PPS: {threshold_pps}")
    print(f"   ├─ Dynamic (ZScore): {zscore_rules}")
    print(f"   └─ Advanced DDoS (sFlow): {advanced_ddos_rules}")
    print()
    print(f"🚀 Auto-Advertisement enabled: {auto_adv}/{len(rules)} rules")
    print()
    print(f"🌐 Monitored prefixes: {len(all_prefixes)}")
    for prefix in sorted(all_prefixes):
        print(f"   - {prefix}")
    print()
    print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def cmd_export():
    """Export configuration to JSON"""
    print_header("EXPORT CONFIGURATION")

    result = api_get()
    if not result.get('success'):
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")
        return

    filename = f"mnm_rules_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, 'w') as f:
        json.dump(result.get('result', []), f, indent=2)

    print_success(f"Configuration exported to: {filename}")

# ============================================
# DDOS SENSITIVITY COMMANDS
# ============================================

def cmd_ddos_status():
    """Show DDoS protection status overview"""
    print_header("DDOS PROTECTION STATUS")

    print("Fetching DDoS managed ruleset...")
    result = ddos_api_get_managed_rules()

    if not result.get('success'):
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")
        return

    rules = result.get('result', {}).get('rules', [])

    # Separate customizable and read-only
    customizable = [r for r in rules if 'read-only' not in r.get('categories', [])]
    read_only = [r for r in rules if 'read-only' in r.get('categories', [])]

    # Count by action
    actions = {}
    for r in rules:
        action = r.get('action', 'unknown')
        actions[action] = actions.get(action, 0) + 1

    # Count customizable by category
    categories = {}
    for r in customizable:
        cats = [c for c in r.get('categories', []) if c != 'read-only']
        main_cat = cats[0] if cats else 'other'
        categories[main_cat] = categories.get(main_cat, 0) + 1

    print(f"\n🛡️  L3/4 DDoS Managed Ruleset")
    print(f"   Version: {result.get('result', {}).get('version', 'N/A')}")
    print(f"   Last Updated: {result.get('result', {}).get('last_updated', 'N/A')[:19]}")
    print()
    print(f"📊 Total Rules: {len(rules)}")
    print(f"   ├─ Customizable: {len(customizable)}")
    print(f"   └─ Read-only: {len(read_only)}")
    print()
    print("📈 Current Actions:")
    for action, count in sorted(actions.items(), key=lambda x: -x[1]):
        desc = ACTION_DESCRIPTIONS.get(action, action)
        icon = {'block': '🛑', 'log': '📝', 'ddos_dynamic': '🔄'}.get(action, '❓')
        print(f"   {icon} {action:15} {count:3} rules - {desc}")
    print()
    print("🏷️  Customizable Categories:")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"   - {cat:15} {count} rules")

def cmd_ddos_list_rules():
    """List customizable DDoS rules by category"""
    print_header("CUSTOMIZABLE DDOS RULES")

    print("Fetching DDoS managed ruleset...")
    result = ddos_api_get_managed_rules()

    if not result.get('success'):
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")
        return

    rules = result.get('result', {}).get('rules', [])
    customizable = [r for r in rules if 'read-only' not in r.get('categories', [])]

    if not customizable:
        print("No customizable rules found.")
        return

    # Group by category
    by_cat = {}
    for r in customizable:
        cats = [c for c in r.get('categories', []) if c != 'read-only']
        main_cat = cats[0] if cats else 'other'
        if main_cat not in by_cat:
            by_cat[main_cat] = []
        by_cat[main_cat].append(r)

    print(f"\nFound {len(customizable)} customizable rules:\n")

    for cat in sorted(by_cat.keys()):
        cat_rules = by_cat[cat]
        print(f"═══ {cat.upper()} ({len(cat_rules)} rules) ═══")
        print()
        for r in cat_rules:
            ref = r.get('ref', 'N/A')
            action = r.get('action', 'N/A')
            desc = r.get('description', '')[:50]
            allowed = r.get('allowed_override_actions', [])

            action_icon = {'block': '🛑', 'log': '📝', 'ddos_dynamic': '🔄'}.get(action, '❓')

            print(f"  {ref:12} {action_icon} [{action:12}]")
            print(f"               {desc}")
            if allowed:
                print(f"               Allowed: {', '.join(allowed)}")
            print()

def cmd_ddos_edit_sensitivity():
    """Edit sensitivity for a specific DDoS rule"""
    print_header("EDIT DDOS RULE SENSITIVITY")

    print("Fetching DDoS managed ruleset...")
    result = ddos_api_get_managed_rules()

    if not result.get('success'):
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")
        return

    rules = result.get('result', {}).get('rules', [])
    customizable = [r for r in rules if 'read-only' not in r.get('categories', [])]

    if not customizable:
        print("No customizable rules found.")
        return

    # Show categories first
    by_cat = {}
    for r in customizable:
        cats = [c for c in r.get('categories', []) if c != 'read-only']
        main_cat = cats[0] if cats else 'other'
        if main_cat not in by_cat:
            by_cat[main_cat] = []
        by_cat[main_cat].append(r)

    print("\nSelect category:\n")
    cat_list = sorted(by_cat.keys())
    for i, cat in enumerate(cat_list, 1):
        print(f"  [{i}] {cat.upper()} ({len(by_cat[cat])} rules)")

    print()
    choice = input(f"Select category [1-{len(cat_list)}] or 'q' to cancel: ").strip()

    if choice.lower() == 'q':
        print("Cancelled.")
        return

    try:
        cat_idx = int(choice) - 1
        if cat_idx < 0 or cat_idx >= len(cat_list):
            raise ValueError()
        selected_cat = cat_list[cat_idx]
    except:
        print_error("Invalid choice")
        return

    # Show rules in category
    cat_rules = by_cat[selected_cat]
    print(f"\n{selected_cat.upper()} Rules:\n")
    for i, r in enumerate(cat_rules, 1):
        ref = r.get('ref', 'N/A')
        action = r.get('action', 'N/A')
        desc = r.get('description', '')[:45]
        action_icon = {'block': '🛑', 'log': '📝', 'ddos_dynamic': '🔄'}.get(action, '❓')
        print(f"  [{i}] {ref:12} {action_icon} {action:12} {desc}")

    print()
    rule_choice = input(f"Select rule [1-{len(cat_rules)}] or 'q' to cancel: ").strip()

    if rule_choice.lower() == 'q':
        print("Cancelled.")
        return

    try:
        rule_idx = int(rule_choice) - 1
        if rule_idx < 0 or rule_idx >= len(cat_rules):
            raise ValueError()
        selected_rule = cat_rules[rule_idx]
    except:
        print_error("Invalid choice")
        return

    # Show current rule details
    print(f"\n{'='*60}")
    print(f"Rule: {selected_rule.get('ref', 'N/A')}")
    print(f"Description: {selected_rule.get('description', 'N/A')}")
    print(f"Current Action: {selected_rule.get('action', 'N/A')}")
    print(f"Allowed Actions: {', '.join(selected_rule.get('allowed_override_actions', []))}")
    print(f"{'='*60}")

    # Show action options
    allowed = selected_rule.get('allowed_override_actions', [])
    if not allowed:
        print_warning("This rule does not allow action overrides.")
        return

    print("\nSelect new action:\n")
    for i, action in enumerate(allowed, 1):
        desc = ACTION_DESCRIPTIONS.get(action, action)
        icon = {'block': '🛑', 'log': '📝', 'ddos_dynamic': '🔄'}.get(action, '❓')
        print(f"  [{i}] {icon} {action:15} - {desc}")

    print()
    action_choice = input(f"Select action [1-{len(allowed)}] or 'q' to cancel: ").strip()

    if action_choice.lower() == 'q':
        print("Cancelled.")
        return

    try:
        action_idx = int(action_choice) - 1
        if action_idx < 0 or action_idx >= len(allowed):
            raise ValueError()
        new_action = allowed[action_idx]
    except:
        print_error("Invalid choice")
        return

    # Confirm
    print(f"\nYou are about to change:")
    print(f"  Rule: {selected_rule.get('ref')} - {selected_rule.get('description', '')[:40]}")
    print(f"  From: {selected_rule.get('action')}")
    print(f"  To:   {new_action}")

    confirm = input("\nConfirm? [Y/n]: ").strip().lower()
    if confirm == 'n':
        print("Cancelled.")
        return

    # Apply override
    print("\nApplying override...")
    update_result = ddos_api_update_override(selected_rule.get('id'), new_action)

    if update_result.get('success'):
        print_success(f"Override applied! Rule {selected_rule.get('ref')} now set to '{new_action}'")
    else:
        print_error(f"Error: {update_result.get('errors', [{}])[0].get('message', 'Unknown')}")

def cmd_ddos_view_overrides():
    """View current DDoS rule overrides"""
    print_header("CURRENT DDOS OVERRIDES")

    print("Fetching account overrides...")
    result = ddos_api_get_overrides()

    if not result.get('success'):
        print_error(f"Error: {result.get('errors', [{}])[0].get('message', 'Unknown')}")
        return

    root_rules = result.get('result', {}).get('rules', [])

    if not root_rules:
        print("No custom overrides configured.")
        print("\nAll DDoS rules are using default Cloudflare settings.")
        return

    print(f"\nFound {len(root_rules)} override configuration(s):\n")

    for i, rule in enumerate(root_rules, 1):
        action_params = rule.get('action_parameters', {})
        overrides = action_params.get('overrides', {})
        rule_overrides = overrides.get('rules', [])

        print(f"Override Set #{i}:")
        print(f"  Enabled: {rule.get('enabled', False)}")

        if rule_overrides:
            for ro in rule_overrides:
                rule_id = ro.get('id', 'N/A')
                action = ro.get('action', 'N/A')
                sensitivity = ro.get('sensitivity_level', 'default')
                print(f"  - Rule ID: {rule_id[:16]}...")
                print(f"    Action: {action}")
                if sensitivity != 'default':
                    print(f"    Sensitivity: {sensitivity}")
        print()

# ============================================
# MAIN MENU
# ============================================

def show_menu():
    """Show main menu"""
    print()
    print("┌────────────────────────────────────────────────────────┐")
    print("│   CLOUDFLARE MAGIC NETWORK MONITORING MANAGER          │")
    print("│   GOLINE SA - SOC Tools v1.4                           │")
    print("├────────────────────────────────────────────────────────┤")
    print("│  MNM RULES                                             │")
    print("│   [1] List all rules                                   │")
    print("│   [2] List dynamic rules (zscore)                      │")
    print("│   [3] List threshold rules (BPS/PPS)                   │")
    print("│   [4] List advanced DDoS rules (sFlow)                 │")
    print("│   [5] General status                                   │")
    print("├────────────────────────────────────────────────────────┤")
    print("│  ADD RULES                                             │")
    print("│   [6] Add BPS rule (bandwidth)                         │")
    print("│   [7] Add PPS rule (packets)                           │")
    print("│   [8] Add dynamic rule (zscore)                        │")
    print("│   [9] Add advanced DDoS rule (sFlow fingerprint)       │")
    print("├────────────────────────────────────────────────────────┤")
    print("│  DELETE RULES                                          │")
    print("│   [d] Delete single rule                               │")
    print("│   [t] Delete rules by type                             │")
    print("├────────────────────────────────────────────────────────┤")
    print("│  DDOS SENSITIVITY (L3/4 Managed Ruleset)               │")
    print("│   [s] DDoS protection status                           │")
    print("│   [l] List customizable DDoS rules                     │")
    print("│   [m] Modify rule sensitivity/action                   │")
    print("│   [o] View current overrides                           │")
    print("├────────────────────────────────────────────────────────┤")
    print("│  OTHER                                                 │")
    print("│   [e] Export configuration (JSON)                      │")
    print("│   [q] Quit                                             │")
    print("└────────────────────────────────────────────────────────┘")

def main():
    """Main loop"""
    commands = {
        # MNM Rules
        '1': cmd_list_all,
        '2': cmd_list_dynamic,
        '3': cmd_list_threshold,
        '4': cmd_list_advanced_ddos,
        '5': cmd_status,
        # Add Rules
        '6': cmd_add_bps,
        '7': cmd_add_pps,
        '8': cmd_add_dynamic,
        '9': cmd_add_advanced_ddos,
        # Delete Rules
        'd': cmd_delete,
        't': cmd_delete_all_type,
        # DDoS Sensitivity
        's': cmd_ddos_status,
        'l': cmd_ddos_list_rules,
        'm': cmd_ddos_edit_sensitivity,
        'o': cmd_ddos_view_overrides,
        # Other
        'e': cmd_export,
    }

    print("\n" + "=" * 55)
    print("  Cloudflare Magic Network Monitoring - Rules Manager")
    print("  GOLINE SA - v1.4")
    print("=" * 55)
    
    while True:
        show_menu()
        choice = input("\nSelect option: ").strip().lower()
        
        if choice == 'q':
            print("\nGoodbye!\n")
            break
        elif choice in commands:
            commands[choice]()
            input("\nPress ENTER to continue...")
        else:
            print_error("Invalid option")

if __name__ == "__main__":
    main()
