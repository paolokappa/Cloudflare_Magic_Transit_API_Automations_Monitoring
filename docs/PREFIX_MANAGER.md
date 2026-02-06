# Cloudflare BGP Prefix Manager

CLI tool for complete management of Magic Transit On-Demand BGP prefixes.

**Script**: `/root/Cloudflare_MT_Integration/scripts/cloudflare-prefix-manager.py`
**Symlink**: `/usr/local/bin/cloudflare-prefix-manager`
**Version**: 1.4.1
**Last Updated**: 2026-02-06

## Table of Contents

- [Description](#description)
- [Installation](#installation)
- [Commands](#commands)
- [Configured Prefixes](#configured-prefixes)
- [15-Minute Constraint](#15-minute-constraint)
- [Telegram Notifications](#telegram-notifications)
- [Usage Examples](#usage-examples)
- [Sample Output](#sample-output)
- [Troubleshooting](#troubleshooting)

---

## Description

`cloudflare-prefix-manager` allows you to:

- **View status** of all BGP prefixes or a specific one
- **Advertise** single prefixes or in bulk
- **Withdraw** single prefixes or in bulk
- **Check** the 15-minute constraint before withdrawal
- **Manage** IPv4 and IPv6 prefixes (including On-Demand ones)
- **Receive Telegram notifications** for every operation
- **Database logging** - All operations logged to `attack_events` for dashboard visibility (v1.4.0)

### Features

- Colored output (ANSI) for easy reading
- **Mandatory 15-minute constraint enforcement** (blocks withdrawal if not satisfied)
- Shows exact time when withdrawal will be available
- Interactive menu when run without parameters
- Full support for all 5 GOLINE prefixes
- Clear API error handling
- SOC-style Telegram notifications with operation IDs

---

## Installation

The script is already installed and configured:

```bash
# Global symlink
ls -la /usr/local/bin/cloudflare-prefix-manager
# -> /root/Cloudflare_MT_Integration/scripts/cloudflare-prefix-manager.py

# Verify it works
cloudflare-prefix-manager --help
```

### Dependencies

- Python 3.8+
- requests (already installed)
- Configuration in `/root/Cloudflare_MT_Integration/config/`

---

## Commands

### `status` - View Status

```bash
# Status of all prefixes
cloudflare-prefix-manager status

# Detailed status of a specific prefix
cloudflare-prefix-manager status 185.54.82.0/24
cloudflare-prefix-manager status 2a02:4460:1::/48
```

**Single status output**:
- Description and ASN
- Prefix ID and BGP Prefix ID
- Status: ADVERTISED / NOT ADVERTISED / On-Demand
- On-Demand Enabled
- Last Modified
- Time remaining for withdraw (if applicable)
- RAW API data (JSON)

### `advertise` - Advertise Prefix

```bash
# Advertise a specific prefix
cloudflare-prefix-manager advertise 185.54.82.0/24

# Advertise all prefixes
cloudflare-prefix-manager advertise --all

# Advertise all without confirmation
cloudflare-prefix-manager advertise --all --force
```

**Behavior**:
- Checks if prefix is already advertised (skip)
- Skips On-Demand prefixes
- Sends Telegram notification for each advertisement
- Exit code 1 if there are failures

### `withdraw` - Withdraw Prefix

```bash
# Withdraw a specific prefix
cloudflare-prefix-manager withdraw 185.54.82.0/24

# Withdraw all prefixes
cloudflare-prefix-manager withdraw --all
```

**Behavior**:
- **Blocks withdrawal** if 15-minute constraint is not satisfied (mandatory)
- Shows exact time when withdrawal will be available (e.g., "00:29:21")
- Shows remaining time (e.g., "in 2m 32s")
- Skips On-Demand and already non-advertised prefixes
- Sends Telegram notification for each successful withdraw
- Exit code 1 if there are failures or blocked prefixes

**Note**: The 15-minute constraint is enforced by Cloudflare and cannot be bypassed.

### `list` - List Configured Prefixes

```bash
cloudflare-prefix-manager list
```

Shows all prefixes in the configuration file with:
- CIDR
- Description
- ASN
- Notes (On-Demand, IPv6)

### Interactive Menu

```bash
# Run without parameters for interactive menu
cloudflare-prefix-manager
```

Menu with numbered options for all operations.

---

## Configured Prefixes

| Prefix | Description | ASN | Notes |
|--------|-------------|-----|-------|
| `185.54.80.0/24` | BGP | 202032 | Primary |
| `185.54.81.0/24` | DMZ | 202032 | Primary |
| `185.54.82.0/24` | DMZ-EXT | 202032 | **TEST** |
| `185.54.83.0/24` | DMZ EXT2 | 202032 | |
| `2a02:4460:1::/48` | DMZv6 | 202032 | On-Demand |

### Test Prefix

The prefix **185.54.82.0/24** (DMZ-EXT) is designated for testing:

```bash
# Full test
cloudflare-prefix-manager status 185.54.82.0/24
cloudflare-prefix-manager advertise 185.54.82.0/24
# Wait 15 minutes
cloudflare-prefix-manager withdraw 185.54.82.0/24
```

### IPv6 Prefix

The prefix `2a02:4460:1::/48` is fully manageable (on-demand):

- Can be advertised/withdrawn via API
- Status is `on_demand_enabled` (not locked)
- Subject to same 15-minute constraint as IPv4 prefixes

---

## 15-Minute Constraint

Cloudflare Magic Transit enforces **two mandatory 15-minute constraints**:

### Withdraw Constraint (after advertise)

```
Timeline:
  T+0      Prefix advertised
  T+2-7    BGP propagation complete
  T+15     Withdrawal available
```

### Re-Advertise Constraint (after withdraw)

```
Timeline:
  T+0      Prefix withdrawn
  T+15     Re-advertisement available
```

### Script Behavior

The script **blocks operations** until the 15-minute constraints are satisfied:

**For Withdrawal**:
- Shows the exact time when withdrawal will be available
- Shows remaining time in minutes and seconds
- No bypass option (Cloudflare enforces this server-side)

**For Re-Advertisement**:
- Checks if prefix was recently withdrawn
- Blocks re-advertisement until 15 minutes have passed
- Shows remaining time with error message:
  ```
  BLOCKED 185.54.82.0/24 - 15min constraint not satisfied
           Advertise available at 14:45:30 (in 3m 21s)
  ```

### Status Output

```bash
# View remaining time and availability in "Withdraw" column
cloudflare-prefix-manager status

# Example output:
# 185.54.82.0/24    ADVERTISED    DMZ-EXT    2m (00:29:21)
# 185.54.83.0/24    ADVERTISED    DMZ EXT2   Now
```

### Withdrawal Blocked Example

```bash
$ cloudflare-prefix-manager withdraw 185.54.82.0/24

BGP WITHDRAWAL: 185.54.82.0/24
Operation ID: 20260119002646-dd30ec
============================================================
  BOn-Demand 185.54.82.0/24 - 15min constraint not satisfied
           Withdraw available at 00:29:21 (in 2m 32s)
------------------------------------------------------------
Completed: 0 successful, 0 failed, 1 skipped

INFO: 1 prefix(es) blocked by 15-minute Cloudflare constraint.
This is a mandatory limit - prefixes can only be withdrawn 15 minutes after advertisement.
Run 'cloudflare-prefix-manager status' to check when withdrawal will be available.
```

---

## Telegram Notifications

The script sends automatic notifications with SOC-style formatting for:

### Prefix Advertisement

```
🛡️ *CLOUDFLARE DDoS PROTECTION*

📡 *BGP ADVERTISEMENT*

🔖 *Operation ID:* `20260119143045-a1b2c3`
✅ *Status:* PREFIX ADVERTISED
🎯 *Action:* Manual Advertisement

📡 *PREFIX INFO*
📍 *CIDR:* `185.54.82.0/24`
📝 *Description:* DMZ-EXT
🔢 *ASN:* 202032
🌍 *Type:* IPv4

⏱️ *TIMING*
🕐 *Advertised at:* 2026-01-19 14:30:45 UTC
⏳ *BGP Propagation:* 2-7 minutes
🔒 *Min. Hold Time:* 15 minutes

🔄 *BGP STATUS*
✅ Prefix now advertised via Cloudflare
🛡️ Traffic will be scrubbed through Magic Transit
📊 DDoS protection active

👤 *Operator:* CLI (Manual)

🏢 *GOLINE SOC* | _Magic Transit On-Demand_
```

### Prefix Withdrawal

```
🛡️ *CLOUDFLARE DDoS PROTECTION*

🔚 *BGP WITHDRAWAL*

🔖 *Operation ID:* `20260119144530-d4e5f6`
✅ *Status:* PREFIX WITHDRAWN
🎯 *Action:* Manual Withdrawal

📡 *PREFIX INFO*
📍 *CIDR:* `185.54.82.0/24`
📝 *Description:* DMZ-EXT
🔢 *ASN:* 202032
🌍 *Type:* IPv4

⏱️ *TIMING*
🕐 *Withdrawn at:* 2026-01-19 14:45:30 UTC
⏳ *BGP Withdrawal:* ~15 minutes
⏱️ *Was advertised for:* 15 minutes

🔄 *BGP STATUS*
🔙 Traffic returning to origin path
⚠️ Direct routing resumed
📊 Magic Transit protection disabled for this prefix

👤 *Operator:* CLI (Manual)

🏢 *GOLINE SOC* | _Magic Transit On-Demand_
```

### Bulk Operations

```
🛡️ *CLOUDFLARE DDoS PROTECTION*

📡 *BULK BGP ADVERTISEMENT*

🔖 *Operation ID:* `20260119143100-789abc`
🎯 *Action:* Bulk Advertise

📊 *SUMMARY*
📦 *Total Prefixes:* 5
✅ *Advertised:* 4
❌ *Failed:* 0
⏭️ *Skipped:* 1

✅ *Successful:*
  • `185.54.80.0/24`
  • `185.54.81.0/24`
  • `185.54.82.0/24`
  • `185.54.83.0/24`

⏭️ *Skipped:*
  • `2a02:4460:1::/48` (Locked)

⏱️ *Completed at:* 2026-01-19 14:31:00 UTC

👤 *Operator:* CLI (Manual)

🏢 *GOLINE SOC* | _Magic Transit On-Demand_
```

### Configuration

Telegram credentials are in `/root/Cloudflare_MT_Integration/config/settings.json`:
- Bot Token
- Chat ID

---

## Usage Examples

### Scenario 1: Check Current Status

```bash
$ cloudflare-prefix-manager status

BGP PREFIX STATUS
===========================================================================
Prefix               Status          Description     Withdraw
---------------------------------------------------------------------------
185.54.80.0/24       NOT ADVERT.     BGP             -
185.54.81.0/24       NOT ADVERT.     DMZ             -
185.54.82.0/24       ADVERTISED      DMZ-EXT         12m
185.54.83.0/24       NOT ADVERT.     DMZ EXT2        -
2a02:4460:1::/48       On-Demand          DMZv6           N/A
===========================================================================
Total: 1 advertised, 1 locked, 3 not advertised

WARNING: 1 prefixes currently advertised
```

### Scenario 2: Advertisement During DDoS Attack

```bash
# Advertise all prefixes for mitigation
$ cloudflare-prefix-manager advertise --all --force

BGP ADVERTISEMENT: ALL PREFIXES
Operation ID: 20260119143045-a1b2c3
============================================================
  OK   185.54.80.0/24 - Advertised
  OK   185.54.81.0/24 - Advertised
  OK   185.54.82.0/24 - Advertised
  OK   185.54.83.0/24 - Advertised
  SKIP 2a02:4460:1::/48 - Prefix On-Demand
------------------------------------------------------------
Completed: 4 successful, 0 failed, 1 skipped

INFO: BGP propagation takes 2-7 minutes
```

### Scenario 3: Post-Attack Withdrawal

```bash
# After 15+ minutes from attack
$ cloudflare-prefix-manager withdraw --all --force

BGP WITHDRAWAL: ALL PREFIXES
Operation ID: 20260119151000-def123
============================================================
  OK   185.54.80.0/24 - Withdrawn
  OK   185.54.81.0/24 - Withdrawn
  OK   185.54.82.0/24 - Withdrawn
  OK   185.54.83.0/24 - Withdrawn
  SKIP 2a02:4460:1::/48 - Prefix On-Demand
------------------------------------------------------------
Completed: 4 successful, 0 failed, 1 skipped
```

### Scenario 4: Withdraw Attempt Too Early

```bash
$ cloudflare-prefix-manager withdraw 185.54.82.0/24

BGP WITHDRAWAL: 185.54.82.0/24
Operation ID: 20260119143500-456789
============================================================
  BOn-Demand 185.54.82.0/24 - 15min constraint not satisfied
           Withdraw available at 14:45:00 (in 8m 32s)
------------------------------------------------------------
Completed: 0 successful, 0 failed, 1 skipped

INFO: 1 prefix(es) blocked by 15-minute Cloudflare constraint.
This is a mandatory limit - prefixes can only be withdrawn 15 minutes after advertisement.
Run 'cloudflare-prefix-manager status' to check when withdrawal will be available.
```

---

## Sample Output

### Help

```bash
$ cloudflare-prefix-manager --help

usage: cloudflare-prefix-manager [-h] {status,advertise,withdraw,list} ...

Cloudflare BGP Prefix Manager - Magic Transit prefix management

positional arguments:
  {status,advertise,withdraw,list}
                        Available commands
    status              Show prefix status
    advertise           Advertise prefix
    withdraw            Withdraw prefix
    list                List configured prefixes

options:
  -h, --help            show this help message and exit

Examples:
  cloudflare-prefix-manager status                    # Status of all prefixes
  cloudflare-prefix-manager status 185.54.82.0/24     # Detailed status
  cloudflare-prefix-manager advertise 185.54.82.0/24  # Advertise prefix
  cloudflare-prefix-manager advertise --all           # Advertise all
  cloudflare-prefix-manager withdraw 185.54.82.0/24   # Withdraw prefix (15min constraint)
  cloudflare-prefix-manager withdraw --all            # Withdraw all (15min constraint)
  cloudflare-prefix-manager list                      # List prefixes
  cloudflare-prefix-manager                           # Interactive menu

Note: Withdrawal is blocked until 15 minutes after advertisement (Cloudflare constraint).
```

### Detailed Status

```bash
$ cloudflare-prefix-manager status 185.54.82.0/24

DETAILED STATUS: 185.54.82.0/24
============================================================
Description: DMZ-EXT
ASN: 202032
Prefix ID: 0b0b3095-b38a-4b67-...
BGP Prefix ID: 13cc09374-2a1f-...
------------------------------------------------------------
Status: ADVERTISED
On-Demand Enabled: Yes
Locked: No
Last Modified: 2026-01-19T14:30:45Z
Withdraw: Wait 8m 23s
------------------------------------------------------------

RAW API Data:
{
  "asn": 202032,
  "cidr": "185.54.82.0/24",
  "on_demand": {
    "advertised": true,
    "advertised_modified_at": "2026-01-19T14:30:45Z",
    "enabled": true,
    "locked": false
  }
}
```

---

## Troubleshooting

### Error: HTTP 429 (Too Many Requests)

**Cause**: Too many API requests in a short time

**Solution**: Wait for rate limit to reset (usually a few seconds)

```bash
# Check remaining time
cloudflare-prefix-manager status 185.54.82.0/24
```

### Withdrawal Blocked (15-minute constraint)

**Cause**: Attempting to withdraw a prefix before 15 minutes have passed since advertisement

**Solution**: Wait until the indicated time. The script shows:
- Exact time when withdrawal will be available (e.g., "00:29:21")
- Remaining time (e.g., "in 2m 32s")

This is a Cloudflare-enforced limit and cannot be bypassed.

### Error: Prefix not found

**Cause**: CIDR not present in configuration

**Solution**: Check `prefix_mapping.json`

```bash
cloudflare-prefix-manager list
```

### Error: API ERROR

**Cause**: Connectivity issues or invalid credentials

**Solution**:
```bash
# Test API connectivity
python3 /root/Cloudflare_MT_Integration/scripts/test_connection.py
```

### Prefix always On-Demand

**Cause**: Cloudflare `on_demand_locked` setting

**Solution**: Contact Cloudflare Support to unlock the prefix

---

## Related Files

| File | Description |
|------|-------------|
| `/root/Cloudflare_MT_Integration/scripts/cloudflare-prefix-manager.py` | Main script |
| `/usr/local/bin/cloudflare-prefix-manager` | Global symlink |
| `/root/Cloudflare_MT_Integration/config/settings.json` | API configuration |
| `/root/Cloudflare_MT_Integration/config/prefix_mapping.json` | Prefix mapping |

---

## Differences from manual_control.py

| Feature | manual_control.py | cloudflare-prefix-manager.py |
|---------|-------------------|------------------------------|
| Supported prefixes | Only test (82.0/24) | **All 5 prefixes** |
| IPv6 | No | **Yes** (with On-Demand handling) |
| Argparse CLI | No | **Yes** (complete) |
| --all flag | No | **Yes** |
| 15-min constraint | Partial | **Enforced (blocks withdrawal)** |
| Withdraw time display | No | **Yes** (exact time + remaining) |
| Colored output | No | **Yes** (ANSI) |
| Telegram notifications | Basic | **SOC-style enriched** |
| Operation IDs | No | **Yes** |
| Bulk operation notifications | No | **Yes** |

---

*Documentation v1.4.0 - 2026-01-22 - GOLINE SA*
