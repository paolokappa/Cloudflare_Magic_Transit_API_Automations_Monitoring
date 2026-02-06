# Cloudflare Auto-Withdraw Manager

**Script**: `cloudflare-autowithdraw.py`
**Version**: 3.5
**Last Updated**: 2026-02-06

---

## Overview

The Auto-Withdraw Manager is the **ONLY** component in the system that performs BGP prefix withdrawals. It monitors advertised prefixes and automatically withdraws them after detecting a sustained "calm period" with no significant mitigated traffic.

### Key Responsibilities

| Responsibility | Description |
|----------------|-------------|
| **Monitor Prefixes** | Queries Cloudflare API every 60 seconds for advertised prefixes |
| **Detect Attacks** | Uses GraphQL to check for dropped/mitigated traffic |
| **Track Calm Periods** | Maintains in-memory timers for each prefix |
| **Auto-Withdraw** | Withdraws prefixes after 15 minutes of calm |
| **Notify** | Sends Telegram notifications for all actions |
| **Log to Database** | Records all withdrawals in shared SQLite database |

---

## Architecture (v2.1.0)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AUTOWITHDRAW - SINGLE SOURCE OF TRUTH                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Every 60 seconds:                                                           │
│                                                                              │
│  1. Query Cloudflare API: Which prefixes are currently advertised?          │
│     └─► GET /accounts/{id}/addressing/prefixes/{prefix_id}/bgp/prefixes/{bgp_prefix_id} │
│         for each prefix in config/prefix_mapping.json                       │
│         Check: on_demand.advertised == true                                 │
│                                                                              │
│  2. For each advertised prefix:                                              │
│     └─► Query GraphQL: magicTransitNetworkAnalyticsAdaptiveGroups           │
│         Filter: outcome="drop", last 5 minutes                              │
│                                                                              │
│  3. Decision Logic (v3.1 - AND logic):                                       │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │  Dropped packets > 5000 AND dropped bits > 10 Mbps?             │     │
│     │                                                                  │     │
│     │  YES → Attack in progress                                        │     │
│     │        Reset calm timer for this prefix                          │     │
│     │                                                                  │     │
│     │  NO  → Calm period (either threshold not met)                    │     │
│     │        Start/continue calm timer                                 │     │
│     │        If calm for 15 minutes → WITHDRAW                         │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  4. On Withdraw:                                                             │
│     ├─► PATCH /accounts/{id}/addressing/prefixes/{id}/bgp/prefixes/{id}     │
│     ├─► Send Telegram notification                                          │
│     └─► Log to SQLite database (attack_events + withdrawal_history)         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Configuration

### Constants (in script)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `CALM_PERIOD_MINUTES` | 15 | Minutes without attacks before auto-withdraw |
| `CHECK_INTERVAL_SECONDS` | 60 | How often to check (polling interval) |
| `ATTACK_LOOKBACK_MINUTES` | 5 | Time window to search for attacks in GraphQL |
| `MIN_DROPPED_PACKETS` | 5000 | Minimum dropped packets to consider as attack |
| `MIN_DROPPED_BITS` | 10000000 | Minimum dropped bits (10 Mbps) to consider as attack |

**Threshold Logic (v3.1)**: Both thresholds must be exceeded (AND logic) for traffic to be considered an attack:
```python
if packets > 5000 AND bits > 10 Mbps:
    # Attack in progress
```
This prevents false positives from background traffic (e.g., Veeam backups) where packet count may be high but bandwidth is low.

### Prefixes Monitored

```python
GOLINE_PREFIXES = [
    "185.54.80.0/24",
    "185.54.81.0/24",
    "185.54.82.0/24",
    "185.54.83.0/24",
    "2a02:4460:1::/48"  # IPv6 DMZv6
]
```

**Note**: IPv6 prefix `2a02:4460:1::/48` is now manageable (on-demand, not locked).

---

## Systemd Service

### Configuration: `/etc/systemd/system/cloudflare-autowithdraw.service`

```ini
[Unit]
Description=Cloudflare Magic Transit Auto-Withdraw Manager
Documentation=https://developers.cloudflare.com/magic-transit/
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/root/Cloudflare_MT_Integration
ExecStart=/usr/bin/python3 /root/Cloudflare_MT_Integration/scripts/cloudflare-autowithdraw.py daemon
Restart=always
RestartSec=10

Environment=PYTHONUNBUFFERED=1

StandardOutput=journal
StandardError=journal
SyslogIdentifier=cloudflare-autowithdraw

[Install]
WantedBy=multi-user.target
```

### Service Management

```bash
# Status
systemctl status cloudflare-autowithdraw

# Start/Stop/Restart
systemctl start cloudflare-autowithdraw
systemctl stop cloudflare-autowithdraw
systemctl restart cloudflare-autowithdraw

# Enable at boot
systemctl enable cloudflare-autowithdraw

# View logs
journalctl -u cloudflare-autowithdraw -f
journalctl -u cloudflare-autowithdraw -n 100 --no-pager
```

---

## CLI Commands

The script can be run interactively with various commands:

### Daemon Mode

```bash
# Run as daemon (normal operation)
python3 cloudflare-autowithdraw.py daemon
```

Starts the continuous monitoring loop. This is what systemd runs.

### Status

```bash
# Show current prefix status and attack info
python3 cloudflare-autowithdraw.py status
```

**Output Example**:
```
============================================================
Cloudflare Magic Transit - Auto Withdraw Manager v3
============================================================

CURRENT PREFIX STATUS
============================================================
🟢 185.54.80.0/24 (BGP)
   └─ Status: Not advertised

🟠 185.54.81.0/24 (DMZ)
   └─ Status: ADVERTISED
   └─ Advertised since: 2026-01-19 14:30:00 UTC
   └─ Calm since: 2026-01-19 14:45:00 (5.2 minutes)

🌐 2a02:4460:1::/48 (DMZv6)
   └─ Status: LOCKED (always advertised)
```

### Manual Withdraw

```bash
# Withdraw specific prefix
python3 cloudflare-autowithdraw.py withdraw 185.54.81.0/24

# Withdraw ALL advertised prefixes
python3 cloudflare-autowithdraw.py withdraw
```

**Sends Telegram notification** on successful withdrawal.

### Emergency Advertise

```bash
# Manually advertise a prefix (emergency protection)
python3 cloudflare-autowithdraw.py advertise 185.54.81.0/24
```

**Use case**: Enable DDoS protection immediately without waiting for MNM rules to trigger.

**15-Minute Re-Advertise Constraint**: Cloudflare enforces a 15-minute cooldown after withdrawing a prefix before it can be re-advertised. The script checks this constraint and shows remaining time:

```
ERROR: Cannot advertise 185.54.81.0/24 - 15-minute constraint not satisfied
       Cloudflare requires 15 minutes between withdrawal and re-advertisement
       Advertise available at 14:45:30 (in 3m 21s)
```

### Test API Connection

```bash
# Test GraphQL API and show sample data
python3 cloudflare-autowithdraw.py test
```

Useful for debugging API connectivity issues.

### Check (Single Cycle)

```bash
# Run a single check cycle without daemon loop
python3 cloudflare-autowithdraw.py check
```

Useful for testing or manual one-off checks.

---

## GraphQL Query

The script uses Cloudflare's GraphQL Analytics API to detect mitigated traffic:

```graphql
query NetworkAnalytics($accountTag: String!, $datetimeStart: Time!, $datetimeEnd: Time!) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      magicTransitNetworkAnalyticsAdaptiveGroups(
        filter: {
          datetime_geq: $datetimeStart
          datetime_leq: $datetimeEnd
          outcome: "drop"
        }
        limit: 100
        orderBy: [sum_packets_DESC]
      ) {
        dimensions {
          mitigationSystem
          outcome
          ipDestinationAddress
        }
        sum {
          packets
          bits
        }
      }
    }
  }
}
```

### Mitigation Systems Detected

| System | Description |
|--------|-------------|
| `dosd` | DDoS protection (L3/L4) |
| `flowtrackd` | Advanced TCP Protection |
| `magic-firewall` | Magic Firewall rules |
| `gatebot` | Gatebot (legacy) |

---

## Database Integration

When a withdrawal occurs, the script logs to two tables:

### 1. attack_events

```sql
INSERT INTO attack_events
(event_type, alert_type, prefix, action_taken, raw_payload, created_at)
VALUES ('WITHDRAW', 'autowithdraw_daemon', ?, 'withdrawn_auto', ?, ?);
```

### 2. withdrawal_history

```sql
INSERT INTO withdrawal_history
(prefix, withdrawn_at, protection_duration_seconds, withdraw_method, status, notes)
VALUES (?, ?, ?, 'autowithdraw_daemon', 'success', ?);
```

### 3. prefix_calm_status (Dashboard Integration)

The daemon syncs calm status to this table every 60 seconds for dashboard display:

```sql
INSERT OR REPLACE INTO prefix_calm_status
(prefix, under_attack, calm_since, calm_minutes, dropped_packets, dropped_bits, last_updated)
VALUES (?, ?, ?, ?, ?, ?, ?);
```

This enables the dashboard to show:
- Real-time attack status per prefix
- Minutes since last attack (calm duration)
- Time remaining until auto-withdraw
- Last dropped traffic statistics

### Query Examples

```bash
# Check calm status for dashboard
sqlite3 db/magic_transit.db "
  SELECT prefix, under_attack, calm_minutes,
         printf('%.2f', dropped_bits/1000000.0) as dropped_mbps,
         last_updated
  FROM prefix_calm_status;
"

# Recent withdrawals by autowithdraw
sqlite3 db/magic_transit.db "
  SELECT prefix, created_at, action_taken
  FROM attack_events
  WHERE event_type='WITHDRAW' AND alert_type='autowithdraw_daemon'
  ORDER BY id DESC LIMIT 10;
"

# Withdrawal history
sqlite3 db/magic_transit.db "
  SELECT prefix, withdrawn_at, protection_duration_seconds/60 as minutes, notes
  FROM withdrawal_history
  WHERE withdraw_method='autowithdraw_daemon'
  ORDER BY id DESC LIMIT 10;
"
```

---

## Telegram Notifications

### On Startup

```
🛡️ CLOUDFLARE DDoS PROTECTION
🚀 AUTO-WITHDRAW DAEMON STARTED

🖥️ Server: lg.goline.ch
⏱️ Calm period: 15 minutes
🔄 Check interval: 60 seconds
```

### On Auto-Withdraw

```
🛡️ CLOUDFLARE DDoS PROTECTION
✅ PREFIX AUTO-WITHDRAWN

🔖 Event ID: 20260119143000-withdraw

⚔️ PREFIX INFO
🌐 Prefix: 185.54.81.0/24
📝 Description: DMZ

📊 CALM PERIOD STATS
⏱️ Calm Duration: 15.2 minutes
📦 Dropped Packets: 0 pkts
📈 Dropped Traffic: 0.0 Mbps
🔧 Systems: None

🔄 BGP STATUS
📤 Action: Withdrawn
🌐 Routing: Direct (Magic Transit OFF)

⏰ Timestamp: 2026-01-19T14:30:00Z

🏢 GOLINE SOC | Cloudflare Magic Transit
```

### On Manual Withdraw

Similar format with "MANUAL PREFIX WITHDRAWAL" header.

---

## Troubleshooting

### Service Won't Start

```bash
# Check Python syntax
python3 -m py_compile scripts/cloudflare-autowithdraw.py

# Test manual run
python3 scripts/cloudflare-autowithdraw.py status

# Check dependencies
python3 -c "import requests; import sqlite3; print('OK')"
```

### No Withdrawals Happening

1. **Check if prefixes are advertised**:
   ```bash
   python3 scripts/cloudflare-autowithdraw.py status
   ```

2. **Check for ongoing attacks**:
   ```bash
   python3 scripts/cloudflare-autowithdraw.py test
   ```

3. **Verify calm period tracking**:
   ```bash
   journalctl -u cloudflare-autowithdraw -n 50 | grep "Calm for"
   ```

4. **Check thresholds**: Traffic below MIN_DROPPED_PACKETS/BITS is considered "calm"

### Withdraw Fails

1. **15-minute Cloudflare constraint**: Prefix must be advertised for at least 15 minutes
   ```bash
   cloudflare-prefix-manager status 185.54.81.0/24
   ```

2. **API errors**: Check logs for HTTP errors
   ```bash
   journalctl -u cloudflare-autowithdraw | grep -i error
   ```

3. **LOCKED prefix**: IPv6 prefix cannot be withdrawn (Cloudflare restriction)

---

## Changelog

### v3.5 (2026-02-06)
- **Telegram Retry Mechanism**
  - **Problem**: Telegram API timeouts caused missed withdrawal notifications
  - **Root Cause**: Intermittent network issues to api.telegram.org (30s timeout with no retry)
  - **Fix**: Added `max_retries=3` parameter with exponential backoff (5s, 10s, 20s)
  - **Logging**: Shows attempt number on retry and final failure message
  - **Result**: Withdrawal notifications now have 3 chances to be delivered

### v3.4 (2026-01-23)
- **Peak Attack Statistics in Withdraw Notifications**
  - **Bug**: Notifications showed "0 pkts, 0 Mbps" because they displayed current traffic (which is 0 during calm period)
  - **Fix**: Added `attack_peak_stats` dictionary to track peak values during attack
  - **Tracking**: Records highest `dropped_packets`, `dropped_mbps`, and all `mitigation_systems`
  - **Display**: Withdraw notification now shows "Peak Dropped Packets" and "Peak Dropped Traffic"
  - **Section renamed**: "CALM PERIOD STATS" → "ATTACK PEAK STATS"
  - **Cleanup**: Peak stats cleared after withdraw to prevent stale data on next attack
- **Result**: Users see meaningful attack statistics in withdraw notifications instead of zeros

### v3.3 (2026-01-21)
- **CRITICAL BUG FIX**: API endpoint for detecting advertised prefixes
  - **Bug**: Script used `/addressing/prefixes` endpoint which returns `advertised: False` for ALL prefixes
  - **Effect**: Script always showed "No prefixes currently advertised" even during active attacks
  - **Root Cause**: The `/addressing/prefixes` endpoint doesn't reflect actual BGP advertisement state
  - **Fix**: Now uses `/addressing/prefixes/{prefix_id}/bgp/prefixes/{bgp_prefix_id}` endpoint
  - **Field**: Checks `on_demand.advertised` instead of top-level `advertised`
- **Updated Functions**:
  - `get_advertised_prefixes()`: Now queries each prefix individually using correct BGP endpoint
  - `get_all_prefixes()`: Same fix applied for dashboard integration
  - `withdraw_prefix()`: Uses correct API structure `{"on_demand": {"advertised": false}}`
  - `advertise_prefix()`: Uses correct API structure `{"on_demand": {"advertised": true}}`
- **Added**: `load_prefix_mapping()` function to read BGP prefix IDs from `config/prefix_mapping.json`
- **Result**: Auto-withdraw now correctly detects advertised prefixes and performs withdrawals after 15 min calm

### v3.2 (2026-01-21)
- **Dashboard Integration**: Added `prefix_calm_status` table for real-time status sharing
  - Dashboard shows calm duration, time-to-withdraw, attack status per prefix
  - Synced every 60 seconds during daemon operation
  - All timestamps in UTC for consistency
- **15-Minute Re-Advertise Constraint**: Added `check_advertise_constraint()` function
  - Checks Cloudflare's 15-minute cooldown before re-advertising a withdrawn prefix
  - Prevents API rate limit errors (HTTP 429)
  - Shows user-friendly message with remaining time
- **IPv6 Support**: Full support for `2a02:4460:1::/48` prefix

### v3.1 (2026-01-19)
- **IMPORTANT FIX**: Changed threshold logic from OR to AND
  - Before: `packets > 5000 OR bits > 10 Mbps` → considered attack
  - After: `packets > 5000 AND bits > 10 Mbps` → considered attack
- Prevents false positives from background traffic (e.g., Veeam backups)
- High packet count with low bandwidth no longer triggers "attack in progress"

### v3.0 (2026-01-19)
- Added database integration (logs to attack_events + withdrawal_history)
- Unified architecture: now the ONLY component that performs withdrawals
- Webhook receiver no longer does withdraw operations

### v2.0
- Initial release with GraphQL-based attack detection
- Telegram notifications
- Daemon mode with configurable intervals

---

*GOLINE SOC - Cloudflare Magic Transit Integration*
