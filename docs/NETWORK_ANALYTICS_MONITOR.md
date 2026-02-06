# Network Analytics Monitor

**Version**: 1.4.1
**Last Updated**: 2026-02-06

## Overview

The Network Analytics Monitor queries the Cloudflare GraphQL API to detect DDoS mitigation events that may not trigger standard webhook notifications. It provides comprehensive visibility into all traffic dropped by Cloudflare's DDoS protection systems, enriched with GeoIP2 geolocation data.

### Key Features

- **GraphQL Polling**: Queries `dosdNetworkAnalyticsAdaptiveGroups` every 5 minutes
- **Dashboard Preference Sync**: Reads "My prefixes only" toggle from dashboard to control notifications
- **Destination Filter**: Notifies for GOLINE prefixes AND/OR Cloudflare anycast based on preference
- **Cloudflare Anycast**: Includes 162.159.0.0/16, 172.64.0.0/13, 104.16.0.0/13 (when filter disabled)
- **GeoIP2 Enrichment**: Source IPs show country, city, and ASN information
- **GeoIP Fallback**: Supports both commercial (GeoIP2) and free (GeoLite2) databases
- **Spoofed IP Detection**: Identifies private/reserved IPs with ⚠️ indicator
- **SQLite Deduplication**: Prevents duplicate notifications via event hash
- **Telegram Notifications**: Single events, aggregated bulk, startup and shutdown messages
- **European Date Format**: All dates displayed as DD/MM/YYYY HH:MM

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  NETWORK ANALYTICS MONITOR v1.4.0                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Cloudflare GraphQL API                                          │
│         │                                                        │
│         │ dosdNetworkAnalyticsAdaptiveGroups (every 5 min)       │
│         ▼                                                        │
│  ┌────────────────────────┐                                      │
│  │   Destination Filter   │ GOLINE: 185.54.80.0/22, 2a02:4460::/32│
│  │                        │ CF Anycast: 162.159/16, 172.64/13    │
│  └───────────┬────────────┘                                      │
│              │                                                   │
│              ▼                                                   │
│  ┌────────────────────────┐     ┌────────────────────────┐      │
│  │    GeoIP2 Enrichment   │────▶│  GeoIP2-City.mmdb      │      │
│  │                        │────▶│  GeoLite2-ASN.mmdb     │      │
│  └───────────┬────────────┘     └────────────────────────┘      │
│              │                                                   │
│    ┌─────────┼─────────┐                                         │
│    ▼         ▼         ▼                                         │
│ SQLite    Telegram   Log files                                   │
│ (dedup)   (alerts)   (debug)                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Configuration

### Paths

| Component | Path |
|-----------|------|
| Script | `/root/Cloudflare_MT_Integration/scripts/cloudflare-network-analytics-monitor.py` |
| Systemd Service | `/etc/systemd/system/cloudflare-analytics-monitor.service` |
| Log File | `/root/Cloudflare_MT_Integration/logs/network-analytics-monitor.log` |
| Database | `/root/Cloudflare_MT_Integration/db/magic_transit.db` |
| Dashboard Prefs | `/root/Cloudflare_MT_Integration/config/dashboard_prefs.json` |
| GeoIP City | `/usr/share/GeoIP/GeoIP2-City.mmdb` |
| GeoIP ASN | `/usr/share/GeoIP/GeoLite2-ASN.mmdb` |

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `POLL_INTERVAL` | 300s (5 min) | Time between API queries |
| `LOOKBACK_MINUTES` | 15 min | Time window for each query |
| `MIN_PACKETS_THRESHOLD` | 1 | Minimum packets to trigger notification |

### Destination Prefix Filter

| Prefix | Type | Description |
|--------|------|-------------|
| `185.54.80.0/22` | GOLINE | All GOLINE IPv4 (covers 80, 81, 82, 83) |
| `2a02:4460::/32` | GOLINE | GOLINE IPv6 (covers 2a02:4460:1::/48) |
| `162.159.0.0/16` | Cloudflare | Anycast IPs (Magic Transit pass-through) |
| `172.64.0.0/13` | Cloudflare | Anycast IPs (Magic Transit pass-through) |
| `104.16.0.0/13` | Cloudflare | Anycast IPs (Magic Transit pass-through) |

**Why include Cloudflare anycast?**
When Magic Transit is active, some attacks target Cloudflare anycast IPs directly (e.g., 162.159.76.173). These are still attacks against GOLINE infrastructure being mitigated by Cloudflare. Including these prefixes ensures complete visibility of all DDoS mitigation events.

### Dashboard Preference Integration

The monitor reads the "My prefixes only" toggle state from the dashboard preferences file:

| File | Path |
|------|------|
| Dashboard Prefs | `config/dashboard_prefs.json` |

**Preference Format:**
```json
{"my_prefixes_only": true}
```

**Behavior:**
| Setting | Notifications For |
|---------|-------------------|
| `my_prefixes_only: true` | Only GOLINE prefixes (185.54.x.x, 2a02:4460:x) |
| `my_prefixes_only: false` | All traffic including Cloudflare anycast |

**Prefix Lists:**
```python
MY_PREFIXES = [
    '185.54.80.0/22',    # GOLINE IPv4
    '2a02:4460::/32',    # GOLINE IPv6
]

ALL_PREFIXES = MY_PREFIXES + [
    '162.159.0.0/16',    # Cloudflare anycast
    '172.64.0.0/13',     # Cloudflare anycast
    '104.16.0.0/13',     # Cloudflare anycast
]
```

**Note:** The preference is read on each poll cycle (every 5 minutes), so changes take effect without restarting the service.

---

## GeoIP2 Enrichment

### Overview

Source IPs in notifications are enriched with geolocation data:

| Data | Source | Example |
|------|--------|---------|
| Country | GeoIP2-City.mmdb | Bangladesh (BD) |
| City | GeoIP2-City.mmdb | Pābna |
| ASN | GeoLite2-ASN.mmdb | AS137959 |
| Organization | GeoLite2-ASN.mmdb | Vision Technologies Ltd. |

### Spoofed IP Detection

Private and reserved IP ranges are automatically detected and marked:

| Range | Type |
|-------|------|
| `10.0.0.0/8` | Private |
| `172.16.0.0/12` | Private |
| `192.168.0.0/16` | Private |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local |
| `224.0.0.0/4` | Multicast |

### Database Paths (with Fallback)

The script searches for GeoIP databases in order of preference:

**City Database (for Country/City):**
```
1. /usr/share/GeoIP/GeoIP2-City.mmdb      # Commercial (more accurate)
2. /usr/share/GeoIP/GeoLite2-City.mmdb    # Free fallback
3. /var/lib/GeoIP/GeoIP2-City.mmdb        # Alternative location
4. /var/lib/GeoIP/GeoLite2-City.mmdb      # Alternative location
```

**ASN Database:**
```
1. /usr/share/GeoIP/GeoIP2-ASN.mmdb       # Commercial
2. /usr/share/GeoIP/GeoLite2-ASN.mmdb     # Free fallback
3. /var/lib/GeoIP/GeoIP2-ASN.mmdb         # Alternative location
4. /var/lib/GeoIP/GeoLite2-ASN.mmdb       # Alternative location
```

**Current Setup:**
```
/usr/share/GeoIP/GeoIP2-City.mmdb     # 122 MB (commercial)
/usr/share/GeoIP/GeoLite2-ASN.mmdb    # 11 MB (free)
```

The startup message indicates which database type is in use (Commercial or Free) and its last update date.

### Dependencies

```bash
apt install python3-geoip2
```

---

## Telegram Notifications

### Single Event Format (with GeoIP)

```
🛡️ *CLOUDFLARE DDoS PROTECTION*

🚨 *MITIGATION EVENT*

⏱️ *Time:* `2026-01-19 22:51:50 UTC`
🆔 *Attack ID:* `k9z3t-xx1g6wwhgqngq523mp0nr`

⚔️ *ATTACK INFO*
💥 *Vector:* ICMP Flood
📋 *Rule:* ICMP-0001
🛡️ *Action:* BLOCKED

🌐 *NETWORK*
📤 *Source:* `103.118.76.198:46181`
🌍 *Origin:* Pābna, Bangladesh (BD)
🏢 *ASN:* AS137959 - Vision Technologies Ltd.
📥 *Target:* `185.54.82.4:0`
🔧 *Protocol:* ICMP
🏷️ *TCP Flags:* N/A

📊 *METRICS*
📦 *Packets:* 1,500
📈 *Data:* 9.00 Mbps

📍 *CLOUDFLARE EDGE*
🌍 *Scrubbed at:* Sofia, Bulgaria (SOF)

🏢 *GOLINE SOC* | _Network Analytics Monitor_
```

### Aggregated Format (>3 events, with GeoIP)

```
🛡️ *CLOUDFLARE DDoS PROTECTION*

🚨 *BULK MITIGATION EVENTS*

📊 *SUMMARY*
📦 *Events:* 15
🆔 *Attack IDs:* 1
📍 *Unique Sources:* 8
⚠️ *Spoofed IPs:* 3/8

⏱️ *TIME RANGE*
🕐 *From:* `2026-01-19T22:50:00Z`
🕑 *To:* `2026-01-19T22:55:00Z`

⚔️ *ATTACK VECTORS*
• ICMP Flood
• GRE Flood

📊 *TOTAL METRICS*
📦 *Packets Dropped:* 15,000
📈 *Data Blocked:* 54.00 Mb

📤 *TOP SOURCE IPs*
• `103.118.76.198` 🌍 BD (AS137959)
• `45.227.254.17` 🌍 BR (AS270523)
• `10.0.0.1` ⚠️ _Spoofed_

🌍 *EDGE LOCATIONS*
SOF (BG), AMS (NL)

🏢 *GOLINE SOC* | _Network Analytics Monitor_
```

### Startup Notification Format

```
🛡️ *CLOUDFLARE DDoS PROTECTION*

🚀 *Network Analytics Monitor STARTED*

📊 *Configuration*
📌 Version: 1.3.8
⏰ Poll: 300s | Lookback: 15 min
🌍 GeoIP: Commercial (updated: 20/01/2026)

🌐 *BGP Status*
📡 Prefixes: 0/5 ✅ All withdrawn

📈 *Attack History*
🎯 Attacks: 6 total (6 this month)
📊 Mitigations: 402 events logged
🚨 Last: `19/01/2026 21:51`
💥 Type: SYN Flood, 1.2 Gbps → 185.54.82.4

⚙️ *Services*
✅ Webhook | ✅ Autowithdraw | ✅ Dashboard

_Monitoring for DDoS mitigation events..._
```

**Data Sources:**

| Field | Source | Description |
|-------|--------|-------------|
| Version | Hardcoded | Script version |
| GeoIP Type | Database detection | Commercial or Free |
| GeoIP Updated | File mtime | Last modification date |
| BGP Prefixes | Cloudflare API | Advertised/Total count |
| Attacks Total | SQLite `attack_events` | WHERE event_type='START' |
| Attacks Month | SQLite `attack_events` | Current month filter |
| Mitigations | SQLite `network_analytics_events` | Total count |
| Last Attack | SQLite `attack_events` | Most recent START event |
| Services | systemctl is-active | Webhook, Autowithdraw, Dashboard |

### Shutdown Notification Format

```
🛡️ *CLOUDFLARE DDoS PROTECTION*

⏹️ *Network Analytics Monitor STOPPED*

📈 *Stats*
🎯 Attacks: 6 total (6 this month)
📊 Mitigations: 402 events

⏰ *Stopped at:* 21/01/2026 03:13:01 UTC

🏢 *GOLINE SOC* | _Network Analytics_
```

---

## Commands

### Service Management

```bash
# Start/Stop/Restart
systemctl start cloudflare-analytics-monitor
systemctl stop cloudflare-analytics-monitor
systemctl restart cloudflare-analytics-monitor

# Status
systemctl status cloudflare-analytics-monitor

# Logs
journalctl -u cloudflare-analytics-monitor -f
```

### Manual Execution

```bash
# Test query (dry run)
python3 scripts/cloudflare-network-analytics-monitor.py --test

# Test with custom lookback (60 minutes)
python3 scripts/cloudflare-network-analytics-monitor.py --test --lookback 60

# Run once and exit
python3 scripts/cloudflare-network-analytics-monitor.py --once
```

### Database Queries

```bash
# Recent events
sqlite3 db/magic_transit.db \
  "SELECT event_datetime, attack_vector, source_ip, packets
   FROM network_analytics_events ORDER BY id DESC LIMIT 10;"

# Events by attack vector
sqlite3 db/magic_transit.db \
  "SELECT attack_vector, COUNT(*)
   FROM network_analytics_events GROUP BY attack_vector;"

# Events today
sqlite3 db/magic_transit.db \
  "SELECT COUNT(*) FROM network_analytics_events
   WHERE date(notified_at) = date('now');"
```

---

## Database Schema

```sql
CREATE TABLE network_analytics_events (
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
);
```

**Deduplication**: Events are deduplicated using SHA256 hash of:
- datetime + attackId + sourceIP + destIP + destPort

---

## High Availability

| Protection | Description |
|------------|-------------|
| `Restart=always` | Systemd auto-restart on crash |
| `RestartSec=30` | Wait 30s before restart |
| **Cron Watchdog** | External check every 5 minutes |

**Note**: `WatchdogSec` removed - script doesn't implement `sd_notify` heartbeat.

---

## Troubleshooting

### No Events Found

1. Check API token has `Account.Account Analytics` permission
2. Verify account ID in `config/settings.json`
3. Try increasing lookback: `--lookback 60`
4. Check if GOLINE prefix filter is too restrictive

### GeoIP Not Working

```bash
# Check GeoIP2 package
python3 -c "import geoip2; print('OK')"

# Check database files exist
ls -la /usr/share/GeoIP/

# Test GeoIP lookup
python3 -c "
import geoip2.database
reader = geoip2.database.Reader('/usr/share/GeoIP/GeoIP2-City.mmdb')
result = reader.city('8.8.8.8')
print(f'{result.city.name}, {result.country.name}')
"
```

### Service Crashes

```bash
# Check systemd logs
journalctl -u cloudflare-analytics-monitor -n 100 --no-pager

# Check log file
tail -100 logs/network-analytics-monitor.log
```

---

## Changelog

### v1.4.0 (2026-02-02)
- **Dashboard Preference Sync** - Reads "My prefixes only" toggle from dashboard
  - New file: `config/dashboard_prefs.json` stores user preference
  - Toggle ON: Only notify for GOLINE prefixes (185.54.x.x, 2a02:4460:x)
  - Toggle OFF: Notify for all traffic including Cloudflare anycast
  - Preference read on each poll (no restart needed)
- **Prefix list split** - Separate MY_PREFIXES and ALL_PREFIXES lists
- **Dynamic filtering** - `is_notifiable_ip()` checks against current preference

### v1.3.10 (2026-02-02)
- **Cloudflare Anycast Visibility** - Added Cloudflare anycast prefixes to destination filter
  - New prefixes: 162.159.0.0/16, 172.64.0.0/13, 104.16.0.0/13
  - Shows Magic Transit pass-through traffic
  - Complete visibility of all DDoS mitigation events

### v1.3.8 (2026-01-21)
- **Removed System section** from startup message (hostname, uptime, Python version)
- **Last attack emoji** - Added 💥 before Type line
- **Alignment fix** - Removed extra spaces before emoji

### v1.3.7 (2026-01-21)
- **European date format** - All dates now DD/MM/YYYY HH:MM
- **Shutdown message** - Updated to use new stats format

### v1.3.6 (2026-01-21)
- **Fixed get_last_attack()** - Was using wrong column name (event_datetime → created_at)
- **Last attack details** - Now shows datetime, vector, Gbps, target IP
- **Clearer stats labels** - Attacks (total/month) and Mitigations (events count)
- **Last attack on two lines** - Better readability

### v1.3.5 (2026-01-21)
- **Enhanced startup message** with:
  - Version number
  - System info (hostname, uptime, Python version)
  - BGP prefix status from Cloudflare API
  - Attack history from database
  - Services health status (systemd)

### v1.3.10 (2026-02-02)
- **Cloudflare Anycast Visibility** - Added Cloudflare anycast prefixes to destination filter
  - New prefixes: 162.159.0.0/16, 172.64.0.0/13, 104.16.0.0/13
  - Shows Magic Transit pass-through traffic (attacks targeting Cloudflare IPs)
  - Complete visibility of all DDoS mitigation events

### v1.3.9 (2026-01-22)
- **Polling visibility** - Changed "no events" log from DEBUG to INFO for better monitoring

### v1.3.8 (2026-01-21)
- **Enhanced startup message** - BGP status, attack history, services health

### v1.3.7 (2026-01-21)
- **European date format** - DD/MM/YYYY throughout, shutdown message with stats

### v1.3.6 (2026-01-21)
- **Source ASN/Country** - Added to GraphQL query and DB schema

### v1.3.5 (2026-01-21)
- **Enhanced startup message** - System info, BGP status, last attack

### v1.3.4 (2026-01-21)
- **GeoIP info in startup** - Shows DB type and update date

### v1.3.3 (2026-01-21)
- **GeoIP DB type in footer** - Notifications show Commercial or Free

### v1.3.2 (2026-01-21)
- **GeoIP fallback** - Supports both commercial (GeoIP2) and free (GeoLite2) databases
- **Multiple search paths** - /usr/share/GeoIP and /var/lib/GeoIP

### v1.3.1 (2026-01-19)
- **GeoIP in aggregated notifications** - Top source IPs show country code and ASN

### v1.3.0 (2026-01-19)
- **GeoIP2 Integration** - Source IP geolocation and ASN info
  - Individual events show: country, city, ASN, organization
  - Spoofed IP detection (private/reserved ranges)
  - Uses GeoIP2-City.mmdb and GeoLite2-ASN.mmdb

### v1.2.0 (2026-01-19)
- **Enhanced notifications** - Spoofed IP detection, hide Unknown fields, edge locations

### v1.1.3 (2026-01-19)
- **GOLINE prefix filter** - Only notify for traffic to 185.54.80.0/22 and 2a02:4460::/32

### v1.1.2 (2026-01-19)
- **Increased lookback** - Changed from 10 to 15 minutes

### v1.1.1 (2026-01-19)
- **Removed WatchdogSec** - Script doesn't implement sd_notify

### v1.1.0 (2026-01-19)
- High Availability setup with systemd protections

### v1.0.0 (2026-01-19)
- Initial release

---

*Documentation v1.3.10 - 2026-02-02 - GOLINE SOC*
