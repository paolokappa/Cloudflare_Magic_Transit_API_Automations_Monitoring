# Cloudflare Magic Transit Dashboard

**Version**: 2.10.4
**Created**: 2026-01-20
**Last Updated**: 2026-02-06
**Author**: GOLINE SOC

---

## Overview

Real-time web dashboard for monitoring Cloudflare Magic Transit infrastructure. Provides visibility into BGP prefix status, DDoS attack events, network analytics, MNM rules, and service health.

### Recent Changes (v2.10.1)

- **IPv6 Attack Events Fix**:
  - **BUG FIXED**: IPv6 attacks not appearing in Network Analytics when "GOLINE only" toggle active
  - **CAUSE 1**: SQL `ORDER BY id DESC` was sorting by the string alias `"webhook_" || id` instead of the integer id
  - **CAUSE 2**: Combined sorting used string comparison on timestamps with different formats:
    - GraphQL: `2026-02-02T01:26:52Z` (with 'T' and 'Z')
    - Webhook: `2026-02-02 08:53:30` (with space)
    - In string comparison, 'T' > ' ', so 01:26 incorrectly sorted after 08:53
  - **FIX 1**: Changed to `ORDER BY attack_events.id DESC` and `ORDER BY network_analytics_events.id DESC`
  - **FIX 2**: Added `normalize_datetime()` function to convert both formats to comparable strings
  - **Result**: IPv6 UDP Flood attacks now display correctly in chronological order

- **Exact Timestamps Display**:
  - **CHANGED**: Network Analytics and Recent Attacks now show exact time instead of just "Xh ago"
  - **Format**: `HH:MM (Xh ago)` for events within 24h, `DD/MM HH:MM` for older events
  - **Reason**: User requested exact timestamps for better incident tracking

- **MNM Webhook Events Indicator**:
  - **CHANGED**: Webhook events (MNM alerts) now show meaningful placeholders instead of empty "-"
  - **Source IP**: Shows "N/A (MNM)" to indicate source info not available from Cloudflare MNM
  - **Country**: Shows "🌐" globe emoji
  - **Note**: Cloudflare MNM webhooks don't include attacker source IP - only GraphQL Network Analytics has that data (IPv4 only)

- **Event Detail Modal Fix**:
  - **BUG FIXED**: Double-click on Network Analytics events no longer opened detail modal
  - **CAUSE**: Event IDs changed from integers to composite strings (e.g., "webhook_117", "graphql_1219")
  - **FIX**: New API endpoint `/api/analytics/detail/<event_id>` handles both ID formats
  - **FIX**: JavaScript ondblclick now passes ID as quoted string

- **Toggle Controls Telegram Notifications**:
  - **NEW**: "My prefixes only" toggle now also controls Network Analytics Monitor notifications
  - **Server-side**: Preference saved to `config/dashboard_prefs.json` when toggle changes
  - **Monitor v1.4.0**: Reads `my_prefixes_only` preference before sending Telegram notifications
  - **ON**: Only notify for traffic to your prefixes (185.54.x.x, 2a02:4460:x)
  - **OFF**: Notify for all traffic including Cloudflare anycast (162.159.x.x, 172.64.x.x)

- **Toggle Label Renamed**:
  - **CHANGED**: "GOLINE only" → "My prefixes only" (more generic for distribution)

### Changes (v2.10.0)

- **Network Analytics Display Modes**:
  - **Auto-collapse when withdrawn**: When all prefixes are withdrawn, Network Analytics shows a collapsed view with summary stats instead of the full event table
  - **"GOLINE only" toggle**: New toggle switch to filter events by destination:
    - **ON**: Shows only traffic to GOLINE IPs (185.54.80.0/22, 2a02:4460::/32)
    - **OFF**: Shows all traffic including Cloudflare anycast (162.159.x.x, 172.64.x.x, 104.16.x.x)
  - **"Show Historical Events" button**: Allows viewing all events even when prefixes are withdrawn
  - **Preferences persistence**: Display preferences saved to localStorage (per browser)
  - **New API endpoints**:
    - `GET /api/analytics-summary` - Returns summary stats for collapsed view
    - `GET /api/dashboard-prefs` - Load dashboard preferences
    - `POST /api/dashboard-prefs` - Save dashboard preferences
  - **Filter parameter**: `/api/analytics?filter=when_protected` filters events by GOLINE destination

### Changes (v2.9.22)

- **DNS Timeout Graceful Handling**:
  - **BUG FIXED**: "Error: 1 (of 70) futures unfinished" in Network Analytics section
  - **CAUSE**: `as_completed(futures, timeout=5)` raises TimeoutError when DNS lookups don't complete
  - **FIX**: Wrapped `as_completed()` loops in try/except TimeoutError to continue with partial results
  - **Affected endpoints**: `/api/analytics` and `/api/network-flow`
  - **Result**: Dashboard displays data even when some hostname resolutions timeout
  - Hostnames that timeout are simply left empty instead of failing the entire API

### Changes (v2.9.19)

- **Network Analytics - Source IP Hostname Resolution**:
  - **NEW**: Added "Hostname" column to Network Analytics table
  - **NEW**: Hostname displayed in detail modal (double-click) under Source section
  - Reverse DNS lookup for each unique source IP
  - Parallel resolution using ThreadPoolExecutor (10 workers, 5s timeout)
  - Hostname cache to avoid duplicate lookups for same IP
  - New CSS class `.hostname-cell` (0.75rem, ellipsis overflow)
  - API fields: `source_hostname` added to `/api/analytics` and `/api/analytics/<id>` responses

### Changes (v2.9.18)

- **Network Flow - Hostname Resolution**:
  - **NEW**: Top Source, Top Router, and Top Destination cards now show hostname
  - Reverse DNS lookup performed with 500ms timeout per IP
  - Hostnames resolved in parallel using ThreadPoolExecutor
  - Displayed in italics below the IP address
  - New CSS class `.stat-hostname` for compact display
  - API fields: `top_source_hostname`, `top_router_hostname`, `top_destination_hostname`

- **Network Flow - Card Layout Reorganization**:
  - **CHANGED**: Labels (titles) moved to top of each card as first element
  - **Before**: Value → Hostname → Label → Description
  - **After**: Label → Value → Hostname → Description
  - Consistent across all 6 Network Flow cards

- **Network Flow - Top Protocol Volume Styling**:
  - **FIXED**: Volume in Top Protocol card now uses same styling as other cards
  - Added `stat-vol` class for consistent amber/gold color (#fbbf24)
  - Same font-size (0.95rem) and font-weight (600) as other volume displays

### Changes (v2.9.17)

- **Network Analytics - Increased Event Limit**:
  - **CHANGED**: Increased `LIMIT` from 30 to 100 events in `/api/analytics` endpoint
  - **Before**: Only showed 30 events despite 843+ events in database
  - **After**: Shows up to 100 most recent events
  - **Reason**: Users reported many events not visible in dashboard

### Changes (v2.9.16)

- **Network Analytics Status Indicator**:
  - **NEW**: Dynamic status indicator in Network Analytics card header
  - Shows real-time monitoring state based on BGP prefix advertisement status
  - **All prefixes withdrawn**: "⏸️ Paused - all prefixes withdrawn" (gray text)
  - **Prefixes advertised**: "✅ Active - N prefix(es) via Cloudflare" (green text)
  - Technical implementation:
    - Global variables `globalAdvertisedCount` and `globalTotalPrefixes` track prefix state
    - Status updates automatically when `loadPrefixes()` refreshes data
    - HTML structure: `.card-title-row` flex container with title left, status right
    - CSS: `.card-status` positioned inline with card title

- **Network Analytics Monitor - Improved Polling Visibility**:
  - **BUG FIXED**: Service appeared "frozen" when no events were found
  - **Cause**: Used `logger.debug()` for "no events" message - not visible at INFO level
  - **Symptom**: No log output for ~22 hours, appeared like service was hung
  - **Fix**: Changed `logger.debug()` to `logger.info("Poll completed - no new events")`
  - **Result**: Regular heartbeat in logs every 5 minutes confirms service is healthy
  - **File**: `scripts/cloudflare-network-analytics-monitor.py` line ~1045

- **Potential Bug Documented** (for future investigation):
  - **Issue**: `cloudflare-analytics-monitor` service got stuck/hung for ~23 hours
  - **Observation**: Process was alive but not polling GraphQL API
  - **Recovery**: Required `SIGKILL` (SIGTERM timed out)
  - **Root Cause**: Unknown - possibly API connection hung without timeout
  - **Mitigation**: Improved logging will help detect this condition earlier
  - **Recommendation**: Consider adding explicit request timeout in GraphQL queries

### Recent Changes (v2.9.15)

- **Stats API Bug Fixes**:
  - **Timestamp Format Fix**: Changed from Python `isoformat()` to SQLite `datetime('now', '-24 hours')` for correct comparisons
  - **Real Attacks Only**: Stats now count only `event_type = 'START'` (actual attacks), excluding END/ADVERTISE/WITHDRAW events
  - Before: "Attacks (24h)" showed 0 due to string comparison failure
  - After: Shows accurate count of real DDoS attacks

### Recent Changes (v2.9.13)

- **DDoS Custom Overrides API**: Full CRUD support for custom override rules
  - `/api/ddos-overrides` - List, create custom rules with wirefilter expressions
  - `/api/ddos-overrides/<id>` - Update, delete individual rules
  - `/api/ddos-overrides/<id>/move` - Reorder rules (position API)
  - `/api/ddos-overrides/validate` - Expression syntax validation
- **Dashboard Section**: "Network-layer DDoS Protection Overrides" with Simple/Advanced editor
- **Rule Ordering**: Up/down arrows + direct position input for rule priority

### Recent Changes (v2.9.12)

- **Prefix Manager Logging (v1.4.0)**: CLI ADVERTISE/WITHDRAW operations now logged to database
- **Dashboard Integration**: Manual CLI operations visible in "DDoS Protection Log" section
- **New alert_type**: `prefix_manager_manual` for CLI tool operations
- **New action_taken**: `advertised_manual`, `withdrawn_manual` for CLI operations

### Recent Changes (v2.9.11)

- **Title Change**: "Recent Attacks" section renamed to "🛡️ DDoS Protection Log"
- **Description**: Updated to "Attack events, BGP announcements, and protection lifecycle"
- **Empty State**: Changed from "No attacks recorded" to "No events recorded"

### Recent Changes (v2.9.10)

- **Event Type Labels**: User-friendly labels instead of raw values
  - `START` → `🚨 ATTACK`, `END` → `✅ ENDED`, `ADVERTISE` → `📡 ADVERTISE`, `WITHDRAW` → `📤 WITHDRAW`
- **Action Labels**: Clear status indicators
  - `mitigating` → `🛡️ Mitigating`, `auto_advertised` → `📡 Auto-Advertised`
- **Attack Events**: Now shows complete attack lifecycle (ADVERTISE → ATTACK → WITHDRAW)
- **Ordering**: Fixed chronological ordering (`ORDER BY created_at DESC`)
- **Modal Cleanup**: Removed redundant "Message" section from Attack Detail modal

### Key Features

- **Real-time monitoring** with 30-second auto-refresh
- **Dark theme UI** optimized for SOC environments
- **HTTPS only** with Let's Encrypt SSL certificate
- **IP-restricted access** based on Fail2ban whitelist
- **Session-based authentication** with bcrypt password hashing
- **Password change functionality** via header modal
- **Responsive design** for desktop and tablet viewing
- **Dual branding** with Cloudflare and GOLINE logos

---

## Authentication

### Overview

The dashboard requires authentication before accessing any protected pages or API endpoints. Authentication is session-based with bcrypt password hashing.

### Configuration

Authentication credentials are stored in `config/auth.json`:

```json
{
  "username": "admin",
  "password_hash": "$2b$12$...",
  "last_changed": "2026-01-21T00:00:00Z"
}
```

### Default Credentials

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `admin` |

**IMPORTANT**: Change the default password immediately after first login!

### Password Requirements

- Minimum 8 characters
- Passwords are hashed using bcrypt with salt

### Routes

| Route | Method | Protected | Description |
|-------|--------|-----------|-------------|
| `/login` | GET | No | Login page |
| `/login` | POST | No | Authentication endpoint |
| `/logout` | GET | No | Clear session and redirect |
| `/api/change-password` | POST | Yes | Change password |

### Header Controls

The dashboard header includes:
- **Settings button** (gear icon): Opens password change modal
- **Logout button**: Clears session and redirects to login

### Password Change Modal

The password change modal requires:
1. Current password (verification)
2. New password (minimum 8 characters)
3. Confirm new password (must match)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DASHBOARD ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Browser (Whitelisted IP)                                                    │
│       │                                                                      │
│       │ HTTPS :443                                                           │
│       ▼                                                                      │
│  ┌────────────────────────────────────┐                                      │
│  │ Apache2 (Reverse Proxy)            │                                      │
│  │ ├── SSL/TLS termination            │                                      │
│  │ ├── IP whitelist enforcement       │                                      │
│  │ └── ProxyPass to Flask             │                                      │
│  └────────────────┬───────────────────┘                                      │
│                   │ HTTP :8081                                               │
│                   ▼                                                          │
│  ┌────────────────────────────────────┐                                      │
│  │ Flask Dashboard (app.py)           │                                      │
│  │ ├── / → dashboard.html             │                                      │
│  │ ├── /health → JSON status          │                                      │
│  │ └── /api/* → JSON endpoints        │                                      │
│  └────────────────┬───────────────────┘                                      │
│                   │                                                          │
│       ┌───────────┼───────────┐                                              │
│       ▼           ▼           ▼                                              │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐                                         │
│  │ SQLite  │ │ CF API  │ │ systemd │                                         │
│  │ Database│ │ (REST)  │ │ (status)│                                         │
│  └─────────┘ └─────────┘ └─────────┘                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Components

### Directory Structure

```
/root/Cloudflare_MT_Integration/dashboard/
├── app.py                      # Flask backend application
├── templates/
│   └── dashboard.html          # Frontend HTML/CSS/JS (single file)
├── static/
│   └── images/
│       ├── Goline_500_160_trasparente.png  # GOLINE logo (500x160, transparent)
│       ├── goline_logo.png                  # GOLINE logo large (1000x386)
│       └── goline_logo_small.png            # GOLINE logo small (236x91)
└── images/                     # Source images (not served)
    ├── Goline_500_160_trasparente.png
    └── GOLINE_Logo.png

/etc/apache2/sites-available/
└── cloudflare.goline.ch.conf   # Apache vhost configuration

/etc/systemd/system/
└── cloudflare-dashboard.service # Systemd service unit
```

### Files Description

| File | Purpose |
|------|---------|
| `app.py` | Flask web application with API endpoints |
| `dashboard.html` | Single-page frontend with embedded CSS/JS |
| `cloudflare.goline.ch.conf` | Apache reverse proxy with IP whitelist |
| `cloudflare-dashboard.service` | Systemd service for auto-start |
| `Goline_500_160_trasparente.png` | GOLINE logo displayed in header |

---

## Backend API Endpoints

### Base URL

- **Internal**: `http://127.0.0.1:8081`
- **External**: `https://cloudflare.goline.ch`

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard HTML page |
| `/health` | GET | Health check (JSON) |
| `/api/prefixes` | GET | BGP prefix status from Cloudflare API |
| `/api/prefix/<cidr>/advertise` | POST | Advertise a BGP prefix |
| `/api/prefix/<cidr>/withdraw` | POST | Withdraw a BGP prefix |
| `/api/attacks` | GET | Recent attack events from database |
| `/api/attacks/<id>` | GET | Full attack event details with raw_payload |
| `/api/analytics` | GET | Network analytics events from database |
| `/api/analytics/<id>` | GET | Full analytics event details with rule description lookup |
| `/api/rules` | GET | MNM rules from Cloudflare API |
| `/api/ddos-sensitivity` | GET | L3/4 DDoS ruleset summary |
| `/api/ddos-rules` | GET | All L3/4 DDoS rules with details |
| `/api/ddos-rules/<action>` | GET | DDoS rules filtered by action (block/ddos_dynamic/log) |
| `/api/ddos-rules/<rule_id>/update` | POST | Update DDoS rule action via override |
| `/ddos-rules` | GET | DDoS Rules Manager page (HTML) |
| `/ddos-rules/<action>` | GET | DDoS Rules Manager filtered by action (HTML) |
| `/api/ddos-overrides` | GET | List custom DDoS override rules |
| `/api/ddos-overrides` | POST | Create new custom DDoS override |
| `/api/ddos-overrides/<id>` | PUT | Update custom DDoS override |
| `/api/ddos-overrides/<id>` | DELETE | Delete custom DDoS override |
| `/api/ddos-overrides/<id>/move` | POST | Move override rule position |
| `/api/ddos-overrides/validate` | POST | Validate wirefilter expression syntax |
| `/api/mnm-rules` | GET | List all MNM rules |
| `/api/mnm-rules` | POST | Create new MNM rule |
| `/api/mnm-rules/<rule_id>` | PUT | Update MNM rule (threshold, duration, auto-adv) |
| `/api/mnm-rules/<rule_id>` | DELETE | Delete MNM rule |
| `/mnm-rules` | GET | MNM Rules Manager page (HTML) |
| `/api/services` | GET | Systemd service status |
| `/api/stats` | GET | Summary statistics |
| `/api/network-flow` | GET | Real-time network flow stats from MNM (Networking > Insights > Network Flow) |
| `/connectors` | GET | Connectors page - IPsec/GRE Tunnels & CNI Interconnects (HTML) |
| `/api/connectors/tunnels` | GET | GRE and IPsec tunnels from Cloudflare API |
| `/api/connectors/interconnects` | GET | CNI Interconnects from Cloudflare API |
| `/api/connectors/health-summary` | GET | Connector health summary for header Status indicator |
| `/api/connectors/tunnel-health` | GET | Tunnel health from GraphQL API |
| `/api/connectors/tunnel/<id>` | GET | Get single tunnel details (GRE or IPsec) |
| `/api/connectors/tunnel/<id>/update` | POST | Update tunnel description (auto-detects type) |
| `/api/connectors/cni/<id>` | GET | Get single CNI details |
| `/api/connectors/cni/<id>/update` | POST | Update CNI description |

### Response Format

All API endpoints return JSON:

```json
{
  "success": true,
  "data": { ... },
  "error": null
}
```

### Endpoint Details

#### `/api/prefixes`

Returns BGP prefix advertisement status from Cloudflare API, merged with calm status from autowithdraw daemon.

```json
{
  "success": true,
  "prefixes": [
    {
      "cidr": "185.54.80.0/24",
      "description": "BGP",
      "advertised": false,
      "status": "withdrawn",
      "advertised_modified_at": "2026-01-19T20:05:30.91381Z",
      "on_demand_enabled": false,
      "under_attack": null,
      "calm_minutes": 0,
      "time_to_withdraw": 0
    },
    {
      "cidr": "185.54.82.0/24",
      "description": "DMZ-EXT",
      "advertised": true,
      "status": "advertised",
      "advertised_modified_at": "2026-01-21T02:30:00Z",
      "on_demand_enabled": true,
      "under_attack": false,
      "calm_minutes": 8.5,
      "time_to_withdraw": 6.5,
      "dropped_packets": 0,
      "dropped_mbps": 0,
      "calm_last_updated": "2026-01-21 02:54:39"
    }
  ]
}
```

**Calm Status Fields** (from autowithdraw daemon):

| Field | Type | Description |
|-------|------|-------------|
| `under_attack` | boolean/null | `true` if under attack, `false` if calm, `null` if no data |
| `calm_minutes` | float | Minutes since last attack (0 if under attack or no data) |
| `time_to_withdraw` | float | Minutes until auto-withdraw (15 - calm_minutes, min 0) |
| `dropped_packets` | int | Last detected dropped packets during attack |
| `dropped_mbps` | float | Last detected dropped traffic in Mbps |
| `calm_last_updated` | string | Timestamp of last status update from daemon |

#### `/api/prefix/<cidr>/advertise` (POST)

Advertise a BGP prefix. Checks the 15-minute constraint.

**Success Response:**
```json
{
  "success": true,
  "message": "Prefix 185.54.82.0/24 advertised successfully",
  "cidr": "185.54.82.0/24"
}
```

**Error Response (15-min constraint):**
```json
{
  "success": false,
  "error": "Must wait 14m 48s before advertising (available at 23:02:28)",
  "remaining_seconds": 888.66,
  "available_at": "23:02:28"
}
```

**Error Response (already advertised):**
```json
{
  "success": false,
  "error": "Prefix is already advertised"
}
```

#### `/api/prefix/<cidr>/withdraw` (POST)

Withdraw a BGP prefix. Checks the 15-minute constraint.

**Success Response:**
```json
{
  "success": true,
  "message": "Prefix 185.54.82.0/24 withdrawn successfully",
  "cidr": "185.54.82.0/24"
}
```

**Error Response (15-min constraint):**
```json
{
  "success": false,
  "error": "Must wait 14m 48s before withdrawing (available at 23:02:28)",
  "remaining_seconds": 888.66,
  "available_at": "23:02:28"
}
```

#### `/api/attacks`

Returns last 20 attack events from SQLite database.

```json
{
  "success": true,
  "attacks": [
    {
      "id": 14,
      "event_type": "WITHDRAW",
      "alert_type": "autowithdraw_daemon",
      "prefix": "2a02:4460:1::/48",
      "attack_id": null,
      "attack_vector": null,
      "target_ip": null,
      "target_port": null,
      "protocol": null,
      "severity": null,
      "action_taken": "withdrawn_auto",
      "timestamp": "2026-01-20 19:32:25"
    }
  ]
}
```

#### `/api/analytics`

Returns last 30 network analytics events (dropped traffic).

```json
{
  "success": true,
  "events": [
    {
      "id": 402,
      "event_datetime": "2026-01-19T22:51:00Z",
      "attack_id": "abc123",
      "attack_vector": "SYN Flood",
      "rule_name": "DDoS Protection",
      "source_ip": "192.0.2.1",
      "source_country": "CN",
      "dest_ip": "185.54.82.4",
      "dest_port": 443,
      "protocol": "TCP",
      "packets_dropped": 125000,
      "bits_dropped": 500000000,
      "outcome": "drop",
      "timestamp": "2026-01-19T22:52:00Z"
    }
  ]
}
```

#### `/api/attacks/<id>`

Returns full details for a single attack event, including the raw webhook payload.

```json
{
  "success": true,
  "attack": {
    "id": 662,
    "event_type": "END",
    "alert_type": "dos_attack_l4",
    "prefix": "185.54.82.0/24",
    "attack_id": "abc123",
    "attack_vector": "TCP SYN Flood",
    "target_ip": "185.54.82.4",
    "target_port": 443,
    "protocol": "TCP",
    "severity": 2,
    "action_taken": "notified",
    "timestamp": "2026-01-21T10:33:30Z",
    "message": "Full notification message text...",
    "raw_payload": {
      "name": "dos_attack_l4",
      "data": {
        "attack_id": "abc123",
        "attack_vector": "TCP SYN Flood",
        "rule_description": "Generic high-volume TCP SYN traffic",
        "...": "..."
      }
    }
  }
}
```

**Use Case**: Double-click on attack row in "Recent Attacks" table to view full event details.

#### `/api/analytics/<id>`

Returns full details for a single network analytics event, including rule description lookup.

```json
{
  "success": true,
  "event": {
    "id": 402,
    "event_datetime": "2026-01-19T22:51:00Z",
    "attack_id": "abc123",
    "attack_vector": "SYN Flood",
    "rule_id": "TCP-0001",
    "rule_name": "DDoS Protection",
    "rule_description": "Generic high-volume TCP SYN traffic coming from known bad sources",
    "source_ip": "192.0.2.1",
    "source_port": 12345,
    "source_country": "CN",
    "dest_ip": "185.54.82.4",
    "dest_port": 443,
    "protocol": "TCP",
    "tcp_flags": "SYN",
    "packets_dropped": 125000,
    "bits_dropped": 500000000,
    "outcome": "drop",
    "mitigation_reason": "DDoS mitigation",
    "timestamp": "2026-01-19T22:52:00Z",
    "raw_data": {
      "colo_city": "Kyiv",
      "colo_code": "KBP",
      "colo_country": "UA",
      "...": "..."
    }
  }
}
```

**Rule Description Lookup**: The API searches `attack_events` table for webhook payloads containing the same `rule_id` and extracts the `rule_description` from the raw payload. This enriches analytics events with human-readable rule descriptions.

**Use Case**: Double-click on analytics row in "Network Analytics" table to view full event details.

#### `/api/rules`

Returns MNM rules categorized by type.

```json
{
  "success": true,
  "total": 12,
  "rules": {
    "threshold": [
      {
        "id": "abc123",
        "name": "DDoS Protection BPS 185.54.80.0-24",
        "prefixes": ["185.54.80.0/24"],
        "automatic_advertisement": true,
        "bandwidth_threshold": 4000000000,
        "packet_threshold": null,
        "duration": "1m0s"
      }
    ],
    "advanced_ddos": [
      {
        "id": "def456",
        "name": "sFlow-DDoS-Attack-IPv4",
        "prefixes": ["185.54.80.0/24", "185.54.81.0/24"],
        "automatic_advertisement": true
      }
    ],
    "zscore": []
  }
}
```

#### `/api/ddos-sensitivity`

Returns L3/4 DDoS Managed Ruleset status.

```json
{
  "success": true,
  "ruleset_name": "Cloudflare L3/4 DDoS Ruleset",
  "total_rules": 124,
  "action_counts": {
    "block": 61,
    "ddos_dynamic": 46,
    "log": 17
  },
  "last_updated": "2026-01-20T11:55:08.172709Z"
}
```

#### `/api/ddos-rules/<rule_id>/update` (POST)

Updates a DDoS rule action via override in the account root ruleset.

**Request Body:**
```json
{
  "action": "log"
}
```

**Valid Actions:**
- `block` - Immediately block matching traffic
- `log` - Log traffic without blocking (monitoring mode)
- `ddos_dynamic` - Use Cloudflare's dynamic mitigation (auto-adjust)

**Success Response:**
```json
{
  "success": true,
  "message": "Rule updated successfully",
  "rule_id": "abc123...",
  "new_action": "log"
}
```

**Error Response (invalid action):**
```json
{
  "success": false,
  "error": "Invalid action. Allowed: block, ddos_dynamic, log"
}
```

**Error Response (rule not editable):**
```json
{
  "success": false,
  "error": "Rule is not editable (read-only category)"
}
```

**Note:** The API modifies the rule via the account root ruleset override mechanism. Only rules with `allowed_override_actions` and without `read-only` category can be modified.

---

#### `/api/ddos-overrides`

**GET** - Returns all custom DDoS override rules (rules with custom wirefilter expressions).

```json
{
  "success": true,
  "total": 3,
  "overrides": [
    {
      "id": "abc123...",
      "description": "Web Services Protection",
      "expression": "ip.dst eq 185.54.81.15 and tcp.dstport in {80 443}",
      "enabled": true,
      "sensitivity_level": "low",
      "target_rule_id": "TCP-0001",
      "last_updated": "2026-01-22T10:00:00Z"
    }
  ]
}
```

**POST** - Create a new custom DDoS override rule.

**Request Body:**
```json
{
  "expression": "ip.dst eq 185.54.81.20 and tcp.dstport in {25 465 587}",
  "description": "Mail Server Protection",
  "sensitivity_level": "low",
  "target_rule_id": "TCP-0001",
  "enabled": true
}
```

**Required Fields:**
- `expression` - Wirefilter expression (see CLOUDFLARE_API_REFERENCE.md for syntax)
- `description` - Rule description
- `target_rule_id` - DDoS rule to override (e.g., TCP-0001, UDP-0001)

**Optional Fields:**
- `sensitivity_level` - `default`, `medium`, `low`, `eoff` (default: `low`)
- `enabled` - Boolean (default: `true`)

---

#### `/api/ddos-overrides/<id>` (PUT)

Update an existing custom DDoS override rule.

**Request Body (partial update):**
```json
{
  "expression": "ip.dst eq 185.54.81.20 and tcp.dstport in {25 465 587 993 995}",
  "sensitivity_level": "medium"
}
```

---

#### `/api/ddos-overrides/<id>` (DELETE)

Delete a custom DDoS override rule.

**Success Response:**
```json
{
  "success": true,
  "message": "Override deleted successfully",
  "override_id": "abc123..."
}
```

---

#### `/api/ddos-overrides/<id>/move` (POST)

Move a DDoS override rule to a new position. Rule order matters - first match wins.

**Request Body Options:**

```json
// Move up/down by one position
{"direction": "up"}
{"direction": "down"}

// Move to exact position (1-based)
{"index": 1}

// Move relative to another rule
{"before": "other_rule_id"}
{"after": "other_rule_id"}
```

**Success Response:**
```json
{
  "success": true,
  "message": "Rule moved successfully"
}
```

---

#### `/api/ddos-overrides/validate` (POST)

Validate a wirefilter expression syntax before creating/updating a rule.

**Request Body:**
```json
{
  "expression": "ip.dst eq 185.54.81.15 and tcp.dstport in {80 443}"
}
```

**Success Response:**
```json
{
  "success": true,
  "valid": true,
  "message": "Expression syntax appears valid"
}
```

**Error Response:**
```json
{
  "success": false,
  "valid": false,
  "errors": ["Unbalanced parentheses", "Expression cannot start with 'and'"]
}
```

---

#### `/api/services`

Returns systemd service status with user-friendly descriptions.

**Response Fields:**

| Field | Description |
|-------|-------------|
| `name` | Systemd service unit name (e.g., `cloudflare-webhook`) |
| `description` | User-friendly name from systemd `Description=` field |
| `status` | Service state (`active` or `inactive`) |
| `uptime` | ISO 8601 timestamp of when service started |

```json
{
  "success": true,
  "services": [
    {
      "name": "cloudflare-webhook",
      "description": "Cloudflare Magic Transit Webhook Receiver",
      "status": "active",
      "uptime": "2026-01-20T20:35:59+01:00"
    },
    {
      "name": "cloudflare-analytics-monitor",
      "description": "Cloudflare Network Analytics Monitor",
      "status": "active",
      "uptime": "2026-01-20T20:35:59+01:00"
    },
    {
      "name": "cloudflare-autowithdraw",
      "description": "Cloudflare Magic Transit Auto-Withdraw Manager",
      "status": "active",
      "uptime": "2026-01-20T20:35:59+01:00"
    },
    {
      "name": "cloudflare-dashboard",
      "description": "Cloudflare Magic Transit Dashboard",
      "status": "active",
      "uptime": "2026-01-20T23:01:44+01:00"
    }
  ]
}
```

**Service Name Mapping:**

| Service Unit | User-Friendly Description |
|--------------|---------------------------|
| `cloudflare-webhook` | Cloudflare Magic Transit Webhook Receiver |
| `cloudflare-analytics-monitor` | Cloudflare Network Analytics Monitor |
| `cloudflare-autowithdraw` | Cloudflare Magic Transit Auto-Withdraw Manager |
| `cloudflare-dashboard` | Cloudflare Magic Transit Dashboard |

**Note**: Descriptions are read from each service's systemd unit file `Description=` field. If not available, the service name is used as fallback.

#### `/api/stats`

Returns summary statistics.

```json
{
  "success": true,
  "stats": {
    "total_attacks": 14,
    "total_analytics": 402,
    "total_webhooks": 57,
    "total_withdrawals": 4,
    "attacks_24h": 1,
    "analytics_24h": 0
  },
  "timestamp": "2026-01-20T20:59:57.068648"
}
```

#### `/api/network-flow`

Returns real-time network flow statistics from Cloudflare MNM (Magic Network Monitoring) Flow Data API.

**Cloudflare Dashboard Equivalent:** Networking > Insights > Network Flow

**GraphQL Data Source:** `mnmFlowDataAdaptiveGroups`

**Query Strategy:** Uses separate sub-queries to avoid 10,000 row limit:
- `total`: Aggregate totals (no dimensions, limit 1)
- `byProtocol`: Top protocols by bits (orderBy: sum_bits_DESC)
- `byRouter`: Top GOLINE routers (185.54.80.1, 185.54.80.2)
- `bySource`: Top source IPs
- `byTcpFlags`: Top TCP flags

**Response:**
```json
{
  "success": true,
  "network_flow": {
    "avg_bit_rate": 346923272.59,
    "avg_packet_rate": 41851.46,
    "top_protocol": "ESP",
    "top_protocol_bits": 21731019184000,
    "top_source": "185.54.80.30",
    "top_source_bits": 22041336328000,
    "top_router": "185.54.80.2",
    "top_router_bits": 29607597696000,
    "top_tcp_flags": "EMPTY",
    "top_tcp_flags_bits": 23012061136000
  },
  "period": "24h",
  "timestamp": "2026-01-21T00:44:31.200954+00:00"
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `avg_bit_rate` | Float | Average bits per second (total_bits / 86400) |
| `avg_packet_rate` | Float | Average packets per second (total_packets / 86400) |
| `top_protocol` | String | Protocol with highest traffic (ESP, TCP, UDP, ICMP) |
| `top_protocol_bits` | Integer | Total bits for top protocol in 24h period |
| `top_source` | String | Source IP with highest traffic volume |
| `top_source_bits` | Integer | Total bits for top source in 24h period |
| `top_router` | String | GOLINE router IP with highest traffic |
| `top_router_bits` | Integer | Total bits for top router in 24h period |
| `top_tcp_flags` | String | TCP flags with highest traffic (EMPTY for non-TCP) |
| `top_tcp_flags_bits` | Integer | Total bits for top TCP flags in 24h period |

**Typical Values (GOLINE Infrastructure):**
- `avg_bit_rate`: ~346 Mbps (346,605,621 bps)
- `avg_packet_rate`: ~41.8 kpps (41,814 pps)
- `top_protocol`: ESP (IPsec tunnel traffic from VPN)
- `top_router`: 185.54.80.2 (primary GOLINE router)
- `top_tcp_flags`: EMPTY (ESP doesn't use TCP)

**Protocol Reference:**

| Protocol | Number | Traffic Type |
|----------|--------|--------------|
| ESP | 50 | IPsec Encapsulating Security Payload (VPN tunnel) |
| TCP | 6 | Transmission Control Protocol |
| UDP | 17 | User Datagram Protocol |
| ICMP | 1 | Internet Control Message Protocol |
| GRE | 47 | Generic Routing Encapsulation |
| HOPOPT | 0 | IPv6 Hop-by-Hop Option |

**TCP Flags Reference:**

| Flag String | Meaning |
|-------------|---------|
| EMPTY | No TCP flags (non-TCP protocols like ESP, UDP, ICMP) |
| ACK | Acknowledgment |
| SYN | Synchronize (connection request) |
| SYN,ACK | Synchronize-Acknowledgment (connection response) |
| PSH,ACK | Push + Acknowledgment (data transfer) |
| FIN,ACK | Finish + Acknowledgment (connection close) |
| RST | Reset (connection abort) |

---

## Frontend

### Technology Stack

- **HTML5** - Semantic markup
- **CSS3** - Custom dark theme with CSS variables
- **Vanilla JavaScript** - No frameworks, native fetch API
- **Responsive Grid** - CSS Grid with auto-fit

### Color Palette (Dark Theme)

| Variable | Value | Usage |
|----------|-------|-------|
| `--bg-primary` | `#0d1117` | Main background |
| `--bg-secondary` | `#161b22` | Card backgrounds |
| `--bg-tertiary` | `#21262d` | Headers, hover states |
| `--border-color` | `#30363d` | Borders |
| `--text-primary` | `#e6edf3` | Main text |
| `--text-secondary` | `#8b949e` | Secondary text |
| `--accent-blue` | `#58a6ff` | Links, info badges |
| `--accent-green` | `#3fb950` | Success, withdrawn |
| `--accent-red` | `#f85149` | Danger, advertised |
| `--accent-yellow` | `#d29922` | Warnings |
| `--accent-orange` | `#f0883e` | Cloudflare branding |
| `--accent-purple` | `#a371f7` | sFlow rules |

### Button Styling (v2.9.4)

All buttons across the dashboard use a consistent solid style with shadows and hover effects for improved visibility and user experience.

**Header Buttons (on orange gradient):**

| Button | Background | Text Color | Shadow |
|--------|------------|------------|--------|
| Refresh | White | Orange (#d35400) | Yes |
| Connectors | White | Orange (#d35400) | Yes |
| Settings | White | Orange (#d35400) | Yes |
| ← Dashboard | White | Orange (#d35400) | Yes |

**Card Buttons:**

| Button | Background | Text Color | Usage |
|--------|------------|------------|-------|
| Manage → | Blue (#58a6ff) | White | MNM Rules, DDoS Rules sections |
| Edit | Blue (#58a6ff) | White | Table rows in rules pages |
| Delete | Red (#f85149) | White | Table rows in rules pages |
| Add Rule | Green (#3fb950) | White | Rules pages headers |
| ▲ Advertise | Red (#f85149) | White | BGP prefix actions |
| ▼ Withdraw | Green (#3fb950) | White | BGP prefix actions |

**Modal Buttons:**

| Button | Background | Text Color | Usage |
|--------|------------|------------|-------|
| Save Changes | Blue (#58a6ff) | White | All modals |
| Cancel / Close | Gray (#21262d) | White | All modals |
| Sign In | Orange gradient | White | Login page |

**CSS Properties (all buttons):**

```css
/* Base button style */
.btn {
    font-weight: 600;
    border: none;
    border-radius: 6px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
    transition: all 0.2s;
}

/* Hover effect */
.btn:hover {
    transform: translateY(-1px);
    box-shadow: 0 3px 6px rgba(0,0,0,0.4);
}

/* Disabled state */
.btn:disabled {
    box-shadow: none;
    transform: none;
}
```

### Header Design

The header uses a **Cloudflare-branded orange gradient** with dual branding:

```css
.header {
    background: linear-gradient(135deg, #f6821f 0%, #ff6633 50%, #faad3f 100%);
}
```

**Header Layout (left to right):**

| Section | Element | Description |
|---------|---------|-------------|
| Left | Cloudflare Logo | SVG embedded as base64, white background container |
| Left | Title | "Magic Transit Dashboard" + subtitle |
| Right | Live Indicator | Green pulsing dot + "Live" text |
| Right | Last Update | Timestamp of last refresh (white text) |
| Right | Refresh Button | Manual refresh trigger |
| Right | GOLINE Logo | PNG with transparent background |

**Logo Details:**

| Logo | File | Size | Format | Notes |
|------|------|------|--------|-------|
| Cloudflare | Embedded SVG | 252x115 | base64 | Official Cloudflare logo |
| GOLINE | `Goline_500_160_trasparente.png` | 500x160 | PNG RGBA | Blue text, transparent bg |

**Header CSS Classes:**

```css
.header-left {
    /* Contains Cloudflare logo + title */
}

.header-right {
    display: flex;
    align-items: center;
    gap: 1rem;
    color: white;
}

.header-right .timestamp {
    color: white;           /* Override default gray */
    font-size: 0.85rem;
}

.goline-logo-container {
    display: flex;
    align-items: center;
}

.goline-logo-img {
    height: 40px;           /* Scaled to fit header */
}
```

### UI Components

| Component | Description |
|-----------|-------------|
| Header | Cloudflare orange gradient with dual branding (CF + GOLINE) |
| Stats Grid | 6 summary cards with key metrics and tooltips |
| Card | Scrollable content area with sticky headers |
| Badge | Status indicators (success, danger, warning, info) |
| Table | Sortable data with monospace IP formatting |
| Loading Spinner | Animated CSS spinner |

### Network Flow Stats (Real-time from Cloudflare MNM)

Real-time traffic statistics from Cloudflare MNM Flow Data GraphQL API (last 24 hours).

**Cloudflare Dashboard Location:** Networking > Insights > Network Flow

**Data Source:** `mnmFlowDataAdaptiveGroups` - Magic Network Monitoring Flow Data

#### Stat Cards

| Card | Color | CSS Class | API Field | Display Format |
|------|-------|-----------|-----------|----------------|
| Avg Bit Rate | Blue (#3b82f6) | `stat-rate` | `avg_bit_rate` | `XXX.XX Mbps` |
| Avg Packet Rate | Blue (#3b82f6) | `stat-rate` | `avg_packet_rate` | `XX.X kpps` |
| Top Protocol | Purple (#8b5cf6) | `stat-protocol` | `top_protocol` | Protocol name (ESP/TCP/UDP) |
| Top Source | Amber (#f59e0b) | `stat-source` | `top_source`, `top_source_hostname` | IP + hostname |
| Top Router | Emerald (#10b981) | `stat-router` | `top_router`, `top_router_hostname` | IP + hostname |
| Top Destination | Pink (#ec4899) | `stat-destination` | `top_destination`, `top_destination_hostname` | IP + hostname |

**Card Layout (v2.9.18):** Each card displays elements in this order:
1. **Label** (title) - e.g., "Top Source", "Top Router"
2. **Value** - IP address or metric value
3. **Hostname** (if available) - Reverse DNS lookup result
4. **Volume** - Traffic volume in TB/GB

**Volume Display:** Each "Top" card shows the total traffic volume in the description area (e.g., "2.72 TB").

**Hostname Resolution:** IP-based cards (Top Source, Top Router, Top Destination) perform reverse DNS lookup with 500ms timeout. Hostnames are resolved in parallel using ThreadPoolExecutor.

#### API Endpoint: `GET /api/network-flow`

**Response Example:**
```json
{
  "success": true,
  "network_flow": {
    "avg_bit_rate": 347527503.24,
    "avg_packet_rate": 41924.09,
    "top_protocol": "ESP",
    "top_protocol_bits": 21794555616000,
    "top_source": "185.54.80.30",
    "top_source_bits": 22105202656000,
    "top_source_hostname": "fortigate01.goline.ch",
    "top_router": "185.54.80.2",
    "top_router_bits": 29659473496000,
    "top_router_hostname": "netengine01.goline.ch",
    "top_destination": "213.144.134.18",
    "top_destination_bits": 16205941048000,
    "top_destination_hostname": "dhcp-213-144-134-18.init7.net"
  },
  "period": "24h",
  "timestamp": "2026-01-21T02:15:00.000000+00:00"
}
```

#### API Response Fields

| Field | Type | Unit (API) | Unit (Display) | Conversion | Example |
|-------|------|------------|----------------|------------|---------|
| `avg_bit_rate` | Float | bits/second | Mbps | ÷ 1,000,000 | 347527503.24 → "347.53 Mbps" |
| `avg_packet_rate` | Float | packets/second | kpps | ÷ 1,000 | 41924.09 → "41.9 kpps" |
| `top_protocol` | String | - | - | None | "ESP" |
| `top_protocol_bits` | Integer | bits (24h total) | TB | ÷ 8 ÷ 1e12 | 21794555616000 → "2.72 TB" |
| `top_source` | String | - | - | None | "185.54.80.30" |
| `top_source_bits` | Integer | bits (24h total) | TB | ÷ 8 ÷ 1e12 | 22105202656000 → "2.76 TB" |
| `top_source_hostname` | String | - | - | Reverse DNS | "fortigate01.goline.ch" |
| `top_router` | String | - | - | None | "185.54.80.2" |
| `top_router_bits` | Integer | bits (24h total) | TB | ÷ 8 ÷ 1e12 | 29659473496000 → "3.71 TB" |
| `top_router_hostname` | String | - | - | Reverse DNS | "netengine01.goline.ch" |
| `top_destination` | String | - | - | None | "213.144.134.18" |
| `top_destination_bits` | Integer | bits (24h total) | TB | ÷ 8 ÷ 1e12 | 16205941048000 → "2.03 TB" |
| `top_destination_hostname` | String | - | - | Reverse DNS | "dhcp-213-144-134-18.init7.net" |

#### Unit Conversions

**Rates (Average over 24h = 86,400 seconds):**
```
avg_bit_rate = total_bits / 86400
avg_packet_rate = total_packets / 86400

Display:
- Mbps = avg_bit_rate / 1,000,000
- kpps = avg_packet_rate / 1,000
```

**Volumes (bits to Bytes):**
```
bytes = bits / 8

Display thresholds:
- TB = bytes / 1,000,000,000,000  (≥ 1 TB)
- GB = bytes / 1,000,000,000      (≥ 1 GB)
- MB = bytes / 1,000,000          (≥ 1 MB)
- KB = bytes / 1,000              (≥ 1 KB)
```

#### Typical Values (GOLINE Infrastructure)

| Metric | Typical Value | Description |
|--------|---------------|-------------|
| `avg_bit_rate` | ~347 Mbps | Average bandwidth utilization |
| `avg_packet_rate` | ~42 kpps | Average packet rate |
| `top_protocol` | ESP | IPsec tunnel traffic (WireGuard/VPN) |
| `top_source` | 185.54.80.30 | fortigate01.goline.ch (high traffic source) |
| `top_router` | 185.54.80.2 | netengine01.goline.ch (primary border router) |
| `top_destination` | 213.144.134.18 | External destination with highest traffic |

#### CSS Styling

**Font Sizes:**

| Element | Class | Size | Style |
|---------|-------|------|-------|
| Rate values | `.stat-rate .stat-value` | 1.3rem | Blue #3b82f6 |
| IP addresses | `.stat-value-ip` | 0.85rem | Monospace, nowrap, weight 600 |
| Protocol text | `.stat-value-text` | 1.2rem | Word-break |
| IP card labels | `.stat-label-sm` | 0.65rem | Nowrap |
| Volume counters | `.stat-vol` | 0.95rem | Gold #fbbf24, weight 600 |
| Hostnames | `.stat-hostname` | 0.65rem | Italic, rgba(255,255,255,0.6), ellipsis |

**Labels:**
- Rate cards: "(last 24h)" in description
- Top cards: Volume in TB/GB (e.g., "2.72 TB") in description, gold color

#### Data Accuracy

**sFlow Sampling:** MNM Flow Data uses sFlow sampling, which means values are statistical estimates, not exact counts. A variance of **±1-2%** compared to Cloudflare dashboard is normal and expected.

| Source | Typical Variance | Reason |
|--------|------------------|--------|
| Our Dashboard | ±1% | Real-time query, current time window |
| Cloudflare Dashboard | baseline | May cache/update less frequently |

**Time Window:**
- Start: `now - 24 hours`
- End: `now` (current UTC time)
- Filter: `datetime_geq` / `datetime_leq` (inclusive boundaries)

#### GraphQL Query Structure

The API uses multiple sub-queries to avoid the 10,000 row limit:

```graphql
query GetNetworkFlow($accountTag: String!, $datetimeStart: Time!, $datetimeEnd: Time!) {
    viewer {
        accounts(filter: { accountTag: $accountTag }) {
            # Aggregate totals (no dimensions)
            total: mnmFlowDataAdaptiveGroups(
                filter: { datetime_geq: $datetimeStart, datetime_leq: $datetimeEnd }
                limit: 1
            ) {
                sum { packets, bits }
            }
            # Top protocols
            byProtocol: mnmFlowDataAdaptiveGroups(
                filter: { datetime_geq: $datetimeStart, datetime_leq: $datetimeEnd }
                limit: 10
                orderBy: [sum_bits_DESC]
            ) {
                dimensions { protocolString }
                sum { bits }
            }
            # Top routers
            byRouter: mnmFlowDataAdaptiveGroups(
                filter: { datetime_geq: $datetimeStart, datetime_leq: $datetimeEnd }
                ...
            ) {
                dimensions { routerAddress }
                sum { bits }
            }
            # Top sources
            bySource: mnmFlowDataAdaptiveGroups(...) {
                dimensions { sourceAddress }
                sum { bits }
            }
            # Top destinations
            byDestination: mnmFlowDataAdaptiveGroups(...) {
                dimensions { destinationAddress }
                sum { bits }
            }
        }
    }
}
```

**Filter Operators:**
| Operator | Meaning | Used |
|----------|---------|------|
| `datetime_geq` | Greater than or equal (≥) | ✅ Start time |
| `datetime_leq` | Less than or equal (≤) | ✅ End time |
| `datetime_gt` | Greater than (>) | ❌ Excludes boundary |
| `datetime_lt` | Less than (<) | ❌ Excludes boundary |

**Available MNM Flow Data Dimensions:**
| Field | Type | Description |
|-------|------|-------------|
| `routerAddress` | String | GOLINE router IP (185.54.80.1, 185.54.80.2) |
| `sourceAddress` | String | Source IP address |
| `destinationAddress` | String | Destination IP address |
| `sourcePort` | Int | Source port |
| `destinationPort` | Int | Destination port |
| `protocol` | Int | IP protocol number (6=TCP, 17=UDP, 50=ESP) |
| `protocolString` | String | Protocol name (TCP, UDP, ESP, ICMP) |
| `sourceAS` | Int | Source AS number |
| `destinationAS` | Int | Destination AS number |
| `tcpFlags` | Int | TCP flags bitmask |
| `tcpFlagsString` | String | TCP flags names (ACK, SYN, PSH,ACK, EMPTY) |
| `ethertype` | Int | Ethernet type |
| `version` | Int | IP version (4 or 6) |
| `deviceID` | String | Device identifier |

### System Stats Cards

| Card | Data Source | Description |
|------|-------------|-------------|
| BGP Prefixes | `/api/prefixes` | Advertised / Total count |
| Total Attacks | `/api/stats` | All recorded attack events |
| Analytics Events | `/api/stats` | Network analytics drops |
| Attacks (24h) | `/api/stats` | Recent attack activity |
| MNM Rules | `/api/rules` | Auto-advertisement triggers |
| Services Active | `/api/services` | Background daemons |

**BGP Prefixes Color Alert:**

| Advertised | Color | Meaning |
|------------|-------|---------|
| 0 | Default (blue) | No attack mitigation active |
| > 0 | **Red (#ef4444)** | Attack mitigation in progress |

```javascript
statPrefixes.style.color = advertisedCount > 0 ? '#ef4444' : '';
```

### Dashboard Sections

| Section | Content | Auto-Refresh | Detail Modal |
|---------|---------|--------------|--------------|
| BGP Prefixes | Prefix status with advertise/withdraw buttons | Yes | No |
| MNM Rules | Threshold + sFlow rules, grouped by type | Yes | No |
| DDoS Sensitivity | L3/4 ruleset summary with action counts + Manage button | Yes | No |
| Services | Cloudflare services with user-friendly names and uptime | Yes | No |
| Recent Attacks | Last 20 attack events from database | Yes | **Double-click** |
| Network Analytics | Last 30 dropped traffic events | Yes | **Double-click** |

### Detail Modals

Both "Recent Attacks" and "Network Analytics" tables support double-click to view detailed event information.

**Interaction**:
- Hover over rows shows pointer cursor and highlight
- Double-click opens modal with full event details
- ESC key or click outside modal to close

#### Dynamic Rendering (v2.8.5)

Both modals dynamically hide empty fields and auto-resize based on available content.

**Helper Functions:**

| Function | Purpose |
|----------|---------|
| `hasValue(val)` | Returns `true` if value is not null/undefined/empty/''-' |
| `dynamicItem(label, value, options)` | Returns HTML item only if value exists |
| `dynamicRow(items)` | Returns row only if it contains visible items |
| `dynamicSection(title, rows)` | Returns section only if it contains visible rows |

**Dynamic Behavior:**

| Scenario | Before (v2.8.4) | After (v2.8.5) |
|----------|-----------------|----------------|
| Empty field | Shows `-` placeholder | Field hidden completely |
| Section without data | Empty section shown | Section not rendered |
| Footer with missing IDs | Shows `-` for missing | Only existing IDs shown |
| Grid with 1 section | Empty column | `grid-template-columns: 1fr` |
| Grid with 2 sections | Fixed 2 columns | `repeat(2, 1fr)` |

**Example - Attack with minimal data:**
```
Before: Event | Target | Attack (-) | Rule (-) | Message (-) | Footer with Attack: - Rule: -
After:  Event | Target | Footer with Event #123 only
```

#### Ultra-Compact CSS (v2.8.4)

Both modals use optimized CSS for minimal height while preserving all information:

| CSS Property | Value | Purpose |
|--------------|-------|---------|
| `.detail-grid gap` | 0.5rem | Reduced grid spacing |
| `.detail-section padding` | 0.6rem 0.75rem | Compact section padding |
| `.detail-section margin-bottom` | 0.5rem | Reduced section spacing |
| `.detail-section-title margin-bottom` | 0.4rem | Compact title spacing |
| `.detail-row padding` | 0.2rem 0 | Minimal row padding |
| `.detail-row font-size` | 0.8rem | Slightly smaller text |
| `.detail-description max-height` | 80px | Scrollable message area |
| `.detail-description font-size` | 0.7rem | Smaller description text |

**Inline Row Layout** (`.detail-row-inline`):
```css
.detail-row-inline {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    padding: 0.2rem 0;
    font-size: 0.8rem;
}
```

Example inline display:
```
Type: START | Alert: L4 DDoS Attack
Time: 2h ago | Action: Notified
```

#### Attack Detail Modal (Recent Attacks)

Shows comprehensive event information parsed from webhook `raw_payload` in ultra-compact layout:

**Row 1 - Event + Target:**
| Section | Fields |
|---------|--------|
| 🔥 Event | Type (badge), Alert, Time, Action |
| 🎯 Target | Prefix, Protocol, Target IP:Port, Cloudflare link |

**Row 2 - Attack + Rule (conditional):**
| Section | Fields |
|---------|--------|
| ⚡ Attack | Vector, **Started** (v2.8.6), Rate (pps/Mbps), Max Rate, Mitigation |
| 🛡️ Rule/Policy | Rule name, Description, Policy name |

**Message Section:**
- Scrollable area (max-height: 60px)
- Font size: 0.7rem
- Shows full notification text

**Footer Bar:**
- Event ID, Attack ID, Rule ID, Policy ID
- Font size: 0.7rem
- Compact padding: 0.4rem

#### Analytics Detail Modal (Network Analytics)

Shows comprehensive event information with compact 2-row layout:

**Row 1 - Attack + Traffic:**
| Section | Fields |
|---------|--------|
| ⚡ Attack | Vector, Protocol, Outcome badge, **Verdict badge** (v2.8.6), Mitigation |
| 📈 Traffic | Packets dropped, Bits dropped, Rate (kpps), Bandwidth (Mbps) |

**Row 2 - Source + Destination:**
| Section | Fields |
|---------|--------|
| 🌍 Source | Source IP:Port, **Country** (v2.8.6), **ASN** (v2.8.6), Cloudflare PoP |
| 🎯 Destination | Dest IP:Port, Rule name |

**Rule Section:**
- Rule Name, Rule ID
- Rule Description (via lookup from attack_events)

**Footer Bar:**
- Event ID, Attack ID, Rule ID
- Notified timestamp

#### Rule Description Lookup

Network Analytics events don't include rule descriptions in GraphQL data.
The API performs a lookup in `attack_events` table to find webhook payloads
containing the same `rule_id` and extracts the `rule_description`.

**Lookup Query:**
```python
SELECT raw_payload FROM attack_events
WHERE raw_payload LIKE '%rule_id%'
ORDER BY id DESC LIMIT 1
```

**Example:**
- Rule `TCP-0001` → "Generic high-volume TCP SYN traffic coming from known bad sources"
- Rule `UDP-0001` → "Generic high-volume UDP traffic from known bad sources"

### Card Descriptions

Each card in the main dashboard displays a description below its title explaining its purpose:

| Card | Title | Description |
|------|-------|-------------|
| BGP Prefixes | 🌐 BGP Prefixes | Cloudflare-protected IP ranges with manual advertise/withdraw controls |
| Services | ⚙️ Services Status | Background daemons for webhook processing, analytics, and auto-withdraw |
| Attacks | 🔥 Recent Attacks | DDoS attack events from webhooks and network monitoring |
| MNM Rules | 📋 MNM Rules | Magic Network Monitoring - Auto-advertisement triggers |
| Analytics | 📊 Network Analytics | Traffic blocked by Cloudflare DDoS protection (dropped packets and bits) |
| DDoS | 🛡️ DDoS L3/4 Managed Ruleset | Cloudflare managed DDoS protection rules with customizable actions |

### BGP Prefix Status Indicators

Each prefix displays real-time status information from two sources:

**1. API Constraint (15-minute rule):**
| Status | Color | Description |
|--------|-------|-------------|
| ⏱️ Can withdraw in X min | Purple | Time until manual withdraw allowed (advertised prefix) |
| ⏱️ Can advertise in X min | Purple | Time until manual advertise allowed (withdrawn prefix) |
| ✅ Can withdraw now | Blue | 15 minutes passed, can withdraw |
| ✅ Can advertise now | Blue | 15 minutes passed, can advertise |

**2. Autowithdraw Daemon Status (advertised prefixes only):**
| Status | Color | Description |
|--------|-------|-------------|
| ⚠️ Under attack (X Mbps) | Red | Active attack detected |
| ✅ Calm X min • Auto-withdraw in Y min | Green | No attacks, countdown to auto-withdraw |
| ⏳ Waiting for auto-withdraw | Blue | 15 min calm, will withdraw on next cycle |
| ⏳ Monitoring for attacks... | Amber | Initial monitoring, no calm time yet |

**Example Display:**
```
185.54.82.0/24                              ADVERTISED
DMZ-EXT
⏱️ Can withdraw in 12.3 min
✅ Calm 2.7 min • Auto-withdraw in 12.3 min
[▲ Advertise] [▼ Withdraw]
```

**CSS Classes:**

```css
.card-title-group {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
}

.card-description {
    font-size: 0.75rem;
    color: var(--text-secondary);
    font-weight: 400;
}
```

### Services Display

The Services section displays all 4 Cloudflare Magic Transit services with:

- **User-friendly names** from systemd `Description=` field (not raw service unit names)
- **Status badge** (ACTIVE/INACTIVE)
- **Relative uptime** (e.g., "2h ago")
- **Hover tooltip** showing original systemd service name

**Example Display:**

```
Cloudflare Magic Transit Webhook Receiver     [ACTIVE] since 2h ago
Cloudflare Network Analytics Monitor          [ACTIVE] since 2h ago
Cloudflare Magic Transit Auto-Withdraw Manager [ACTIVE] since 2h ago
Cloudflare Magic Transit Dashboard            [ACTIVE] since 10m ago
```

**Frontend Implementation:**

```javascript
// Service name display with tooltip for original name
<span class="service-name" title="${service.name}">
    ${service.description || service.name}
</span>
```

The `title` attribute ensures the original service name (e.g., `cloudflare-webhook`) is visible on mouse hover, while the main display shows the user-friendly description.

### Recent Attacks Display

The Recent Attacks table shows attack events with human-readable labels instead of internal codes.

**Double-Click for Details**: Clicking twice on any row opens a detailed modal showing:
- 🔥 Event Information: ID, type, alert type, timestamp, action taken
- 🎯 Target Information: Prefix, target IP, port, protocol
- ⚡ Attack Details: Vector, attack ID, max rate, packets/sec, bandwidth, mitigation
- 🛡️ Cloudflare Rule: Rule name, ID, and description (when available)
- 📋 Policy: Policy name and ID
- 🔗 Links: Direct link to Cloudflare dashboard

> **Note v2.9.7**: The "📝 Full Message" section was removed as it contained redundant information.

**Implementation**:
```javascript
// Row with double-click handler
<tr class="attack-row" data-id="${attack.id}"
    ondblclick="showAttackDetail(${attack.id})"
    title="Double-click for details">
```

**Alert Type Mapping (12 types):**

| Internal Code | Display Name |
|---------------|--------------|
| `advanced_ddos_attack_l4_alert` | Advanced L4 DDoS |
| `dos_attack_l4` | L4 DDoS Attack |
| `dos_attack_l7` | L7 DDoS Attack |
| `fbm_dosd_attack` | MNM DDoS Attack |
| `fbm_volumetric_attack` | MNM Volumetric Attack |
| `fbm_auto_advertisement` | MNM Auto-Advertise |
| `magic_tunnel_health_check_event` | Tunnel Health Check |
| `health_check_status_notification` | Health Check |
| `incident_alert` | Cloudflare Incident |
| `bgp_hijack_notification` | BGP Hijack Alert |
| `dashboard_manual` | Dashboard (Manual) |
| `autowithdraw_daemon` | Auto-Withdraw Daemon |

**Action Mapping (12 types):**

| Internal Code | Display Name |
|---------------|--------------|
| `withdrawn_manual` | Withdrawn (Manual) |
| `withdrawn_auto` | Withdrawn (Auto) |
| `withdrawn_immediate` | Withdrawn (Immediate) |
| `advertised` | Advertised |
| `advertised_manual` | Advertised (Manual) |
| `mitigating` | 🛡️ Mitigating |
| `auto_advertised` | 📡 Auto-Advertised |
| `notified` | Notified |
| `notified_autowithdraw_handles` | Notified (Auto-Withdraw) |
| `processing` | Processing |
| `received` | Received |
| `imported` | Imported |

**Event Type Labels (v2.9.8):**

| Internal Code | Display Label | Badge Color |
|---------------|---------------|-------------|
| `START` | 🚨 ATTACK | Red (danger) |
| `END` | ✅ ENDED | Green (success) |
| `ADVERTISE` | 📡 ADVERTISE | Yellow (warning) |
| `WITHDRAW` | 📤 WITHDRAW | Blue (info) |

**Fallback**: Unknown values are displayed as-is (no mapping).

**Frontend Implementation:**

```javascript
function formatAlertType(alertType) {
    const mapping = {
        'advanced_ddos_attack_l4_alert': 'Advanced L4 DDoS',
        'dos_attack_l4': 'L4 DDoS Attack',
        // ... etc
    };
    return mapping[alertType] || alertType || '-';
}

function formatAction(action) {
    const mapping = {
        'withdrawn_manual': 'Withdrawn (Manual)',
        'withdrawn_auto': 'Withdrawn (Auto)',
        // ... etc
    };
    return mapping[action] || action || '-';
}
```

### DDoS Rules Manager Page

Dedicated page for viewing and editing Cloudflare L3/4 DDoS rules.

**URL**: `/ddos-rules` or `/ddos-rules/<action>`

**Page Title**: 🛡️ DDoS L3/4 Rules Manager

**Header Features:**
- Title with ruleset name subtitle
- Last refresh timestamp (HH:MM:SS)
- Manual refresh button (↻)
- Back to Dashboard link

**Stats Cards (5 cards):**

| Card | Color | Description |
|------|-------|-------------|
| Total Rules | Blue | All 124 L3/4 DDoS rules |
| Block | Red | Rules with `block` action |
| Dynamic | Blue | Rules with `ddos_dynamic` action |
| Log | Yellow | Rules with `log` action |
| Editable | Green | Rules that can be modified (29 total) |

**Main Table - All Rules:**

| Column | Description |
|--------|-------------|
| Status | Enabled/Disabled badge |
| Description | Rule name with tooltip |
| Action | Current action (Block/Dynamic/Log) |
| Sensitivity | Sensitivity level (default/medium/low/eoff) |
| Categories | Rule categories (TCP, UDP, etc.) |
| Edit | Edit button (only for editable rules) |

**Editable Rules Section:**

Separate table showing only the 29 editable rules with additional Override column:

| Column | Description |
|--------|-------------|
| Status | Enabled/Disabled badge |
| Description | Rule name with tooltip |
| Action | Current action (Block/Dynamic/Log) |
| Sensitivity | Sensitivity level |
| Override | Custom (blue) or Default (gray) badge |
| Edit | Edit button |

**Override Badge:**
- **Custom** (blue): Rule has account-specific override applied
- **Default** (gray): Rule uses Cloudflare default settings

**Edit Modal:**

When clicking Edit on an editable rule:
1. Rule info box shows current action and sensitivity
2. Action dropdown with allowed options (varies per rule)
3. Sensitivity dropdown (only visible for `ddos_dynamic` action)
4. Save Changes button

**Sensitivity Levels (only for ddos_dynamic):**

| Value | Display Name |
|-------|--------------|
| `default` | High (default) |
| `medium` | Medium |
| `low` | Low (less aggressive) |
| `eoff` | Essentially Off |

**Dynamic Data Loading:**

- Rules are loaded from Cloudflare API on each page load
- No auto-refresh (manual refresh only)
- If Cloudflare adds/removes rules, they appear on next page load
- Filter by action via stat card clicks or URL

**Search Functionality:**

Search box filters rules by:
- Description text
- Category names

### MNM Rules Manager Page

Dedicated page for managing Magic Network Monitoring rules that trigger automatic BGP prefix advertisement.

**URL**: `/mnm-rules`

**Page Title**: 📋 MNM Rules Manager

**Header Features:**
- Title with subtitle "Magic Network Monitoring - Auto-advertisement triggers"
- Last refresh timestamp (HH:MM:SS)
- Manual refresh button (↻)
- Back to Dashboard link

**Stats Cards (3 cards):**

| Card | Color | Description |
|------|-------|-------------|
| Total Rules | Blue | All MNM rules configured |
| Threshold (BPS/PPS) | Orange | Bandwidth and packet threshold rules |
| Advanced DDoS (sFlow) | Purple | Fingerprint-based sFlow rules |

**Threshold Rules Section:**

> *"Trigger BGP advertisement when traffic exceeds a fixed bandwidth (Gbps) or packet rate (kpps) for a specified duration"*

Table displaying bandwidth (BPS) and packet (PPS) threshold rules:

| Column | Description |
|--------|-------------|
| Name | Rule name (auto-generated) |
| Prefixes | BGP prefixes protected by this rule |
| Threshold | BPS (Gbps) or PPS (kpps) value |
| Duration | Time before triggering (e.g., 1m0s) |
| Auto-Adv | Auto-advertisement enabled (Yes/No) |
| Actions | Edit and Delete buttons |

**Advanced DDoS (sFlow) Section:**

> *"Automatically detect attack patterns using sFlow fingerprinting - no manual thresholds needed"*

Table displaying sFlow fingerprint-based rules:

| Column | Description |
|--------|-------------|
| Name | Rule name |
| Prefixes | BGP prefixes protected |
| Type | Always "sFlow" |
| Auto-Adv | Auto-advertisement enabled |
| Actions | Edit and Delete buttons |

**Add Rule Modal:**

The Add Rule modal adapts based on which section's button was clicked:

| Section | Modal Title | Type Options | Fields Shown |
|---------|-------------|--------------|--------------|
| Threshold Rules | "Add Threshold Rule" | BPS, PPS | Type, Prefix, Threshold, Duration, Auto-Adv |
| Advanced DDoS | "Add sFlow Rule" | sFlow only | Prefix, Auto-Adv |

**Form Fields:**

| Field | Options | Description |
|-------|---------|-------------|
| Rule Type | BPS, PPS (threshold only) | Type of detection rule |
| Prefix | Dropdown | BGP prefix to protect |
| Threshold | Number | Gbps (BPS) or kpps (PPS) |
| Duration | Number | Minutes before trigger |
| Auto-advertisement | Checkbox | Enable auto BGP advertisement |

**Rule Types:**

| Type | Detection Method | Parameters |
|------|-----------------|------------|
| **BPS** | Bandwidth threshold | Gbps, duration |
| **PPS** | Packet rate threshold | kpps, duration |
| **sFlow** | Fingerprint-based | None (automatic) |

**Delete Confirmation:**

When clicking Delete:
1. Modal shows rule name
2. Warning about irreversible action
3. Cancel or Delete buttons

**Edit Rule Modal:**

When clicking Edit on a rule:

| Field | Threshold Rules | sFlow Rules | Description |
|-------|:--------------:|:-----------:|-------------|
| Threshold | ✅ | ❌ | BPS: 1-100 Gbps, PPS: 10-10,000 kpps |
| Duration | ✅ | ❌ | 1-60 minutes |
| Auto-Adv | ✅ | ✅ | Enable/disable auto-advertisement |

**Validation Limits:**

| Parameter | Type | Min | Max | Unit |
|-----------|------|-----|-----|------|
| Bandwidth Threshold | BPS | 1 | 100 | Gbps |
| Packet Threshold | PPS | 10 | 10,000 | kpps |
| Duration | All | 1 | 60 | minutes |

- Limits are shown as hints below input fields
- Client-side and server-side validation
- Values outside range show error toast

**API Endpoints Used:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/mnm-rules` | GET | List all MNM rules |
| `/api/mnm-rules` | POST | Create new rule |
| `/api/mnm-rules/<id>` | PUT | Update rule |
| `/api/mnm-rules/<id>` | DELETE | Delete rule |

### Connectors Page

Dedicated page for viewing IPsec/GRE Tunnels and CNI Network Interconnects status.

**URL**: `/connectors`

**Page Title**: Connectors - IPsec/GRE Tunnels & Network Interconnects

**Header Features:**
- Title "Connectors" with subtitle "IPsec/GRE Tunnels & Network Interconnects"
- Last refresh timestamp
- Manual refresh button
- Back to Dashboard link

**Layout**: Single-column vertical layout (cards stacked, not side-by-side)
- Tables use full horizontal width
- Text wraps properly in cells
- IP addresses break correctly on narrow screens

**Stats Cards (7 cards):**

| Card | Color | Description |
|------|-------|-------------|
| Total Tunnels | Cyan | GRE + IPsec tunnel count |
| GRE Tunnels | Orange | GRE tunnel count |
| IPsec Tunnels | Purple | IPsec tunnel count |
| Interconnects | Green | CNI interconnect count |
| Healthy | Green | Tunnels with health state = 1 |
| Degraded | Yellow | Tunnels with health state = 0.5 |
| Down | Red | Tunnels with health state = 0 |

**IPsec/GRE Tunnels Section:**

> *"Magic Transit tunnel endpoints for traffic encapsulation"*

| Column | Description |
|--------|-------------|
| Name | Tunnel name + description |
| Type | GRE or IPsec badge |
| Cloudflare Endpoint | Cloudflare's tunnel endpoint IP |
| Customer Endpoint | Customer's tunnel endpoint IP |
| Health | Status badge + pass rate % (1h) + check interval |
| BGP Status | BGP state + TCP established status |
| MTU | Maximum transmission unit |

**Network Interconnects (CNI) Section:**

> *"Direct private connections to Cloudflare network"*

| Column | Description |
|--------|-------------|
| Name | Conduit name + description |
| Facility | Datacenter location (e.g., "Equinix Zurich (ZH4)") |
| Speed | Connection speed (e.g., "10G") |
| Status | Active/Inactive badge |
| P2P (Cloudflare) | Cloudflare P2P IP address |
| P2P (Customer) | Customer P2P IP address |

**API Endpoints Used:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/connectors/tunnels` | GET | GRE and IPsec tunnels |
| `/api/connectors/interconnects` | GET | CNI Interconnects |
| `/api/connectors/health-summary` | GET | Connector health summary (overall status) |
| `/api/connectors/tunnel-health` | GET | Tunnel health from GraphQL |
| `/api/connectors/tunnel/<id>/update` | POST | Update tunnel description |
| `/api/connectors/cni/<id>/update` | POST | Update CNI description |

**Editing Connectors:**

Double-click on any tunnel or CNI row to open a detail modal.

**Tunnel Modal - Editable Fields:**
| Field | Type | Validation |
|-------|------|------------|
| Description | Text | Optional |
| Customer Endpoint IP | IPv4 | Format validation |
| MTU | Number | 576-1500 (GRE default: 1476) |
| Health Check Rate | Select | low (60s) / mid (10s) / high (1s) |
| Health Check Enabled | Checkbox | On/Off |

**Read-Only Fields:** Type, Cloudflare Endpoint, Health Status, Pass Rate, BGP Status, Tunnel ID

**CNI Modal - Editable Fields:**
| Field | Type |
|-------|------|
| Description | Text |

The tunnel update endpoint auto-detects whether the tunnel is GRE or IPsec.

**API Response: `/api/connectors/tunnels`**

```json
{
  "success": true,
  "tunnels": [
    {
      "id": "tunnel_id",
      "name": "ZH-COLT-NE8000-GRE",
      "type": "gre",
      "description": "Primary GRE tunnel",
      "cloudflare_endpoint": "162.159.X.X",
      "customer_endpoint": "185.54.81.X",
      "interface_address": "10.0.0.1/31",
      "mtu": 1476,
      "health_status": "healthy",
      "health_check": { "rate": "mid" },
      "bgp_status": {
        "state": "BGP_UP",
        "tcp_established": true
      },
      "pass_rate": 99.58,
      "total_checks": 495532,
      "colos_count": 331
    }
  ],
  "gre_count": 2,
  "ipsec_count": 0,
  "health_stats": {
    "ZH-COLT-NE8000-GRE": {"pass_rate": 99.58, "total_checks": 495532, "colos_count": 331, "status": "healthy"},
    "MI-COGENT-MX204-GRE": {"pass_rate": 99.25, "total_checks": 478195, "colos_count": 342, "status": "healthy"}
  }
}
```

**API Response: `/api/connectors/interconnects`**

> ⚠️ **Note:** The Cloudflare CNI API has a different response structure than other Cloudflare APIs.

```json
{
  "success": true,
  "interconnects": [
    {
      "id": "cni_abc123",
      "name": "ZRH-CNI",
      "description": "CNI_GOLINE_ZH",
      "facility": "Equinix Zurich (ZH4)",
      "speed": "10G",
      "status": "healthy",
      "type": "dedicated_nni",
      "p2p_cloudflare": "169.254.66.30/31",
      "p2p_customer": "169.254.66.31/31",
      "mtu": 1500,
      "pass_rate": 99.56,
      "total_checks": 508066,
      "colos_count": 327
    }
  ],
  "total": 1
}
```

**CNI API Parsing Notes:**

The Cloudflare CNI API (`/cni/interconnects` and `/cni/cnis`) differs from other APIs:

| Standard API | CNI API |
|--------------|---------|
| `result.items` | `items` (top level) |
| `p2p_ip` as string | `p2p_ip` as object: `{"ip": "...", "cidr": 31}` |
| `facility` as string | `facility` as object: `{"name": "...", "address": "..."}` |

**Health Status Interpretation:**

| Value | Status | Badge Color | Description |
|-------|--------|-------------|-------------|
| `1` or `healthy` | Healthy | Green | >80% health checks passing |
| `0.5` or `degraded` | Degraded | Yellow | 40-80% health checks passing |
| `0` or `down` | Down | Red | <40% health checks passing |
| null | Unknown | Gray | No health data available |

**Health Check Interval (rate field):**

| API Value | Display | Interval |
|-----------|---------|----------|
| `low` | Check every 60s | 1 minute |
| `mid` | Check every 10s | 10 seconds |
| `high` | Check every 1s | 1 second |

**Pass Rate Calculation (v2.9.20):**

The pass rate is calculated from GraphQL `magicTransitTunnelHealthChecksAdaptiveGroups` using `resultStatus`:

```
pass_rate = count(resultStatus='ok') / total_count * 100
```

| resultStatus | Meaning | Counted as |
|--------------|---------|------------|
| `ok` | Health check passed | ✅ Passed |
| `timeout` | Health check timed out | ❌ Failed |

> **Note:** Prior to v2.9.20, the pass rate was incorrectly calculated using `avg(tunnelState)` which always returned ~50% for CNI connections. The fix uses `resultStatus` dimension to match Cloudflare dashboard values.

**CSS Classes:**

| Class | Color | Usage |
|-------|-------|-------|
| `.type-gre` | Orange | GRE tunnel type badge |
| `.type-ipsec` | Purple | IPsec tunnel type badge |
| `.type-cni` | Green | CNI type badge |
| `.ip-address` | Blue | Monospace IP display with word-break |
| `.status-healthy` | Green | Health/status badge |
| `.status-degraded` | Yellow | Health/status badge |
| `.status-down` | Red | Health/status badge |

**Auto-refresh**: 30 seconds (same as main dashboard)

### Auto-Refresh

- **Interval**: 30 seconds
- **Method**: Parallel fetch of all API endpoints
- **Indicator**: "Live" status with pulsing green dot
- **Manual**: "Refresh" button in header
- **Timestamp**: Shows last update time in header (white text)

### Responsive Design

The dashboard adapts to different screen sizes using CSS media queries with fixed breakpoints:

**Stats Grid (6 cards):**

| Screen Width | Columns | Rows | Layout |
|--------------|---------|------|--------|
| > 1300px | 6 | 1 | All cards in single row |
| 768px - 1300px | 3 | 2 | Two rows of 3 cards |
| 500px - 768px | 2 | 3 | Three rows of 2 cards |
| < 500px | 1 | 6 | Single column, stacked |

**Note**: Fixed column counts (6, 3, 2, 1) ensure cards always divide evenly without orphaned cards.

**Header Adaptations:**

| Breakpoint | Changes |
|------------|---------|
| ≤ 1400px | Reduced title font and logo size |
| ≤ 1200px | Compressed header, smaller status indicator |
| ≤ 1000px | Timestamp hidden, reduced button padding |
| ≤ 768px | Vertical header layout, centered elements |

**Other Responsive Features:**

- Service names truncate with ellipsis on small screens
- Main grid switches to single column at 1200px
- Container padding reduced on mobile

### Footer Design

Minimal professional footer with two-column layout.

**Layout:**

```
┌────────────────────────────────────────────────────────────────────────────┐
│  [Logo] GOLINE SOC · Magic Transit Dashboard              🟢 Auto-refresh 30s │
└────────────────────────────────────────────────────────────────────────────┘
```

**Structure:**

| Section | Content |
|---------|---------|
| Left | GOLINE logo + "GOLINE SOC · Magic Transit Dashboard" (white text) |
| Right | Green pulsing dot + "Auto-refresh 30s" (gray text) |

**CSS Classes:**

| Class | Purpose |
|-------|---------|
| `.footer-text` | White text (`--text-primary`), font-weight 500 |
| `.footer-dot` | Green pulsing indicator (6px) |

**Responsive:** Footer stacks vertically and centers on screens < 768px.

### Dynamic Version (Auto-Sync)

The dashboard version is automatically read from this file (`DASHBOARD.md`) - safe for GitHub distribution.

**Source:** `**Version**: X.Y.Z` at the top of `/root/Cloudflare_MT_Integration/docs/DASHBOARD.md`

**Implementation:**

```python
# app.py
def load_version():
    """Load version from docs/DASHBOARD.md (safe for GitHub distribution)"""
    import re
    try:
        dashboard_md = os.path.join(BASE_DIR, "docs", "DASHBOARD.md")
        with open(dashboard_md, 'r') as f:
            for _ in range(10):
                line = f.readline()
                match = re.search(r'\*\*Version\*\*:\s*(\d+\.\d+\.\d+)', line)
                if match:
                    return match.group(1)
    except:
        pass
    return "2.4.0"  # fallback
```

**How It Works:**

1. When dashboard loads, `load_version()` reads first 10 lines of DASHBOARD.md
2. Regex finds `**Version**: X.Y.Z` pattern
3. Extracts version number (e.g., `2.4.14`)
4. Passes to all templates via `{{ version }}`

**Benefits:**

- No separate VERSION file to maintain
- Version stored in GitHub-safe documentation file
- CLAUDE.md (with credentials) not required for version

**Pages with Dynamic Version:**

| Page | Template | Route |
|------|----------|-------|
| Main Dashboard | `dashboard.html` | `/` |
| MNM Rules Manager | `mnm_rules.html` | `/mnm-rules` |
| DDoS Rules Manager | `ddos_rules.html` | `/ddos-rules` |
| Connectors | `connectors.html` | `/connectors` |

---

## Apache Configuration

### SSL/TLS

- **Certificate**: Let's Encrypt via Certbot
- **Protocol**: TLS 1.2+ only (no SSLv3, TLS 1.0/1.1)
- **Cipher Suite**: ECDHE with AES-GCM and ChaCha20-Poly1305
- **HSTS**: Enabled (2 years, includeSubDomains, preload)

### Security Headers

```apache
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
```

### IP Whitelist

Access is restricted to authorized networks only:

| Network | Description |
|---------|-------------|
| `127.0.0.1`, `::1` | Localhost |
| `185.54.80.0/22` | GOLINE Networks |
| `2a02:4460::/32` | GOLINE IPv6 |
| `185.109.164.26` | Admin (Cadro) |
| `213.193.119.162` | Admin secondary |
| `2001:470:26:100::/64` | Admin HE tunnel |
| `2001:470:b5b2::/48` | Admin HE routed |
| `83.150.40.202` | Lily's Office |
| `83.150.40.207` | Lily's Factory |
| `83.150.42.99` | Lily's Original |
| `185.160.244.194` | Lily's Maxim |
| `192.168.220.0/22` | Internal LAN |
| `192.168.1.0/24` | Internal LAN |
| `172.27.224.0/24` | WireGuard VPN |

### Proxy Configuration

```apache
ProxyPreserveHost On
ProxyRequests Off
ProxyPass / http://127.0.0.1:8081/
ProxyPassReverse / http://127.0.0.1:8081/
ProxyTimeout 30
```

---

## Systemd Service

### Service File

```ini
[Unit]
Description=Cloudflare Magic Transit Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/Cloudflare_MT_Integration/dashboard
ExecStart=/usr/bin/python3 /root/Cloudflare_MT_Integration/dashboard/app.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

### Management Commands

```bash
# Start/Stop/Restart
systemctl start cloudflare-dashboard
systemctl stop cloudflare-dashboard
systemctl restart cloudflare-dashboard

# Enable/Disable on boot
systemctl enable cloudflare-dashboard
systemctl disable cloudflare-dashboard

# View status
systemctl status cloudflare-dashboard

# View logs
journalctl -u cloudflare-dashboard -f
journalctl -u cloudflare-dashboard -n 100
```

---

## Configuration

### Settings File

The dashboard uses `/root/Cloudflare_MT_Integration/config/settings.json`:

```json
{
  "cloudflare": {
    "account_id": "YOUR_ACCOUNT_ID",
    "api_token": "YOUR_API_TOKEN",
    "auth_email": "YOUR_EMAIL",
    "global_api_key": "YOUR_GLOBAL_KEY"
  }
}
```

### Prefix Mapping

The dashboard uses `/root/Cloudflare_MT_Integration/config/prefix_mapping.json`:

```json
{
  "prefixes": {
    "185.54.80.0/24": {
      "prefix_id": "...",
      "bgp_prefix_id": "...",
      "description": "BGP"
    }
  }
}
```

### Database

The dashboard reads from `/root/Cloudflare_MT_Integration/db/magic_transit.db`:

| Table | Purpose |
|-------|---------|
| `attack_events` | START/END/WITHDRAW events |
| `network_analytics_events` | Dropped traffic events |
| `webhook_events` | Raw webhook payloads |
| `withdrawal_history` | Completed withdrawals |

---

## Deployment

### Prerequisites

```bash
# Python packages
apt install python3 python3-flask python3-requests

# Apache modules
a2enmod ssl proxy proxy_http headers
```

### Installation Steps

1. **Copy files**:
   ```bash
   mkdir -p /root/Cloudflare_MT_Integration/dashboard/templates
   cp app.py /root/Cloudflare_MT_Integration/dashboard/
   cp dashboard.html /root/Cloudflare_MT_Integration/dashboard/templates/
   ```

2. **Install systemd service**:
   ```bash
   cp cloudflare-dashboard.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable cloudflare-dashboard
   systemctl start cloudflare-dashboard
   ```

3. **Install Apache vhost**:
   ```bash
   cp cloudflare.goline.ch.conf /etc/apache2/sites-available/
   a2ensite cloudflare.goline.ch.conf
   systemctl reload apache2
   ```

4. **Obtain SSL certificate**:
   ```bash
   certbot --apache -d cloudflare.goline.ch
   ```

### Verification

```bash
# Test Flask backend
curl -s http://127.0.0.1:8081/health | jq

# Test all API endpoints
curl -s http://127.0.0.1:8081/api/prefixes | jq
curl -s http://127.0.0.1:8081/api/stats | jq
curl -s http://127.0.0.1:8081/api/services | jq

# Check Apache vhost
apache2ctl -S | grep cloudflare

# View service status
systemctl status cloudflare-dashboard
```

---

## Troubleshooting

### Dashboard Not Loading

1. **Check Flask service**:
   ```bash
   systemctl status cloudflare-dashboard
   journalctl -u cloudflare-dashboard -n 50
   ```

2. **Check Apache**:
   ```bash
   systemctl status apache2
   tail -20 /var/log/apache2/cloudflare-dashboard-error.log
   ```

3. **Test local Flask**:
   ```bash
   curl -s http://127.0.0.1:8081/health
   ```

### API Errors

1. **Check config files exist**:
   ```bash
   ls -la /root/Cloudflare_MT_Integration/config/
   ```

2. **Verify API credentials**:
   ```bash
   cat /root/Cloudflare_MT_Integration/config/settings.json | jq
   ```

3. **Test Cloudflare API**:
   ```bash
   curl -s "https://api.cloudflare.com/client/v4/user/tokens/verify" \
     -H "Authorization: Bearer YOUR_TOKEN"
   ```

### Access Denied (403)

Your IP is not in the whitelist. Check:

```bash
# View current whitelist
grep "Require ip" /etc/apache2/sites-available/cloudflare.goline.ch.conf

# Add new IP
# Edit the file and add: Require ip X.X.X.X
systemctl reload apache2
```

### SSL Certificate Issues

```bash
# Check certificate
openssl s_client -connect cloudflare.goline.ch:443 -servername cloudflare.goline.ch

# Renew certificate
certbot renew --dry-run
certbot renew
```

---

## Security Considerations

### Access Control

- Dashboard is accessible only from whitelisted IPs
- HTTPS enforced with HSTS
- No authentication required (network-level security)

### API Security

- Flask runs on localhost only (127.0.0.1:8081)
- Apache acts as reverse proxy with SSL termination
- No public exposure of Flask port

### Data Sensitivity

- Dashboard reads but never writes to database
- API credentials loaded from config file at startup
- No credentials exposed in frontend

### Logging

- Apache access logs: `/var/log/apache2/cloudflare-dashboard-access.log`
- Apache error logs: `/var/log/apache2/cloudflare-dashboard-error.log`
- Flask logs: `journalctl -u cloudflare-dashboard`

---

## Backup and Recovery

### Backup Location

```
/root/Cloudflare_MT_Integration/backup/dashboard_YYYYMMDD_HHMMSS/
├── dashboard/              # Flask application
├── cloudflare.goline.ch.conf  # Apache vhost
├── cloudflare-dashboard.service  # Systemd service
├── FILES.txt               # File listing
└── checksums.md5           # MD5 checksums
```

### Create Backup

```bash
BACKUP_DIR="/root/Cloudflare_MT_Integration/backup/dashboard_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r /root/Cloudflare_MT_Integration/dashboard "$BACKUP_DIR/"
cp /etc/apache2/sites-available/cloudflare.goline.ch.conf "$BACKUP_DIR/"
cp /etc/systemd/system/cloudflare-dashboard.service "$BACKUP_DIR/"
```

### Restore from Backup

```bash
BACKUP_DIR="/root/Cloudflare_MT_Integration/backup/dashboard_XXXXXXXX_XXXXXX"
cp -r "$BACKUP_DIR/dashboard" /root/Cloudflare_MT_Integration/
cp "$BACKUP_DIR/cloudflare.goline.ch.conf" /etc/apache2/sites-available/
cp "$BACKUP_DIR/cloudflare-dashboard.service" /etc/systemd/system/
systemctl daemon-reload
systemctl restart cloudflare-dashboard
systemctl reload apache2
```

---

## Known Issues and Solutions

### Logo Integration Issues (Resolved)

**Problem 1: Base64 Image API Error**

When attempting to embed the GOLINE logo as base64 directly in bash output, Claude Code API returned:
```
API Error: 400 {"type":"error","error":{"type":"invalid_request_error",
"message":"Could not process image"}}
```

**Cause**: The base64 data was being interpreted as image content by the API when output in bash.

**Solution**: Save logo as static file and reference via URL instead of embedding base64.

---

**Problem 2: Logo Not Visible on Orange Header**

Initial attempts placed the logo with a white container background, making it look out of place.

**Attempted Fix**: Applied CSS filter `brightness(0) invert(1)` to make logo white.

**Issue**: This removed the original blue GOLINE branding colors.

**Final Solution**: Use the `Goline_500_160_trasparente.png` logo (which has blue text on transparent background) without any CSS filter. The blue text is visible on the orange header.

---

**Problem 3: Timestamp Not Readable**

The "Last update: HH:MM:SS" timestamp in the header was using `var(--text-secondary)` (gray color), making it unreadable on the orange background.

**Solution**: Added specific CSS rule to override the color:
```css
.header-right .timestamp {
    color: white;
    font-size: 0.85rem;
}
```

---

### Logo File Selection

Multiple logo files were tested:

| File | Size | Result |
|------|------|--------|
| `goline_logo.png` | 1000x386, 68KB | Too large, wrong proportions |
| `goline_logo_small.png` | 236x91, 3KB | From ClamAV, different style |
| `Goline_500_160_trasparente.png` | 500x160, 26KB | **Best fit** - blue text, transparent |

**Recommendation**: Always use `Goline_500_160_trasparente.png` for headers with colored backgrounds.

---

### Static Files in Flask

Flask serves static files from the `static/` directory by default:
- URL: `/static/images/filename.png`
- Path: `dashboard/static/images/filename.png`

Ensure static files are placed in the correct directory, not in `dashboard/images/` (which is not served).

---

### Services Display Issues (Resolved)

**Problem 1: "NaNd ago" Displayed Instead of Uptime**

The Services section showed "since NaNd ago" because JavaScript couldn't parse the systemd timestamp format.

**Cause**: Backend returned systemd's default format: `"Tue 2026-01-20 20:35:59 CET"`

JavaScript's `Date.parse()` doesn't recognize this format, returning `NaN`.

**Solution**: Convert to ISO 8601 format in backend:

```python
# Before (broken)
uptime = "Tue 2026-01-20 20:35:59 CET"

# After (fixed)
uptime = "2026-01-20T20:35:59+01:00"
```

Backend conversion code:
```python
# Get ActiveEnterTimestamp
result = subprocess.run(
    ["systemctl", "show", service, "--property=ActiveEnterTimestamp", "--value"],
    capture_output=True, text=True, timeout=5
)
timestamp_str = result.stdout.strip()  # "Tue 2026-01-20 20:35:59 CET"

# Parse and convert to ISO format
dt = datetime.strptime(timestamp_str[4:23], "%Y-%m-%d %H:%M:%S")
# Extract timezone offset (CET = +01:00, CEST = +02:00)
tz_offset = "+02:00" if "CEST" in timestamp_str else "+01:00"
uptime = dt.strftime(f"%Y-%m-%dT%H:%M:%S{tz_offset}")
```

---

**Problem 2: Service Names Not User-Friendly**

The Services section displayed raw systemd service names (e.g., `cloudflare-webhook`) which were not descriptive for users.

**Solution**: Read the `Description=` field from each systemd service unit and display that instead:

```python
# Get service description
result = subprocess.run(
    ["systemctl", "show", service, "--property=Description", "--value"],
    capture_output=True, text=True, timeout=5
)
description = result.stdout.strip() or service  # Fallback to service name
```

Frontend displays description with original name as tooltip:
```html
<span class="service-name" title="cloudflare-webhook">
    Cloudflare Magic Transit Webhook Receiver
</span>
```

---

**Problem 3: Missing Dashboard Service**

Initially only 3 services were monitored. The dashboard service itself was not included.

**Solution**: Added `cloudflare-dashboard` to the monitored services list:

```python
SERVICES = [
    "cloudflare-webhook",
    "cloudflare-analytics-monitor",
    "cloudflare-autowithdraw",
    "cloudflare-dashboard"       # Added
]
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.9.22 | 2026-02-02 | DNS timeout graceful handling: `as_completed()` TimeoutError wrapped in try/except to continue with partial results |
| 2.9.21 | 2026-01-23 | Improved constraint messages: "Can X in Y min (Cloudflare API cooldown)", "Ready to X", backend returns updated state |
| 2.9.20 | 2026-01-23 | CNI/Tunnel pass rate fix: Calculate from `resultStatus=ok` instead of `tunnelState` to match Cloudflare dashboard |
| 2.9.19 | 2026-01-23 | Network Analytics hostname resolution: Added Hostname column with reverse DNS lookup |
| 2.9.18 | 2026-01-23 | Network Flow hostnames: Top Source/Router/Destination now show resolved hostnames |
| 2.9.17 | 2026-01-23 | Network Analytics: Increased event limit from 30 to 100 |
| 2.9.16 | 2026-01-22 | Network Analytics status indicator: Shows paused/active based on prefix advertisement |
| 2.9.15 | 2026-01-22 | Stats: Count only real attacks (event_type=START) instead of all events |
| 2.9.13 | 2026-01-22 | Stats API timestamp fix: Use SQLite `datetime()` instead of Python isoformat() |
| 2.9.12 | 2026-01-21 | Prefix Manager logging: Manual operations appear in dashboard attack log |
| 2.9.11 | 2026-01-21 | Autowithdraw API fix: Correct endpoint for detecting advertised prefixes |
| 2.9.10 | 2026-01-21 | Fixed attack events ordering: `ORDER BY created_at DESC`, increased LIMIT to 50 |
| 2.9.9 | 2026-01-21 | Auto-advertisement support: Complete attack lifecycle display, new action labels |
| 2.9.8 | 2026-01-21 | User-friendly event type labels: 🚨 ATTACK, ✅ ENDED, 📡 ADVERTISE, 📤 WITHDRAW |
| 2.9.7 | 2026-01-21 | Attack modal cleanup: Removed redundant Message section |
| 2.9.6 | 2026-01-21 | MNM alerts database logging: fbm_dosd_attack, fbm_volumetric_attack now saved to DB |
| 2.9.5 | 2026-01-21 | Footer readability: Brightened footer text color to rgba(255,255,255,0.85) across all pages |
| 2.9.4 | 2026-01-21 | UI Polish: Consistent button styling across all pages - solid backgrounds, shadows, hover lift effects for header, card, modal, and action buttons |
| 2.9.3 | 2026-01-21 | Connectors: Extended tunnel editing (Customer Endpoint, MTU, Health Check Rate/Enabled), read-only fields display |
| 2.9.2 | 2026-01-21 | Connectors: Editable detail modals with double-click, tunnel/CNI description editing, auto-detect GRE/IPsec |
| 2.9.1 | 2026-01-21 | Connectors: vertical layout, health check pass rate % (1h) from GraphQL, human-readable intervals, CNI API fix |
| 2.9.0 | 2026-01-21 | Connectors page: IPsec/GRE Tunnels & CNI Interconnects with health status, new API endpoints |
| 2.8.8 | 2026-01-21 | Cloudflare constraint enforcement: Advertise/Withdraw buttons disabled during 15-min timer |
| 2.8.7 | 2026-01-21 | Double-click edit on all rule pages: Dashboard MNM, /mnm-rules, /ddos-rules (editable rules only) |
| 2.8.6 | 2026-01-21 | Enhanced modals: start_time in Attack, verdict/sourceAsn/sourceCountry in Analytics, GraphQL dimensions, bug fix for items.filter error |
| 2.8.5 | 2026-01-21 | Dynamic detail modals: auto-hide empty fields with hasValue()/dynamicItem()/dynamicRow()/dynamicSection() helpers |
| 2.8.4 | 2026-01-21 | Ultra-compact modals: Inline rows, reduced padding/fonts, ~40% height reduction |
| 2.8.3 | 2026-01-21 | Attack detail modal compact layout: Reorganized to 2-row grid + footer bar with IDs |
| 2.8.2 | 2026-01-21 | Rule description lookup: Analytics modal shows rule descriptions via attack_events lookup, compact 2-row layout |
| 2.8.1 | 2026-01-21 | Network Analytics detail modal: Double-click for full event details with GeoIP info |
| 2.8.0 | 2026-01-21 | Attack detail modal: Double-click on Recent Attacks for comprehensive event view with raw_payload |
| 2.7.4 | 2026-01-21 | Timestamp timezone fix: Added Z suffix (ISO 8601 UTC) to all timestamps in API responses |
| 2.4.14 | 2026-01-21 | Dynamic version: auto-sync from DASHBOARD.md (GitHub-safe), card descriptions, minimal footer |
| 2.4.1 | 2026-01-21 | Card descriptions & Footer redesign: descriptions for all 6 cards, minimal footer with GOLINE branding |
| 2.4.0 | 2026-01-21 | MNM Rules Edit: Edit button, validation limits, PUT API endpoint, section-specific Add modal, section descriptions, DDoS Manage button |
| 2.3.0 | 2026-01-21 | MNM Rules Manager: new page for managing MNM rules, create/delete BPS/PPS/sFlow rules, Manage button in dashboard |
| 2.2.0 | 2026-01-21 | DDoS Rules Manager: renamed page title, Editable stat card, dedicated Editable Rules section with Override column, manual refresh button |
| 2.1.0 | 2026-01-21 | Override merge: API reads root ruleset overrides, sensitivity dropdown for ddos_dynamic, has_override field |
| 2.0.0 | 2026-01-20 | DDoS rule editing: Edit button, modal interface, POST endpoint for action updates |
| 1.9.0 | 2026-01-20 | Clickable DDoS cards with detail page, new API endpoints, search functionality |
| 1.8.0 | 2026-01-20 | DDoS Sensitivity redesign with mini stat cards (Total, Block, Dynamic, Log) |
| 1.7.0 | 2026-01-20 | Human-readable Alert Type (12 mappings) and Action (10 mappings) in Recent Attacks |
| 1.6.0 | 2026-01-20 | Responsive design: fixed stats grid (6→3→2→1 columns), header wrapping fix, service name truncation |
| 1.5.0 | 2026-01-20 | User-friendly service names from systemd, ISO 8601 timestamps, all 4 services monitored |
| 1.4.0 | 2026-01-20 | Advertise/Withdraw buttons with 15-min constraint, POST API endpoints |
| 1.3.0 | 2026-01-20 | GOLINE logo in header-right, timestamp color fix, documentation |
| 1.2.0 | 2026-01-20 | Embedded Cloudflare logo (base64), stat card descriptions with tooltips |
| 1.1.0 | 2026-01-20 | Parallel prefix loading, improved header with Cloudflare logo |
| 1.0.0 | 2026-01-20 | Initial release |

---

*GOLINE SOC - Cloudflare Magic Transit Dashboard*
