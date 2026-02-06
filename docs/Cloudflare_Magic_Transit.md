# Cloudflare Magic Transit Integration

## Complete Technical Documentation

**Project**: Cloudflare Magic Transit On-Demand Integration
**Version**: 2.10.4
**Last Updated**: 2026-02-06
**Organization**: GOLINE SA
**Author**: SOC Team

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
3. [Components Overview](#3-components-overview)
4. [Web Dashboard](#4-web-dashboard)
5. [Webhook Receiver](#5-webhook-receiver)
6. [Network Analytics Monitor](#6-network-analytics-monitor)
7. [Auto-Withdraw Daemon](#7-auto-withdraw-daemon)
8. [BGP Prefix Management](#8-bgp-prefix-management)
9. [Database System](#9-database-system)
10. [Telegram Notifications](#10-telegram-notifications)
11. [Cloudflare API Integration](#11-cloudflare-api-integration)
12. [Configuration Files](#12-configuration-files)
13. [Operations Guide](#13-operations-guide)
14. [Monitoring and Logging](#14-monitoring-and-logging)
15. [Troubleshooting](#15-troubleshooting)
16. [Security Considerations](#16-security-considerations)
17. [Appendix](#17-appendix)

---

## 1. Executive Summary

### 1.1 Purpose

This system provides automated management of Cloudflare Magic Transit On-Demand BGP prefix advertisements in response to DDoS attacks. It receives real-time webhooks from Cloudflare, manages BGP prefix lifecycle, and ensures proper withdrawal timing while maintaining full audit trails.

### 1.2 Key Features

| Feature | Description |
|---------|-------------|
| **Web Dashboard** | Real-time monitoring UI at cloudflare.goline.ch with full lifecycle visibility |
| **Real-time Webhook Processing** | Receives and processes 11 different Cloudflare alert types |
| **Unified Withdraw Architecture** | Single service (`cloudflare-autowithdraw`) handles ALL BGP withdrawals |
| **GraphQL-based Attack Detection** | Monitors dropped traffic via Network Analytics API with GeoIP enrichment |
| **Calm Period Detection** | Auto-withdraws prefixes after 15 minutes without attacks |
| **Complete Audit Trail** | SQLite database stores all events, webhooks, and operations |
| **DDoS Protection Log** | Full lifecycle display: ATTACK → ADVERTISE → WITHDRAW |
| **MNM/DDoS Rules Management** | Web-based management of threshold and sensitivity rules |
| **15-Minute Constraint Handling** | Enforces Cloudflare's mandatory wait period before withdrawal |
| **Manual Override** | CLI tool and dashboard for manual prefix management with DB logging |
| **High Availability** | Services watchdog with auto-restart and Telegram alerts |

### 1.3 System Requirements

- **Server**: Ubuntu 22.04+ / Debian 12+
- **Python**: 3.10+
- **Web Server**: Apache 2.4+ with mod_proxy
- **Database**: SQLite 3
- **Network**: HTTPS access from Cloudflare webhook IPs
- **Services**: systemd, cron
- **Optional**: GeoIP2 databases for source IP enrichment

### 1.4 Quick Reference

| Resource | Location |
|----------|----------|
| Project Directory | `/root/Cloudflare_MT_Integration/` |
| **Dashboard** | `https://cloudflare.goline.ch` |
| Webhook Endpoint | `https://lg.goline.ch/webhook/cloudflare` |
| Health Check | `https://lg.goline.ch/mt-health` |
| Database | `/root/Cloudflare_MT_Integration/db/magic_transit.db` |
| Webhook Service | `cloudflare-webhook.service` |
| Analytics Service | `cloudflare-analytics-monitor.service` |
| **Autowithdraw Service** | `cloudflare-autowithdraw.service` |
| **Dashboard Service** | `cloudflare-dashboard.service` |
| Watchdog Cron | `/etc/cron.d/cloudflare-services-watchdog` |

---

## 2. System Architecture

### 2.1 Unified Architecture (v2.9.x)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           UNIFIED ARCHITECTURE v2.9.12                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────┐      ┌─────────────────────────┐               │
│  │  cloudflare-webhook     │      │  cloudflare-analytics   │               │
│  │  v1.8.0                 │      │  v1.3.8                 │               │
│  ├─────────────────────────┤      ├─────────────────────────┤               │
│  │ • Receives webhooks     │      │ • Polls GraphQL API     │               │
│  │ • 11 alert types        │      │ • GeoIP2 enrichment     │               │
│  │ • Telegram alerts       │      │ • GOLINE prefix filter  │               │
│  │ • Database logging      │      │ • Spoofed IP detection  │               │
│  │ • Auto-adv logging      │      │ • NO withdraw ops       │               │
│  └─────────────────────────┘      └─────────────────────────┘               │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │              cloudflare-autowithdraw v3.3 (ONLY withdraw source)    │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ • Monitors GraphQL for dropped traffic (every 60s)                   │    │
│  │ • Uses correct BGP prefix endpoint with on_demand.advertised         │    │
│  │ • Tracks "calm since" for each advertised prefix                     │    │
│  │ • If calm for 15 minutes → AUTO WITHDRAW                             │    │
│  │ • Telegram notifications + database logging                          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     cloudflare-dashboard v2.9.12 (Web UI)           │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ • Real-time BGP prefix status with calm time tracking                │    │
│  │ • DDoS Protection Log: ATTACK → ADVERTISE → WITHDRAW lifecycle       │    │
│  │ • Network Analytics with GeoIP                                       │    │
│  │ • MNM/DDoS Rules management with edit modals                         │    │
│  │ • Connectors (IPsec/GRE/CNI) status                                  │    │
│  │ • Manual ADVERTISE/WITHDRAW with database logging                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │              cloudflare-prefix-manager v1.4.0 (CLI)                  │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │ • Manual prefix management from command line                         │    │
│  │ • ADVERTISE/WITHDRAW operations logged to database                   │    │
│  │ • Visible in dashboard "DDoS Protection Log" section                 │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              ATTACK LIFECYCLE                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  PHASE 1: ATTACK DETECTED                                                        │
│  ════════════════════════                                                        │
│                                                                                  │
│  Cloudflare DDoS Protection                                                      │
│         │                                                                        │
│         ├──▶ Detects L3/L4/L7 attack via MNM rules                               │
│         ├──▶ Triggers auto-advertisement (fbm_auto_advertisement webhook)        │
│         └──▶ Sends webhook: ALERT_STATE_EVENT_START                              │
│                      │                                                           │
│                      ▼                                                           │
│              Webhook Receiver v1.8.0                                             │
│                      │                                                           │
│         ┌───────────┴───────────┐                                                │
│         ▼                       ▼                                                │
│  log_attack_event()     send_telegram_notification()                             │
│  (event_type=START      "🚨 DDoS ATTACK IN PROGRESS"                             │
│   OR ADVERTISE)                                                                  │
│                                                                                  │
│  PHASE 2: MITIGATION ACTIVE                                                      │
│  ═══════════════════════════                                                     │
│                                                                                  │
│  Network Analytics Monitor v1.3.8                                                │
│         │                                                                        │
│         ├──▶ Polls GraphQL every 5 minutes                                       │
│         ├──▶ Detects dropped traffic (outcome=drop)                              │
│         ├──▶ GeoIP enrichment of source IPs                                      │
│         └──▶ Logs to database + Telegram notification                            │
│                                                                                  │
│  Dashboard shows:                                                                │
│         ├── 🚨 ATTACK event in DDoS Protection Log                               │
│         ├── 📡 ADVERTISE event in DDoS Protection Log                            │
│         └── Dropped traffic in Network Analytics section                         │
│                                                                                  │
│  PHASE 3: ATTACK ENDS                                                            │
│  ════════════════════                                                            │
│                                                                                  │
│  Cloudflare sends webhook: ALERT_STATE_EVENT_END                                 │
│         │                                                                        │
│         ▼                                                                        │
│  Webhook Receiver → log_attack_event(END) + Telegram "✅ ATTACK ENDED"           │
│                     (NO withdraw operation - handled by autowithdraw)            │
│                                                                                  │
│  PHASE 4: AUTO-WITHDRAW (after 15 min calm)                                      │
│  ══════════════════════════════════════════                                      │
│                                                                                  │
│  cloudflare-autowithdraw.service (every 60 seconds)                              │
│         │                                                                        │
│         ├──▶ Queries GraphQL for dropped traffic                                 │
│         ├──▶ Uses correct API: /bgp/prefixes/{id} with on_demand.advertised      │
│         ├──▶ Tracks "calm since" for each advertised prefix                      │
│         ├──▶ If calm for 15 consecutive minutes:                                 │
│         │         └──▶ BGP WITHDRAW via API                                      │
│         │         └──▶ log_attack_event(WITHDRAW)                                │
│         │         └──▶ Telegram "📤 PREFIX AUTO-WITHDRAWN"                       │
│         └──▶ Dashboard shows: 📤 WITHDRAW event                                  │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Components Overview

### 3.1 Directory Structure

```
/root/Cloudflare_MT_Integration/
├── README.md                           # Project overview and quick start
├── CLAUDE.md                           # Project context for Claude Code
│
├── docs/                               # Documentation
│   ├── Cloudflare_Magic_Transit.md     # This comprehensive guide
│   ├── AUTOWITHDRAW.md                 # Auto-withdraw daemon documentation (v3.3)
│   ├── DASHBOARD.md                    # Web dashboard documentation (v2.9.12)
│   ├── DATABASE.md                     # Database schema and operations (v2.0)
│   ├── DB_MANAGER.md                   # Database manager module (v1.3.0)
│   ├── NETWORK_ANALYTICS_MONITOR.md    # GraphQL poller documentation (v1.3.8)
│   ├── PREFIX_MANAGER.md               # CLI tool documentation (v1.4.0)
│   ├── RULES_MANAGER.md                # MNM rules manager documentation (v1.4)
│   ├── SERVICES_WATCHDOG.md            # Watchdog script documentation (v1.2)
│   ├── WEBHOOK_RECEIVER.md             # Webhook handler documentation (v1.8.0)
│   └── CLOUDFLARE_API_REFERENCE.md     # Unified API documentation (v1.0)
│
├── config/                             # Configuration files
│   ├── settings.json                   # API credentials and settings
│   ├── prefix_mapping.json             # BGP prefix to ID mappings
│   └── auth.json                       # Dashboard authentication (bcrypt)
│
├── db/                                 # Database directory
│   └── magic_transit.db                # SQLite database file
│
├── scripts/                            # Python scripts
│   ├── cloudflare-webhook-receiver.py             # Webhook receiver v1.8.0
│   ├── cloudflare-network-analytics-monitor.py    # Network Analytics v1.3.8
│   ├── cloudflare-autowithdraw.py                 # BGP withdraw daemon v3.3
│   ├── cloudflare-rules-manager.py                # MNM rules manager v1.4
│   ├── cloudflare-services-watchdog.sh            # Services watchdog v1.2
│   ├── db_manager.py                              # Database operations v1.3.0
│   └── cloudflare-prefix-manager.py               # CLI prefix manager v1.4.0
│
├── dashboard/                          # Web dashboard
│   ├── app.py                          # Flask backend (v2.9.12)
│   ├── static/
│   │   ├── favicon.ico                 # Cloudflare favicon
│   │   └── images/                     # Logo images
│   └── templates/
│       ├── dashboard.html              # Main dashboard HTML/CSS/JS
│       ├── login.html                  # Login page
│       ├── ddos_rules.html             # DDoS Rules Manager page
│       ├── mnm_rules.html              # MNM Rules Manager page
│       └── connectors.html             # IPsec/GRE/CNI Connectors page
│
├── logs/                               # Log files
│   ├── webhook.log                     # Webhook receiver logs
│   ├── network-analytics-monitor.log  # Network Analytics logs
│   ├── autowithdraw.log                # Auto-withdraw daemon logs
│   ├── watchdog.log                    # Services watchdog logs
│   └── webhooks/                       # Raw webhook JSON files
│
├── backup/                             # Project backups
└── github/                             # GitHub repository (sanitized)
```

### 3.2 Services and Daemons

| Service | Type | Port | Version | Description |
|---------|------|------|---------|-------------|
| `cloudflare-webhook.service` | systemd | 8080 | v1.8.0 | Webhook receiver + DB logging |
| `cloudflare-analytics-monitor.service` | systemd | - | v1.3.8 | Network Analytics with GeoIP |
| `cloudflare-autowithdraw.service` | systemd | - | **v3.3** | **ONLY BGP withdraw source** |
| `cloudflare-dashboard.service` | systemd | 8081 | v2.9.12 | Web dashboard UI |
| `apache2.service` | systemd | 443 | - | HTTPS reverse proxy |
| `cloudflare-services-watchdog` | cron | - | v1.2 | Auto-restart watchdog (*/5 min) |

### 3.3 Script Versions

| Script | Version | Description |
|--------|---------|-------------|
| `cloudflare-webhook-receiver.py` | **1.8.0** | Webhook handler + auto-adv logging |
| `cloudflare-network-analytics-monitor.py` | 1.3.8 | GraphQL poller with GeoIP2 |
| `cloudflare-autowithdraw.py` | **3.3** | BGP withdraw daemon (correct API endpoint) |
| `cloudflare-rules-manager.py` | 1.4 | Interactive MNM/DDoS rules manager |
| `cloudflare-services-watchdog.sh` | 1.2 | Services watchdog with Telegram |
| `db_manager.py` | **1.3.0** | Database operations with MNM fix |
| `cloudflare-prefix-manager.py` | **1.4.0** | CLI with database logging |
| `dashboard/app.py` | **2.9.12** | Web dashboard backend |

---

## 4. Web Dashboard

### 4.1 Overview

Real-time monitoring dashboard for Cloudflare Magic Transit integration.

| Component | Value |
|-----------|-------|
| **URL** | `https://cloudflare.goline.ch` |
| **Backend** | Flask (Python) on port 8081 |
| **Frontend** | HTML/CSS/JS (dark theme) |
| **Proxy** | Apache2 with SSL termination |
| **SSL** | Let's Encrypt (cloudflare.goline.ch) |
| **Access** | IP whitelist + login authentication |
| **Auto-refresh** | 30 seconds |

### 4.2 Dashboard Sections

| Section | Description |
|---------|-------------|
| **Network Flow (24h)** | Real-time traffic stats (avg rates, top protocol/source/destination) |
| **BGP Prefixes** | Prefix status with calm time, API constraint timer, Advertise/Withdraw buttons |
| **DDoS Protection Log** | Attack lifecycle: 🚨 ATTACK → 📡 ADVERTISE → 📤 WITHDRAW |
| **Network Analytics** | Dropped traffic with GeoIP enrichment |
| **MNM Rules** | Magic Network Monitoring rules (threshold + sFlow) |
| **DDoS Sensitivity** | L3/4 Managed Ruleset with 124 rules |
| **Services Status** | Systemd service health with auto-restart |

### 4.3 Event Types (DDoS Protection Log)

| Badge | Event Type | Description |
|-------|------------|-------------|
| 🚨 ATTACK | START | Attack detected |
| ✅ ENDED | END | Attack ended |
| 📡 ADVERTISE | ADVERTISE | Prefix announced BGP |
| 📤 WITHDRAW | WITHDRAW | Prefix withdrawn BGP |

### 4.4 Action Types

| Badge | Action | Source |
|-------|--------|--------|
| 🛡️ Mitigating | mitigating | DDoS L4 active mitigation |
| 📡 Auto-Advertised | auto_advertised | Cloudflare auto-advertisement |
| 📤 Withdrawn Auto | withdrawn_auto | Autowithdraw daemon |
| 📤 Withdrawn Manual | withdrawn_manual | CLI or dashboard |
| 📡 Advertised Manual | advertised_manual | CLI or dashboard |

### 4.5 Additional Pages

| Page | URL | Description |
|------|-----|-------------|
| **MNM Rules** | `/mnm-rules` | Full MNM rules management |
| **DDoS Rules** | `/ddos-rules` | L3/4 sensitivity rules |
| **Connectors** | `/connectors` | IPsec/GRE tunnels + CNI interconnects |

### 4.6 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard HTML |
| `/health` | GET | Health check JSON |
| `/api/prefixes` | GET | BGP prefix status with calm time |
| `/api/prefix/<cidr>/advertise` | POST | Advertise BGP prefix |
| `/api/prefix/<cidr>/withdraw` | POST | Withdraw BGP prefix |
| `/api/attacks` | GET | DDoS Protection Log events |
| `/api/attacks/<id>` | GET | Attack event details |
| `/api/analytics` | GET | Network analytics events |
| `/api/analytics/<id>` | GET | Analytics event details |
| `/api/rules` | GET | MNM rules |
| `/api/mnm-rules` | GET/POST/DELETE | MNM rules CRUD |
| `/api/ddos-rules` | GET | DDoS L3/4 rules |
| `/api/ddos-rules/<id>/update` | POST | Update DDoS rule action |
| `/api/network-flow` | GET | 24h traffic statistics |
| `/api/connectors/*` | GET/POST | Tunnel and CNI management |
| `/api/services` | GET | Service status |

---

## 5. Webhook Receiver

### 5.1 Overview (v1.8.0)

The webhook receiver is a Flask application that processes Cloudflare notifications with full database logging.

**Key Changes in v1.8.0:**
- `fbm_auto_advertisement` events logged to database as `ADVERTISE` with `auto_advertised`
- DDoS L4 attacks show `action_taken='mitigating'` instead of `'notified'`
- Complete attack lifecycle visible in dashboard

### 5.2 Supported Alert Types (11)

| Alert Type | Category | Priority | DB Logging |
|------------|----------|----------|:----------:|
| `advanced_ddos_attack_l4_alert` | DDoS Protection | HIGH | ✅ |
| `dos_attack_l4` | DDoS Protection | HIGH | ✅ |
| `dos_attack_l7` | DDoS Protection | HIGH | ✅ |
| `fbm_dosd_attack` | Magic Network Monitoring | HIGH | ✅ (v1.7.0) |
| `fbm_volumetric_attack` | Magic Network Monitoring | MEDIUM | ✅ (v1.7.0) |
| `fbm_auto_advertisement` | Magic Transit | INFO | ✅ (v1.8.0) |
| `magic_tunnel_health_check_event` | Magic Transit | HIGH | ❌ |
| `incident_alert` | Cloudflare Status | VARIES | ❌ |
| `health_check_status_notification` | Health Checks | MEDIUM | ❌ |
| `bgp_hijack_notification` | Route Leak Detection | CRITICAL | ❌ |

### 5.3 Important: Notifications Only

Since v2.1.0, the webhook receiver does **NOT** perform any BGP withdraw operations. All withdrawals are handled by `cloudflare-autowithdraw.service`.

---

## 6. Network Analytics Monitor

### 6.1 Overview (v1.3.8)

Polls Cloudflare GraphQL API for DDoS mitigation events with GeoIP enrichment.

| Parameter | Value |
|-----------|-------|
| Poll Interval | 5 minutes |
| Lookback Window | 15 minutes |
| GraphQL Node | `dosdNetworkAnalyticsAdaptiveGroups` |
| Filter | `outcome: "drop"` |
| **Prefix Filter** | `185.54.80.0/22`, `2a02:4460::/32` (GOLINE only) |
| Database Table | `network_analytics_events` |
| **GeoIP2** | City + ASN enrichment for source IPs |

### 6.2 GeoIP Enrichment

Source IPs in notifications include:
- Country and city (from GeoIP2-City.mmdb)
- ASN number and organization (from GeoLite2-ASN.mmdb)
- Spoofed IP detection (private/reserved ranges marked with ⚠️)

---

## 7. Auto-Withdraw Daemon

### 7.1 Overview (v3.3)

The autowithdraw daemon is the **ONLY** service that performs BGP withdrawals.

**Critical Fix in v3.3:**
- **Bug**: Was using `/addressing/prefixes` endpoint which returns `advertised: False` for ALL prefixes
- **Fix**: Now uses `/addressing/prefixes/{prefix_id}/bgp/prefixes/{bgp_prefix_id}` with `on_demand.advertised`
- **Result**: Correctly detects advertised prefixes and tracks calm periods

### 7.2 Configuration

| Parameter | Value |
|-----------|-------|
| Check Interval | 60 seconds |
| Calm Period | 15 minutes |
| Min Dropped Packets | 5000 |
| Min Dropped Bits | 10 Mbps |
| Threshold Logic | **AND** (both must be exceeded) |

### 7.3 Commands

```bash
# Check prefix status
python3 scripts/cloudflare-autowithdraw.py status

# Manual withdraw (single prefix)
python3 scripts/cloudflare-autowithdraw.py withdraw 185.54.81.0/24

# Manual withdraw (all advertised)
python3 scripts/cloudflare-autowithdraw.py withdraw

# Emergency advertise
python3 scripts/cloudflare-autowithdraw.py advertise 185.54.81.0/24

# Test GraphQL API connection
python3 scripts/cloudflare-autowithdraw.py test
```

---

## 8. BGP Prefix Management

### 8.1 Managed Prefixes

| Prefix | Description | Status |
|--------|-------------|--------|
| `185.54.80.0/24` | BGP | On-Demand |
| `185.54.81.0/24` | DMZ | On-Demand |
| `185.54.82.0/24` | DMZ-EXT (Test) | On-Demand |
| `185.54.83.0/24` | DMZ-EXT2 | On-Demand |
| `2a02:4460:1::/48` | DMZv6 | On-Demand |

### 8.2 CLI Tool: cloudflare-prefix-manager (v1.4.0)

**New in v1.4.0:** ADVERTISE and WITHDRAW operations are now logged to the database and visible in the dashboard's "DDoS Protection Log" section.

```bash
# View status of all prefixes
cloudflare-prefix-manager status

# Advertise a prefix (logged to DB)
cloudflare-prefix-manager advertise 185.54.82.0/24

# Withdraw a prefix (logged to DB)
cloudflare-prefix-manager withdraw 185.54.82.0/24

# Bulk operations
cloudflare-prefix-manager advertise --all
cloudflare-prefix-manager withdraw --all

# Interactive menu
cloudflare-prefix-manager
```

### 8.3 Dashboard Manual Operations

Operations from the dashboard (Advertise/Withdraw buttons) are also logged with:
- `alert_type`: `dashboard_manual`
- `action_taken`: `advertised_manual` or `withdrawn_manual`

---

## 9. Database System

### 9.1 Overview

SQLite database for persistent storage of all events and operations.

**File**: `/root/Cloudflare_MT_Integration/db/magic_transit.db`

### 9.2 Tables

| Table | Purpose |
|-------|---------|
| `attack_events` | All START/END/ADVERTISE/WITHDRAW events |
| `withdrawal_history` | Completed withdrawal records |
| `webhook_events` | All received webhooks |
| `network_analytics_events` | Network Analytics dropped traffic with GeoIP |
| `prefix_calm_status` | Calm time tracking for dashboard |

### 9.3 Event Sources in attack_events

| alert_type | Source |
|------------|--------|
| `advanced_ddos_attack_l4_alert` | Webhook - L4 DDoS |
| `dos_attack_l4` | Webhook - L4 DDoS |
| `fbm_dosd_attack` | Webhook - MNM DDoS |
| `fbm_auto_advertisement` | Webhook - Auto-advertisement |
| `dashboard_manual` | Dashboard UI |
| `prefix_manager_manual` | CLI tool |
| `autowithdraw_daemon` | Auto-withdraw service |

---

## 10. Telegram Notifications

### 10.1 Configuration

| Parameter | Value |
|-----------|-------|
| Bot Token | See `config/settings.json` |
| Chat ID | See `config/settings.json` |
| Parse Mode | Markdown |

### 10.2 Unified Header

All notifications use a consistent header:

```
🛡️ *CLOUDFLARE DDoS PROTECTION*
```

### 10.3 Notification Types

- 🚨 **DDoS Attack Started** - Attack details with vector, target, metrics
- ✅ **Attack Mitigated** - Attack ended notification
- 📤 **BGP Withdraw** - Prefix withdrawn (auto or manual)
- 🔴 **Service Down** - Watchdog alert for failed services
- 🟢 **Service Restarted** - Watchdog recovery notification

---

## 11. Cloudflare API Integration

### 11.1 Authentication Methods

| Method | Header | Used By |
|--------|--------|---------|
| **API Token** | `Authorization: Bearer <token>` | Most scripts |
| **Global API Key** | `X-Auth-Email` + `X-Auth-Key` | `cloudflare-rules-manager.py` |

### 11.2 Key Endpoints

| Endpoint | Description |
|----------|-------------|
| `/accounts/{id}/addressing/prefixes` | List IP prefixes |
| `/accounts/{id}/addressing/prefixes/{prefix_id}/bgp/prefixes/{bgp_id}` | BGP prefix status (correct endpoint) |
| `/accounts/{id}/mnm/rules` | MNM rules management |
| `/accounts/{id}/rulesets` | DDoS L3/4 rules |
| `/graphql` | Network Analytics queries |

### 11.3 BGP Prefix API (Correct Usage)

**Get Prefix Status:**
```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/{account_id}/addressing/prefixes/{prefix_id}/bgp/prefixes/{bgp_prefix_id}" \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

Response includes:
```json
{
  "result": {
    "on_demand": {
      "advertised": true,
      "advertised_modified_at": "2026-01-21T10:00:00Z"
    }
  }
}
```

**Update Advertisement:**
```bash
curl -X PATCH "https://api.cloudflare.com/client/v4/accounts/{account_id}/addressing/prefixes/{prefix_id}/bgp/prefixes/{bgp_prefix_id}" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"on_demand": {"advertised": false}}'
```

---

## 12. Configuration Files

### 12.1 settings.json

**Location**: `/root/Cloudflare_MT_Integration/config/settings.json`

```json
{
  "cloudflare": {
    "account_id": "YOUR_ACCOUNT_ID",
    "api_token": "YOUR_API_TOKEN",
    "webhook_secret": "YOUR_WEBHOOK_SECRET"
  },
  "telegram": {
    "bot_token": "YOUR_BOT_TOKEN",
    "chat_id": "YOUR_CHAT_ID"
  },
  "polling": {
    "interval_seconds": 180,
    "ddos_threshold_pps": 12000
  }
}
```

### 12.2 prefix_mapping.json

**Location**: `/root/Cloudflare_MT_Integration/config/prefix_mapping.json`

Contains mapping of CIDR to Cloudflare prefix_id and bgp_prefix_id.

### 12.3 auth.json

**Location**: `/root/Cloudflare_MT_Integration/config/auth.json`

Contains bcrypt-hashed password for dashboard authentication.

---

## 13. Operations Guide

### 13.1 Daily Operations

```bash
# Check all services
systemctl status cloudflare-webhook cloudflare-analytics-monitor cloudflare-autowithdraw cloudflare-dashboard

# Check prefix status with calm times
cloudflare-prefix-manager status

# View dashboard
open https://cloudflare.goline.ch
```

### 13.2 Responding to Attacks

**Automatic Flow (No intervention needed):**
1. Attack detected → Cloudflare auto-advertises prefix
2. Webhook START → System logs and notifies
3. Attack ends → Webhook END → System logs
4. Autowithdraw monitors → 15 min calm → Auto-withdraw

**Manual Intervention (If needed):**
```bash
# Force immediate withdrawal
cloudflare-prefix-manager withdraw 185.54.82.0/24 --force

# Or use dashboard buttons
```

### 13.3 Service Management

```bash
# Restart all services
systemctl restart cloudflare-webhook cloudflare-analytics-monitor cloudflare-autowithdraw cloudflare-dashboard

# View logs
journalctl -u cloudflare-webhook -f
journalctl -u cloudflare-autowithdraw -f
journalctl -u cloudflare-dashboard -f
```

---

## 14. Monitoring and Logging

### 14.1 Log Files

| Log File | Purpose |
|----------|---------|
| `logs/webhook.log` | Webhook receiver logs |
| `logs/network-analytics-monitor.log` | Analytics monitor logs |
| `logs/autowithdraw.log` | Auto-withdraw daemon logs |
| `logs/watchdog.log` | Services watchdog logs |
| `logs/webhooks/*.json` | Raw webhook payloads |

### 14.2 Health Checks

```bash
# Service health
curl -s https://lg.goline.ch/mt-health | jq

# Dashboard health
curl -s https://cloudflare.goline.ch/health | jq

# Database stats
sqlite3 db/magic_transit.db "SELECT COUNT(*) FROM attack_events"
```

### 14.3 Services Watchdog

**Script**: `cloudflare-services-watchdog.sh`
**Cron**: Every 5 minutes

Services monitored:
- `cloudflare-webhook`
- `cloudflare-analytics-monitor`
- `cloudflare-autowithdraw`
- `cloudflare-dashboard`

On failure: Auto-restart + Telegram notification

---

## 15. Troubleshooting

### 15.1 Autowithdraw Not Detecting Prefixes

**Symptom**: "No prefixes currently advertised" when prefix is actually advertised

**Cause**: Using wrong API endpoint (`/addressing/prefixes` instead of BGP endpoint)

**Fix**: Updated in v3.3 to use correct endpoint with `on_demand.advertised`

### 15.2 Manual Operations Not in Dashboard

**Symptom**: CLI advertise/withdraw not visible in "DDoS Protection Log"

**Cause**: Prefix manager not logging to database

**Fix**: Updated in v1.4.0 with `log_event_to_db()` function

### 15.3 Common Checks

```bash
# Check webhook receiving
tail -f logs/webhook.log

# Check autowithdraw activity
journalctl -u cloudflare-autowithdraw -f

# Check database events
sqlite3 db/magic_transit.db "SELECT * FROM attack_events ORDER BY id DESC LIMIT 10;"
```

---

## 16. Security Considerations

### 16.1 Access Control

| Resource | Access Level |
|----------|--------------|
| Project directory | root only |
| Configuration files | root only (contains API tokens) |
| Database file | root only |
| Dashboard | IP whitelist + authentication |
| Webhook endpoint | Public (HTTPS required) |

### 16.2 Credential Security

- API tokens stored in `config/settings.json`
- Dashboard passwords hashed with bcrypt in `config/auth.json`
- GitHub repository uses sanitized templates (`.example` files)

---

## 17. Appendix

### 17.1 Version History

| Version | Date | Changes |
|---------|------|---------|
| **2.9.12** | 2026-01-21 | Prefix Manager v1.4.0 - DB logging for manual operations |
| **2.9.11** | 2026-01-21 | Autowithdraw v3.3 - Critical fix for API endpoint |
| **2.9.10** | 2026-01-21 | Dashboard - Fixed event ordering |
| **2.9.9** | 2026-01-21 | Webhook v1.8.0 - Auto-advertisement logging |
| **2.9.8** | 2026-01-21 | Dashboard - User-friendly event labels |
| **2.9.7** | 2026-01-21 | Dashboard - Modal cleanup, db_manager fix |
| **2.9.6** | 2026-01-21 | Webhook v1.7.0 - MNM alerts to database |
| 2.9.0-2.9.5 | 2026-01-21 | Dashboard - Connectors, styling, modals |
| 2.4.0-2.8.x | 2026-01-21 | Dashboard features, auth, rules management |
| 2.3.0 | 2026-01-20 | IPv6 support |
| 2.2.0 | 2026-01-19 | GeoIP2 integration |
| 2.1.0 | 2026-01-19 | Unified Withdraw Architecture |
| 2.0.0 | 2026-01-19 | Services Watchdog with HA |
| 1.0.0 | 2026-01-18 | Initial implementation |

### 17.2 References

- [Cloudflare Magic Transit Documentation](https://developers.cloudflare.com/magic-transit/)
- [Cloudflare API Documentation](https://developers.cloudflare.com/api/)
- [Cloudflare Webhook Notifications](https://developers.cloudflare.com/notifications/)
- [BGP Prefix Advertisement](https://developers.cloudflare.com/magic-transit/on-demand/)

### 17.3 Glossary

| Term | Definition |
|------|------------|
| BGP | Border Gateway Protocol - routing protocol for the internet |
| Magic Transit | Cloudflare's DDoS protection service for network layer |
| On-Demand | Magic Transit mode where prefixes are only advertised during attacks |
| Prefix | IP address block (e.g., 185.54.82.0/24) |
| Advertisement | Announcing a BGP prefix to the internet |
| Withdrawal | Removing a BGP prefix announcement |
| 15-Minute Constraint | Cloudflare requirement for minimum advertisement duration |
| Calm Period | 15 minutes without attack traffic before auto-withdraw |

### 17.4 Support Contacts

| Type | Contact |
|------|---------|
| GOLINE SOC | YOUR_EMAIL |
| Cloudflare Support | Enterprise Support Portal |

---

**Document Control**

| Field | Value |
|-------|-------|
| Document ID | GOLINE-MT-001 |
| Version | 2.10.4 |
| Classification | Internal |
| Owner | SOC Team |
| Last Review | 2026-02-06 |
| Next Review | 2026-04-21 |

---

*GOLINE SA - Cloudflare Magic Transit Integration*
