# Cloudflare Magic Transit Integration - Directory Structure

**Last Updated**: 2026-02-06
**Version**: 2.10.4

---

## Overview

This document provides a complete reference of the project directory structure, including all files, scripts, configurations, and external system integrations.

---

## Root Directory Layout

```
/root/Cloudflare_MT_Integration/          # 5.3 MB total
│
├── README.md                              # Project overview (internal)
├── CLAUDE.md                              # Claude Code project context (31 KB)
├── requirements.txt                       # Python dependencies
│
├── config/                    [12 KB]     # Configuration files (CREDENTIALS)
├── db/                        [588 KB]    # SQLite database
├── scripts/                   [692 KB]    # Application scripts (24 files)
├── logs/                      [352 KB]    # Log files and raw webhooks
├── docs/                      [376 KB]    # Documentation (current + archive)
├── backup/                    [1.5 MB]    # All backups (14 files)
└── github/                    [1.7 MB]    # GitHub repository (sanitized)
```

---

## Detailed Structure

### `/config/` - Configuration Files

| File | Size | Description |
|------|------|-------------|
| `settings.json` | 538 B | API credentials (Cloudflare, Telegram) |
| `prefix_mapping.json` | 1 KB | BGP prefix to Cloudflare ID mappings |

**SECURITY**: These files contain real credentials and are NOT in GitHub.

```json
// settings.json structure
{
  "cloudflare": {
    "api_token": "...",
    "account_id": "YOUR_ACCOUNT_ID",
    "email": "YOUR_EMAIL"
  },
  "telegram": {
    "bot_token": "YOUR_TELEGRAM_BOT_TOKEN",
    "chat_id": "YOUR_TELEGRAM_CHAT_ID"
  },
  "webhook": {
    "secret": "YOUR_WEBHOOK_SECRET",
    "port": 8080
  }
}
```

```json
// prefix_mapping.json structure
{
  "198.51.100.0/24": { "id": "...", "description": "BGP" },
  "192.0.2.0/24": { "id": "...", "description": "DMZ" },
  "203.0.113.0/24": { "id": "...", "description": "DMZ-EXT (Test)" },
  "203.0.113.128/25": { "id": "...", "description": "DMZ-EXT2" },
  "2001:db8:1::/48": { "id": "...", "description": "DMZv6" }
}
```

---

### `/db/` - Database

| File | Size | Description |
|------|------|-------------|
| `magic_transit.db` | 594 KB | SQLite database |

**Tables**:

| Table | Records | Description |
|-------|---------|-------------|
| `attack_events` | 14 | START/END/WITHDRAW events |
| `webhook_events` | 57 | All received webhooks |
| `network_analytics_events` | 402 | Dropped traffic events (GraphQL) |
| `withdrawal_history` | 4 | Completed withdrawals |
| `pending_withdrawals` | 0 | **DEPRECATED** (v2.1.0) |

---

### `/scripts/` - Application Scripts

#### Core Services (Active)

| Script | Size | Version | Description |
|--------|------|---------|-------------|
| `cloudflare-webhook-receiver.py` | 33 KB | v1.6.0 | Webhook receiver (notifications only) |
| `cloudflare-network-analytics-monitor.py` | 28 KB | v1.3.1 | GraphQL poller + GeoIP2 enrichment |
| `cloudflare-autowithdraw.py` | 33 KB | v3.1 | **ONLY** BGP withdraw source |
| `cloudflare-prefix-manager.py` | 29 KB | v1.3.0 | CLI prefix management tool |
| `cloudflare-rules-manager.py` | 37 KB | v1.4 | Interactive MNM rules + DDoS sensitivity |
| `cloudflare-services-watchdog.sh` | 4 KB | v1.1 | HA watchdog (auto-restart) |
| `db_manager.py` | 23 KB | v1.2.0 | Database operations module |

#### Utility Scripts

| Script | Size | Description |
|--------|------|-------------|
| `cloudflare-check-pending-withdrawals.py` | 17 KB | Scheduled withdrawals (DEPRECATED) |
| `import_webhooks.py` | 5 KB | Import JSON webhooks to database |
| `check_withdraw_time.py` | 6 KB | Check 15-minute constraint |
| `create_sflow_ddos_rules.sh` | 2 KB | Create sFlow DDoS rules |
| `test.sh` | 3 KB | Quick test script |

#### Test Scripts

| Script | Size | Description |
|--------|------|-------------|
| `test_connection.py` | 8 KB | API connectivity test |
| `test_graphql.py` | 7 KB | GraphQL API test |
| `test_system.py` | 11 KB | Full system test |

#### Legacy Scripts (Deprecated)

| Script | Size | Status |
|--------|------|--------|
| `monitor.py` | 20 KB | Replaced by autowithdraw |
| `manual_control.py` | 12 KB | Replaced by prefix-manager |
| `attack_detector_v3.py` | 21 KB | Legacy |
| `check_attacks.py` | 18 KB | Legacy |
| `check_attacks_v2.py` | 15 KB | Legacy |
| `check_attacks_rest.py` | 9 KB | Legacy |

---

### `/logs/` - Log Files

| File | Size | Description |
|------|------|-------------|
| `webhook.log` | 49 KB | Webhook receiver logs |
| `network-analytics-monitor.log` | 14 KB | Analytics monitor logs |
| `watchdog.log` | 181 B | Watchdog logs |
| `withdrawal_checker.log` | 20 KB | Withdrawal checker (deprecated) |
| `withdrawal_cron.log` | 20 KB | Cron output (deprecated) |

#### `/logs/webhooks/` - Raw Webhook Payloads

- **Files**: 57 JSON files
- **Total lines**: ~1,500
- **Format**: `webhook_YYYYMMDD_HHMMSS.json`
- **Purpose**: Debug and replay capability

---

### `/docs/` - Documentation

#### Current Documentation

| File | Size | Description |
|------|------|-------------|
| `AUTOWITHDRAW.md` | 14 KB | Auto-withdraw daemon (v3.1) |
| `Cloudflare_Magic_Transit.md` | 75 KB | **MAIN** Complete technical reference |
| `DATABASE.md` | 30 KB | Database schema and operations |
| `DB_MANAGER.md` | 16 KB | Database module documentation |
| `NETWORK_ANALYTICS_MONITOR.md` | 11 KB | GraphQL poller (v1.3.1 GeoIP) |
| `PREFIX_MANAGER.md` | 16 KB | CLI prefix manager (v1.3.0) |
| `RULES_MANAGER.md` | 37 KB | MNM rules manager (v1.4) |
| `SERVICES_WATCHDOG.md` | 10 KB | HA watchdog script |
| `WEBHOOK_RECEIVER.md` | 28 KB | Webhook receiver (v1.6.0) |

#### `/docs/archive/` - Legacy Documentation

| File | Size | Description |
|------|------|-------------|
| `API_EXAMPLES.md` | 12 KB | Cloudflare API examples |
| `API_STATUS.md` | 5 KB | API status reference |
| `CREDENTIALS_AND_CONFIG.md` | 4 KB | Old credentials docs |
| `DIRECTORY_STRUCTURE.md` | 7 KB | Old structure docs |
| `GOLINE_Cloudflare_Magic_Transit_Documentazione_Completa.md` | 28 KB | Italian docs |
| `HOW_TO_USE_MONITOR_SCRIPT.md` | 17 KB | Monitor script guide |
| `OPERATIONAL_NOTES.md` | 13 KB | Operational notes |
| `PROJECT_PLAN.md` | 4 KB | Original project plan |
| `REQUIREMENTS.md` | 11 KB | Old requirements |
| `SYSTEM_STATUS.md` | 4 KB | Old status docs |

---

### `/backup/` - Backups

| File | Size | Date | Description |
|------|------|------|-------------|
| `20260119_221244/` | dir | 2026-01-19 | Script backup directory |
| `Cloudflare_MT_Integration_20260119_004012.tar.gz` | 67 KB | 2026-01-19 | Early backup |
| `Cloudflare_MT_Integration_20260119_005648.tar.gz` | 86 KB | 2026-01-19 | |
| `Cloudflare_MT_Integration_20260119_010500.tar.gz` | 100 KB | 2026-01-19 | |
| `Cloudflare_MT_Integration_20260119_010733.tar.gz` | 101 KB | 2026-01-19 | |
| `Cloudflare_MT_Integration_20260119_011533.tar.gz` | 116 KB | 2026-01-19 | |
| `full_backup_20260119_032546.tar.gz` | 145 KB | 2026-01-19 | Full backup |
| `magic_transit_20260119_032553.db` | 147 KB | 2026-01-19 | Database backup |
| `mt_integration_FINAL_v1.9.0_20260119_013713.tar.gz` | 102 KB | 2026-01-19 | v1.9.0 |
| `mt_integration_FINAL_v1.9.1_20260119_014506.tar.gz` | 103 KB | 2026-01-19 | v1.9.1 |
| `mt_integration_v1.8.0_20260119_012134.tar.gz` | 110 KB | 2026-01-19 | v1.8.0 |
| `mt_integration_v1.8.0_20260119_012157.tar.gz` | 95 KB | 2026-01-19 | v1.8.0 |
| `mt_integration_v1.9.0_20260119_013114.tar.gz` | 98 KB | 2026-01-19 | v1.9.0 |
| `mt_integration_v2.0.0_20260119_025652.tar.gz` | 138 KB | 2026-01-19 | v2.0.0 |

---

### `/github/` - GitHub Repository (Sanitized)

**Repository**: https://github.com/paolokappa/Cloudflare_Magic_Transit_API_Automations_Monitoring

```
github/                                    [1.7 MB]
├── .git/                                  # Git repository data
├── .gitignore                             # Exclusion rules
│
├── README.md                   [14 KB]    # Professional README (logo, badges, Mermaid)
├── DIRECTORY_STRUCTURE.md      [7 KB]     # This file (sanitized)
├── REQUIREMENTS.md             [11 KB]    # System requirements
├── SYSTEM_STATUS.md            [4 KB]     # Current status
├── requirements.txt            [226 B]    # Python dependencies
│
├── config/                                # Configuration TEMPLATES
│   ├── settings.json.example   [344 B]    # Credential template
│   └── prefix_mapping.json.example [464 B] # Prefix mapping template
│
├── scripts/                               # Sanitized scripts (no credentials)
│   ├── cloudflare-webhook-receiver.py          [33 KB]
│   ├── cloudflare-network-analytics-monitor.py [28 KB]
│   ├── cloudflare-autowithdraw.py              [31 KB]
│   ├── cloudflare-prefix-manager.py            [27 KB]
│   ├── cloudflare-rules-manager.py             [36 KB]
│   ├── cloudflare-check-pending-withdrawals.py [17 KB]
│   ├── cloudflare-services-watchdog.sh         [4 KB]
│   └── db_manager.py                           [23 KB]
│
├── systemd/                               # Systemd service files
│   ├── cloudflare-webhook.service         [792 B]
│   ├── cloudflare-analytics-monitor.service [846 B]
│   └── cloudflare-autowithdraw.service    [701 B]
│
├── cron/                                  # Cron job definitions
│   └── cloudflare-services-watchdog       [349 B]
│
├── docs/                                  # Documentation (public)
│   ├── AUTOWITHDRAW.md
│   ├── Cloudflare_Magic_Transit.md
│   ├── DATABASE.md
│   ├── DB_MANAGER.md
│   ├── NETWORK_ANALYTICS_MONITOR.md
│   ├── PREFIX_MANAGER.md
│   ├── RULES_MANAGER.md
│   ├── SERVICES_WATCHDOG.md
│   └── WEBHOOK_RECEIVER.md
│
├── db/                                    # Empty (placeholder)
│   └── .gitkeep
│
└── logs/                                  # Empty (placeholder)
    └── .gitkeep
```

#### Credential Sanitization

| Production Value | GitHub Placeholder |
|------------------|-------------------|
| `YOUR_ACCOUNT_ID` | `YOUR_ACCOUNT_ID` |
| `YOUR_EMAIL` | `YOUR_AUTH_EMAIL` |
| API Key | `YOUR_GLOBAL_API_KEY` |
| Telegram Bot Token | `YOUR_TELEGRAM_BOT_TOKEN` |
| Telegram Chat ID | `YOUR_TELEGRAM_CHAT_ID` |
| Ruleset ID | `YOUR_ROOT_RULESET_ID` |

---

## External System Files

### Systemd Services

```
/etc/systemd/system/
├── cloudflare-webhook.service           # Webhook receiver
├── cloudflare-analytics-monitor.service # Network Analytics monitor
└── cloudflare-autowithdraw.service      # Auto-withdraw daemon
```

| Service | Script | Auto-Restart | Binding |
|---------|--------|--------------|---------|
| `cloudflare-webhook` | `cloudflare-webhook-receiver.py` | Yes (5s) | 127.0.0.1:8080 |
| `cloudflare-analytics-monitor` | `cloudflare-network-analytics-monitor.py` | Yes (30s) | - |
| `cloudflare-autowithdraw` | `cloudflare-autowithdraw.py` | Yes (10s) | - |

### Cron Jobs

```
/etc/cron.d/
└── cloudflare-services-watchdog         # */5 * * * * (HA watchdog)
```

**Note**: `cloudflare-mt-withdrawals` was DISABLED in v2.1.0. Withdrawals are now handled by `cloudflare-autowithdraw.service`.

### Symlinks

```
/usr/local/bin/
├── cloudflare-prefix-manager -> /root/Cloudflare_MT_Integration/scripts/cloudflare-prefix-manager.py
└── cloudflare-rules-manager  -> /root/Cloudflare_MT_Integration/scripts/cloudflare-rules-manager.py
```

### Apache Configuration

```
/etc/apache2/sites-available/
└── your-server.example.com-le-ssl.conf             # HTTPS reverse proxy to :8080
```

Proxy configuration:
```apache
ProxyPass /webhook/cloudflare http://127.0.0.1:8080/webhook/cloudflare
ProxyPassReverse /webhook/cloudflare http://127.0.0.1:8080/webhook/cloudflare
ProxyPass /mt-health http://127.0.0.1:8080/mt-health
ProxyPassReverse /mt-health http://127.0.0.1:8080/mt-health
```

### GeoIP2 Databases

```
/usr/share/GeoIP/
├── GeoIP2-City.mmdb                     # 122 MB (Commercial)
└── GeoLite2-ASN.mmdb                    # 11 MB (Free)
```

---

## Script Dependencies

```
cloudflare-webhook-receiver.py
├── db_manager.py
├── Flask
├── requests
└── config/settings.json

cloudflare-network-analytics-monitor.py
├── db_manager.py
├── requests
├── geoip2 (optional)
└── config/settings.json

cloudflare-autowithdraw.py
├── db_manager.py
├── requests
└── config/settings.json, prefix_mapping.json

cloudflare-prefix-manager.py
├── requests
└── config/settings.json, prefix_mapping.json

cloudflare-rules-manager.py
├── requests (Global API Key auth)
└── Hardcoded credentials (sanitized in GitHub)

cloudflare-services-watchdog.sh
├── systemctl
└── curl (Telegram API)
```

---

## Quick Reference Commands

```bash
# Directory sizes
du -sh /root/Cloudflare_MT_Integration/*

# Script versions
grep -h "Version\|__version__" scripts/cloudflare-*.py

# Database stats
sqlite3 db/magic_transit.db "SELECT COUNT(*) FROM attack_events;"

# Service status
systemctl status cloudflare-webhook cloudflare-analytics-monitor cloudflare-autowithdraw

# Full backup
tar -czvf backup/full_backup_$(date +%Y%m%d_%H%M%S).tar.gz \
  --exclude='backup' --exclude='github/.git' --exclude='__pycache__' .
```

---

*Generated: 2026-01-20 - GOLINE SOC - Cloudflare Magic Transit Integration v2.3.3*
