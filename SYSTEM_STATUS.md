# Cloudflare Magic Transit Integration - System Status

**Version**: 2.10.4
**Last Updated**: 2026-02-06
**Status**: **PRODUCTION - FULLY OPERATIONAL**

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    UNIFIED ARCHITECTURE v2.3.3                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  NOTIFICATIONS ONLY                                                      │
│  ══════════════════                                                      │
│  cloudflare-webhook.service      cloudflare-analytics-monitor.service    │
│  • 11 alert types                • GraphQL polling (5 min)               │
│  • Telegram notifications        • GeoIP2 enrichment                     │
│  • Database logging              • Telegram notifications                │
│  • NO withdraw operations        • NO withdraw operations                │
│                                                                          │
│  WITHDRAW OPERATIONS (Single Source of Truth)                            │
│  ════════════════════════════════════════════                            │
│  cloudflare-autowithdraw.service                                         │
│  • Monitors GraphQL for dropped traffic (every 60s)                      │
│  • Tracks "calm since" for each advertised prefix                        │
│  • 15 minutes calm → AUTO WITHDRAW                                       │
│  • Threshold: packets > 5000 AND bits > 10 Mbps                          │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Service Status

| Service | Status | Script | Purpose |
|---------|--------|--------|---------|
| `cloudflare-webhook` | ✅ Active | `cloudflare-webhook-receiver.py` | Webhook receiver |
| `cloudflare-analytics-monitor` | ✅ Active | `cloudflare-network-analytics-monitor.py` | GraphQL poller + GeoIP |
| `cloudflare-autowithdraw` | ✅ Active | `cloudflare-autowithdraw.py` | BGP withdraw manager |
| Watchdog (cron) | ✅ Active | `cloudflare-services-watchdog.sh` | HA auto-restart |

### Quick Status Check

```bash
# Service status
systemctl status cloudflare-webhook cloudflare-analytics-monitor cloudflare-autowithdraw

# Health check
curl -s https://your-server.example.com/mt-health | jq

# Prefix status
cloudflare-prefix-manager status
```

---

## BGP Prefixes

| Prefix | Description | Status | MNM Rules |
|--------|-------------|--------|-----------|
| `198.51.100.0/24` | BGP | On-Demand | BPS + PPS + sFlow |
| `192.0.2.0/24` | DMZ | On-Demand | BPS + PPS + sFlow |
| `203.0.113.0/24` | DMZ-EXT (Test) | On-Demand | BPS + PPS + sFlow |
| `203.0.113.128/25` | DMZ-EXT2 | On-Demand | BPS + PPS + sFlow |
| `2001:db8:1::/48` | DMZv6 | On-Demand | BPS + PPS + sFlow |

### MNM Rules Configuration

| Rule Type | Threshold | Duration | Action |
|-----------|-----------|----------|--------|
| BPS (Bandwidth) | 4 Gbps | 1 min | Auto-advertise |
| PPS (Packets) | 500k pps | 1 min | Auto-advertise |
| Advanced DDoS (sFlow) | Fingerprint | - | Auto-advertise |

**Total MNM Rules**: 12 (was 10 before IPv6 + sFlow)

---

## Database Statistics

| Table | Records | Description |
|-------|---------|-------------|
| `attack_events` | 14 | START/END/WITHDRAW events |
| `webhook_events` | 57 | All received webhooks |
| `network_analytics_events` | 402 | Dropped traffic (GraphQL) |
| `withdrawal_history` | 4 | Completed withdrawals |

---

## API Status

| API | Status | Usage |
|-----|--------|-------|
| REST Prefix Management | ✅ 100% | Advertise/Withdraw |
| GraphQL `dosdNetworkAnalyticsAdaptiveGroups` | ✅ 100% | Traffic monitoring |
| MNM Rules API | ✅ 100% | Rule management |
| DDoS Managed Ruleset API | ✅ 100% | Sensitivity control |
| Telegram API | ✅ 100% | Notifications |

---

## Alert Types Supported (11)

| Category | Alert Type | Priority |
|----------|------------|----------|
| DDoS Protection | `advanced_ddos_attack_l4_alert` | HIGH |
| DDoS Protection | `dos_attack_l4` | HIGH |
| DDoS Protection | `dos_attack_l7` | HIGH |
| Magic Network Monitoring | `fbm_dosd_attack` | HIGH |
| Magic Network Monitoring | `fbm_volumetric_attack` | MEDIUM |
| Magic Transit | `fbm_auto_advertisement` | INFO |
| Magic Transit | `magic_tunnel_health_check_event` | HIGH |
| Route Leak Detection | `bgp_hijack_notification` | **CRITICAL** |
| Platform Status | `incident_alert` | VARIES |
| Health Checks | `health_check_status_notification` | MEDIUM |

---

## Management Tools

### Prefix Manager CLI

```bash
cloudflare-prefix-manager status           # Show all prefixes
cloudflare-prefix-manager advertise <cidr> # Advertise prefix
cloudflare-prefix-manager withdraw <cidr>  # Withdraw prefix
cloudflare-prefix-manager advertise --all  # Advertise all
cloudflare-prefix-manager withdraw --all   # Withdraw all
```

### Rules Manager (Interactive)

```bash
python3 scripts/cloudflare-rules-manager.py
```

**Features (v1.4)**:
- List/Add/Delete MNM rules (BPS, PPS, Dynamic, sFlow)
- DDoS Sensitivity Management (L3/4 Managed Ruleset)
- 124 rules (29 customizable, 95 read-only)
- Export configuration backup

---

## External Integrations

| System | Status | Purpose |
|--------|--------|---------|
| Apache2 | ✅ | HTTPS reverse proxy |
| GeoIP2 | ✅ | IP geolocation |
| Telegram | ✅ | SOC notifications |
| SQLite | ✅ | Event database |

---

## Endpoints

| Endpoint | URL | Status |
|----------|-----|--------|
| Webhook | `https://your-server.example.com/webhook/cloudflare` | ✅ |
| Health Check | `https://your-server.example.com/mt-health` | ✅ |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| **2.3.3** | 2026-01-20 | Rules Manager v1.4: DDoS Sensitivity Management |
| 2.3.2 | 2026-01-20 | Rules Manager v1.3: sFlow support |
| 2.3.1 | 2026-01-20 | 15-min re-advertise constraint |
| 2.3.0 | 2026-01-20 | IPv6 prefix support |
| 2.2.1 | 2026-01-20 | Autowithdraw v3.1: threshold fix |
| 2.2.0 | 2026-01-19 | GeoIP2 integration |
| 2.1.0 | 2026-01-19 | Unified withdraw architecture |
| 2.0.0 | 2026-01-19 | Services watchdog, HA |

---

## Checklist

- [x] All 3 services running and monitored
- [x] Watchdog cron active (*/5 min)
- [x] 11 alert types supported
- [x] GeoIP2 enrichment operational
- [x] 12 MNM rules configured
- [x] DDoS sensitivity control available
- [x] Database logging active
- [x] Telegram notifications tested
- [x] GitHub repository synchronized

---

**SYSTEM IS FULLY OPERATIONAL**

*GOLINE SOC - Cloudflare Magic Transit Integration*
