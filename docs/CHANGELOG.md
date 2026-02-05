# Changelog

All notable changes to the Cloudflare Magic Transit Integration project.

**Current Version**: 2.10.2
**Last Updated**: 2026-02-05

---

## [2.10.2] - 2026-02-05

### Web Dashboard v2.10.2 - Connector Health Indicator
- **BUG FIX**: `/api/connectors/health-summary` always returned 500 error
  - **CAUSE 1**: Used undefined variable `CF_API_BASE` (should be `API_BASE`)
  - **CAUSE 2**: Parsed API response as `result[]` instead of `result.gre_tunnels[]` / `result.ipsec_tunnels[]`
  - **CAUSE 3**: CNI interconnects were not included in health summary count
  - **FIX**: Rewrote endpoint using same API call pattern as working `/api/connectors/tunnels`
  - **FIX**: CNI health detected via remaining entries in GraphQL `health_stats` not matching any tunnel name
- **NEW**: "Status" pill indicator in dashboard header (next to Connectors button)
  - Styled identically to "Live" indicator (pill shape, same font/padding)
  - Green dot: all connectors healthy
  - Yellow dot (`#ffd000`): one or more connectors degraded
  - Red dot: one or more connectors down
  - Gray dot: status unknown
  - Static dot (no blinking animation)
- **CHANGED**: Connectors button restored to plain button style (no embedded dot)
- **FIX**: Connectors page (`/connectors`) health stats now include CNI interconnects
  - **BEFORE**: Healthy/Degraded/Down counters only counted GRE + IPsec tunnels
  - **AFTER**: `loadTunnels()` and `loadInterconnects()` return health counts, combined in `refreshAll()`
- **CHANGED**: Degraded color unified to `#ffd000` (bright yellow) across dashboard and connectors page
  - Dashboard header Status indicator
  - Connectors page `--accent-yellow` CSS variable
  - Connectors page `.status-degraded` badge background

## [2.10.1] - 2026-02-02

### Web Dashboard v2.10.1
- **BUG FIX**: IPv6 attacks not appearing in Network Analytics when "GOLINE only" toggle active
  - **CAUSE 1**: SQL `ORDER BY id DESC` sorted by string alias instead of integer id
  - **CAUSE 2**: Combined sorting used incompatible timestamp formats (T vs space separator)
  - **FIX 1**: Changed to `ORDER BY table_name.id DESC` for proper integer sorting
  - **FIX 2**: Added `normalize_datetime()` function for consistent timestamp comparison
- **NEW**: Exact timestamps in Network Analytics and Recent Attacks tables
  - Format: `HH:MM (Xh ago)` within 24h, `DD/MM HH:MM` for older events
- **NEW**: MNM webhook events show meaningful placeholders
  - Source IP: "N/A (MNM)" instead of empty "-"
  - Country: "🌐" globe emoji
  - Note: Cloudflare MNM webhooks don't include attacker source IP (API limitation)
- **FIX**: Event detail modal not opening on double-click
  - Cause: Composite string IDs ("webhook_117", "graphql_1219") passed unquoted
  - New API endpoint: `/api/analytics/detail/<event_id>` handles both formats
- **NEW**: "My prefixes only" toggle now controls Telegram notifications
  - Toggle saves preference to `config/dashboard_prefs.json`
  - Network Analytics Monitor (v1.4.0) reads this preference
  - ON: Only notify for traffic to your prefixes
  - OFF: Notify for all traffic including Cloudflare anycast
- **CHANGED**: Toggle label renamed from "GOLINE only" to "My prefixes only"

### Network Analytics Monitor v1.4.0
- **NEW**: Dashboard Preference Sync - reads "My prefixes only" toggle
- **NEW**: Separate MY_PREFIXES and ALL_PREFIXES lists
- **NEW**: `is_notifiable_ip()` checks against current preference
- **Preference read on each poll** - no service restart needed

---

## [2.10.0] - 2026-02-02

### Web Dashboard v2.10.0
- **NEW**: Auto-collapse when all prefixes are withdrawn
  - Shows summary view with total events, 24h events, GOLINE direct count
  - "Show Historical Events" button to expand full table
- **NEW**: "GOLINE only" toggle switch in Network Analytics card header
  - ON: Shows only traffic to GOLINE IPs
  - OFF: Shows all traffic including Cloudflare anycast
  - Toggle state persisted in localStorage
- **NEW API endpoints**:
  - `GET /api/analytics-summary` - Summary stats for collapsed view
  - `GET /api/dashboard-prefs` - Load dashboard preferences
  - `POST /api/dashboard-prefs` - Save dashboard preferences
- **CHANGED**: `/api/analytics?filter=when_protected` now filters by GOLINE destination IP
- **Config file**: `config/dashboard_prefs.json` for server-side preferences

---

## [2.9.22] - 2026-02-02

### Web Dashboard v2.9.22
- **BUG FIX**: "Error: 1 (of 70) futures unfinished" in Network Analytics section
- **CAUSE**: `as_completed(futures, timeout=5)` raises TimeoutError when DNS lookups don't complete
- **FIX**: Wrapped `as_completed()` loops in try/except TimeoutError to continue with partial results
- **Affected**: `/api/analytics` and `/api/network-flow` endpoints
- **Result**: Dashboard shows data even when some hostname resolutions timeout

### Network Analytics Monitor v1.3.10
- **NEW**: Added Cloudflare anycast prefixes to destination filter
- **Prefixes Added**: `162.159.0.0/16`, `172.64.0.0/13`, `104.16.0.0/13`
- **BEFORE**: Only showed traffic destined to direct GOLINE IPs (185.54.80.0/22)
- **AFTER**: Also shows traffic to Cloudflare anycast IPs (Magic Transit pass-through)
- **Result**: Dashboard displays all DDoS mitigation events including those targeting Cloudflare anycast

---

## [2.9.21] - 2026-01-23

### Web Dashboard v2.9.21
- **CHANGED**: Constraint message now clearer with Cloudflare attribution
  - Before: `Can advertise in X min`
  - After: `Can advertise in X.X min (Cloudflare API cooldown)`
- **CHANGED**: Ready message simplified
  - Before: `Can advertise now`
  - After: `Ready to advertise`
- **FIX**: Backend now returns `advertised` and `advertised_modified_at` in operation response
- **FIX**: Frontend adds 500ms delay before refresh to allow API state propagation

---

## [2.9.20] - 2026-01-23

### Web Dashboard v2.9.20
- **BUG FIX**: CNI pass rate showed 50% instead of correct ~74%
- **CAUSE**: Code used `avg(tunnelState)` which is always 0.5 for CNI
- **FIX**: Now calculates pass rate as `count(resultStatus=ok) / total_count * 100`
- **GraphQL**: Added `resultStatus` dimension to query, increased limit to 10000
- **Function**: `fetch_tunnel_health_stats()` completely rewritten

---

## [2.9.19] - 2026-01-23

### Web Dashboard v2.9.19
- **NEW**: Added "Hostname" column to Network Analytics table
- **NEW**: Hostname in detail modal (Source section) on double-click
- Reverse DNS lookup for each unique source IP
- Parallel resolution using ThreadPoolExecutor (10 workers, 5s timeout)
- Hostname cache to avoid duplicate lookups

---

## [2.9.18] - 2026-01-23

### Web Dashboard v2.9.18
- **NEW**: Hostname resolution for Top Source, Top Router, Top Destination
- **CHANGED**: Card layout reorganized - labels (titles) now at top
- **FIXED**: Top Protocol volume now uses same styling as other cards

---

## [2.9.17] - 2026-01-23

### Web Dashboard v2.9.17
- **CHANGED**: Increased `LIMIT` from 30 to 100 events in `/api/analytics` endpoint

### Webhook Receiver v1.9.0
- **ADDED**: `log_attack_event()` calls to ALL webhook handlers
- **Result**: Dashboard "DDoS Protection Log" now shows complete event history

### Autowithdraw v3.4
- **NEW**: Peak attack statistics in withdraw notifications
- **FIX**: Notifications now show "Peak Dropped Packets" instead of current (0) values

---

## [2.9.16] - 2026-01-22

### Web Dashboard v2.9.16
- **NEW**: Dynamic status indicator in Network Analytics card header
- Shows "Paused - all prefixes withdrawn" or "Active - N prefix(es) via Cloudflare"

### Network Analytics Monitor v1.3.9
- **FIX**: Changed "no events" log from DEBUG to INFO for better polling visibility

---

## [2.9.15] - 2026-01-22

### Web Dashboard v2.9.15
- **CHANGED**: Stats now count only real attacks (`event_type = 'START'`)

---

## [2.9.13] - 2026-01-22

### Web Dashboard v2.9.13
- **BUG FIX**: "Attacks (24h)" and "Analytics (24h)" always showed 0
- **FIX**: Changed queries to use SQLite native `datetime('now', '-24 hours')`

---

## [2.9.12] - 2026-01-21

### Prefix Manager v1.4.0
- **NEW**: ADVERTISE and WITHDRAW operations now logged to `attack_events` table
- **Dashboard**: Manual operations appear in "Recent Attacks" section

---

## [2.9.11] - 2026-01-21

### Autowithdraw v3.3
- **BUG FIX**: Script was using wrong API endpoint for detecting advertised prefixes
- **FIX**: Now uses correct `/addressing/prefixes/{id}/bgp/prefixes/{bgp_id}` endpoint

---

## [2.9.10] - 2026-01-21

### Web Dashboard
- **FIX**: Changed `ORDER BY id DESC` to `ORDER BY created_at DESC`
- **FIX**: Increased LIMIT from 20 to 50 events

---

## [2.9.9] - 2026-01-21

### Webhook Receiver v1.8.0
- **NEW**: `fbm_auto_advertisement` events now saved to database
- **CHANGED**: DDoS L4 attacks now show `action_taken='mitigating'`

---

## [2.9.8] - 2026-01-21

### Web Dashboard
- User-friendly Event Type Labels with emoji badges

---

## [2.9.7] - 2026-01-21

### Web Dashboard
- **Removed**: "Message" section from Attack Event Details modal

### db_manager.py v1.3.0
- Fixed attack_vector for MNM alerts

---

## [2.9.6] - 2026-01-21

### Webhook Receiver v1.7.0
- **FIX**: MNM alerts now saved to `attack_events` database

---

## [2.9.5] - 2026-01-21

### Web Dashboard v2.9.5
- **Footer Text**: Brightened for better readability

---

## [2.9.4] - 2026-01-21

### Web Dashboard v2.9.4
- UI Polish: Consistent Button Styling across all pages

---

## [2.9.3] - 2026-01-21

### Web Dashboard v2.9.3
- Extended Tunnel Editing: MTU, Health Check Rate, Customer Endpoint IP

---

## [2.9.2] - 2026-01-21

### Web Dashboard v2.9.2
- **NEW**: Double-click on tunnel/CNI rows to open editable detail modal
- **NEW**: API endpoints for tunnel and CNI updates

---

## [2.9.1] - 2026-01-21

### Web Dashboard v2.9.1
- Connectors Page: Vertical layout, full-width tables
- Health Check Pass Rate from GraphQL
- Human-readable health check intervals

---

## [2.9.0] - 2026-01-21

### Web Dashboard v2.9.0
- **NEW PAGE**: `/connectors` - IPsec/GRE Tunnels & CNI Interconnects
- Header button for Connectors page
- Summary stats for tunnel health

---

## [2.8.8] - 2026-01-21

### Web Dashboard v2.8.8
- Cloudflare Constraint Enforcement on Advertise/Withdraw buttons

---

## [2.8.7] - 2026-01-21

### Web Dashboard v2.8.7
- Double-Click Edit on all rule pages

---

## [2.8.6] - 2026-01-21

### Web Dashboard v2.8.6
- Enhanced Detail Modals with ASN, Country, Verdict fields

### Network Analytics Monitor v1.3.6
- GraphQL query now fetches `sourceAsn`, `sourceAsnName`, `sourceCountry`

---

## [2.8.5] - 2026-01-21

### Web Dashboard v2.8.5
- Dynamic Detail Modals: auto-hide empty fields

---

## [2.8.4] - 2026-01-21

### Web Dashboard v2.8.4
- Ultra-Compact Detail Modals: ~40% height reduction

---

## [2.8.3] - 2026-01-21

### Web Dashboard v2.8.3
- Attack Detail Modal: Compact 2-row grid layout

---

## [2.8.2] - 2026-01-21

### Web Dashboard v2.8.2
- Rule Description Lookup in Analytics modal

---

## [2.8.1] - 2026-01-21

### Web Dashboard v2.8.1
- **NEW**: Network Analytics Detail Modal (double-click)

---

## [2.8.0] - 2026-01-21

### Web Dashboard v2.8.0
- **NEW**: Attack Event Detail Modal (double-click)
- Comprehensive event view with all fields

---

## [2.7.4] - 2026-01-21

### Web Dashboard v2.7.4
- **BUG FIX**: Timestamp Timezone Fix (added Z suffix for UTC)

---

## [2.7.3] - 2026-01-21

### Web Dashboard v2.7.3
- **BUG FIX**: CLI Override Preservation
- **BUG FIX**: Editable Rules Filter

---

## [2.7.2] - 2026-01-21

### Web Dashboard v2.7.2
- Status Text: "Waiting for auto-withdraw" instead of "Ready"

---

## [2.7.1] - 2026-01-21

### Web Dashboard v2.7.1
- API Constraint Display (15-minute cooldown)

### Web Dashboard v2.7.0
- Calm Status Display for advertised prefixes

### Autowithdraw v3.2
- Dashboard Integration with `prefix_calm_status` table

---

## [1.3.8] - 2026-01-21

### Network Analytics Monitor v1.3.8
- Enhanced Startup Message with BGP status, attack history, services

---

## [2.6.1] - 2026-01-21

### Web Dashboard v2.6.1
- Login Page Logo Fix (cache-busting)

---

## [2.6.0] - 2026-01-21

### Web Dashboard v2.6.0
- **NEW**: Login Authentication System
- Session-based auth with bcrypt passwords
- Password change modal

---

## [2.5.10] - 2026-01-21

### Web Dashboard v2.5.10
- BGP Prefixes Alert Color (red when advertised > 0)

---

## [2.5.9] - 2026-01-21

### Web Dashboard v2.5.9
- Network Flow Cards Sizing Fix

---

## [2.5.8] - 2026-01-21

### Web Dashboard v2.5.8
- UI Polish & Query Optimization

---

## [2.5.7] - 2026-01-21

### Web Dashboard v2.5.7
- Top Destination card (replaced Top TCP Flags)

---

## [2.5.6] - 2026-01-21

### Web Dashboard v2.5.6
- Volume display now uses Bytes (TB/GB/MB)

---

## [2.5.5] - 2026-01-21

### Web Dashboard v2.5.5
- Traffic Volume Display in stat cards

---

## [2.5.4] - 2026-01-21

### Web Dashboard v2.5.4
- Network Flow Query Optimization (split queries)

---

## [2.5.3] - 2026-01-21

### Web Dashboard v2.5.3
- **BREAKING**: Changed to `mnmFlowDataAdaptiveGroups` data source

---

## [2.5.1] - 2026-01-21

### Web Dashboard v2.5.1
- Network Flow Stats Redesign (6 stat cards)

---

## [2.5.0] - 2026-01-21

### Web Dashboard v2.5.0
- **NEW**: Network Flow Stats section (24h traffic analytics)

---

## [2.4.14] - 2026-01-21

### Web Dashboard v2.4.14
- Dynamic Version from DASHBOARD.md

---

## [2.4.13] - 2026-01-21

### Web Dashboard v2.4.1
- Card Descriptions & Footer Redesign

---

## [2.4.12] - 2026-01-21

### Web Dashboard v2.4.0
- MNM Rules Edit Functionality

---

## [2.4.11] - 2026-01-21

### Web Dashboard v2.3.0
- **NEW PAGE**: `/mnm-rules` - MNM Rules Manager

---

## [2.4.10] - 2026-01-21

### Web Dashboard v2.2.0
- DDoS Rules Manager Enhancements

---

## [2.4.9] - 2026-01-21

### Web Dashboard v2.1.0
- Override Merge & Sensitivity Support

---

## [2.4.8] - 2026-01-20

### Web Dashboard v2.0.0
- DDoS Rule Editing

---

## [2.4.7] - 2026-01-20

### Web Dashboard v1.9.0
- **NEW PAGE**: `/ddos-rules` - DDoS Rules Detail Page

---

## [2.4.6] - 2026-01-20

### Web Dashboard v1.8.0
- DDoS Sensitivity Section Redesign

---

## [2.4.5] - 2026-01-20

### Web Dashboard v1.7.0
- Human-Readable Attack Events

---

## [2.4.4] - 2026-01-20

### Web Dashboard v1.6.0
- Responsive Design Improvements

### Watchdog v1.2
- Added `cloudflare-dashboard` to monitored services

---

## [2.4.3] - 2026-01-20

### Web Dashboard v1.5.0
- User-Friendly Service Names

---

## [2.4.2] - 2026-01-20

### Web Dashboard v1.4.0
- Prefix Management Buttons (Advertise/Withdraw)

---

## [2.4.1] - 2026-01-20

### Web Dashboard v1.3.0
- GOLINE Logo and UI improvements

---

## [2.4.0] - 2026-01-20

### Web Dashboard v1.0.0
- **INITIAL RELEASE**: Real-time monitoring dashboard
- URL: `https://cloudflare.goline.ch`
- Flask backend, dark theme frontend

---

## [2.3.3] - 2026-01-20

### Rules Manager v1.4
- DDoS Sensitivity Management (124 rules)

---

## [2.3.2] - 2026-01-20

### Rules Manager v1.3
- Advanced DDoS (sFlow) Support

---

## [2.3.1] - 2026-01-20

- 15-Minute Re-Advertise Constraint added to all scripts

---

## [2.3.0] - 2026-01-20

- **IPv6 Prefix Support**: Added `2a02:4460:1::/48`

---

## [2.2.1] - 2026-01-19

### Autowithdraw v3.1
- Threshold Logic Fix: Changed from OR to AND

---

## [2.2.0] - 2026-01-19

### Network Analytics Monitor v1.3.1
- GeoIP2 Integration for source IP enrichment

---

## [2.1.2] - 2026-01-19

### Network Analytics Monitor v1.1.3
- GOLINE prefix filter added

---

## [2.1.1] - 2026-01-19

- Comprehensive Documentation for all scripts

---

## [2.1.0] - 2026-01-19

- **Unified Withdraw Architecture**: `cloudflare-autowithdraw.service` is now the ONLY service that performs BGP withdrawals

---

## [2.0.3] - 2026-01-19

- **GitHub Repository** published

---

## [2.0.2] - 2026-01-19

### Network Analytics Monitor v1.1.2
- Increased lookback window to 15 minutes

---

## [2.0.1] - 2026-01-19

### Network Analytics Monitor v1.1.1
- Fixed watchdog timeout issue (removed WatchdogSec)

---

## [2.0.0] - 2026-01-19

- Network Analytics Monitor v1.1.0 - High availability
- Services Watchdog - Unified monitoring script
- Script Rename - `cloudflare-` prefix convention

---

## [1.5.0] - 2026-01-19

- Prefix Manager v1.3.0 - Complete CLI with all 5 prefixes
- Webhook Receiver v1.6.0 - 11 alert types
- Unified Telegram Header - SOC-style branding

---

*GOLINE SOC - Cloudflare Magic Transit Integration*
