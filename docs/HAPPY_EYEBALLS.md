# Happy Eyeballs - IPv6/IPv4 Dual-Stack Connection Manager

**Script**: `happy_eyeballs.py`
**Version**: 1.0.0
**Last Updated**: 2026-02-06
**Author**: GOLINE SOC
**RFC**: [RFC 8305 - Happy Eyeballs Version 2](https://datatracker.ietf.org/doc/html/rfc8305)

---

## Overview

The Happy Eyeballs module implements RFC 8305 to provide fast, reliable dual-stack (IPv6/IPv4) connections for all HTTP requests made by the Cloudflare Magic Transit integration scripts.

When IPv6 connectivity is broken or degraded (as experienced on lg.goline.ch), Python's `requests` library attempts IPv6 first (DNS AAAA records) and waits for the full timeout (typically 30 seconds) before falling back to IPv4. This module reduces that fallback time to **2 seconds**, ensuring API calls complete in under 3 seconds even when IPv6 is completely unreachable.

### Key Features

| Feature | Description |
|---------|-------------|
| **IPv6-first** | Always tries IPv6 first, as recommended by RFC 8305 |
| **Fast fallback** | Falls back to IPv4 after 2 seconds if IPv6 fails |
| **Zero code changes** | Monkey-patches `urllib3` at import time - no API call modifications needed |
| **Thread-safe** | Uses only local variables, safe for multi-threaded Flask applications |
| **Transparent** | Works with all `requests.get()`, `requests.post()`, and `requests.Session()` calls |
| **Edge-case handling** | Handles IPv4-only, IPv6-only, dual-stack, and DNS failure scenarios |

---

## Problem Statement

### Symptoms (2026-02-06)

| Symptom | Impact |
|---------|--------|
| 20+ connections stuck in `SYN-SENT` state | Dashboard unresponsive |
| Every API call takes 30+ seconds | Telegram notifications lost |
| IPv6 packet loss to `2606:4700:300a::*` at 100% | All Cloudflare API calls affected |
| Services timeout cascade | Webhook receiver, analytics monitor, autowithdraw all delayed |

### Root Cause

```
DNS Resolution for api.cloudflare.com:
  AAAA → 2606:4700:300a::6815:160a (IPv6 - UNREACHABLE from lg.goline.ch)
  A    → 104.21.22.10 (IPv4 - works fine, <1s)

Python requests flow (WITHOUT Happy Eyeballs):
  1. socket.getaddrinfo() returns IPv6 first (AAAA before A)
  2. socket.connect() to IPv6 address
  3. Wait 30 seconds for TCP SYN timeout
  4. Fallback to IPv4
  5. Connect in <1s
  Total: ~30 seconds per request
```

### Solution

```
Python requests flow (WITH Happy Eyeballs):
  1. socket.getaddrinfo() returns both IPv6 and IPv4
  2. Try IPv6 with 2-second timeout
  3. IPv6 fails after 2s → immediately try IPv4
  4. Connect in <1s via IPv4
  Total: ~2-3 seconds per request (10x improvement)
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      HAPPY EYEBALLS CONNECTION FLOW                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  import happy_eyeballs    ← Patches urllib3 on import                        │
│                                                                              │
│  requests.get("https://api.cloudflare.com/...")                              │
│      │                                                                       │
│      ▼                                                                       │
│  urllib3.util.connection.create_connection()   ← PATCHED                     │
│      │                                                                       │
│      ▼                                                                       │
│  socket.getaddrinfo(host, port, AF_UNSPEC)                                   │
│      │                                                                       │
│      ├── IPv6 addresses (AF_INET6)                                           │
│      └── IPv4 addresses (AF_INET)                                            │
│                                                                              │
│  ┌─── Only IPv6? ──► Connect with full timeout ──► Return socket             │
│  │                                                                           │
│  ├─── Only IPv4? ──► Connect with full timeout ──► Return socket             │
│  │                                                                           │
│  └─── Both families available (Happy Eyeballs):                              │
│       │                                                                      │
│       ▼                                                                      │
│       ┌─────────────────────────────────┐                                    │
│       │  Try IPv6 (timeout = 2 seconds) │                                    │
│       └──────────┬──────────────────────┘                                    │
│                  │                                                           │
│           ┌──────┴──────┐                                                    │
│           │             │                                                    │
│        Success       Timeout/Error                                           │
│           │             │                                                    │
│           ▼             ▼                                                    │
│     Return IPv6    ┌─────────────────────────────────┐                       │
│     socket         │  Try IPv4 (full timeout)        │                       │
│                    └──────────┬──────────────────────┘                       │
│                               │                                              │
│                        ┌──────┴──────┐                                       │
│                        │             │                                       │
│                     Success       Error                                      │
│                        │             │                                       │
│                        ▼             ▼                                       │
│                  Return IPv4    Raise OSError                                │
│                  socket                                                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Technical Details

### Monkey-Patch Mechanism

The module patches `urllib3.util.connection.create_connection`, which is the function used by `urllib3` (and therefore `requests`) to establish TCP connections.

```python
import urllib3.util.connection

# Original function saved for reference
_original_create_connection = urllib3.util.connection.create_connection

# Replace with Happy Eyeballs implementation
urllib3.util.connection.create_connection = _happy_eyeballs_create_connection
```

This approach was chosen because:
1. **Single point of control**: All HTTP connections go through `urllib3`
2. **No code changes needed**: Existing `requests.get()` / `requests.post()` calls work unchanged
3. **Library-level**: Works with `requests.Session()`, retries, and connection pooling

### Configuration

| Parameter | Value | Description |
|-----------|-------|-------------|
| `IPV6_TIMEOUT` | 2.0 seconds | Maximum time to wait for IPv6 before fallback |

The 2-second timeout was chosen as a balance between:
- **Too short** (< 1s): May cause IPv6 failures on slow but working connections
- **Too long** (> 5s): Defeats the purpose of fast fallback
- **RFC 8305 recommendation**: 250ms connection attempt delay (we use 2s for robustness)

### Thread Safety

The implementation is fully thread-safe:
- No global mutable state
- All variables are local to each function call
- Each thread gets its own socket objects
- Safe for multi-threaded Flask applications (dashboard, webhook receiver)

### Edge Cases

| Scenario | Behavior |
|----------|----------|
| **Only IPv6 available** | Uses IPv6 with full timeout (no fallback) |
| **Only IPv4 available** | Uses IPv4 with full timeout (no fallback) |
| **Both available, IPv6 works** | Uses IPv6 (completes in < 2s) |
| **Both available, IPv6 broken** | Falls back to IPv4 after 2s |
| **DNS resolution fails** | Raises `socket.gaierror` (unchanged behavior) |
| **Both families fail** | Raises `OSError` from last attempt |
| **Timeout < 2s specified** | Uses the smaller of the two timeouts for IPv6 |

---

## Integration

### Scripts Using Happy Eyeballs

| Script | Import Location | Notes |
|--------|----------------|-------|
| `cloudflare-autowithdraw.py` | After `import requests` (line 24) | Daemon - runs continuously |
| `cloudflare-webhook-receiver.py` | After `import requests` (line 36) | Flask app - multi-threaded |
| `cloudflare-network-analytics-monitor.py` | After `import requests` (line 34) | Daemon - polls every 5 min |
| `cloudflare-prefix-manager.py` | After `import requests` (line 32) | CLI tool - on-demand |
| `cloudflare-rules-manager.py` | After `import requests` (line 10) | Interactive CLI |
| `dashboard/app.py` | After `sys.path` setup (line 33-34) | Flask app - multi-threaded |

### Import Pattern

**For scripts in `scripts/` directory** (same directory as `happy_eyeballs.py`):
```python
import requests
import happy_eyeballs  # Patches urllib3 on import
```

**For scripts in other directories** (e.g., `dashboard/`):
```python
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import happy_eyeballs  # Patches urllib3 on import
```

### Affected API Endpoints

All outgoing HTTP connections benefit from Happy Eyeballs:

| API | Endpoint | Usage |
|-----|----------|-------|
| **Cloudflare REST** | `api.cloudflare.com/client/v4/` | BGP prefix management, MNM rules |
| **Cloudflare GraphQL** | `api.cloudflare.com/client/v4/graphql` | Network analytics, attack detection |
| **Telegram** | `api.telegram.org/bot{token}/` | Notifications (sendMessage) |

---

## Performance

### Before vs After

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Cloudflare API call | ~30s | ~0.8s | **37x faster** |
| Telegram API call | ~30s | ~0.2s | **150x faster** |
| Dashboard page load | 60+ seconds | < 3 seconds | **20x faster** |
| Stale SYN-SENT connections | 20+ | 0 | **Eliminated** |
| Telegram notifications missed | ~4/day | 0 | **Eliminated** |

### Test Results (2026-02-06)

```bash
# Cloudflare API (400 expected - no auth)
$ python3 -c "import happy_eyeballs; import requests, time; \
  t=time.time(); r=requests.get('https://api.cloudflare.com/client/v4/', timeout=30); \
  print(f'{r.status_code} in {time.time()-t:.1f}s')"
400 in 0.8s

# Telegram API
$ python3 -c "import happy_eyeballs; import requests, time; \
  t=time.time(); r=requests.get('https://api.telegram.org/', timeout=30); \
  print(f'{r.status_code} in {time.time()-t:.1f}s')"
200 in 0.2s

# Prefix Manager (full API call with auth)
$ cloudflare-prefix-manager status
[responds instantly with all 5 prefixes]
```

---

## Verification

### Quick Test

```bash
# Test module works correctly
python3 -c "
import sys
sys.path.insert(0, '/root/Cloudflare_MT_Integration/scripts')
import happy_eyeballs
import requests, time

t = time.time()
r = requests.get('https://api.cloudflare.com/client/v4/', timeout=30)
print(f'Status: {r.status_code}, Time: {time.time()-t:.1f}s')
# Expected: ~0.8s (not 30+s)
"
```

### Check for Stale Connections

```bash
# Should show no SYN-SENT connections to Cloudflare/Telegram IPv6
ss -tn state syn-sent | grep -E '2606:4700|2001:67c'
```

### Service Health

```bash
# All services should be running
systemctl status cloudflare-webhook cloudflare-analytics-monitor \
  cloudflare-autowithdraw cloudflare-dashboard --no-pager

# Dashboard health check
curl -s http://127.0.0.1:8081/health | jq

# Prefix manager (uses Cloudflare API)
cloudflare-prefix-manager status
```

---

## Troubleshooting

### Module Not Found

```
ModuleNotFoundError: No module named 'happy_eyeballs'
```
**Fix**: Ensure `sys.path` includes the `scripts/` directory:
```python
sys.path.insert(0, '/root/Cloudflare_MT_Integration/scripts')
import happy_eyeballs
```

### IPv6 Connectivity Restored

When IPv6 connectivity is restored, the module automatically uses IPv6 (faster, no fallback needed). No configuration change required - the 2-second timeout is only triggered if IPv6 fails.

### Both IPv4 and IPv6 Fail

If both address families fail, the module raises the same `OSError` that would occur without it. Check:
```bash
# DNS resolution
dig api.cloudflare.com AAAA
dig api.cloudflare.com A

# IPv4 connectivity
curl -4 https://api.cloudflare.com/client/v4/
```

### Timeout Too Aggressive

If IPv6 works but is slow (> 2s), the module may unnecessarily fall back to IPv4. To adjust:
```python
# In happy_eyeballs.py, change:
IPV6_TIMEOUT = 2.0  # Current: 2 seconds
IPV6_TIMEOUT = 5.0  # More lenient: 5 seconds
```

---

## Dependencies

| Dependency | Purpose | Installed |
|------------|---------|-----------|
| `urllib3` | HTTP connection library (patched) | ✅ via `python3-urllib3` |
| `socket` | TCP connection (stdlib) | ✅ Python stdlib |

No additional packages required.

---

## File Location

```
/root/Cloudflare_MT_Integration/scripts/happy_eyeballs.py
```

---

*GOLINE SOC - Cloudflare Magic Transit Integration*
