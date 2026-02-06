# Webhook Receiver per Cloudflare Magic Transit

**Version**: 2.4.0 (script v1.9.1)
**Last Updated**: 2026-02-06

## Panoramica

Il webhook receiver riceve notifiche **real-time** da Cloudflare per tutti i tipi di alert disponibili:
- **DDoS Protection**: Attacchi L3/L4/L7
- **Magic Network Monitoring**: Volumetric attacks, sFlow detection
- **Magic Transit**: Tunnel health, BGP advertisement
- **Route Leak Detection**: BGP hijack alerts
- **Health Checks**: Origin health monitoring
- **Cloudflare Status**: Platform incidents

### Principio Operativo (v2.1.0)

> **IMPORTANTE**: A partire dalla versione 2.1.0, il webhook receiver **NON esegue più operazioni di withdraw BGP**.
> Tutte le operazioni di withdraw sono gestite da `cloudflare-autowithdraw.service`.

- **Cloudflare** annuncia automaticamente i prefissi BGP durante l'attacco
- **Webhook receiver** invia notifiche Telegram e logga eventi nel database
- **Autowithdraw daemon** ritira i prefissi dopo 15 minuti di calma (assenza di attacchi)

---

## Architettura

```
                         HTTPS (443)
Cloudflare Notifications ─────────────────► Apache (lg.goline.ch)
                                                  │
                                                  │ ProxyPass /webhook
                                                  ▼
                                             Flask (127.0.0.1:8080)
                                                  │
                                   ┌──────────────┼──────────────┐
                                   ▼              ▼              ▼
                             Telegram API   SQLite Database   Log files
                             (notifiche)    (attack_events)   (debug)
```

> **Note v2.1.0**: Il webhook NON chiama più Cloudflare API per withdraw.
> I withdraw sono gestiti da `cloudflare-autowithdraw.service`.

---

## Configurazione

### Endpoints

| Endpoint | URL | Descrizione |
|----------|-----|-------------|
| **Webhook** | `https://lg.goline.ch/webhook/cloudflare` | Riceve notifiche Cloudflare |
| **Health Check** | `https://lg.goline.ch/mt-health` | Verifica stato servizio |
| **Test** | `http://localhost:8080/test/attack` | Test locale (solo interno) |

### Autenticazione
- **Header**: `cf-webhook-auth`
- **Secret**: `YOUR_WEBHOOK_SECRET`

---

## Systemd Service

### Configurazione: `/etc/systemd/system/cloudflare-webhook.service`

```ini
[Unit]
Description=Cloudflare Magic Transit Webhook Receiver
Documentation=https://developers.cloudflare.com/notifications/
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/root/Cloudflare_MT_Integration
ExecStart=/usr/bin/python3 /root/Cloudflare_MT_Integration/scripts/cloudflare-webhook-receiver.py
Restart=always
RestartSec=5

Environment=PYTHONUNBUFFERED=1

StandardOutput=journal
StandardError=journal
SyslogIdentifier=cloudflare-webhook

NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/root/Cloudflare_MT_Integration/logs

[Install]
WantedBy=multi-user.target
```

### Comandi Gestione

```bash
# Stato servizio
systemctl status cloudflare-webhook

# Avvio/Stop/Restart
systemctl start cloudflare-webhook
systemctl stop cloudflare-webhook
systemctl restart cloudflare-webhook

# Abilitare all'avvio
systemctl enable cloudflare-webhook

# Log in tempo reale
journalctl -u cloudflare-webhook -f

# Ultimi 50 log
journalctl -u cloudflare-webhook -n 50 --no-pager
```

### Affidabilità

| Protection | Valore | Descrizione |
|------------|--------|-------------|
| Auto-start | `enabled` | Parte automaticamente al boot |
| `Restart=always` | ✅ | Si riavvia automaticamente se crasha |
| `RestartSec` | 5s | Attende 5 secondi prima di riavviarsi |
| `StartLimitBurst` | 5 | Max 5 restart in 5 minuti |
| `StartLimitIntervalSec` | 300s | Reset counter dopo 5 minuti |
| **Cron Watchdog** | */5 min | Controllo esterno ogni 5 minuti |

**Watchdog Cron**: `/etc/cron.d/cloudflare-services-watchdog`
- Verifica stato servizio ogni 5 minuti
- Auto-restart se down
- Notifica Telegram su restart/failure

---

## Alert Types Supportati (11)

### Riepilogo

| Alert Type | Handler | Categoria | Priorità |
|------------|---------|-----------|----------|
| `advanced_ddos_attack_l4_alert` | `handle_ddos_l4_attack()` | DDoS Protection | HIGH |
| `dos_attack_l4` | `handle_ddos_l4_attack()` | DDoS Protection | HIGH |
| `dos_attack_l7` | `handle_ddos_l7_attack()` | DDoS Protection | HIGH |
| `fbm_dosd_attack` | `handle_mnm_ddos_attack()` | Magic Network Monitoring | HIGH |
| `fbm_volumetric_attack` | `handle_volumetric_attack()` | Magic Network Monitoring | MEDIUM |
| `fbm_auto_advertisement` | `handle_auto_advertisement()` | Magic Transit | INFO |
| `magic_tunnel_health_check_event` | `handle_tunnel_health()` | Magic Transit | HIGH |
| `incident_alert` | `handle_incident_alert()` | Cloudflare Status | VARIES |
| `health_check_status_notification` | `handle_health_check_alert()` | Health Checks | MEDIUM |
| `bgp_hijack_notification` | `handle_bgp_hijack_alert()` | Route Leak Detection | CRITICAL |
| Altri | `handle_unknown_alert()` | Generic | INFO |

---

## Dettaglio Alert Types

### 1. Advanced L3/L4 DDoS Attack (`advanced_ddos_attack_l4_alert`)

**Descrizione**: Attacco DDoS Layer 3/4 rilevato dal sistema avanzato di Cloudflare.

**Payload Esempio**:
```json
{
  "name": "Layer 3/4 DDoS Attack Alert",
  "alert_type": "advanced_ddos_attack_l4_alert",
  "alert_event": "ALERT_STATE_EVENT_START",
  "data": {
    "attack_id": "aBcD1234efgh567i890j1kl234567m80",
    "attack_vector": "UDP Flood",
    "target_ip": "185.54.82.10",
    "target_port": 53,
    "protocol": "UDP",
    "packets_per_second": "750000",
    "megabits_per_second": "3500",
    "action": "block",
    "mitigation": "managed-challenge",
    "rule_name": "DNS Amplification Protection",
    "start_time": "2026-01-19T00:00:00Z",
    "severity": "HIGH"
  },
  "ts": 1737241000
}
```

**Campi Estratti**:
- `attack_id` - ID univoco attacco Cloudflare
- `attack_vector` - Tipo di attacco (UDP Flood, SYN Flood, etc.)
- `target_ip` - IP destinazione
- `target_port` - Porta destinazione
- `protocol` - Protocollo (TCP/UDP)
- `packets_per_second` - Rate pacchetti
- `megabits_per_second` - Banda
- `action` - Azione intrapresa
- `mitigation` - Tipo mitigazione
- `rule_name` - Regola che ha triggerato

---

### 2. Basic L3/L4 DDoS Attack (`dos_attack_l4`)

**Descrizione**: Attacco DDoS Layer 3/4 base.

**Payload Esempio**:
```json
{
  "name": "Layer 3/4 DDoS Attack Alert",
  "alert_type": "dos_attack_l4",
  "data": {
    "attack_id": "aBcD1234efgh567i890j1kl234567m80",
    "attack_vector": "fake-vector",
    "target_ip": "127.0.0.1",
    "target_port": 80,
    "protocol": "TCP",
    "max_rate": "800.00 pps",
    "megabits_per_second": "1",
    "rule_name": "fake-name",
    "severity": "INFO"
  }
}
```

---

### 3. HTTP DDoS Attack - Layer 7 (`dos_attack_l7`)

**Descrizione**: Attacco DDoS a livello applicativo (HTTP).

**Payload Esempio**:
```json
{
  "name": "HTTP DDoS Attack Alert",
  "alert_type": "dos_attack_l7",
  "data": {
    "attack_id": "aBcD1234efgh567i890j1kl234567m80",
    "attack_type": "HTTP Flood",
    "target_hostname": "example.com",
    "target_zone_name": "fake-zone-name",
    "requests_per_second": "50000",
    "action": "block",
    "mitigation": "managed-challenge",
    "rule_description": "HTTP flood protection",
    "start_time": "2026-01-19T00:00:00Z",
    "severity": "HIGH"
  }
}
```

**Campi Estratti**:
- `attack_type` - Tipo attacco HTTP
- `target_hostname` - Hostname target
- `requests_per_second` - Rate richieste

---

### 4. Magic Network Monitoring DDoS (`fbm_dosd_attack`)

**Descrizione**: Attacco rilevato tramite sFlow da Magic Network Monitoring.

**Payload Esempio**:
```json
{
  "name": "DDoS Attack",
  "alert_type": "fbm_dosd_attack",
  "data": {
    "target_ip": "185.54.82.10",
    "target_port": 80,
    "attack_type": "UDP Amplification",
    "protocol": "UDP",
    "packets_per_second": "500000",
    "megabits_per_second": "2000",
    "max_rate": "500K pps",
    "rule_name": "MNM Rule 1",
    "start_time": "2026-01-19T00:00:00Z",
    "auto_advertised": true,
    "advertise_status": [
      {"prefix": "185.54.82.0/24", "status": "advertised"}
    ],
    "severity": "HIGH"
  }
}
```

**Campi Estratti**:
- `auto_advertised` - Se BGP è stato annunciato automaticamente
- `advertise_status` - Stato dei prefissi BGP

---

### 5. Volumetric Attack (`fbm_volumetric_attack`)

**Descrizione**: Soglia di traffico volumetrico superata.

**Payload Esempio**:
```json
{
  "name": "Volumetric Attack",
  "alert_type": "fbm_volumetric_attack",
  "data": {
    "rule_name": "High Traffic Threshold",
    "rule_threshold": "10000",
    "rule_duration": "5m",
    "rule_zscore_sensitivity": "low",
    "packets_per_second": "20000",
    "packets_per_second_string": "20,000 pps",
    "megabits_per_second": "1500",
    "start_time": "2026-01-19T00:00:00Z",
    "auto_advertised": true,
    "severity": "MEDIUM"
  }
}
```

**Campi Estratti**:
- `rule_name` - Nome regola triggerata
- `rule_threshold` - Soglia configurata
- `rule_duration` - Durata finestra
- `rule_zscore_sensitivity` - Sensibilità (low/medium/high)

---

### 6. Auto BGP Advertisement (`fbm_auto_advertisement`)

**Descrizione**: Notifica di annuncio automatico prefissi BGP.

**Payload Esempio**:
```json
{
  "name": "Auto Advertisement",
  "alert_type": "fbm_auto_advertisement",
  "data": {
    "rule_name": "Auto Advertise Rule",
    "attack_type": "Volumetric",
    "start_time": "2026-01-19T00:00:00Z",
    "advertise_status": [
      {"prefix": "185.54.82.0/24", "status": "advertised"},
      {"prefix": "185.54.83.0/24", "status": "pending"}
    ]
  }
}
```

---

### 7. Tunnel Health Check (`magic_tunnel_health_check_event`)

**Descrizione**: Stato dei tunnel GRE/IPsec di Magic Transit.

**Payload Esempio**:
```json
{
  "name": "Tunnel Health Check",
  "alert_type": "magic_tunnel_health_check_event",
  "alert_event": "TUNNEL_STATUS_CHANGE",
  "data": {
    "tunnel_name": "gre-tunnel-primary",
    "tunnel_id": "tunnel-123",
    "new_status": "MAGIC_TUNNEL_STATUS_DOWN",
    "previous_status": "MAGIC_TUNNEL_STATUS_UP",
    "pop_names": "ZRH, MXP",
    "slo": "99.9",
    "observed_slo": "85.5",
    "mwan_site_name": "GOLINE-DC1",
    "event_ts": "2026-01-19T00:00:00Z",
    "severity": "HIGH"
  }
}
```

**Campi Estratti**:
- `tunnel_name` - Nome tunnel
- `new_status` / `previous_status` - Cambio stato
- `pop_names` - PoP Cloudflare coinvolti
- `slo` / `observed_slo` - SLO target vs osservato

---

### 8. Cloudflare Incident (`incident_alert`)

**Descrizione**: Incidenti sulla piattaforma Cloudflare (status page).

**Payload Esempio**:
```json
{
  "name": "Cloudflare Incident",
  "alert_type": "incident_alert",
  "data": {
    "incident_name": "Regional degraded connectivity for Secure Web Gateway",
    "incident_id": "n7058grjk59r",
    "incident_status": "INCIDENT_STATUS_MONITORING",
    "incident_impact": "INCIDENT_IMPACT_MINOR",
    "message": "A fix has been implemented and we are monitoring the results.",
    "created_at": "2026-01-19T00:00:00Z",
    "affected_components": [
      {"id": "kf0ktv29xrfy", "name": "Zero Trust"}
    ],
    "severity": "INFO"
  }
}
```

**Campi Estratti**:
- `incident_name` - Nome incidente
- `incident_status` - INVESTIGATING, MONITORING, RESOLVED
- `incident_impact` - MINOR, MAJOR, CRITICAL
- `affected_components` - Componenti impattati
- `message` - Ultimo messaggio

**Link**: `https://www.cloudflarestatus.com/incidents/{incident_id}`

---

### 9. Health Check Status (`health_check_status_notification`)

**Descrizione**: Stato degli health check sugli origin.

**Payload Esempio**:
```json
{
  "name": "Health Check Status",
  "alert_type": "health_check_status_notification",
  "data": {
    "name": "origin-web-server",
    "health_check_id": "hc-12345",
    "status": "Unhealthy",
    "reason": "Connection timeout",
    "expected_codes": "[2xx 302]",
    "actual_code": 0,
    "time": "2026-01-19T00:00:00Z",
    "preview": false,
    "severity": "HIGH"
  }
}
```

**Campi Estratti**:
- `name` - Nome health check
- `status` - Healthy/Unhealthy
- `expected_codes` - Codici HTTP attesi
- `actual_code` - Codice ricevuto
- `reason` - Motivo stato
- `preview` - Se è un test preview

---

### 10. BGP Hijack / Route Leak (`bgp_hijack_notification`) - CRITICAL

**Descrizione**: Rilevamento di BGP hijack o route leak. **ALERT CRITICO**.

**Payload Esempio**:
```json
{
  "name": "Route Leak Detection",
  "alert_type": "bgp_hijack_notification",
  "data": {
    "alert_title": "Potential BGP Hijack Detected",
    "alert_priority_level": "CRITICAL",
    "prefix_configured": "185.54.80.0/22",
    "prefix_hijacked": "185.54.82.0/24",
    "hijack_as": "AS12345",
    "ASNs_seen": ["12345", "67890"],
    "alert_start_time": "2026-01-19T00:00:00Z",
    "additional_info": "Prefix seen from unexpected origin",
    "dashboard_link": "dash.cloudflare.com/account-id",
    "account_name": "GOLINE SA",
    "severity": "CRITICAL"
  }
}
```

**Campi Estratti**:
- `alert_priority_level` - CRITICAL, HIGH, MEDIUM
- `prefix_configured` - Prefisso configurato
- `prefix_hijacked` - Prefisso hijackato
- `hijack_as` - AS che sta annunciando
- `ASNs_seen` - Lista AS che vedono l'annuncio

**AZIONE RICHIESTA**: Investigare immediatamente!

---

## Telegram Messages

All Telegram messages use **Markdown** format with a unified header: `🛡️ *CLOUDFLARE DDoS PROTECTION*`

### Unified Header Format

All notifications now start with the same header for brand consistency:

```
🛡️ *CLOUDFLARE DDoS PROTECTION*

[Alert-specific content...]

🏢 *GOLINE SOC* | _Cloudflare Magic Transit_
```

### Example: DDoS Attack L4
```
🛡️ *CLOUDFLARE DDoS PROTECTION*

🚨 *Advanced L3/L4 DDoS ATTACK*

🔖 *Alert ID:* `20260119000544-a1b2c3`
⚠️ *Severity:* HIGH

⚔️ *ATTACK INFO*
🆔 *Attack ID:* `cf-atk-xxxxx`
💥 *Vector:* UDP Amplification
🔧 *Protocol:* UDP
🛡️ *Action:* block
🔒 *Mitigation:* managed-challenge

📊 *TRAFFIC METRICS*
📦 *Packets:* 750.00K pps
📈 *Bandwidth:* 3.50 Gbps
⏱️ *Start:* 2026-01-19T00:00:00Z

🎯 *TARGET*
🌐 *IP:* `185.54.82.10`
🔌 *Port:* 53
📡 *Prefix:* `185.54.82.0/24`

🔄 *BGP STATUS*
✅ Auto-advertised by Cloudflare
🛡️ Traffic scrubbing active

📋 *RULE:* DNS Amplification Protection

🏢 *GOLINE SOC* | _Cloudflare Magic Transit_
```

### Example: BGP Hijack (CRITICAL)
```
🛡️ *CLOUDFLARE DDoS PROTECTION*

🚨🚨🚨 *CRITICAL: BGP HIJACK DETECTED* 🚨🚨🚨

🔖 *Alert ID:* `20260119001234-x9y8z7`
🔴 *Priority:* CRITICAL
🏢 *Account:* GOLINE SA

📋 *HIJACK DETAILS*
📛 *Title:* Potential BGP Hijack Detected
⏱️ *Detected:* 2026-01-19T00:00:00Z

🌐 *PREFIX INFO*
✅ *Configured:* `185.54.80.0/22`
❌ *Hijacked:* `185.54.82.0/24`

🏴‍☠️ *HIJACKER*
🔢 *Hijack AS:* `AS12345`
📡 *ASNs Advertising:* 12345, 67890

ℹ️ *Additional Info:*
Prefix seen from unexpected origin

🔗 [View Dashboard](https://dash.cloudflare.com/account-id)

🏢 *GOLINE SOC* | _Cloudflare Route Leak Detection_
```

### Example: Cloudflare Incident
```
🛡️ *CLOUDFLARE DDoS PROTECTION*

🌐 *CLOUDFLARE INCIDENT*

🔖 *Alert ID:* `20260119001500-abc123`
🟠 *Impact:* MAJOR
👀 *Status:* MONITORING

📋 *INCIDENT DETAILS*
📛 *Name:* Regional degraded connectivity
🆔 *ID:* `n7058grjk59r`
⏱️ *Created:* 2026-01-19T00:15:00Z

💬 *Message:*
A fix has been implemented and we are monitoring the results.

🔧 *AFFECTED COMPONENTS*
• Zero Trust
• Access

🔗 [View on Status Page](https://www.cloudflarestatus.com/incidents/n7058grjk59r)

🏢 *GOLINE SOC* | _Cloudflare Status_
```

### Example: Health Check
```
🛡️ *CLOUDFLARE DDoS PROTECTION*

🚨 *HEALTH CHECK*

🔖 *Alert ID:* `20260119002000-def456`
🔴 *Status:* Unhealthy

🔍 *CHECK DETAILS*
📛 *Name:* origin-web-server
🆔 *ID:* `hc-12345`
⏱️ *Time:* 2026-01-19T00:20:00Z

📊 *RESPONSE*
✅ *Expected:* [2xx 302]
📥 *Received:* 0
💬 *Reason:* Connection timeout

🏢 *GOLINE SOC* | _Cloudflare Health Checks_
```

### Example: Tunnel Health
```
🛡️ *CLOUDFLARE DDoS PROTECTION*

🚨🚨🚨 *TUNNEL DOWN*

🔖 *Alert ID:* `20260119002500-ghi789`
⚠️ *Severity:* HIGH

🔗 *TUNNEL INFO*
📛 *Name:* gre-tunnel-primary
🆔 *ID:* `tunnel-123`
🏢 *Site:* GOLINE-DC1

📊 *STATUS*
🔴 *Current:* DOWN
🔄 *Previous:* UP
🌍 *PoPs:* ZRH, MXP

📈 *SLO METRICS*
🎯 *Target SLO:* 99.9%
📊 *Current SLI:* 85.5%
⏱️ *Time:* 2026-01-19T00:25:00Z

🏢 *GOLINE SOC* | _Cloudflare Magic Transit_
```

---

## Workflow per Tipo Alert

### DDoS Attack (L3/L4/L7) - v2.1.0

```
┌─────────────────────────────────────────────────────────────┐
│ ATTACK START                                                │
├─────────────────────────────────────────────────────────────┤
│ Cloudflare rileva attacco                                   │
│     │                                                       │
│     ├──► Annuncia prefisso BGP (automatico via MNM rules)   │
│     └──► Invia webhook ALERT_STATE_EVENT_START              │
│               │                                             │
│               ▼                                             │
│     Webhook Receiver                                        │
│     ├──► Identifica prefisso da IP target                   │
│     ├──► Logga evento START nel database                    │
│     └──► Invia notifica Telegram                            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ ATTACK END                                                  │
├─────────────────────────────────────────────────────────────┤
│ Cloudflare rileva fine attacco                              │
│     │                                                       │
│     └──► Invia webhook ALERT_STATE_EVENT_END                │
│               │                                             │
│               ▼                                             │
│     Webhook Receiver                                        │
│     ├──► Logga evento END nel database                      │
│     └──► Invia notifica Telegram                            │
│          (NON esegue withdraw - delegato ad autowithdraw)   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ AUTO-WITHDRAW (servizio separato)                           │
├─────────────────────────────────────────────────────────────┤
│ cloudflare-autowithdraw.service (ogni 60 secondi)           │
│     │                                                       │
│     ├──► Verifica prefissi advertised                       │
│     ├──► Query GraphQL per traffico mitigato                │
│     │                                                       │
│     └──► Se calmo per 15 minuti:                            │
│           ├──► Ritira prefisso BGP                          │
│           ├──► Logga WITHDRAW nel database                  │
│           └──► Invia notifica Telegram                      │
└─────────────────────────────────────────────────────────────┘
```

### Tunnel Health

```
Tunnel DOWN ──► Webhook ──► Telegram Alert 🔴
Tunnel UP   ──► Webhook ──► Telegram Alert 🟢
```

### BGP Hijack (CRITICAL)

```
Cloudflare Route Leak Detection ──► Webhook ──► Telegram Alert 🚨🚨🚨
                                                      │
                                          AZIONE IMMEDIATA RICHIESTA
```

---

## Log Files

| Log | Path | Descrizione |
|-----|------|-------------|
| Application | `/root/Cloudflare_MT_Integration/logs/webhook.log` | Log applicazione |
| Webhooks Raw | `/root/Cloudflare_MT_Integration/logs/webhooks/*.json` | Payload JSON (debug) |
| Systemd | `journalctl -u cloudflare-webhook` | Log systemd |

### Monitoraggio

```bash
# Log applicazione tempo reale
tail -f /root/Cloudflare_MT_Integration/logs/webhook.log

# Log systemd tempo reale
journalctl -u cloudflare-webhook -f

# Ultimi webhook ricevuti
ls -lt /root/Cloudflare_MT_Integration/logs/webhooks/ | head -10

# Cercare specifico alert type
grep "bgp_hijack" /root/Cloudflare_MT_Integration/logs/webhook.log

# Contare webhook per tipo oggi
grep "$(date +%Y-%m-%d)" /root/Cloudflare_MT_Integration/logs/webhook.log | grep "Webhook received" | awk -F'Type: ' '{print $2}' | cut -d' ' -f1 | sort | uniq -c
```

---

## Testing

### Health Check
```bash
curl -s https://lg.goline.ch/mt-health | jq
```

### Test con Payload Salvato
```bash
# Usa un webhook salvato
curl -s -X POST http://localhost:8080/webhook/cloudflare \
  -H "Content-Type: application/json" \
  -d @/root/Cloudflare_MT_Integration/logs/webhooks/webhook_20260119_000123.json
```

### Test Endpoint Interno
```bash
curl -s -X POST http://localhost:8080/test/attack \
  -H "Content-Type: application/json" \
  -d '{"type": "advanced_ddos_attack_l4_alert", "event": "ALERT_STATE_EVENT_START"}'
```

### Simulare BGP Hijack
```bash
curl -s -X POST https://lg.goline.ch/webhook/cloudflare \
  -H "Content-Type: application/json" \
  -H "cf-webhook-auth: YOUR_WEBHOOK_SECRET" \
  -d '{
    "name": "Test BGP Hijack",
    "alert_type": "bgp_hijack_notification",
    "data": {
      "alert_title": "TEST - BGP Hijack",
      "alert_priority_level": "CRITICAL",
      "prefix_configured": "185.54.80.0/22",
      "prefix_hijacked": "185.54.82.0/24",
      "hijack_as": "AS99999",
      "ASNs_seen": ["99999"],
      "alert_start_time": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
      "additional_info": "TEST ALERT",
      "dashboard_link": "dash.cloudflare.com/test",
      "account_name": "GOLINE SA"
    }
  }'
```

---

## Troubleshooting

### Servizio non attivo
```bash
systemctl status cloudflare-webhook
journalctl -u cloudflare-webhook -n 50 --no-pager
```

### Webhook non ricevuti
1. Verificare Apache: `systemctl status apache2`
2. Verificare ProxyPass: `apachectl -t`
3. Testare connettività: `curl https://lg.goline.ch/mt-health`

### Telegram non funziona
```bash
# Test diretto
curl -X POST "https://api.telegram.org/botYOUR_TELEGRAM_BOT_TOKEN/sendMessage" \
  -d "chat_id=YOUR_TELEGRAM_CHAT_ID" \
  -d "text=Test"
```

### Errore withdraw prefisso
1. Verificare vincolo 15 minuti
2. Controllare token API
3. Verificare prefix mapping

---

## Sicurezza

| Misura | Stato |
|--------|-------|
| HTTPS (TLS 1.2+) | ✅ Attivo |
| Webhook Secret | ✅ Configurato |
| Localhost only (Flask) | ✅ 127.0.0.1:8080 |
| Apache Reverse Proxy | ✅ Attivo |
| systemd hardening | ✅ ProtectSystem=strict |
| Auto-restart on crash | ✅ Restart=always |

---

## Configurazione Cloudflare

### 1. Creare Webhook Destination

1. **Cloudflare Dashboard** > **Notifications** > **Destinations**
2. **Create** > **Webhook**
3. Configurare:
   - **Name**: `GOLINE Magic Transit Webhook`
   - **URL**: `https://lg.goline.ch/webhook/cloudflare`
   - **Secret**: `YOUR_WEBHOOK_SECRET`

### 2. Creare Notification Policies

Per ogni alert type desiderato:

1. **Notifications** > **Create**
2. Selezionare alert type
3. Selezionare webhook destination
4. Salvare

**Alert types raccomandati**:
- Advanced Layer 3/4 DDoS Attack Alert
- HTTP DDoS Attack Alert
- Magic Transit Tunnel Health Alert
- Magic Network Monitoring: Volumetric Attack
- Magic Network Monitoring: DDoS Attack
- BGP Hijack Event Notification
- Cloudflare Status Alert
- Health Check Status Notification

---

## Database Integration

### Database Location

```
/root/Cloudflare_MT_Integration/db/magic_transit.db
```

### Tables Used by Webhook Receiver (v1.7.0)

| Table | Purpose | Status |
|-------|---------|--------|
| `attack_events` | Log START/END events | **Active** |
| `webhook_events` | Store all received webhooks | **Active** |
| `pending_withdrawals` | ~~Queue for scheduled withdrawals~~ | **Deprecated** |

> **Note v2.1.0**: La tabella `pending_withdrawals` non è più usata dal webhook receiver.
> I withdraw sono gestiti da `cloudflare-autowithdraw.service` che logga direttamente
> in `attack_events` e `withdrawal_history`.

### Alert Types che Salvano in Database (v1.9.0)

| Alert Type | Handler | Salva in `attack_events` |
|------------|---------|:------------------------:|
| `advanced_ddos_attack_l4_alert` | `handle_ddos_l4_attack()` | ✅ |
| `dos_attack_l4` | `handle_ddos_l4_attack()` | ✅ |
| `dos_attack_l7` | `handle_ddos_l7_attack()` | ✅ (v1.9.0) |
| `fbm_dosd_attack` | `handle_mnm_ddos_attack()` | ✅ (v1.7.0) |
| `fbm_volumetric_attack` | `handle_volumetric_attack()` | ✅ (v1.7.0) |
| `fbm_auto_advertisement` | `handle_auto_advertisement()` | ✅ (v1.8.0) |
| `magic_tunnel_health_check_event` | `handle_tunnel_health()` | ✅ (v1.9.0) |
| `incident_alert` | `handle_incident_alert()` | ✅ (v1.9.0) |
| `health_check_status_notification` | `handle_health_check_alert()` | ✅ (v1.9.0) |
| `bgp_hijack_notification` | `handle_bgp_hijack_alert()` | ✅ (v1.9.0) |

> **Note v1.9.0**: A partire dalla versione 1.9.0, **TUTTI** gli alert types vengono
> salvati in `attack_events` e appaiono nella sezione "DDoS Protection Log" della dashboard.

### Differenza: attack_events vs network_analytics_events

| Tabella | Fonte Dati | Cosa Contiene |
|---------|------------|---------------|
| `attack_events` | Webhook receiver | Alert DDoS, MNM triggers, azioni manuali |
| `network_analytics_events` | GraphQL polling | Traffico **effettivamente droppato** da Cloudflare |

**Importante**: Un alert MNM (`fbm_dosd_attack`) può essere ricevuto anche se il prefix
NON è advertised. In questo caso Cloudflare rileva il traffico anomalo via sFlow ma
non può mitigarlo. L'evento apparirà in "Recent Attacks" ma NON in "Network Analytics"
(che mostra solo traffico realmente droppato).

### Attack END Workflow (v2.1.0)

```
Attack END received
       │
       ├──► Log to attack_events (event_type='END')
       │
       └──► Send Telegram notification
            (withdraw delegated to autowithdraw daemon)
```

### Related Documentation

- [AUTOWITHDRAW.md](AUTOWITHDRAW.md) - BGP withdraw manager
- [DATABASE.md](DATABASE.md) - Complete database schema

---

## Changelog

### v1.9.0 (2026-01-23) - COMPLETE DATABASE LOGGING
- **NEW**: ALL alert types now saved to `attack_events` database
  - `handle_ddos_l7_attack()` - L7 DDoS attacks now saved
  - `handle_tunnel_health()` - Tunnel health events now saved
  - `handle_incident_alert()` - Cloudflare incidents now saved
  - `handle_health_check_alert()` - Health check status now saved
  - `handle_bgp_hijack_alert()` - BGP hijack alerts now saved (critical!)
- **Dashboard**: Complete event history now visible in "DDoS Protection Log"
- **Before**: Only some events were saved (97 webhooks received, 49 saved)
- **After**: ALL webhook events are logged to database

### v1.8.0 (2026-01-21) - AUTO-ADVERTISEMENT LOGGING
- **NEW**: `fbm_auto_advertisement` events now saved to database
  - Logged as `event_type='ADVERTISE'` with `action_taken='auto_advertised'`
  - Shows complete attack lifecycle: ADVERTISE → ATTACK → WITHDRAW
- **CHANGED**: DDoS L4 attacks (`dos_attack_l4`, `advanced_ddos_attack_l4_alert`)
  - Now use `action_taken='mitigating'` instead of `'notified'`
  - Reflects that Cloudflare is actively mitigating the attack
- **db_manager.py v1.3.0**: Fixed `attack_vector` extraction
  - Uses `attack_type` as fallback if `attack_vector` not present (MNM alerts)

### v1.7.0 (2026-01-21) - MNM DATABASE LOGGING
- **FIX**: MNM alerts now saved to `attack_events` database
  - `fbm_dosd_attack` (MNM DDoS Attack) - Added `log_attack_event()` call
  - `fbm_volumetric_attack` (Volumetric Attack) - Added `log_attack_event()` call
- **Dashboard**: MNM alerts now appear in "Recent Attacks" section
- **Before**: MNM alerts only sent Telegram notifications, not visible in dashboard
- **Root Cause**: `handle_mnm_ddos_attack()` and `handle_volumetric_attack()` were missing database logging

### v2.0.0 (2026-01-19) - UNIFIED ARCHITECTURE
- **BREAKING CHANGE**: Webhook receiver no longer performs BGP withdrawals
- Removed: `add_pending_withdrawal` import and usage
- Removed: All withdraw logic from `handle_attack_end()`
- Changed: `handle_attack_end()` now only sends notifications
- Updated: Telegram message to inform that withdraw is handled by autowithdraw
- All BGP withdrawals are now handled by `cloudflare-autowithdraw.service`

### v1.6.0 (2026-01-19)
- **High Availability**: Systemd protections + unified watchdog
- `StartLimitBurst=5`, `StartLimitIntervalSec=300`
- Cron watchdog: `/etc/cron.d/cloudflare-services-watchdog`
- Telegram alerts on service restart/failure

### v1.5.0 (2026-01-19)
- **Database Integration**: SQLite database for persistent state
- Attack events logged to `attack_events` table
- Pending withdrawals stored in `pending_withdrawals` table
- Automatic scheduled withdrawals via cron job (every 5 minutes)
- New script: `cloudflare-check-pending-withdrawals.py`
- New module: `db_manager.py`

### v1.4.0 (2026-01-19)
- **Unified Telegram header**: All notifications now start with `🛡️ *CLOUDFLARE DDoS PROTECTION*`
- Consistent branding across all 11 alert types
- Updated all handler functions with new header format

### v1.3.0 (2026-01-19)
- Added 11 alert types (from 2 to 11)
- New handlers for incident, health check, BGP hijack
- SOC-style Telegram formatting

---

*Documentation v2.3.0 - 2026-01-23 - GOLINE SA*
