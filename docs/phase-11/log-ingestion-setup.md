# Passive Log Ingestion Setup Guide

## 1. Overview
Log Ingestion provides zero-code, passive monitoring for web servers (Nginx, Apache, Caddy) or log forwarders (Fluentd, Logstash, Vector).

---

## 2. Supported Formats

### Format 1: Nginx Combined Log Format
```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```
*Example line:*
```
198.51.100.12 - - [10/Oct/2026:13:55:36 +0700] "GET /api/user?token=secret123 HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"
```

### Format 2: Apache Common Log Format
```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
```
*Example line:*
```
203.0.113.5 - - [10/Oct/2026:14:02:10 +0700] "POST /login HTTP/1.1" 401 512
```

### Format 3: JSON Lines (NDJSON)
```json
{"timestamp":"2026-10-29T14:00:00Z","ip":"198.51.100.42","method":"POST","url":"/admin/login","statusCode":401,"responseTime":45.2,"userAgent":"curl/7.88"}
```

---

## 3. Ingestion API Endpoint

- **URL**: `POST http://localhost:3000/api/ingest/logs`
- **Headers**:
  - `Content-Type: text/plain` (or `application/json`)
  - `X-Website-Id: <registered_website_id>`
  - `X-Agent-Secret: <plaintext_secret>` (or `X-Agent-Signature: t=<ts>,v1=<sig>`)
- **Body**: Plaintext log file or JSON array. Max size: 5MB per batch.

### Example: Ingestion via cURL
```bash
curl -X POST "http://localhost:3000/api/ingest/logs" \
  -H "X-Website-Id: site_prod_blog" \
  -H "X-Agent-Secret: secguard_ag_your_secret_here" \
  -H "Content-Type: text/plain" \
  --data-binary @/var/log/nginx/access.log
```

### Sample API Response:
```json
{
  "status": "success",
  "websiteId": "site_prod_blog",
  "totalReceived": 250,
  "parsedCount": 248,
  "insertedCount": 248,
  "duplicatesSkipped": 2,
  "errorCount": 0,
  "errors": []
}
```

---

## 4. Deduplication & Sanitization
1. **Deduplication**: Hashes `websiteId + timestamp + ip + method + url + statusCode`. Duplicate records submitted in repeated batch uploads are automatically deduplicated.
2. **IP Normalization**: Strips ports and converts IPv4-mapped IPv6 (`::ffff:192.0.2.1` -> `192.0.2.1`).
3. **Passive Label**: Telemetry entries are marked with `isPassive: true` to indicate passive observation.
