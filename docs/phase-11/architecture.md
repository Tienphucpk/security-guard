# Phase 11 — External Website Integration Architecture

## 1. System Overview

Security Guard Phase 11 expands the monitoring and active enforcement perimeter from built-in demo targets to arbitrary external websites across heterogeneous environments.

```mermaid
flowchart TD
    subgraph Clients["Clients & Attack Traffic"]
        A1[Client / Attacker]
        A2[App End Users]
    end

    subgraph IntegrationLayer["Heterogeneous Integration Methods"]
        direction TB
        subgraph RP["1. Reverse Proxy Gateway (Port 8080)"]
            GW[Gateway Reverse Proxy]
            SSRF[SSRF & DNS Boundary]
        end
        subgraph AG["2. Application Agent"]
            MW[Express / WSGI Middleware]
            QUEUE[Bounded Memory Queue]
            HMAC[HMAC-SHA256 Signer]
        end
        subgraph LI["3. Passive Log Ingestion"]
            SHIPPER[Nginx / Apache / Fluentd / Vector]
        end
    end

    subgraph SecurityGuardCore["Security Guard Core Platform"]
        WA[Web Application - Port 3000]
        PE[Policy Engine & Rate Limiter]
        DB[(PostgreSQL - Port 5432)]
        DE[FastAPI Detection Engine - Port 5000]
        DASH[React Dashboard - Port 5173]
    end

    A1 -->|HTTP/HTTPS| GW
    GW --> SSRF
    SSRF -->|SSRF-Protected Forward| EXT_RP[External Web Server 1]
    GW <-->|Policy Decision & Telemetry| WA

    A2 -->|HTTP/HTTPS| EXT_APP[External Web Server 2]
    EXT_APP --> MW
    MW --> QUEUE --> HMAC -->|POST /api/ingest/events| WA

    SHIPPER -->|POST /api/ingest/logs| WA

    WA <--> DB
    WA -->|Forward Log| DE
    WA -->|SSE Stream| DASH
```

---

## 2. Integration Archetypes

| Method | Traffic Flow | Active Enforcement Support | Invasiveness | Best Suited For |
| :--- | :--- | :--- | :--- | :--- |
| **REVERSE_PROXY** | In-line via Gateway (8080) | **Yes** (Instant 403 Forbidden drop) | Non-invasive (DNS routing only) | Legacy systems, unmodifiable apps, APIs |
| **APPLICATION_AGENT** | Out-of-band asynchronous | Observability & Policy alerting | Low (single middleware line) | Modern Express/Flask/Django services |
| **LOG_INGESTION** | Passive batch ingestion | Passive detection only | Zero (log shipper daemon) | Nginx/Apache clusters, cloud log streams |

---

## 3. Data Protection & Sensitive Field Redaction

All data entering the telemetry ingestion pipeline undergoes automatic sanitization before persistence and forward propagation:
1. **Query Parameters**: Parameters matching `password`, `token`, `secret`, `api_key`, `auth`, `cookie`, `credit_card` are scrubbed and replaced with `[REDACTED]`.
2. **Payload Bodies**: JSON payloads are recursively traversed, replacing sensitive keys while preserving structure and length metrics for ML feature extraction.
3. **URL Normalization**: URLs are decoded, normalized, and trimmed of trailing delimiters to prevent pattern evasion.

---

## 4. SSRF & DNS Rebinding Hardening

External website proxying is guarded by `ssrfValidator.js`:
- Prohibits non-routable, link-local, loopback, and private IPv4 ranges: `0.0.0.0/8`, `10.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`.
- Prohibits cloud metadata endpoints: `169.254.169.254` (AWS, GCP, Azure, OpenStack).
- Prohibits IPv6 private / link-local: `::1`, `fc00::/7`, `fe80::/10`.
- Inspects all resolved IP addresses returned by DNS queries before issuing upstream sockets.
