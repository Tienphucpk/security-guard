# Phase 11 — Security & Risk Analysis Review

## 1. Threat Modeling & Defensive Controls

| Threat Scenario | Vulnerability / Attack Surface | Defensive Countermeasure Implemented |
| :--- | :--- | :--- |
| **SSRF / Cloud Metadata Theft** | Reverse proxy configured to query internal services or AWS metadata (`169.254.169.254`). | Strict IP parser rejects loopback, RFC1918, link-local, multicast, and metadata IPs before socket connection. |
| **DNS Rebinding Attack** | Domain initially resolves to public IP, then switches to internal IP (`127.0.0.1`). | Full DNS resolution inspects all returned A/AAAA records immediately prior to request dispatch. |
| **Agent Secret Compromise** | Secret leaked in codebase or logs. | Secret is never logged; database stores only SHA-256 hash and AES-256-GCM encrypted envelope; rotation invalidates old key instantly. |
| **Replay Attack on Agent Telemetry** | Attacker intercepts network packet and resends it to poison detection metrics. | Timestamp checking enforces a strict 300-second window (`MAX_TIMESTAMP_SKEW_SEC = 300`). Outdated signatures are rejected. |
| **Buffer Exhaustion / DoS** | Target server unavailable causing memory explosion in agent. | In-memory queue is bounded (`maxQueueSize = 500`). Oldest packets are dropped when queue fills up. |
| **Privilege Escalation** | Analyst or Operator attempts to add/delete websites or rotate secrets. | RBAC middleware enforces `requireRole(['ADMIN'])` on all website registration, modification, policy creation, and secret rotation endpoints. |

---

## 2. Fail-Open vs. Fail-Closed Architectural Policy

### Enforcement Gateway (Port 8080)
- **Policy Engine Reachable**:
  - `MONITOR_ONLY` mode: Requests are inspected and forwarded. Alerts are generated; client is never blocked.
  - `ENFORCE` mode: Requests matching detection signatures or custom block rules are terminated immediately with **HTTP 403 Forbidden**.
- **Policy Engine Unreachable / Timeout**:
  - The Gateway adopts a **Fail-Open** stance for traffic availability to ensure business continuity during diagnostic engine restarts, while tagging audit logs with `degraded: true`.

### Application Agent Middleware
- **Collector Unreachable**:
  - The agent silently queues events up to 500 entries and retries up to 2 times with backoff.
  - If the collector remains unreachable, excess events are safely discarded. The host application's HTTP response is **never blocked or delayed**.
