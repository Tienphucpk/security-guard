# Comprehensive Security Review & Threat Model

## 1. Threat Model & Trust Boundaries

The security posture of SECURITY GUARD was assessed against potential adversary actions targeting both protected upstreams and the security system itself.

```
Untrusted Internet / Attacker
            |
            | (Perimeter Boundary)
            v
[Gateway :8080]  <--- X-Gateway-Secret --->  [Web App :3000]
            |                                       |
            | Private Lab Subnet                    | Internal Localhost
            v                                       v
[Upstream Apps]                        [Detection Engine :5000]
                                                    |
                                                    v
                                         [PostgreSQL DB :5432]
```

### Trust Zones:
1. **Perimeter Boundary**: Incoming public client traffic to Port 8080. Untrusted.
2. **Control Plane**: Port 3000 (Web App). Requires server-side session authentication (`HttpOnly` cookie) with RBAC (`ADMIN` vs `ANALYST`) or Gateway Agent Secret.
3. **Internal Detection Plane**: Port 5000 (Python Uvicorn). Bound strictly to `127.0.0.1`.
4. **Data Plane**: PostgreSQL Port 5432. Bound strictly to `127.0.0.1`.

---

## 2. Server-Side Request Forgery (SSRF) Defense

When administrators register external upstream URLs (`POST /api/websites/external`), the system executes a multi-layer SSRF validation pipeline (`web-app/src/services/ssrfValidator.js`):
1. **Scheme Validation**: Whitelists strictly `http:` and `https:`. Rejects `file:`, `gopher:`, `ftp:`, `dict:`.
2. **Credential Stripping**: Rejects URLs containing inline user credentials (`user:pass@host`).
3. **Hostname Filtering**: Rejects `localhost`, `*.local`, `*.internal`, and link-local keywords.
4. **DNS Resolution & Subnet Masking**: Resolves all A and AAAA records and verifies against banned subnets:
   - Loopback: `127.0.0.0/8`, `::1`
   - Private RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Link-Local: `169.254.0.0/16`, `fe80::/10`
   - Cloud Metadata Service: `169.254.169.254` (AWS, GCP, Azure metadata endpoints strictly blocked).
5. **DNS Rebinding Prevention**: Gateway re-validates DNS records prior to socket connection.

---

## 3. Fail-Open vs. Fail-Closed Resilience Policy

In high-availability web architectures, a critical design question is handling detector or policy engine outages:
- **Decision Engine Timeout**: Default timeout is strictly capped at `600ms`.
- **Resilience Policy**:
  - If the Python Detection Engine or Policy Engine is temporarily offline, the Gateway adopts a **Fail-Open Strategy for Monitored Sites** (`degraded: true`).
  - **Rationale**: An availability outage in the anomaly monitoring subsystem must not result in an unintended Denial of Service against legitimate customer traffic.
  - A persistent degraded health indicator is broadcast via SSE to alert SOC operators immediately.

---

## 4. Credential & Evidence Protection (Zero Secret Leakage)

1. **Password Hashing**: User credentials in PostgreSQL are hashed using `scrypt` with unique cryptographic salts.
2. **Session Security**: Session tokens use signed `HttpOnly`, `SameSite=Lax` cookies, preventing XSS-based session hijacking.
3. **Secret Redaction**:
   - `requestNormalizer.sanitizeHeaders()` strips `Authorization`, `Cookie`, `Set-Cookie`, and API keys before saving request logs or detection evidence.
   - Plaintext agent secrets are displayed only once upon generation and hashed with SHA-256 before storage.
