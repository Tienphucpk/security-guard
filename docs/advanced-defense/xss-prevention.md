# Practical Prevention: Cross-Site Scripting (XSS) Defense In-Depth

## 1. Vulnerability Analysis & Attack Vectors

Cross-Site Scripting (XSS) occurs when untrusted input is included in dynamic web pages without adequate validation or context-aware output encoding, allowing malicious client-side JavaScript to execute within the victim's session.

### 1.1 Evaluated Vectors
1. **Reflected XSS**: `<script>alert(document.cookie)</script>`
2. **Event Handler Injection**: `<img src=x onerror=alert(1)>`, `<svg/onload=confirm(1)>`
3. **DOM-based & Pseudo-Protocol**: `javascript:alert(1)`, `data:text/html;base64,...`
4. **Encoding Evasions**:
   - Nested HTML entities: `&lt;script&gt;alert(1)&lt;/script&gt;`
   - Case & Space Obfuscation: `<sCrIpt >`, `<iframe/src="javascript:...">`
   - Double URL Encoding: `%253Cscript%253E`

---

## 2. In-Line Gateway & WAF Defense (SECURITY GUARD Implementation)

SECURITY GUARD provides autonomous gateway-level filtering before malicious payloads reach the upstream service:

```
[Attacker Client]
       |
       v (HTTP GET /comment?text=<script>alert(1)</script>)
+--------------------------------------------------------------+
| Security Guard Gateway (Port 8080)                           |
| 1. Normalization: Decode entities & double URL encoding      |
| 2. Detection Engine: Pattern match on <script, onerror=, etc.|
| 3. Adaptive Risk Scorer: Severity HIGH (Score: 75.0 - 87.0)  |
+--------------------------------------------------------------+
       |
      / \
[ENFORCE Mode]       [MONITOR_ONLY Mode]
     /                     \
    v                       v
403 Forbidden          Forward to Upstream
Dropped at Gateway     Rendered to Victims if Unsanitized
```

### 2.1 Gateway Response in ENFORCE Mode
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json
X-Security-Guard-Enforced: BLOCK

{
  "status": "blocked",
  "error": "Forbidden by Security Guard",
  "website_id": "site_demo_node",
  "reason": "Detected Attack [XSS_ATTACK]: Cross-site scripting (XSS) payload detected in URL or parameters",
  "mode": "ENFORCE",
  "matched_rule": "XSS_ATTACK"
}
```

---

## 3. Application-Layer Remediation vs. Gateway Filtering

Perimeter inspection at the Gateway is a valuable **outer defense**, but true remediation requires **Context-Aware Output Encoding** and strict **Content Security Policy (CSP)** at the application layer:

| Dimension | Gateway / WAF Perimeter Defense (SECURITY GUARD) | Application-Layer Output Encoding & CSP |
|---|---|---|
| **Mechanism** | String and regex filtering of common injection patterns. | Context-aware sanitization of output characters + browser execution restrictions. |
| **Context Awareness** | **Low**; cannot know if input will be rendered in HTML Body, Attribute, JavaScript literal, or CSS context. | **Complete**; encoder applies context-specific character translations. |
| **Bypass Potential** | Moderate; novel DOM-based sinks and mutation XSS (mXSS) may slip past regex. | Very Low when standard libraries (`DOMPurify`, `he`, `DOMPurify.sanitize`) are used. |
| **Defense Depth** | Stops network transmission of attack before upstream processing. | Neutralizes malicious payload even if it resides in the database. |

### 3.1 Recommended Context-Aware Remediation

#### HTML Body Context:
Translate `<`, `>`, `&`, `"`, `'` to their corresponding HTML character entities:
```javascript
function encodeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}
```

#### Content Security Policy (CSP) Headers:
Enforce browser-level execution policies in Express.js via `helmet`:
```javascript
const helmet = require('helmet');

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"], // Disallow 'unsafe-inline' and 'unsafe-eval'
    objectSrc: ["'none'"],
    upgradeInsecureRequests: [],
  }
}));
```

#### Modern Framework Auto-Escaping:
Modern frontend frameworks like React automatically escape expressions embedded in JSX (`<div>{userInput}</div>`), neutralizing classic reflected XSS unless `dangerouslySetInnerHTML` is explicitly invoked.

---

## 4. Verification Matrix

| Scenario | Payload | Mode | Status | Defense Mechanism |
|---|---|---|---|---|
| Reflected Script | `?q=<script>alert(1)</script>` | ENFORCE | 403 Forbidden | Dropped at Gateway |
| Event Handler | `?img=<img src=x onerror=alert(1)>` | ENFORCE | 403 Forbidden | Dropped at Gateway |
| Entity Obfuscation | `?input=&lt;script&gt;` | ENFORCE | 403 Forbidden | De-obfuscated & Dropped |
| Benign Text | `?q=Hello World & Welcome` | ENFORCE | 200 OK | Allowed (Risk < 15) |
| Passive Monitor | `?q=<script>alert(1)</script>` | MONITOR_ONLY | 200 OK | Forwarded with Alert |
