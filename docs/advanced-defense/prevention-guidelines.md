# Defense & Prevention Guidelines: Path Traversal, Command Injection & Brute Force

This document outlines the vulnerability analysis, detection mechanisms, application-level remediation, and infrastructure controls for Path Traversal, Command Injection, and Brute Force attacks.

---

## 1. Path Traversal (Directory Traversal)

### 1.1 Root Cause & Exploit Mechanics
Path Traversal occurs when user input is used to construct file paths without strict canonicalization or directory whitelisting, allowing attackers to access arbitrary files on the server (e.g. `../../../../etc/passwd` or `..\..\..\windows\win.ini`).

Attackers leverage:
- Relative sequence traversal: `../`, `..\`
- URL encoding: `%2e%2e%2f`, `%252e%252e%252f` (double encoded)
- Null byte poisoning (historical): `../../file.txt%00.png`

### 1.2 SECURITY GUARD Detection Implementation
In SECURITY GUARD's Python Detection Engine (`rules/path_traversal.json`):
- Rule Code: `RULE-TRAV-001`
- Severity: `HIGH` (Base score: 75.0)
- Patterns: `../`, `..\\`, `..%2f`, `..%5c`, `%2e%2e%2f`, `%2e%2e/`
- In Gateway ENFORCE mode, detected path traversal requests return `403 Forbidden`.

### 1.3 Application-Level Defense & Secure Implementation
Never concatenate unsanitized user inputs into file system operations.

#### Vulnerable Code:
```javascript
// DANGEROUS: User can supply "../../etc/passwd"
const filePath = path.join('/var/www/uploads', req.query.file);
const content = fs.readFileSync(filePath);
```

#### Secure Remediation:
1. Canonicalize with `path.resolve()`.
2. Verify that the resolved absolute path starts with the intended base directory.
```javascript
const BASE_DIRECTORY = path.resolve('/var/www/uploads');

function getSafeFilePath(userInput) {
  // 1. Resolve absolute canonical path
  const safePath = path.resolve(BASE_DIRECTORY, userInput);
  
  // 2. Path containment check
  if (!safePath.startsWith(BASE_DIRECTORY + path.sep)) {
    throw new Error('Access Denied: Path Traversal Attempt');
  }
  return safePath;
}
```

### 1.4 Infrastructure & Operating System Defense
- Run web processes under dedicated unprivileged service accounts (`nobody`, `appuser`).
- Apply `chroot` jails or containerized namespaces (Docker / Linux namespaces) to limit reachable directories.
- Mount sensitive system directories as read-only.

---

## 2. OS Command Injection

### 2.1 Root Cause & Exploit Mechanics
Command Injection arises when untrusted data is passed to system shell interpreters (e.g., `bash`, `sh`, `cmd.exe`, `powershell.exe`) via functions like `child_process.exec()` or `os.system()`, allowing attackers to execute arbitrary system commands using metacharacters (`;`, `|`, `&&`, `` ` ``, `$()`).

### 2.2 SECURITY GUARD Detection Implementation
In SECURITY GUARD's Detection Engine (`rules/command_injection.json`):
- Rule Code: `RULE-CMDI-001`
- Severity: `CRITICAL` (Base score: 90.0)
- Signatures: `; ls`, `| cat`, `&& whoami`, `| dir`, `powershell`, `/bin/sh`, `; rm`
- In Gateway ENFORCE mode, detected attempts return `403 Forbidden` and trigger active blocking.

### 2.3 Application-Level Defense & Secure Implementation

#### Anti-Pattern:
```javascript
// DANGEROUS: Invokes system shell; user can supply "8.8.8.8; cat /etc/passwd"
child_process.exec(`ping -c 4 ${req.body.ip}`);
```

#### Secure Remediation:
1. Avoid shell invocation altogether: use dedicated programming language APIs or libraries.
2. If binary execution is strictly required, use `execFile` or `spawn` without shell invocation (`shell: false`), passing arguments as a separated string array:
```javascript
const { execFile } = require('child_process');

// Validate IP format strictly using regex or net.isIP()
if (!net.isIP(req.body.ip)) {
  throw new Error('Invalid IP address');
}

// Executes binary directly without passing through a shell interpreter
execFile('/bin/ping', ['-c', '4', req.body.ip], { shell: false }, (err, stdout) => {
  // Handle results safely
});
```

### 2.4 Infrastructure & Operating System Defense
- AppArmor / SELinux profiles restricting which binaries web processes can launch.
- Read-only root filesystems for containerized workloads.
- Minimalist container images (distroless) lacking shell binaries (`/bin/sh`, `/bin/bash`).

---

## 3. Credential Stuffing & Brute Force Attacks

### 3.1 Root Cause & Exploit Mechanics
Automated bots rapidly attempt authentication with wordlists or credential dumps to compromise user accounts. The vulnerability stems from lack of rate limiting, absence of account lockout, and predictable login feedback.

### 3.2 SECURITY GUARD Detection Implementation
In SECURITY GUARD's Detection Engine:
- Rule Code: `RULE-BRUTE-001`
- Tracked sliding window: Monitors consecutive failed authentications or rapid identical requests from single IP / target user within 60 seconds.
- Synergistic Isolation Forest anomaly: Repeated identical burst requests exhibit statistical frequency outlier properties.

### 3.3 Application-Level Defense & Secure Implementation
1. **Exponential Backoff & Rate Limiting**: Apply sliding window limits via Redis or in-memory token buckets (e.g. `express-rate-limit`):
   ```javascript
   const rateLimit = require('express-rate-limit');
   
   const loginLimiter = rateLimit({
     windowMs: 15 * 60 * 1000, // 15 minutes
     max: 5, // Maximum 5 attempts per IP
     message: { status: 'error', message: 'Too many login attempts. Please try again after 15 minutes.' },
     standardHeaders: true,
     legacyHeaders: false
   });
   
   app.use('/api/auth/login', loginLimiter);
   ```
2. **Account Lockout Policy**: Increment failed login attempts; lock account after 5 consecutive failures for 30 minutes.
3. **Generic Error Responses**: Always respond with `"Invalid username or password"`, preventing username enumeration.
4. **Multi-Factor Authentication (MFA / TOTP)**: Require second-factor verification, neutralizing credential dumps.

### 3.4 Infrastructure Defense
- Web Application Firewall rate limiting at edge proxies (Cloudflare, Nginx `limit_req`).
- CAPTCHA / Proof of Work challenges triggered upon anomalous traffic scores.
