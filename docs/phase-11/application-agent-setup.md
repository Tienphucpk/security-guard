# Application Agent & Middleware Integration Guide

## 1. Overview
The Security Guard Application Agent is a lightweight, non-intrusive middleware package embedded directly within web applications. It streams telemetry asynchronously without blocking client responses.

---

## 2. Express.js (Node.js) Agent

### Installation
Copy `agents/node-agent/index.js` into your project or install the package:
```bash
npm install --save ./agents/node-agent
```

### Integration
```javascript
const express = require('express');
const { securityGuardAgent } = require('@security-guard/node-agent');

const app = express();

// Register the agent middleware at the top of your middleware stack
app.use(securityGuardAgent({
  websiteId: process.env.SECURITY_GUARD_WEBSITE_ID || 'site_prod_blog',
  agentSecret: process.env.SECURITY_GUARD_SECRET || 'secguard_ag_your_secret_key',
  collectorUrl: process.env.SECURITY_GUARD_URL ? `${process.env.SECURITY_GUARD_URL}/api/ingest/events` : 'http://localhost:3000/api/ingest/events',
  maxQueueSize: 500, // Drop oldest if queue exceeds limit (bounded memory)
  timeoutMs: 3000,   // HTTP timeout for event dispatch
  maxRetries: 2      // Max retry attempts on dispatch failure
}));

app.get('/api/articles', (req, res) => {
  res.json({ articles: ['Intro to Cybersecurity', 'WAF Architecture'] });
});

app.listen(3000);
```

---

## 3. Cryptographic Replay Protection (HMAC-SHA256)

Every telemetry packet forwarded by the Application Agent includes an authentication signature:
- **Header**: `X-Agent-Signature: t=<unix_timestamp_sec>,v1=<hmac_sha256_hex>`
- **Header**: `X-Website-Id: <website_id>`
- **String to Sign**: `<unix_timestamp_sec>.<json_string_payload>`

### Server-Side Verification:
1. Server retrieves stored `encrypted_agent_secret` for `X-Website-Id`.
2. Decrypts AES-256-GCM envelope in memory using server vault key.
3. Checks `|now - timestamp| <= 300s` (5-minute maximum window). Reject stale packets to prevent replay attacks.
4. Computes expected HMAC-SHA256 and validates using constant-time string comparison (`crypto.timingSafeEqual`).

---

## 4. Failure Mode & Resilience
- **Fail-Safe Asynchronous Dispatch**: Event dispatch hooks into Express `res.on('finish')`. The host application's HTTP response is sent immediately to the user without waiting for the Security Guard collector.
- **Bounded Buffer**: In-memory event queue is capped at `maxQueueSize` (default: 500 entries). If the collector is temporarily unavailable, older items are dropped to prevent memory leaks.
- **Circuit Protection**: Retries are throttled with exponential backoff and capped at `maxRetries` (default: 2).
