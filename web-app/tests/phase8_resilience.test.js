/**
 * Phase 8 Resilience & Security Validation Test Suite
 * Tests input validation, payload size limits, security headers,
 * error sanitization, and failure recovery.
 */

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const app = require('../src/server');

let server;
let baseUrl;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });
});

test.after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('Phase 8.2 - Security Headers: Response contains defensive security headers', async () => {
  const res = await fetch(`${baseUrl}/api/health`);
  assert.strictEqual(res.status, 200);

  const headers = res.headers;
  assert.strictEqual(headers.get('x-content-type-options'), 'nosniff');
  assert.strictEqual(headers.get('x-frame-options'), 'SAMEORIGIN');
  assert.strictEqual(headers.get('x-xss-protection'), '1; mode=block');
  assert.strictEqual(headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
});

test('Phase 8.2 - Payload Limits: Request body exceeding 1MB returns 413 Payload Too Large', async () => {
  // Generate a payload slightly larger than 1MB
  const massiveBody = JSON.stringify({ data: 'A'.repeat(1024 * 1024 + 1024) });

  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: massiveBody
  });

  assert.strictEqual(res.status, 413);
  const data = await res.json();
  assert.strictEqual(data.status, 413);
  assert.strictEqual(data.error, 'Payload Too Large');
});

test('Phase 8.2 - Malformed JSON Handling: Malformed JSON in request returns 400 Bad Request', async () => {
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{"invalid_json": true,' // Syntax error
  });

  // Express body-parser returns 400 for JSON syntax errors
  assert.strictEqual(res.status, 400);
});

test('Phase 8.3 - SSE Disconnect & Reconnect: Client can connect, disconnect, and reconnect cleanly', async () => {
  // 1. First connection
  const res1 = await fetch(`${baseUrl}/api/alerts/stream`, {
    headers: { Accept: 'text/event-stream' }
  });
  assert.strictEqual(res1.status, 200);
  assert.strictEqual(res1.headers.get('content-type'), 'text/event-stream');

  const reader1 = res1.body.getReader();
  const { value: val1 } = await reader1.read();
  const text1 = new TextDecoder().decode(val1);
  assert.ok(text1.includes('event: connected'));
  await reader1.cancel(); // Disconnect client 1

  // Small delay to allow cleanup
  await new Promise((r) => setTimeout(r, 100));

  // 2. Reconnection by a new client
  const res2 = await fetch(`${baseUrl}/api/alerts/stream`, {
    headers: { Accept: 'text/event-stream' }
  });
  assert.strictEqual(res2.status, 200);
  const reader2 = res2.body.getReader();
  const { value: val2 } = await reader2.read();
  const text2 = new TextDecoder().decode(val2);
  assert.ok(text2.includes('event: connected'));
  await reader2.cancel(); // Clean up client 2
});

test('Phase 8.3 - Database Resilience: Invalid Alert ID returns 404 cleanly without 500 crash', async () => {
  const res = await fetch(`${baseUrl}/api/alerts/999999999`);
  assert.strictEqual(res.status, 404);
  const data = await res.json();
  assert.strictEqual(data.status, 'error');
});
