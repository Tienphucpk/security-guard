/**
 * Phase 9 - Authentication, Authorization & User Management Test Suite
 * Tests session lifecycle, HttpOnly cookies, rate limiting, RBAC,
 * alert mutation permissions, and user management APIs.
 */

const test = require('node:test');
const assert = require('node:assert');
const app = require('../src/server');
const db = require('../src/services/database');
const authController = require('../src/controllers/auth.controller');
const bootstrapAdmin = require('../src/scripts/bootstrap-admin');

let server;
let baseUrl;
let adminCookie;
let adminSessionId;
let analystCookie;
let analystSessionId;
let testAlertId;
let createdTestUserId;

test.before(async () => {
  // Ensure database has initial admin and analyst accounts
  await bootstrapAdmin();

  // Reset rate limiting map
  authController.resetLoginAttempts();

  // Start test server on random port
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });

  // Create a test alert
  try {
    const inserted = await db.insertSecurityAlert({
      timestamp: new Date().toISOString(),
      sourceIp: '127.0.0.1',
      method: 'GET',
      targetUrl: '/phase9-user-test',
      alertType: 'USER_AUTH_TEST',
      severity: 'HIGH',
      riskScore: 70.0,
      description: 'Phase 9 User Auth Alert',
      status: 'new'
    });
    testAlertId = inserted.id || 1;
  } catch {
    testAlertId = 1;
  }
});

test.after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
});

// ==============================================================================
// 1. Authentication Tests
// ==============================================================================

test('Auth 1: Login succeeds with valid username and password (ADMIN)', async () => {
  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'admin',
      password: 'Admin@123456'
    })
  });

  assert.strictEqual(res.status, 200);
  const data = await res.json();
  assert.strictEqual(data.status, 'success');
  assert.strictEqual(data.user.username, 'admin');
  assert.strictEqual(data.user.role, 'ADMIN');
  assert.strictEqual(data.user.password_hash, undefined, 'Password hash must never be returned');
  assert.ok(data.sessionId, 'Session ID must be returned');

  adminSessionId = data.sessionId;

  // Verify Set-Cookie header contains HttpOnly session
  const setCookie = res.headers.get('set-cookie');
  assert.ok(setCookie, 'set-cookie header must be present');
  assert.ok(setCookie.includes('secguard_session='), 'Cookie name must be secguard_session');
  assert.ok(setCookie.includes('HttpOnly'), 'Cookie must be HttpOnly');

  adminCookie = setCookie.split(';')[0];
});

test('Auth 2: Login succeeds with valid email address (ANALYST)', async () => {
  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'analyst@securityguard.local',
      password: 'Analyst@123456'
    })
  });

  assert.strictEqual(res.status, 200);
  const data = await res.json();
  assert.strictEqual(data.status, 'success');
  assert.strictEqual(data.user.username, 'analyst');
  assert.strictEqual(data.user.role, 'ANALYST');
  assert.strictEqual(data.user.password_hash, undefined);

  analystSessionId = data.sessionId;
  const setCookie = res.headers.get('set-cookie');
  analystCookie = setCookie.split(';')[0];
});

test('Auth 3: Login fails with incorrect password and returns safe 401 error', async () => {
  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'admin',
      password: 'WrongPassword999!'
    })
  });

  assert.strictEqual(res.status, 401);
  const data = await res.json();
  assert.strictEqual(data.status, 'error');
  assert.strictEqual(data.message, 'Invalid username or password');
});

test('Auth 4: Login fails with non-existent user and returns identical safe 401 error', async () => {
  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'non_existent_hacker_user_404',
      password: 'AnyPassword123'
    })
  });

  assert.strictEqual(res.status, 401);
  const data = await res.json();
  assert.strictEqual(data.status, 'error');
  // Must return the exact same generic message to prevent username enumeration
  assert.strictEqual(data.message, 'Invalid username or password');
});

test('Auth 5: Login with missing fields returns 400 Bad Request', async () => {
  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'admin'
      // missing password
    })
  });

  assert.strictEqual(res.status, 400);
  const data = await res.json();
  assert.strictEqual(data.status, 'error');
});

test('Auth 6: GET /api/auth/me returns current user info when authenticated via cookie', async () => {
  const res = await fetch(`${baseUrl}/api/auth/me`, {
    headers: {
      'Cookie': adminCookie
    }
  });

  assert.strictEqual(res.status, 200);
  const data = await res.json();
  assert.strictEqual(data.status, 'success');
  assert.strictEqual(data.user.username, 'admin');
  assert.strictEqual(data.user.role, 'ADMIN');
  assert.strictEqual(data.user.password_hash, undefined);
});

test('Auth 7: GET /api/auth/me returns current user when authenticated via Bearer token', async () => {
  const res = await fetch(`${baseUrl}/api/auth/me`, {
    headers: {
      'Authorization': `Bearer ${analystSessionId}`
    }
  });

  assert.strictEqual(res.status, 200);
  const data = await res.json();
  assert.strictEqual(data.status, 'success');
  assert.strictEqual(data.user.username, 'analyst');
  assert.strictEqual(data.user.role, 'ANALYST');
});

test('Auth 8: GET /api/auth/me without session returns 401 Unauthorized', async () => {
  const res = await fetch(`${baseUrl}/api/auth/me`);
  assert.strictEqual(res.status, 401);
});

test('Auth 9: Rate limiting triggers 429 Too Many Requests after 5 consecutive failed logins', async () => {
  authController.resetLoginAttempts();
  const testUser = 'rate_limit_victim';

  for (let i = 0; i < 5; i++) {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: testUser, password: 'WrongPassword' })
    });
    assert.strictEqual(res.status, 401);
  }

  // 6th attempt should be blocked with 429
  const blockedRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: testUser, password: 'AnyPassword' })
  });

  assert.strictEqual(blockedRes.status, 429);
  const data = await blockedRes.json();
  assert.strictEqual(data.error, 'Too Many Requests');

  // Clean up rate limiting map
  authController.resetLoginAttempts();
});

test('Auth 10: POST /api/auth/logout destroys session in database and clears cookie', async () => {
  // Create a temporary session to log out
  const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'analyst', password: 'Analyst@123456' })
  });
  const loginData = await loginRes.json();
  const tempCookie = loginRes.headers.get('set-cookie').split(';')[0];
  const tempSessionId = loginData.sessionId;

  // Logout
  const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
    method: 'POST',
    headers: { 'Cookie': tempCookie }
  });

  assert.strictEqual(logoutRes.status, 200);
  const clearCookieHeader = logoutRes.headers.get('set-cookie');
  assert.ok(clearCookieHeader.includes('secguard_session=;') || clearCookieHeader.includes('Expires=Thu, 01 Jan 1970'));

  // Subsequent call to /me using old session must be rejected with 401
  const meRes = await fetch(`${baseUrl}/api/auth/me`, {
    headers: { 'Cookie': tempCookie }
  });
  assert.strictEqual(meRes.status, 401);

  // Calling with bearer token also rejected
  const meBearerRes = await fetch(`${baseUrl}/api/auth/me`, {
    headers: { 'Authorization': `Bearer ${tempSessionId}` }
  });
  assert.strictEqual(meBearerRes.status, 401);
});

// ==============================================================================
// 2. Authorization & RBAC Tests
// ==============================================================================

test('RBAC 1: Unauthenticated request to acknowledge alert is rejected with 401', async () => {
  const res = await fetch(`${baseUrl}/api/alerts/${testAlertId}/acknowledge`, {
    method: 'PATCH'
  });
  assert.strictEqual(res.status, 401);
});

test('RBAC 2: Analyst role attempting to mutate alert is rejected with 403 Forbidden', async () => {
  const res = await fetch(`${baseUrl}/api/alerts/${testAlertId}/acknowledge`, {
    method: 'PATCH',
    headers: {
      'Cookie': analystCookie
    }
  });

  assert.strictEqual(res.status, 403);
  const data = await res.json();
  assert.strictEqual(data.error, 'Forbidden');
  assert.ok(data.message.includes('Insufficient permissions'));
});

test('RBAC 3: Analyst role attempting to resolve alert is rejected with 403 Forbidden', async () => {
  const res = await fetch(`${baseUrl}/api/alerts/${testAlertId}/resolve`, {
    method: 'PATCH',
    headers: {
      'Cookie': analystCookie
    }
  });

  assert.strictEqual(res.status, 403);
});

test('RBAC 4: Admin role successfully acknowledges alert (200 OK)', async () => {
  const res = await fetch(`${baseUrl}/api/alerts/${testAlertId}/acknowledge`, {
    method: 'PATCH',
    headers: {
      'Cookie': adminCookie
    }
  });

  assert.strictEqual(res.status, 200);
  const data = await res.json();
  assert.strictEqual(data.status, 'ok');
  assert.strictEqual(data.alert.status, 'acknowledged');
});

test('RBAC 5: Admin role successfully resolves alert (200 OK)', async () => {
  const res = await fetch(`${baseUrl}/api/alerts/${testAlertId}/resolve`, {
    method: 'PATCH',
    headers: {
      'Cookie': adminCookie
    }
  });

  assert.strictEqual(res.status, 200);
  const data = await res.json();
  assert.strictEqual(data.status, 'ok');
  assert.strictEqual(data.alert.status, 'resolved');
});

test('RBAC 6: Analyst role accessing GET /api/users is rejected with 403 Forbidden', async () => {
  const res = await fetch(`${baseUrl}/api/users`, {
    headers: {
      'Cookie': analystCookie
    }
  });

  assert.strictEqual(res.status, 403);
  const data = await res.json();
  assert.strictEqual(data.error, 'Forbidden');
});

test('RBAC 7: Analyst role attempting to create a user is rejected with 403 Forbidden', async () => {
  const res = await fetch(`${baseUrl}/api/users`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': analystCookie
    },
    body: JSON.stringify({
      username: 'illegal_user',
      email: 'illegal@test.local',
      password: 'Password123!',
      role: 'ADMIN'
    })
  });

  assert.strictEqual(res.status, 403);
});

test('RBAC 8: Analyst role attempting to change user role is rejected with 403 Forbidden', async () => {
  const res = await fetch(`${baseUrl}/api/users/2/role`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': analystCookie
    },
    body: JSON.stringify({ role: 'ADMIN' })
  });

  assert.strictEqual(res.status, 403);
});

// ==============================================================================
// 3. User Management APIs (Admin Only)
// ==============================================================================

test('UserMgmt 1: Admin can retrieve user list (GET /api/users)', async () => {
  const res = await fetch(`${baseUrl}/api/users`, {
    headers: {
      'Cookie': adminCookie
    }
  });

  assert.strictEqual(res.status, 200);
  const data = await res.json();
  assert.strictEqual(data.status, 'success');
  assert.ok(Array.isArray(data.users));
  assert.ok(data.users.length >= 2);

  // Check that no password hashes are exposed
  for (const user of data.users) {
    assert.strictEqual(user.password_hash, undefined, 'password_hash must not be returned');
    assert.ok(user.username);
    assert.ok(user.role);
  }
});

test('UserMgmt 2: Admin can create a new Analyst user (POST /api/users)', async () => {
  const testUsername = `user_test_${Date.now()}`;
  const testEmail = `${testUsername}@example.local`;

  const res = await fetch(`${baseUrl}/api/users`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': adminCookie
    },
    body: JSON.stringify({
      username: testUsername,
      email: testEmail,
      password: 'SafePassword123!',
      role: 'ANALYST'
    })
  });

  assert.strictEqual(res.status, 201);
  const data = await res.json();
  assert.strictEqual(data.status, 'success');
  assert.strictEqual(data.user.username, testUsername);
  assert.strictEqual(data.user.role, 'ANALYST');
  assert.strictEqual(data.user.password_hash, undefined);

  createdTestUserId = data.user.id;
});

test('UserMgmt 3: Duplicate username is rejected with 400 Bad Request', async () => {
  const res = await fetch(`${baseUrl}/api/users`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': adminCookie
    },
    body: JSON.stringify({
      username: 'admin', // already exists
      email: 'unique_email_123@test.local',
      password: 'Password123',
      role: 'ANALYST'
    })
  });

  assert.strictEqual(res.status, 400);
  const data = await res.json();
  assert.strictEqual(data.error, 'Bad Request');
  assert.ok(data.message.includes('already'));
});

test('UserMgmt 4: Admin can toggle user active status (PATCH /api/users/:id/status)', async () => {
  assert.ok(createdTestUserId, 'createdTestUserId must be set');

  // 1. Deactivate
  const deactRes = await fetch(`${baseUrl}/api/users/${createdTestUserId}/status`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': adminCookie
    },
    body: JSON.stringify({ isActive: false })
  });

  assert.strictEqual(deactRes.status, 200);
  const deactData = await deactRes.json();
  assert.strictEqual(deactData.user.isActive, false);

  // 2. Reactivate
  const reactRes = await fetch(`${baseUrl}/api/users/${createdTestUserId}/status`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': adminCookie
    },
    body: JSON.stringify({ isActive: true })
  });

  assert.strictEqual(reactRes.status, 200);
  const reactData = await reactRes.json();
  assert.strictEqual(reactData.user.isActive, true);
});

test('UserMgmt 5: Admin can promote user to ADMIN and demote back (PATCH /api/users/:id/role)', async () => {
  assert.ok(createdTestUserId, 'createdTestUserId must be set');

  // Promote to ADMIN
  const promoteRes = await fetch(`${baseUrl}/api/users/${createdTestUserId}/role`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': adminCookie
    },
    body: JSON.stringify({ role: 'ADMIN' })
  });

  assert.strictEqual(promoteRes.status, 200);
  const promoteData = await promoteRes.json();
  assert.strictEqual(promoteData.user.role, 'ADMIN');

  // Demote to ANALYST
  const demoteRes = await fetch(`${baseUrl}/api/users/${createdTestUserId}/role`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': adminCookie
    },
    body: JSON.stringify({ role: 'ANALYST' })
  });

  assert.strictEqual(demoteRes.status, 200);
  const demoteData = await demoteRes.json();
  assert.strictEqual(demoteData.user.role, 'ANALYST');
});

test('UserMgmt 6: Safety Rule - Cannot deactivate the last active Admin account', async () => {
  // Find current admin account ID
  const usersRes = await fetch(`${baseUrl}/api/users`, {
    headers: { 'Cookie': adminCookie }
  });
  const usersData = await usersRes.json();
  const primaryAdmin = usersData.users.find(u => u.username === 'admin');
  assert.ok(primaryAdmin, 'primary admin account must exist');

  // Ensure only 1 active admin exists before testing safety rule
  // (Demote test user if it was left as ADMIN)
  if (createdTestUserId) {
    await fetch(`${baseUrl}/api/users/${createdTestUserId}/role`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', 'Cookie': adminCookie },
      body: JSON.stringify({ role: 'ANALYST' })
    });
  }

  // Attempt to deactivate primary admin
  const res = await fetch(`${baseUrl}/api/users/${primaryAdmin.id}/status`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': adminCookie
    },
    body: JSON.stringify({ isActive: false })
  });

  assert.strictEqual(res.status, 400);
  const data = await res.json();
  assert.strictEqual(data.error, 'Bad Request');
  assert.ok(data.message.includes('last active Admin'));
});

test('UserMgmt 7: Safety Rule - Cannot demote the last active Admin account', async () => {
  const usersRes = await fetch(`${baseUrl}/api/users`, {
    headers: { 'Cookie': adminCookie }
  });
  const usersData = await usersRes.json();
  const primaryAdmin = usersData.users.find(u => u.username === 'admin');

  // Attempt to demote primary admin to ANALYST
  const res = await fetch(`${baseUrl}/api/users/${primaryAdmin.id}/role`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': adminCookie
    },
    body: JSON.stringify({ role: 'ANALYST' })
  });

  assert.strictEqual(res.status, 400);
  const data = await res.json();
  assert.strictEqual(data.error, 'Bad Request');
  assert.ok(data.message.includes('last active Admin'));
});
