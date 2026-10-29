/**
 * Bootstrap Admin Account Script for SECURITY GUARD
 * Creates or updates initial ADMIN and ANALYST accounts with secure bcrypt hashes.
 * 
 * Usage:
 *   node src/scripts/bootstrap-admin.js
 * Or with custom credentials:
 *   ADMIN_USERNAME=myadmin ADMIN_PASSWORD=StrongPassword123 node src/scripts/bootstrap-admin.js
 */

const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

// Auto-load .env configuration
try {
  const envPath = path.resolve(__dirname, '../../.env');
  const rootEnvPath = path.resolve(__dirname, '../../../.env');
  if (process.loadEnvFile) {
    if (fs.existsSync(envPath)) process.loadEnvFile(envPath);
    else if (fs.existsSync(rootEnvPath)) process.loadEnvFile(rootEnvPath);
  }
} catch {}

const db = require('../services/database');

async function bootstrapAdmin() {
  console.log('===================================================');
  console.log('  SECURITY GUARD - Bootstrap Admin & Roles');
  console.log('===================================================');

  const adminUsername = process.env.ADMIN_USERNAME || 'admin';
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@securityguard.local';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin@123456';

  const analystUsername = process.env.ANALYST_USERNAME || 'analyst';
  const analystEmail = process.env.ANALYST_EMAIL || 'analyst@securityguard.local';
  const analystPassword = process.env.ANALYST_PASSWORD || 'Analyst@123456';

  try {
    const adminHash = await bcrypt.hash(adminPassword, 10);
    const analystHash = await bcrypt.hash(analystPassword, 10);

    // 1. Upsert Admin User
    const adminCheck = await db.pool.query('SELECT id FROM users WHERE username = $1 OR email = $2', [adminUsername, adminEmail]);
    if (adminCheck.rows.length > 0) {
      await db.pool.query(
        `UPDATE users 
         SET password_hash = $1, role = 'ADMIN', is_active = true, updated_at = CURRENT_TIMESTAMP
         WHERE id = $2`,
        [adminHash, adminCheck.rows[0].id]
      );
      console.log(`[OK] Updated existing Admin account: '${adminUsername}' (Role: ADMIN, Active: true)`);
    } else {
      await db.pool.query(
        `INSERT INTO users (username, email, password_hash, role, is_active)
         VALUES ($1, $2, $3, 'ADMIN', true)`,
        [adminUsername, adminEmail, adminHash]
      );
      console.log(`[OK] Created new Admin account: '${adminUsername}' (Role: ADMIN, Active: true)`);
    }

    // 2. Upsert Analyst User (for testing role distinction)
    const analystCheck = await db.pool.query('SELECT id FROM users WHERE username = $1 OR email = $2', [analystUsername, analystEmail]);
    if (analystCheck.rows.length > 0) {
      await db.pool.query(
        `UPDATE users 
         SET password_hash = $1, role = 'ANALYST', is_active = true, updated_at = CURRENT_TIMESTAMP
         WHERE id = $2`,
        [analystHash, analystCheck.rows[0].id]
      );
      console.log(`[OK] Updated existing Analyst account: '${analystUsername}' (Role: ANALYST, Active: true)`);
    } else {
      await db.pool.query(
        `INSERT INTO users (username, email, password_hash, role, is_active)
         VALUES ($1, $2, $3, 'ANALYST', true)`,
        [analystUsername, analystEmail, analystHash]
      );
      console.log(`[OK] Created new Analyst account: '${analystUsername}' (Role: ANALYST, Active: true)`);
    }

    console.log('===================================================');
    console.log('  Bootstrap complete! Accounts ready for login:');
    console.log(`  - ADMIN  : ${adminUsername} / ${adminPassword}`);
    console.log(`  - ANALYST: ${analystUsername} / ${analystPassword}`);
    console.log('===================================================');
    return { success: true };
  } catch (err) {
    console.error('[ERROR] Bootstrap failed:', err.message);
    return { success: false, error: err.message };
  } finally {
    if (require.main === module) {
      await db.close();
    }
  }
}

if (require.main === module) {
  bootstrapAdmin().then(() => process.exit(0)).catch(() => process.exit(1));
}

module.exports = bootstrapAdmin;
