/**
 * One-click PostgreSQL Database Setup & Schema Applier
 * Uses provided password to create database, grant permissions, and apply schemas.
 */

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

const DB_PASSWORD = process.env.DB_PASSWORD || 'Tubadench28@';

async function main() {
  console.log('===================================================');
  console.log('  SECURITY GUARD - Automated PostgreSQL Setup');
  console.log('===================================================');

  // 1. Connect to root postgres database
  const rootClient = new Client({
    host: 'localhost',
    port: 5432,
    user: 'postgres',
    password: DB_PASSWORD,
    database: 'postgres'
  });

  try {
    await rootClient.connect();
    console.log('[OK] Connected to PostgreSQL root server as user postgres');
  } catch (err) {
    console.error('[ERROR] Cannot connect to PostgreSQL with provided password:', err.message);
    process.exit(1);
  }

  // 2. Check/create database security_guard
  try {
    const res = await rootClient.query("SELECT 1 FROM pg_database WHERE datname = 'security_guard'");
    if (res.rows.length === 0) {
      console.log('[1/4] Creating database security_guard...');
      await rootClient.query('CREATE DATABASE security_guard');
      console.log('[OK] Database security_guard created.');
    } else {
      console.log('[1/4] Database security_guard already exists.');
    }
  } catch (err) {
    console.warn('[WARN] Error checking/creating database:', err.message);
  }

  // 3. Check/create user security_guard
  try {
    const userRes = await rootClient.query("SELECT 1 FROM pg_roles WHERE rolname = 'security_guard'");
    if (userRes.rows.length === 0) {
      console.log('[2/4] Creating user security_guard...');
      await rootClient.query(`CREATE USER security_guard WITH PASSWORD '${DB_PASSWORD}'`);
    } else {
      console.log('[2/4] Updating user security_guard password...');
      await rootClient.query(`ALTER USER security_guard WITH PASSWORD '${DB_PASSWORD}'`);
    }
    await rootClient.query('GRANT ALL PRIVILEGES ON DATABASE security_guard TO security_guard');
    console.log('[OK] User security_guard configured with full privileges.');
  } catch (err) {
    console.warn('[WARN] Error setting up user security_guard:', err.message);
  } finally {
    await rootClient.end();
  }

  // 4. Connect to target database security_guard
  const appClient = new Client({
    host: 'localhost',
    port: 5432,
    user: 'postgres',
    password: DB_PASSWORD,
    database: 'security_guard'
  });

  try {
    await appClient.connect();
    console.log('[3/4] Connected to target database security_guard.');

    // Apply schema
    const schemaFile = path.resolve(__dirname, '../../../database/schema/01_init.sql');
    if (fs.existsSync(schemaFile)) {
      console.log('      Applying schema: 01_init.sql...');
      const schemaSql = fs.readFileSync(schemaFile, 'utf-8');
      await appClient.query(schemaSql);
      console.log('      [OK] 01_init.sql applied.');

      // Ensure all required columns exist in older tables
      await appClient.query(`
        ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS response_time_ms NUMERIC(10, 2);
        ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS status_code INTEGER;
        ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS user_agent TEXT;
        ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS severity VARCHAR(20) DEFAULT 'medium';
        ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS method VARCHAR(10) DEFAULT 'GET';
        ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS request_log_id BIGINT;
      `);
      console.log('      [OK] Columns verified & synced.');
    }

    // Apply seed 1
    const seed1File = path.resolve(__dirname, '../../../database/seed/01_seed.sql');
    if (fs.existsSync(seed1File)) {
      console.log('      Applying seed: 01_seed.sql...');
      const seed1Sql = fs.readFileSync(seed1File, 'utf-8');
      await appClient.query(seed1Sql);
      console.log('      [OK] 01_seed.sql applied.');
    }

    // Apply seed 3 (rules)
    const seed3File = path.resolve(__dirname, '../../../database/seed/03_detection_rules_seed.sql');
    if (fs.existsSync(seed3File)) {
      console.log('      Applying seed: 03_detection_rules_seed.sql...');
      const seed3Sql = fs.readFileSync(seed3File, 'utf-8');
      await appClient.query(seed3Sql);
      console.log('      [OK] 03_detection_rules_seed.sql applied.');
    }

    // Grant all table permissions
    await appClient.query('GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO security_guard');
    await appClient.query('GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO security_guard');

    console.log('[4/4] All schema and seed data initialized successfully!');
  } catch (err) {
    console.error('[ERROR] Failed executing schema/seed on security_guard:', err.message);
  } finally {
    await appClient.end();
  }

  // 5. Update or create .env in project root & web-app
  const envContent = `# SECURITY GUARD Environment Variables
NODE_ENV=development
WEB_PORT=3000
WEB_HOST=0.0.0.0
DETECTION_ENGINE_PORT=5000
DETECTION_ENGINE_HOST=0.0.0.0
DETECTION_ENGINE_URL=http://localhost:5000
DASHBOARD_PORT=5173

# Database Configuration (PostgreSQL)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=security_guard
DB_USER=postgres
DB_PASSWORD=${DB_PASSWORD}

DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=security_guard
DATABASE_USER=postgres
DATABASE_PASSWORD=${DB_PASSWORD}

LOG_TO_FILE=true
DETECTION_FORWARD_ENABLED=true
`;

  const rootEnvPath = path.resolve(__dirname, '../../../.env');
  const webEnvPath = path.resolve(__dirname, '../../.env');
  fs.writeFileSync(rootEnvPath, envContent, 'utf-8');
  fs.writeFileSync(webEnvPath, envContent, 'utf-8');
  console.log('[OK] Updated .env files with PostgreSQL credentials.');

  console.log('===================================================');
  console.log('  Database setup completed successfully! (Status: ONLINE)');
  console.log('===================================================');
}

main().catch(console.error);
