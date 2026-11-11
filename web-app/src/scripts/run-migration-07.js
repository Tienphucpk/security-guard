const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

async function runMigration() {
  const dbPassword = process.env.DB_PASSWORD || process.env.DATABASE_PASSWORD || 'Tubadench28@';
  const client = new Client({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    user: process.env.DB_USER || 'postgres',
    password: dbPassword,
    database: process.env.DB_NAME || 'security_guard'
  });

  try {
    await client.connect();
    console.log('[OK] Connected to PostgreSQL security_guard database.');

    const sqlPath = path.resolve(__dirname, '../../../database/migrations/07_adaptive_defense_evidence.sql');
    const sql = fs.readFileSync(sqlPath, 'utf-8');

    console.log('[INFO] Applying migration 07_adaptive_defense_evidence.sql...');
    await client.query(sql);

    // Grant permissions to security_guard user
    await client.query('GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO security_guard').catch(() => {});
    await client.query('GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO security_guard').catch(() => {});

    console.log('[OK] Migration 07 applied successfully!');
  } catch (err) {
    console.error('[ERROR] Failed applying migration 07:', err);
    process.exit(1);
  } finally {
    await client.end();
  }
}

runMigration();
