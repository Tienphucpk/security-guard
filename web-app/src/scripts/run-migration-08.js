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

    const sqlPath = path.resolve(__dirname, '../../../database/migrations/08_docker_security_labs.sql');
    const sql = fs.readFileSync(sqlPath, 'utf-8');

    console.log('[INFO] Applying migration 08_docker_security_labs.sql...');
    await client.query(sql);

    // Grant permissions to security_guard user if present
    await client.query('GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO security_guard').catch(() => {});
    await client.query('GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO security_guard').catch(() => {});

    console.log('[OK] Migration 08 applied successfully!');
  } catch (err) {
    console.error('[ERROR] Failed applying migration 08:', err);
    process.exit(1);
  } finally {
    await client.end();
  }
}

runMigration();
