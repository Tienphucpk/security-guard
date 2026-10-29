/**
 * Database Initialization Script for SECURITY GUARD
 * Applies schema and seed files to PostgreSQL if available
 */

const fs = require('fs');
const path = require('path');
const db = require('../services/database');

async function initDatabase() {
  console.log('===================================================');
  console.log('  SECURITY GUARD - Database Initialization');
  console.log('===================================================');

  const health = await db.checkHealth();
  if (!health.connected) {
    console.warn(`[WARN] PostgreSQL unavailable at ${db.config.host}:${db.config.port}`);
    console.warn(`Reason: ${health.error}`);
    console.warn('System will run in graceful file-only degradation mode.');
    await db.close();
    return;
  }

  console.log(`[OK] Connected to PostgreSQL: ${db.config.database}@${db.config.host}:${db.config.port}`);

  const schemaPath = path.resolve(__dirname, '../../../database/schema/01_init.sql');
  const seed1Path = path.resolve(__dirname, '../../../database/seed/01_seed.sql');
  const seed2Path = path.resolve(__dirname, '../../../database/seed/02_request_logs_seed.sql');

  try {
    if (fs.existsSync(schemaPath)) {
      console.log('[1/3] Applying schema: 01_init.sql...');
      const schemaSql = fs.readFileSync(schemaPath, 'utf-8');
      await db.pool.query(schemaSql);
      console.log('[OK] Schema applied successfully.');
    }

    if (fs.existsSync(seed1Path)) {
      console.log('[2/3] Applying initial seed: 01_seed.sql...');
      const seed1Sql = fs.readFileSync(seed1Path, 'utf-8');
      await db.pool.query(seed1Sql);
      console.log('[OK] Seed 1 applied.');
    }

    if (fs.existsSync(seed2Path)) {
      console.log('[3/3] Applying request logs seed: 02_request_logs_seed.sql...');
      const seed2Sql = fs.readFileSync(seed2Path, 'utf-8');
      await db.pool.query(seed2Sql);
      console.log('[OK] Request logs seed applied.');
    }

    console.log('===================================================');
    console.log('  Database initialization complete!');
    console.log('===================================================');
  } catch (err) {
    console.error('[ERROR] Failed applying database script:', err.message);
  } finally {
    await db.close();
  }
}

if (require.main === module) {
  initDatabase().catch(console.error);
}

module.exports = initDatabase;
