require('dotenv').config();
const fs = require('node:fs');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const { createPool } = require('./db/pool');

async function main() {
  let databasePassword=process.env.PGPASSWORD || '';
  if (!databasePassword && process.env.DATABASE_URL) {
    try { databasePassword=decodeURIComponent(new URL(process.env.DATABASE_URL).password); } catch { throw new Error('DATABASE_URL must be a valid PostgreSQL connection URL.'); }
  }
  if(databasePassword.length<24||/your_postgres_password|change-me/i.test(databasePassword))throw new Error('Use a unique database password of at least 24 characters.');
  const pool = createPool();
  try {
    const check = await pool.query("SELECT to_regclass('public.users') AS users_table");
    if (!check.rows[0].users_table) {
      const schema = fs.readFileSync(path.join(__dirname, 'db', 'schema.sql'), 'utf8');
      await pool.query(schema);
      console.log('Database schema installed.');
    } else {
      await pool.query(fs.readFileSync(path.join(__dirname, 'db', 'migrate-existing.sql'), 'utf8'));
      console.log('Existing database detected; additive schema updates applied.');
    }
    for (const name of ['North Plant','South Warehouse','East Distribution','West Assembly']) {
      await pool.query('INSERT INTO sites(name,tenant_key) VALUES($1,$2) ON CONFLICT(name) DO NOTHING', [name,'visionon']);
    }
    const existing = await pool.query('SELECT id FROM users LIMIT 1');
    if (!existing.rowCount) {
      const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
      const password = String(process.env.ADMIN_PASSWORD || '');
      const name = String(process.env.ADMIN_NAME || 'VisionON Administrator').trim();
      if (!/^\S+@\S+\.\S+$/.test(email) || email.includes('your-company') || password.length < 16 || /use-a-different|change-me|password123/i.test(password)) throw new Error('Set a real ADMIN_EMAIL and a unique ADMIN_PASSWORD (at least 16 characters) for the first administrator.');
      const hash = await bcrypt.hash(password, 12);
      await pool.query('INSERT INTO users(display_name,email,password_hash,role) VALUES($1,$2,$3,$4)', [name,email,hash,'platform_admin']);
      console.log('Initial platform administrator provisioned.');
    }
  } finally { await pool.end(); }
}
main().catch(err => { console.error('Setup failed:', err.message); process.exitCode = 1; });
