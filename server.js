require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const {
  DATABASE_URL,
  DB_HOST,
  DB_PORT = 5432,
  DB_NAME,
  DB_USER,
  DB_PASSWORD,
  PORT = 3000,
  JWT_SECRET,
  ALLOWED_ORIGINS = '*'
} = process.env;

if (!DATABASE_URL && (!DB_HOST || !DB_NAME || !DB_USER)) {
  console.error('Warning: Missing DATABASE_URL (or DB_HOST/DB_NAME/DB_USER) — database routes will fail until these are set.');
}
if (!JWT_SECRET) {
  console.error('Warning: Missing JWT_SECRET — admin login/auth routes will fail until this is set.');
}

// Use a single DATABASE_URL when provided (e.g. Neon, Supabase — these require SSL).
// Otherwise fall back to discrete DB_* vars for plain local Postgres.
const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000
    })
  : new Pool({
      host: DB_HOST,
      port: Number(DB_PORT),
      database: DB_NAME,
      user: DB_USER,
      password: DB_PASSWORD,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000
    });

pool.on('error', (err) => {
  console.error('Unexpected idle client error', err);
});

// Close the pool cleanly when the server stops, so connections
// don't get left open on the Postgres side.
function shutdown() {
  console.log('Shutting down, closing DB pool...');
  pool.end(() => process.exit(0));
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

const app = express();
app.use(express.json());

const allowedOrigins = ALLOWED_ORIGINS.split(',').map(s => s.trim());
app.use(cors({
  origin: allowedOrigins.includes('*') ? true : allowedOrigins
}));

app.use(express.static(path.join(__dirname, 'public')));

// ---------- helpers ----------
function toPublicProduct(row) {
  const price = Number(row.price);
  const discount = Number(row.discount_percent) || 0;
  const finalPrice = +(price * (1 - discount / 100)).toFixed(2);
  return {
    slug: row.slug,
    name: row.name,
    currency: row.currency,
    price,                 // original price
    discount_percent: discount,
    final_price: finalPrice,
    on_sale: discount > 0,
    updated_at: row.updated_at
  };
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ---------- public API ----------

app.get('/api/products', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM products ORDER BY id ASC');
    res.json(rows.map(toPublicProduct));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/products/:slug', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM products WHERE slug = $1', [req.params.slug]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(toPublicProduct(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- admin auth (backed by admin_users table) ----------
// Assumes a table: admin_users(id, username, password_hash, ...)

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT id, username, password_hash FROM admin_users WHERE username = $1',
      [username]
    );

    if (!rows.length) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const admin = rows[0];
    const ok = await bcrypt.compare(password, admin.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ sub: admin.username, id: admin.id }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- admin-only product management (requires Bearer token) ----------

app.get('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM products ORDER BY id ASC');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/admin/products/:slug', requireAuth, async (req, res) => {
  const { slug } = req.params;
  let { price, discount_percent, currency } = req.body || {};

  price = Number(price);
  discount_percent = Number(discount_percent ?? 0);
  currency = typeof currency === 'string' ? currency.trim().toUpperCase() : '';

  if (!Number.isFinite(price) || price < 0) {
    return res.status(400).json({ error: 'price must be a non-negative number' });
  }
  if (!Number.isFinite(discount_percent) || discount_percent < 0 || discount_percent > 100) {
    return res.status(400).json({ error: 'discount_percent must be between 0 and 100' });
  }
  if (!['USD', 'IQD'].includes(currency)) {
    return res.status(400).json({ error: 'currency must be USD or IQD' });
  }

  try {
    const { rows } = await pool.query(
      `UPDATE products SET price = $1, discount_percent = $2, currency = $3
       WHERE slug = $4 RETURNING *`,
      [price, discount_percent, currency, slug]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(toPublicProduct(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Starlink Kurd pricing API running on http://localhost:${PORT}`);
    console.log(`Admin panel:  http://localhost:${PORT}/admin.html`);
  });
}

module.exports = app;