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
// Images are uploaded as base64 JSON, so allow a generous body size.
app.use(express.json({ limit: '12mb' }));

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
    sort_order: row.sort_order,
    image: row.image_id ? `/api/images/${row.image_id}` : (row.image_url || null),
    tagline: { ku: row.tagline_ku || '', en: row.tagline_en || '', ar: row.tagline_ar || '' },
    description: { ku: row.desc_ku || '', en: row.desc_en || '', ar: row.desc_ar || '' },
    badge: { ku: row.badge_ku || '', en: row.badge_en || '', ar: row.badge_ar || '' },
    features: row.features || [],
    bestfor: row.bestfor || [],
    updated_at: row.updated_at
  };
}

function toPublicTrust(row) {
  return {
    id: row.id,
    icon: row.icon,
    sort_order: row.sort_order,
    title: { ku: row.title_ku || '', en: row.title_en || '', ar: row.title_ar || '' },
    description: { ku: row.desc_ku || '', en: row.desc_en || '', ar: row.desc_ar || '' }
  };
}

function toPublicGallery(row) {
  return {
    id: row.id,
    sort_order: row.sort_order,
    image: row.image_id ? `/api/images/${row.image_id}` : row.image_url,
    alt: row.alt || ''
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

// Accepts { mime_type, data } (base64, no data: prefix) and stores it,
// returning the new image id. Used by product/gallery image uploads.
async function saveImage(mime_type, data) {
  if (!mime_type || !data) return null;
  const { rows } = await pool.query(
    'INSERT INTO images (mime_type, data) VALUES ($1, $2) RETURNING id',
    [mime_type, data]
  );
  return rows[0].id;
}

function slugify(str) {
  return String(str || '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60) || `item-${Date.now()}`;
}

// ---------- public API ----------

app.get('/api/products', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM products ORDER BY sort_order ASC, id ASC');
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

app.get('/api/trust-features', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM trust_features ORDER BY sort_order ASC, id ASC');
    res.json(rows.map(toPublicTrust));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/gallery', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM gallery_images ORDER BY sort_order ASC, id ASC');
    res.json(rows.map(toPublicGallery));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Serves an uploaded image's actual bytes with the right content type.
app.get('/api/images/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT mime_type, data FROM images WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).end();
    const { mime_type, data } = rows[0];
    res.setHeader('Content-Type', mime_type);
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    res.send(Buffer.from(data, 'base64'));
  } catch (err) {
    console.error(err);
    res.status(500).end();
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

// ---------- admin: image upload (shared by products & gallery) ----------

app.post('/api/admin/images', requireAuth, async (req, res) => {
  const { mime_type, data } = req.body || {};
  if (!mime_type || !data) return res.status(400).json({ error: 'mime_type and data required' });
  if (!/^image\//.test(mime_type)) return res.status(400).json({ error: 'mime_type must be an image type' });
  // rough size guard: base64 is ~4/3 the byte size, cap around 8MB decoded
  if (data.length > 11_000_000) return res.status(400).json({ error: 'Image too large — please use a smaller file (under ~8MB)' });
  try {
    const id = await saveImage(mime_type, data);
    res.json({ id, url: `/api/images/${id}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- admin-only product management (requires Bearer token) ----------

app.get('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM products ORDER BY sort_order ASC, id ASC');
    res.json(rows.map(toPublicProduct));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

function readProductBody(body) {
  const b = body || {};
  const num = (v, d = 0) => (Number.isFinite(Number(v)) ? Number(v) : d);
  return {
    name: String(b.name || '').trim(),
    price: num(b.price, 0),
    discount_percent: num(b.discount_percent, 0),
    currency: typeof b.currency === 'string' ? b.currency.trim().toUpperCase() : 'USD',
    sort_order: num(b.sort_order, 0),
    image_id: b.image_id || null,
    image_url: b.image_url || null,
    tagline_ku: b.tagline_ku || '', tagline_en: b.tagline_en || '', tagline_ar: b.tagline_ar || '',
    desc_ku: b.desc_ku || '', desc_en: b.desc_en || '', desc_ar: b.desc_ar || '',
    badge_ku: b.badge_ku || '', badge_en: b.badge_en || '', badge_ar: b.badge_ar || '',
    features: Array.isArray(b.features) ? b.features : [],
    bestfor: Array.isArray(b.bestfor) ? b.bestfor : []
  };
}

// Create a new device/product
app.post('/api/admin/products', requireAuth, async (req, res) => {
  const p = readProductBody(req.body);
  if (!p.name) return res.status(400).json({ error: 'name is required' });
  if (!Number.isFinite(p.price) || p.price < 0) return res.status(400).json({ error: 'price must be a non-negative number' });
  if (!['USD', 'IQD'].includes(p.currency)) return res.status(400).json({ error: 'currency must be USD or IQD' });

  let slug = slugify(req.body.slug || p.name);

  try {
    // ensure uniqueness
    const { rows: existing } = await pool.query('SELECT 1 FROM products WHERE slug = $1', [slug]);
    if (existing.length) slug = `${slug}-${Date.now().toString().slice(-5)}`;

    const { rows } = await pool.query(
      `INSERT INTO products
        (slug, name, price, discount_percent, currency, sort_order, image_id, image_url,
         tagline_ku, tagline_en, tagline_ar, desc_ku, desc_en, desc_ar,
         badge_ku, badge_en, badge_ar, features, bestfor)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
       RETURNING *`,
      [slug, p.name, p.price, p.discount_percent, p.currency, p.sort_order, p.image_id, p.image_url,
       p.tagline_ku, p.tagline_en, p.tagline_ar, p.desc_ku, p.desc_en, p.desc_ar,
       p.badge_ku, p.badge_en, p.badge_ar, JSON.stringify(p.features), JSON.stringify(p.bestfor)]
    );
    res.status(201).json(toPublicProduct(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/admin/products/:slug', requireAuth, async (req, res) => {
  const { slug } = req.params;
  const p = readProductBody(req.body);

  if (!Number.isFinite(p.price) || p.price < 0) {
    return res.status(400).json({ error: 'price must be a non-negative number' });
  }
  if (!Number.isFinite(p.discount_percent) || p.discount_percent < 0 || p.discount_percent > 100) {
    return res.status(400).json({ error: 'discount_percent must be between 0 and 100' });
  }
  if (!['USD', 'IQD'].includes(p.currency)) {
    return res.status(400).json({ error: 'currency must be USD or IQD' });
  }

  try {
    const { rows } = await pool.query(
      `UPDATE products SET
         name = COALESCE(NULLIF($1,''), name),
         price = $2, discount_percent = $3, currency = $4, sort_order = $5,
         image_id = COALESCE($6, image_id), image_url = COALESCE($7, image_url),
         tagline_ku = $8, tagline_en = $9, tagline_ar = $10,
         desc_ku = $11, desc_en = $12, desc_ar = $13,
         badge_ku = $14, badge_en = $15, badge_ar = $16,
         features = $17, bestfor = $18,
         updated_at = now()
       WHERE slug = $19 RETURNING *`,
      [p.name, p.price, p.discount_percent, p.currency, p.sort_order,
       p.image_id, p.image_url,
       p.tagline_ku, p.tagline_en, p.tagline_ar,
       p.desc_ku, p.desc_en, p.desc_ar,
       p.badge_ku, p.badge_en, p.badge_ar,
       JSON.stringify(p.features), JSON.stringify(p.bestfor),
       slug]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(toPublicProduct(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/products/:slug', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('DELETE FROM products WHERE slug = $1 RETURNING slug', [req.params.slug]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- admin-only trust features (why choose us) ----------

app.get('/api/admin/trust-features', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM trust_features ORDER BY sort_order ASC, id ASC');
    res.json(rows.map(toPublicTrust));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/trust-features', requireAuth, async (req, res) => {
  const b = req.body || {};
  try {
    const { rows } = await pool.query(
      `INSERT INTO trust_features (sort_order, icon, title_ku, title_en, title_ar, desc_ku, desc_en, desc_ar)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [Number(b.sort_order) || 0, b.icon || 'bolt',
       b.title_ku || '', b.title_en || '', b.title_ar || '',
       b.desc_ku || '', b.desc_en || '', b.desc_ar || '']
    );
    res.status(201).json(toPublicTrust(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/admin/trust-features/:id', requireAuth, async (req, res) => {
  const b = req.body || {};
  try {
    const { rows } = await pool.query(
      `UPDATE trust_features SET
         sort_order = $1, icon = $2,
         title_ku = $3, title_en = $4, title_ar = $5,
         desc_ku = $6, desc_en = $7, desc_ar = $8,
         updated_at = now()
       WHERE id = $9 RETURNING *`,
      [Number(b.sort_order) || 0, b.icon || 'bolt',
       b.title_ku || '', b.title_en || '', b.title_ar || '',
       b.desc_ku || '', b.desc_en || '', b.desc_ar || '',
       req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(toPublicTrust(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/trust-features/:id', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('DELETE FROM trust_features WHERE id = $1 RETURNING id', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- admin-only gallery ----------

app.get('/api/admin/gallery', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM gallery_images ORDER BY sort_order ASC, id ASC');
    res.json(rows.map(toPublicGallery));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/gallery', requireAuth, async (req, res) => {
  const b = req.body || {};
  if (!b.image_id && !b.image_url) return res.status(400).json({ error: 'image_id or image_url required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO gallery_images (sort_order, image_id, image_url, alt)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [Number(b.sort_order) || 0, b.image_id || null, b.image_url || null, b.alt || '']
    );
    res.status(201).json(toPublicGallery(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/admin/gallery/:id', requireAuth, async (req, res) => {
  const b = req.body || {};
  try {
    const { rows } = await pool.query(
      `UPDATE gallery_images SET
         sort_order = $1,
         image_id = COALESCE($2, image_id),
         image_url = COALESCE($3, image_url),
         alt = $4,
         updated_at = now()
       WHERE id = $5 RETURNING *`,
      [Number(b.sort_order) || 0, b.image_id || null, b.image_url || null, b.alt || '', req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(toPublicGallery(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/gallery/:id', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('DELETE FROM gallery_images WHERE id = $1 RETURNING id', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
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