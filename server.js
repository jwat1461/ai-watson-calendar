require('dotenv').config();
const express  = require('express');
const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const path     = require('path');

const app  = express();
const pool = new Pool({
  host:     process.env.DB_HOST,
  port:     Number(process.env.DB_PORT),
  user:     process.env.DB_USER,
  password: String(process.env.DB_PASSWORD || ''),
  database: process.env.DB_NAME,
});

app.use(cors());
app.use(express.json());
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'calendar.html')));

// ── Auth middleware ──────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Register ─────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'All fields are required.' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
    if (exists.rows.length)
      return res.status(409).json({ error: 'An account with that email already exists.' });
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3)',
      [name, email.toLowerCase(), hash]
    );
    res.status(201).json({ message: 'Account created. You can now log in.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── Login ────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required.' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase()]);
    const user   = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash)))
      return res.status(401).json({ error: 'Invalid email or password.' });
    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token, name: user.name, email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── Me (verify token) ────────────────────────────────────────
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ id: req.user.id, name: req.user.name, email: req.user.email });
});

// ── Events ───────────────────────────────────────────────────
app.get('/api/events', authMiddleware, async (req, res) => {
  const { year, month } = req.query;
  try {
    const result = await pool.query(
      'SELECT id, day, title FROM events WHERE user_id=$1 AND year=$2 AND month=$3 ORDER BY day, id',
      [req.user.id, Number(year), Number(month)]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/api/events', authMiddleware, async (req, res) => {
  const { year, month, day, title } = req.body;
  if (!title?.trim()) return res.status(400).json({ error: 'title required' });
  try {
    const result = await pool.query(
      'INSERT INTO events (user_id, year, month, day, title) VALUES ($1,$2,$3,$4,$5) RETURNING id, day, title',
      [req.user.id, Number(year), Number(month), Number(day), title.trim()]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.delete('/api/events/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM events WHERE id=$1 AND user_id=$2', [Number(req.params.id), req.user.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── Error handler ────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error.' });
});

// ── DB setup + start ─────────────────────────────────────────
async function start() {
  // Create DB if it doesn't exist (connect to postgres first)
  const admin = new Pool({
    host: process.env.DB_HOST, port: Number(process.env.DB_PORT),
    user: process.env.DB_USER, password: String(process.env.DB_PASSWORD || ''),
    database: 'postgres',
  });
  const dbExists = await admin.query(
    `SELECT 1 FROM pg_database WHERE datname=$1`, [process.env.DB_NAME]
  );
  if (!dbExists.rows.length) {
    await admin.query(`CREATE DATABASE ${process.env.DB_NAME}`);
    console.log(`Database "${process.env.DB_NAME}" created.`);
  }
  await admin.end();

  // Create tables
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      name          TEXT NOT NULL,
      email         TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      year       INTEGER NOT NULL,
      month      INTEGER NOT NULL,
      day        INTEGER NOT NULL,
      title      TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  console.log('Tables ready.');

  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`Watson AI server running → http://localhost:${port}`));
}

start().catch(err => { console.error('Startup error:', err); process.exit(1); });
