require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { Pool } = require('pg');
const { Resend } = require('resend');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    verified BOOLEAN DEFAULT false, code VARCHAR(6), code_expires BIGINT,
    created_at TIMESTAMP DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS videos (
    id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL, description TEXT DEFAULT '', category VARCHAR(50) DEFAULT 'other',
    video_url TEXT NOT NULL, thumbnail_url TEXT DEFAULT '', cloudinary_id TEXT DEFAULT '',
    duration INTEGER DEFAULT 0, views INTEGER DEFAULT 0, likes INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS likes (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, video_id)
  );
`).then(() => console.log('БД готова')).catch(console.error);

const resend = new Resend(process.env.RESEND_API_KEY);
const sendCode = (to, code) => resend.emails.send({
  from: 'CosmоVibe <onboarding@resend.dev>', to,
  subject: '🚀 Код входа в CosmоVibe',
  html: `<div style="background:#060612;padding:40px;font-family:sans-serif;color:#c8c0f0;border-radius:12px"><h2 style="color:#b48aff">CosmоVibe</h2><p>Твой код:</p><div style="background:#12122e;border:1px solid rgba(124,92,252,.3);border-radius:10px;padding:24px;text-align:center"><span style="font-size:42px;font-weight:700;letter-spacing:12px;color:#fff;font-family:monospace">${code}</span></div><p style="color:#6b65a0;font-size:13px;margin-top:16px">Код действует 10 минут.</p></div>`
});
const notifyOwner = (username, email) => resend.emails.send({
  from: 'CosmоVibe <onboarding@resend.dev>', to: process.env.OWNER_EMAIL,
  subject: '🌌 НОВЫЙ ПОЛЬЗОВАТЕЛЬ!',
  html: `<div style="background:#060612;padding:40px;font-family:sans-serif;color:#c8c0f0;border-radius:12px"><h2 style="color:#b48aff">Новый пользователь!</h2><p><b style="color:#b48aff">Имя:</b> ${username}</p><p><b style="color:#b48aff">Email:</b> ${email}</p></div>`
});

cloudinary.config({ cloud_name: process.env.CLOUDINARY_CLOUD_NAME, api_key: process.env.CLOUDINARY_API_KEY, api_secret: process.env.CLOUDINARY_API_SECRET });

const code6 = () => String(Math.floor(100000 + Math.random() * 900000));
const makeToken = (u) => jwt.sign({ id: u.id, username: u.username, email: u.email }, process.env.JWT_SECRET, { expiresIn: '30d' });
function auth(req, res, next) {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Нет доступа' }); }
}

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Заполни все поля' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE email=$1 OR username=$2', [email, username]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email или имя уже заняты' });
    const hash = await bcrypt.hash(password, 10);
    const c = code6(), exp = Date.now() + 600000;
    await pool.query('INSERT INTO users (username,email,password_hash,code,code_expires) VALUES($1,$2,$3,$4,$5)', [username, email, hash, c, exp]);
    await sendCode(email, c);
    res.json({ step: 'verify', email });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/verify', async (req, res) => {
  const { email, code } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const u = rows[0];
    if (!u) return res.status(404).json({ error: 'Не найдено' });
    if (u.code !== code) return res.status(400).json({ error: 'Неверный код' });
    if (Date.now() > Number(u.code_expires)) return res.status(400).json({ error: 'Код устарел' });
    await pool.query('UPDATE users SET verified=true,code=NULL,code_expires=NULL WHERE id=$1', [u.id]);
    notifyOwner(u.username, u.email).catch(() => {});
    res.json({ token: makeToken(u), user: { id: u.id, username: u.username, email: u.email } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const u = rows[0];
    if (!u || !(await bcrypt.compare(password, u.password_hash))) return res.status(401).json({ error: 'Неверный email или пароль' });
    if (!u.verified) return res.status(403).json({ error: 'Подтверди email сначала' });
    const c = code6(), exp = Date.now() + 600000;
    await pool.query('UPDATE users SET code=$1,code_expires=$2 WHERE id=$3', [c, exp, u.id]);
    await sendCode(email, c);
    res.json({ step: 'verify', email });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login-verify', async (req, res) => {
  const { email, code } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const u = rows[0];
    if (!u) return res.status(404).json({ error: 'Не найдено' });
    if (u.code !== code) return res.status(400).json({ error: 'Неверный код' });
    if (Date.now() > Number(u.code_expires)) return res.status(400).json({ error: 'Код устарел' });
    await pool.query('UPDATE users SET code=NULL,code_expires=NULL WHERE id=$1', [u.id]);
    res.json({ token: makeToken(u), user: { id: u.id, username: u.username, email: u.email } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/resend', async (req, res) => {
  const { email } = req.body;
  try {
    const { rows } = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
    if (!rows[0]) return res.status(404).json({ error: 'Не найдено' });
    const c = code6(), exp = Date.now() + 600000;
    await pool.query('UPDATE users SET code=$1,code_expires=$2 WHERE id=$3', [c, exp, rows[0].id]);
    await sendCode(email, c);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/videos', async (req, res) => {
  const { category = 'all', search = '', limit = 24 } = req.query;
  try {
    let q = 'SELECT v.*,u.username FROM videos v JOIN users u ON u.id=v.user_id WHERE 1=1';
    const p = [];
    if (category !== 'all') { p.push(category); q += ` AND v.category=$${p.length}`; }
    if (search) { p.push(`%${search}%`); q += ` AND (v.title ILIKE $${p.length} OR v.description ILIKE $${p.length})`; }
    p.push(+limit); q += ` ORDER BY v.created_at DESC LIMIT $${p.length}`;
    res.json((await pool.query(q, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ✅ ВАЖНО: /upload должен быть ВЫШЕ /:id
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });
app.post('/api/videos/upload', auth, upload.single('video'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не выбран' });
  const { title, description = '', category = 'other' } = req.body;
  if (!title) return res.status(400).json({ error: 'Укажи название' });
  try {
    const result = await new Promise((ok, fail) => {
      const s = cloudinary.uploader.upload_stream({
        resource_type: 'video',
        folder: 'cosmovibe',
        format: 'mp4',
        transformation: [{ video_codec: 'h264', audio_codec: 'aac' }]
      }, (err, r) => err ? fail(err) : ok(r));
      s.end(req.file.buffer);
    });
    const thumb = result.secure_url.replace(/\.[^/.]+$/, '.jpg').replace('/upload/', '/upload/w_640/');
    const { rows } = await pool.query(
      'INSERT INTO videos(user_id,title,description,category,video_url,thumbnail_url,cloudinary_id,duration) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [req.user.id, title, description, category, result.secure_url, thumb, result.public_id, Math.round(result.duration || 0)]
    );
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/videos/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT v.*,u.username FROM videos v JOIN users u ON u.id=v.user_id WHERE v.id=$1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Не найдено' });
    await pool.query('UPDATE videos SET views=views+1 WHERE id=$1', [req.params.id]);
    rows[0].views++; res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/videos/:id', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM videos WHERE id=$1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Не найдено' });
    if (rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Нет прав' });
    if (rows[0].cloudinary_id) await cloudinary.uploader.destroy(rows[0].cloudinary_id, { resource_type: 'video' });
    await pool.query('DELETE FROM videos WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos/:id/like', auth, async (req, res) => {
  try {
    const exists = await pool.query('SELECT 1 FROM likes WHERE user_id=$1 AND video_id=$2', [req.user.id, req.params.id]);
    if (exists.rows.length) {
      await pool.query('DELETE FROM likes WHERE user_id=$1 AND video_id=$2', [req.user.id, req.params.id]);
      await pool.query('UPDATE videos SET likes=likes-1 WHERE id=$1', [req.params.id]);
      res.json({ liked: false });
    } else {
      await pool.query('INSERT INTO likes VALUES($1,$2)', [req.user.id, req.params.id]);
      await pool.query('UPDATE videos SET likes=likes+1 WHERE id=$1', [req.params.id]);
      res.json({ liked: true });
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(process.env.PORT || 3000, () => console.log('🚀 CosmоVibe запущен'));
