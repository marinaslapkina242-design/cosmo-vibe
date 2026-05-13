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
  CREATE TABLE IF NOT EXISTS subscriptions (
    follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    target_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (follower_id, target_id)
  );
  CREATE TABLE IF NOT EXISTS comments (
    id SERIAL PRIMARY KEY,
    video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    from_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(20) NOT NULL,
    video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
    comment_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
    read BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
  );
`).then(() => console.log('БД готова')).catch(console.error);

// Migration: add parent_id to comments if missing
pool.query(`ALTER TABLE comments ADD COLUMN IF NOT EXISTS parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE`).catch(() => {});

const resend = new Resend(process.env.RESEND_API_KEY);
const notifyOwner = (username, email) => resend.emails.send({
  from: 'CosmоVibe <onboarding@resend.dev>', to: process.env.OWNER_EMAIL,
  subject: '🌌 НОВЫЙ ПОЛЬЗОВАТЕЛЬ!',
  html: `<p>Имя: ${username}, Email: ${email}</p>`
}).catch(() => {});

cloudinary.config({ cloud_name: process.env.CLOUDINARY_CLOUD_NAME, api_key: process.env.CLOUDINARY_API_KEY, api_secret: process.env.CLOUDINARY_API_SECRET });

const makeToken = u => jwt.sign({ id: u.id, username: u.username, email: u.email }, process.env.JWT_SECRET, { expiresIn: '30d' });
function auth(req, res, next) {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Нет доступа' }); }
}
function optAuth(req, res, next) {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), process.env.JWT_SECRET); } catch {}
  next();
}

async function createNotification(userId, fromUserId, type, videoId = null, commentId = null) {
  if (userId === fromUserId) return;
  await pool.query(
    'INSERT INTO notifications(user_id,from_user_id,type,video_id,comment_id) VALUES($1,$2,$3,$4,$5)',
    [userId, fromUserId, type, videoId, commentId]
  ).catch(() => {});
}

// AUTH
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Заполни все поля' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE email=$1 OR username=$2', [email, username]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email или имя уже заняты' });
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query('INSERT INTO users(username,email,password_hash) VALUES($1,$2,$3) RETURNING *', [username, email, hash]);
    notifyOwner(username, email);
    res.json({ token: makeToken(rows[0]), user: { id: rows[0].id, username: rows[0].username } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const u = rows[0];
    if (!u || !(await bcrypt.compare(password, u.password_hash))) return res.status(401).json({ error: 'Неверный email или пароль' });
    const { rows: subRows } = await pool.query('SELECT COUNT(*) FROM subscriptions WHERE target_id=$1', [u.id]);
    res.json({ token: makeToken(u), user: { id: u.id, username: u.username }, subscriberCount: parseInt(subRows[0].count) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// VIDEOS
app.get('/api/videos', async (req, res) => {
  const { category = 'all', search = '', limit = 24 } = req.query;
  try {
    let q = `SELECT v.*, u.username,
      (SELECT COUNT(*) FROM subscriptions WHERE target_id=u.id) as subscriber_count
      FROM videos v JOIN users u ON u.id=v.user_id WHERE 1=1`;
    const p = [];
    if (category !== 'all') { p.push(category); q += ` AND v.category=$${p.length}`; }
    if (search) { p.push(`%${search}%`); q += ` AND (v.title ILIKE $${p.length} OR u.username ILIKE $${p.length})`; }
    p.push(+limit); q += ` ORDER BY v.created_at DESC LIMIT $${p.length}`;
    res.json((await pool.query(q, p)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });
app.post('/api/videos/upload', auth, upload.single('video'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не выбран' });
  const { title, description = '', category = 'other' } = req.body;
  if (!title) return res.status(400).json({ error: 'Укажи название' });
  try {
    const result = await new Promise((ok, fail) => {
      const s = cloudinary.uploader.upload_stream({
        resource_type: 'video', folder: 'cosmovibe',
        format: 'mp4', transformation: [{ video_codec: 'h264', audio_codec: 'aac' }]
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

app.get('/api/videos/:id', optAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT v.*, u.username, u.id as author_id,
        (SELECT COUNT(*) FROM subscriptions WHERE target_id=u.id) as author_subscriber_count
      FROM videos v JOIN users u ON u.id=v.user_id WHERE v.id=$1
    `, [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Не найдено' });
    await pool.query('UPDATE videos SET views=views+1 WHERE id=$1', [req.params.id]);
    rows[0].views++;
    let liked = false;
    if (req.user) {
      const l = await pool.query('SELECT 1 FROM likes WHERE user_id=$1 AND video_id=$2', [req.user.id, req.params.id]);
      liked = l.rows.length > 0;
    }
    res.json({ ...rows[0], liked });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

const OWNER_USERNAME = 'Maksim';

app.delete('/api/videos/:id', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM videos WHERE id=$1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Не найдено' });
    const isOwner = req.user.username && req.user.username.toLowerCase() === OWNER_USERNAME.toLowerCase();
    if (rows[0].user_id !== req.user.id && !isOwner) return res.status(403).json({ error: 'Нет прав' });
    if (rows[0].cloudinary_id) await cloudinary.uploader.destroy(rows[0].cloudinary_id, { resource_type: 'video' });
    await pool.query('DELETE FROM videos WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos/:id/like', auth, async (req, res) => {
  try {
    const vid = await pool.query('SELECT user_id FROM videos WHERE id=$1', [req.params.id]);
    if (!vid.rows[0]) return res.status(404).json({ error: 'Не найдено' });
    const exists = await pool.query('SELECT 1 FROM likes WHERE user_id=$1 AND video_id=$2', [req.user.id, req.params.id]);
    if (exists.rows.length) {
      await pool.query('DELETE FROM likes WHERE user_id=$1 AND video_id=$2', [req.user.id, req.params.id]);
      await pool.query('UPDATE videos SET likes=likes-1 WHERE id=$1', [req.params.id]);
      res.json({ liked: false });
    } else {
      await pool.query('INSERT INTO likes VALUES($1,$2)', [req.user.id, req.params.id]);
      await pool.query('UPDATE videos SET likes=likes+1 WHERE id=$1', [req.params.id]);
      await createNotification(vid.rows[0].user_id, req.user.id, 'like', parseInt(req.params.id));
      res.json({ liked: true });
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// COMMENTS
app.get('/api/videos/:id/comments', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT c.*, u.username,
        (SELECT COUNT(*) FROM subscriptions WHERE target_id=c.user_id) as subscriber_count
       FROM comments c JOIN users u ON u.id=c.user_id WHERE c.video_id=$1 ORDER BY c.created_at ASC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/videos/:id/comments', auth, async (req, res) => {
  const { text, parent_id } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'Пустой комментарий' });
  try {
    const vid = await pool.query('SELECT user_id FROM videos WHERE id=$1', [req.params.id]);
    if (!vid.rows[0]) return res.status(404).json({ error: 'Видео не найдено' });
    const { rows } = await pool.query(
      'INSERT INTO comments(video_id,user_id,text,parent_id) VALUES($1,$2,$3,$4) RETURNING *',
      [req.params.id, req.user.id, text.trim(), parent_id || null]
    );
    const comment = rows[0];
    const userRow = await pool.query('SELECT username FROM users WHERE id=$1', [req.user.id]);
    comment.username = userRow.rows[0].username;
    if (parent_id) {
      // Notify parent comment author
      const parentRow = await pool.query('SELECT user_id FROM comments WHERE id=$1', [parent_id]);
      if (parentRow.rows[0]) await createNotification(parentRow.rows[0].user_id, req.user.id, 'reply', parseInt(req.params.id), comment.id);
    } else {
      await createNotification(vid.rows[0].user_id, req.user.id, 'comment', parseInt(req.params.id), comment.id);
    }
    res.json(comment);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/comments/:id', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM comments WHERE id=$1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Не найдено' });
    const isOwner = req.user.username && req.user.username.toLowerCase() === OWNER_USERNAME.toLowerCase();
    if (rows[0].user_id !== req.user.id && !isOwner) return res.status(403).json({ error: 'Нет прав' });
    await pool.query('DELETE FROM comments WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// NOTIFICATIONS
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT n.*, u.username as from_username, v.title as video_title
      FROM notifications n
      JOIN users u ON u.id=n.from_user_id
      LEFT JOIN videos v ON v.id=n.video_id
      WHERE n.user_id=$1
      ORDER BY n.created_at DESC LIMIT 30
    `, [req.user.id]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/notifications/read', auth, async (req, res) => {
  try {
    await pool.query('UPDATE notifications SET read=true WHERE user_id=$1', [req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/notifications/count', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT COUNT(*) FROM notifications WHERE user_id=$1 AND read=false', [req.user.id]);
    res.json({ count: parseInt(rows[0].count) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// CHANNELS
app.get('/api/channel/:username', optAuth, async (req, res) => {
  try {
    const { rows: users } = await pool.query('SELECT id,username,created_at FROM users WHERE username=$1', [req.params.username]);
    if (!users[0]) return res.status(404).json({ error: 'Канал не найден' });
    const u = users[0];
    const { rows: videos } = await pool.query(`
      SELECT v.*, u.username,
        (SELECT COUNT(*) FROM subscriptions WHERE target_id=u.id) as subscriber_count
      FROM videos v JOIN users u ON u.id=v.user_id WHERE v.user_id=$1 ORDER BY v.created_at DESC
    `, [u.id]);
    const { rows: subRows } = await pool.query('SELECT COUNT(*) FROM subscriptions WHERE target_id=$1', [u.id]);
    let isSubscribed = false;
    if (req.user) {
      const s = await pool.query('SELECT 1 FROM subscriptions WHERE follower_id=$1 AND target_id=$2', [req.user.id, u.id]);
      isSubscribed = s.rows.length > 0;
    }
    res.json({ user: u, videos, subscriberCount: parseInt(subRows[0].count), isSubscribed });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/channel/:username/subscribe', auth, async (req, res) => {
  try {
    const { rows: users } = await pool.query('SELECT id FROM users WHERE username=$1', [req.params.username]);
    if (!users[0]) return res.status(404).json({ error: 'Не найдено' });
    const targetId = users[0].id;
    if (targetId === req.user.id) return res.status(400).json({ error: 'Нельзя подписаться на себя' });
    const exists = await pool.query('SELECT 1 FROM subscriptions WHERE follower_id=$1 AND target_id=$2', [req.user.id, targetId]);
    if (exists.rows.length) {
      await pool.query('DELETE FROM subscriptions WHERE follower_id=$1 AND target_id=$2', [req.user.id, targetId]);
      res.json({ subscribed: false });
    } else {
      await pool.query('INSERT INTO subscriptions(follower_id,target_id) VALUES($1,$2)', [req.user.id, targetId]);
      await createNotification(targetId, req.user.id, 'subscribe');
      res.json({ subscribed: true });
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/channel/:username/subscribers', async (req, res) => {
  try {
    const { rows: users } = await pool.query('SELECT id FROM users WHERE username=$1', [req.params.username]);
    if (!users[0]) return res.status(404).json({ error: 'Не найдено' });
    const { rows } = await pool.query(
      `SELECT u.id, u.username,
        (SELECT COUNT(*) FROM subscriptions WHERE target_id=u.id) as subscriber_count
       FROM subscriptions s JOIN users u ON u.id=s.follower_id WHERE s.target_id=$1 ORDER BY s.created_at DESC`,
      [users[0].id]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// USERS SEARCH
app.get('/api/users/search', async (req, res) => {
  const { q = '' } = req.query;
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username,
        (SELECT COUNT(*) FROM subscriptions WHERE target_id=u.id) as subscriber_count,
        (SELECT COUNT(*) FROM videos WHERE user_id=u.id) as video_count
       FROM users u
       WHERE u.username ILIKE $1
       ORDER BY subscriber_count DESC LIMIT 20`,
      [`%${q}%`]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ALL USERS (for all channels panel)
app.get('/api/users/all', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username,
        (SELECT COUNT(*) FROM subscriptions WHERE target_id=u.id) as subscriber_count,
        (SELECT COUNT(*) FROM videos WHERE user_id=u.id) as video_count
       FROM users u
       ORDER BY subscriber_count DESC, u.created_at DESC`
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// USER SUBSCRIPTIONS (sidebar)
app.get('/api/user/subscriptions', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.username,
        (SELECT COUNT(*) FROM subscriptions WHERE target_id=u.id) as subscriber_count
       FROM subscriptions s JOIN users u ON u.id=s.target_id
       WHERE s.follower_id=$1
       ORDER BY s.created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// RENAME
app.post('/api/auth/rename', auth, async (req, res) => {
  const { username } = req.body;
  if (!username || !username.trim()) return res.status(400).json({ error: 'Введи никнейм' });
  const clean = username.trim();
  if (clean.length < 2 || clean.length > 50) return res.status(400).json({ error: 'Никнейм: 2–50 символов' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE username=$1 AND id!=$2', [clean, req.user.id]);
    if (exists.rows.length) return res.status(409).json({ error: 'Никнейм уже занят' });
    await pool.query('UPDATE users SET username=$1 WHERE id=$2', [clean, req.user.id]);
    const { rows } = await pool.query('SELECT id,username,email FROM users WHERE id=$1', [req.user.id]);
    res.json({ token: makeToken(rows[0]), user: { id: rows[0].id, username: rows[0].username } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// LOGIN: return subscriberCount
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(process.env.PORT || 3000, () => console.log('🚀 CosmоVibe запущен'));
