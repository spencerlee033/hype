require('dotenv').config({ path: require('path').join(__dirname, '.env') });
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const axios     = require('axios');
const geoip     = require('geoip-lite');
const UAParser  = require('ua-parser-js');
const path      = require('path');
const sqlite3   = require('sqlite3').verbose();

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const API_URL = process.env.API_URL || `http://localhost:${PORT}`;
const VISITOR_TTL = parseInt(process.env.VISITOR_TTL) || 3600000;

// ─────────────────────────────────────────────────────────────
//  SQLITE DATABASE SETUP
// ─────────────────────────────────────────────────────────────
const db = new sqlite3.Database(path.join(__dirname, 'referrals.db'));

db.serialize(() => {
  // Workers table (replaces in-memory Map)
  db.run(`CREATE TABLE IF NOT EXISTS workers (
    workerId TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hash TEXT NOT NULL,
    referralCode TEXT UNIQUE,
    referralLink TEXT,
    linkCleared INTEGER DEFAULT 0,
    totalClicks INTEGER DEFAULT 0,
    totalClaims INTEGER DEFAULT 0,
    totalCompletes INTEGER DEFAULT 0,
    isActive INTEGER DEFAULT 1,
    createdAt TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  // Visitors table (with TTL support)
  db.run(`CREATE TABLE IF NOT EXISTS visitors (
    visitorId TEXT PRIMARY KEY,
    workerId TEXT,
    referralCode TEXT,
    ip TEXT,
    country TEXT,
    device TEXT,
    browser TEXT,
    status TEXT DEFAULT 'clicked',
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    expiresAt INTEGER,
    FOREIGN KEY(workerId) REFERENCES workers(workerId)
  )`);

  // Admin table (single admin)
  db.run(`CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL,
    hash TEXT NOT NULL
  )`);
});

// ─────────────────────────────────────────────────────────────
//  MIDDLEWARE
// ─────────────────────────────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://127.0.0.1:3000')
  .split(',')
  .map(o => o.trim())
  .filter(o => o);

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log(`[CORS] Blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: true,
  optionsSuccessStatus: 204
};

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https:"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "http://localhost:*", "http://127.0.0.1:*"],
      fontSrc: ["'self'", "https:", "data:"],
      objectSrc: ["'none'"],
    },
  },
}));

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname), { index: false }));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
// Rate limiting
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' }
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' }
});

app.use('/api/admin/login', strictLimiter);
app.use('/api/worker/get-link', strictLimiter);
app.use('/api/track-visit', strictLimiter);
app.use('/api/', generalLimiter);

// ─────────────────────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────────────────────
function nextWorkerId() {
  return new Promise((resolve, reject) => {
    db.get("SELECT workerId FROM workers ORDER BY workerId DESC LIMIT 1", [], (err, row) => {
      if (err) return reject(err);
      if (!row) return resolve('WRK-001');
      const num = parseInt(row.workerId.replace('WRK-', ''));
      resolve(`WRK-${String(num + 1).padStart(3, '0')}`);
    });
  });
}

function makeCode() {
  return uuidv4().replace(/-/g, '').slice(0, 10).toUpperCase();
}

function getIP(req) {
  return (req.headers['x-forwarded-for'] || req.ip || '127.0.0.1').split(',')[0].trim();
}

function isValidUrl(string) {
  try {
    const url = new URL(string);
    return url.protocol === 'https:' || url.protocol === 'http:';
  } catch (_) {
    return false;
  }
}

async function telegram(text) {
  const token  = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId || token === 'PUT_YOUR_TOKEN_HERE' || chatId === 'PUT_YOUR_CHAT_ID_HERE') return;
  try {
    await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
      chat_id: chatId, parse_mode: 'HTML', text
    });
  } catch (e) {
    console.log('Telegram error (non-fatal):', e.message);
  }
}

// ─────────────────────────────────────────────────────────────
//  AUTH MIDDLEWARE
// ─────────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Not admin' });
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─────────────────────────────────────────────────────────────
//  BOOT — create admin from .env
// ─────────────────────────────────────────────────────────────
async function boot() {
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;

  console.log('🔧 ENV check:');
  console.log('   ADMIN_USERNAME:', username || 'NOT SET');
  console.log('   ADMIN_PASSWORD:', password ? '***SET***' : 'NOT SET');
  console.log('   JWT_SECRET:', process.env.JWT_SECRET ? '***SET***' : 'NOT SET');
  console.log('   ALLOWED_ORIGINS:', allowedOrigins.join(', ') || 'NOT SET');
  console.log('   API_URL:', API_URL);
  console.log('   VISITOR_TTL:', VISITOR_TTL + 'ms');
  console.log('   PORT:', PORT);

  if (!username || !password) {
    console.error('❌ ADMIN_USERNAME and ADMIN_PASSWORD must be set in .env');
    process.exit(1);
  }

  if (!process.env.JWT_SECRET) {
    console.error('❌ JWT_SECRET must be set in .env');
    process.exit(1);
  }

  if (password.length < 8) {
    console.error('❌ ADMIN_PASSWORD must be at least 8 characters');
    process.exit(1);
  }

  const hash = await bcrypt.hash(password, 12);

  // Upsert admin
  db.run(
    `INSERT INTO admin (id, username, hash) VALUES (1, ?, ?)
     ON CONFLICT(id) DO UPDATE SET username=excluded.username, hash=excluded.hash`,
    [username, hash],
    (err) => {
      if (err) {
        console.error('❌ Failed to setup admin:', err.message);
        process.exit(1);
      }
      console.log(`\n✅ Admin ready → username: ${username}`);
    }
  );
}

// ═════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ═════════════════════════════════════════════════════════════

// POST /api/admin/login
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  db.get("SELECT * FROM admin WHERE id = 1", [], async (err, admin) => {
    if (err || !admin || username !== admin.username) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const ok = await bcrypt.compare(password, admin.hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ role: 'admin', username }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ success: true, token });
  });
});

// GET /api/admin/workers
app.get('/api/admin/workers', requireAdmin, (req, res) => {
  db.all(`SELECT workerId, name, referralCode, referralLink, linkCleared,
          totalClicks, totalClaims, totalCompletes, isActive, createdAt
          FROM workers ORDER BY workerId`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const workers = rows.map(w => ({
      ...w,
      linkCleared: !!w.linkCleared,
      isActive: !!w.isActive
    }));
    res.json({ success: true, workers });
  });
});

// POST /api/admin/workers — create worker
app.post('/api/admin/workers', requireAdmin, async (req, res) => {
  const { workerId: customId, name, password, referralLink } = req.body || {};
  if (!name || !password) return res.status(400).json({ error: 'name and password required' });
  if (password.length < 4) return res.status(400).json({ error: 'password must be at least 4 characters' });
  if (referralLink && !isValidUrl(referralLink)) {
    return res.status(400).json({ error: 'referralLink must be a valid http:// or https:// URL' });
  }

  try {
    // Use custom ID if provided and valid, otherwise auto-generate
    let workerId;
    if (customId && /^[A-Z0-9\-_]{3,20}$/i.test(customId)) {
      workerId = customId.toUpperCase();
      // Check if ID already exists
      const existing = await new Promise((resolve, reject) => {
        db.get(`SELECT workerId FROM workers WHERE workerId = ?`, [workerId], (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      });
      if (existing) return res.status(400).json({ error: 'Worker ID already exists' });
    } else {
      workerId = await nextWorkerId();
    }

    const referralCode = referralLink ? makeCode() : null;
    const hash = await bcrypt.hash(password, 12);

    db.run(
      `INSERT INTO workers (workerId, name, hash, referralCode, referralLink, linkCleared, isActive)
       VALUES (?, ?, ?, ?, ?, 0, 1)`,
      [workerId, name, hash, referralCode, referralLink || null],
      function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ 
          success: true, 
          worker: { workerId, name, referralCode, referralLink: referralLink || null } 
        });
      }
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/workers/:id/link — assign or update link
app.put('/api/admin/workers/:id/link', requireAdmin, (req, res) => {
  const { referralLink } = req.body || {};
  if (!referralLink) return res.status(400).json({ error: 'referralLink required' });
  if (!isValidUrl(referralLink)) {
    return res.status(400).json({ error: 'referralLink must be a valid http:// or https:// URL' });
  }

  const newCode = makeCode();
  db.run(
    `UPDATE workers SET referralCode = ?, referralLink = ?, linkCleared = 0 WHERE workerId = ?`,
    [newCode, referralLink, req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(404).json({ error: 'Worker not found' });
      res.json({ success: true, referralCode: newCode, referralLink });
    }
  );
});

// DELETE /api/admin/workers/:id/link — remove link
app.delete('/api/admin/workers/:id/link', requireAdmin, (req, res) => {
  db.run(
    `UPDATE workers SET referralCode = NULL, referralLink = NULL, linkCleared = 0 WHERE workerId = ?`,
    [req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(404).json({ error: 'Worker not found' });
      res.json({ success: true });
    }
  );
});

// DELETE /api/admin/workers/:id — delete worker
app.delete('/api/admin/workers/:id', requireAdmin, (req, res) => {
  db.run(`DELETE FROM workers WHERE workerId = ?`, [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Worker not found' });
    res.json({ success: true });
  });
});

// PATCH /api/admin/workers/:id/toggle — activate/deactivate
app.patch('/api/admin/workers/:id/toggle', requireAdmin, (req, res) => {
  db.run(
    `UPDATE workers SET isActive = CASE WHEN isActive = 1 THEN 0 ELSE 1 END WHERE workerId = ?`,
    [req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(404).json({ error: 'Worker not found' });
      db.get(`SELECT isActive FROM workers WHERE workerId = ?`, [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, isActive: !!row.isActive });
      });
    }
  );
});

// ═════════════════════════════════════════════════════════════
//  WORKER PORTAL
// ═════════════════════════════════════════════════════════════

// POST /api/worker/get-link
app.post('/api/worker/get-link', async (req, res) => {
  const { workerId, password } = req.body || {};
  if (!workerId || !password) return res.status(400).json({ error: 'workerId and password required' });

  db.get(`SELECT * FROM workers WHERE workerId = ?`, [workerId.toUpperCase()], async (err, w) => {
    if (err || !w) return res.status(401).json({ error: 'Invalid Worker ID or password' });

    const ok = await bcrypt.compare(password, w.hash);
    if (!ok) return res.status(401).json({ error: 'Invalid Worker ID or password' });
    if (!w.isActive) return res.status(403).json({ error: 'Account deactivated. Contact admin.' });

    if (!w.referralLink || !w.referralCode) {
      return res.json({ 
        success: true, hasLink: false, cleared: false, 
        name: w.name, workerId: w.workerId,
        message: 'No referral link assigned yet. Contact your admin.' 
      });
    }
    if (w.linkCleared) {
      return res.json({ 
        success: true, hasLink: false, cleared: true, 
        name: w.name, workerId: w.workerId,
        message: 'Your link has been used and cleared. Contact admin for a new one.' 
      });
    }

    const sep = w.referralLink.includes('?') ? '&' : '?';
    const link = `${w.referralLink}${sep}ref=${w.referralCode}`;
    res.json({
      success: true, hasLink: true,
      workerId: w.workerId, name: w.name,
      referralLink: link, referralCode: w.referralCode,
      stats: { totalClicks: w.totalClicks, totalClaims: w.totalClaims, totalCompletes: w.totalCompletes }
    });
  });
});

// ═════════════════════════════════════════════════════════════
//  PUBLIC TRACKING
// ═════════════════════════════════════════════════════════════

// POST /api/track-visit
app.post('/api/track-visit', (req, res) => {
  const { refCode } = req.body || {};
  if (!refCode || !/^[A-Z0-9]{10}$/.test(refCode)) {
    return res.status(400).json({ error: 'Invalid code' });
  }

  db.get(`SELECT * FROM workers WHERE referralCode = ? AND isActive = 1 AND linkCleared = 0`, 
    [refCode], (err, w) => {
    if (err || !w) return res.status(404).json({ error: 'Code not found or inactive' });

    const ip = getIP(req);
    const geo = geoip.lookup(ip) || { country: 'Unknown' };
    const ua = new UAParser(req.headers['user-agent'] || '').getResult();
    const device = `${ua.os.name || 'Unknown'} ${ua.os.version || ''}`.trim();
    const browser = `${ua.browser.name || 'Unknown'} ${ua.browser.version || ''}`.trim();
    const vid = uuidv4();
    const expiresAt = Date.now() + VISITOR_TTL;

    db.run(
      `INSERT INTO visitors (visitorId, workerId, referralCode, ip, country, device, browser, status, expiresAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'clicked', ?)`,
      [vid, w.workerId, refCode, ip, geo.country || 'Unknown', device, browser, expiresAt],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to track visit' });

        db.run(`UPDATE workers SET totalClicks = totalClicks + 1 WHERE workerId = ?`, [w.workerId]);
        res.json({ success: true, visitorId: vid });
      }
    );
  });
});

// POST /api/claim — now merges claim + complete in one step
app.post('/api/claim', (req, res) => {
  const { visitorId } = req.body || {};
  if (!visitorId) return res.status(400).json({ error: 'visitorId required' });

  db.get(`SELECT v.*, w.name as workerName, w.totalClicks, w.totalClaims, w.totalCompletes
          FROM visitors v JOIN workers w ON v.workerId = w.workerId WHERE v.visitorId = ?`,
    [visitorId], async (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Visitor not found or expired' });
    if (row.status !== 'clicked') return res.status(400).json({ error: 'Already processed' });

    // Mark claimed
    db.run(`UPDATE visitors SET status = 'claimed' WHERE visitorId = ?`, [visitorId], function(err) {
      if (err) return res.status(500).json({ error: err.message });

      // Update claims count
      db.run(`UPDATE workers SET totalClaims = totalClaims + 1 WHERE workerId = ?`, [row.workerId]);

      // ─── MERGED: immediately do complete logic ───
      const msg = [
        `🏁 <b>Referral Completed!</b>`,
        ``,
        `🪪 <b>Worker ID:</b> <code>${row.workerId}</code>`,
        `👤 <b>Worker:</b> ${row.workerName || 'Unknown'}`,
        `🔗 <b>Ref Code:</b> <code>${row.referralCode}</code>`,
        ``,
        `📋 <b>Visitor Info:</b>`,
        `🌍 Country: ${row.country}`,
        `📱 Device: ${row.device}`,
        `🌐 Browser: ${row.browser}`,
        `⏱ Time: ${new Date(row.timestamp).toLocaleString()}`,
        ``,
        `📊 <b>Worker Totals:</b>`,
        `  🖱 Clicks: ${row.totalClicks}`,
        `  ✅ Claims: ${row.totalClaims + 1}`,
        `  🏁 Completes: ${row.totalCompletes + 1}`
      ].join('\n');

      telegram(msg);

      db.run(`UPDATE workers SET totalCompletes = totalCompletes + 1 WHERE workerId = ?`, [row.workerId]);
      db.run(`DELETE FROM visitors WHERE visitorId = ?`, [visitorId]);

      console.log(`✅ Claim+Complete — visitor deleted — worker: ${row.workerId}`);
      res.json({ success: true, completed: true });
    });
  });
});



// DEBUG: Test claim endpoint directly (no auth needed)
app.post('/api/debug/test-claim', (req, res) => {
  const { visitorId } = req.body || {};
  if (!visitorId) return res.status(400).json({ error: 'visitorId required' });

  db.get(`SELECT v.*, w.name as workerName, w.totalClicks, w.totalClaims, w.totalCompletes
          FROM visitors v JOIN workers w ON v.workerId = w.workerId WHERE v.visitorId = ?`,
    [visitorId], async (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Visitor not found', detail: err?.message });
    if (row.status !== 'clicked') return res.status(400).json({ error: 'Already processed', status: row.status });

    // Mark claimed
    db.run(`UPDATE visitors SET status = 'claimed' WHERE visitorId = ?`, [visitorId], function(err) {
      if (err) return res.status(500).json({ error: err.message });

      db.run(`UPDATE workers SET totalClaims = totalClaims + 1 WHERE workerId = ?`, [row.workerId]);

      const msg = [
        `🏁 <b>Referral Completed!</b>`,
        ``,
        `🪪 <b>Worker ID:</b> <code>${row.workerId}</code>`,
        `👤 <b>Worker:</b> ${row.workerName || 'Unknown'}`,
        `🔗 <b>Ref Code:</b> <code>${row.referralCode}</code>`,
        ``,
        `📋 <b>Visitor Info:</b>`,
        `🌍 Country: ${row.country}`,
        `📱 Device: ${row.device}`,
        `🌐 Browser: ${row.browser}`,
        `⏱ Time: ${new Date(row.timestamp).toLocaleString()}`,
        ``,
        `📊 <b>Worker Totals:</b>`,
        `  🖱 Clicks: ${row.totalClicks}`,
        `  ✅ Claims: ${row.totalClaims + 1}`,
        `  🏁 Completes: ${row.totalCompletes + 1}`
      ].join('\n');

      telegram(msg);

      db.run(`UPDATE workers SET totalCompletes = totalCompletes + 1 WHERE workerId = ?`, [row.workerId]);
      db.run(`DELETE FROM visitors WHERE visitorId = ?`, [visitorId]);

      console.log(`✅ DEBUG Claim+Complete — visitor deleted — worker: ${row.workerId}`);
      res.json({ success: true, completed: true, workerId: row.workerId });
    });
  });
});

// POST /api/complete
app.post('/api/complete', async (req, res) => {
  const { visitorId } = req.body || {};
  if (!visitorId) return res.status(400).json({ error: 'visitorId required' });

  db.get(`SELECT v.*, w.name as workerName, w.totalClicks, w.totalClaims, w.totalCompletes
          FROM visitors v JOIN workers w ON v.workerId = w.workerId WHERE v.visitorId = ?`, 
    [visitorId], async (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Visitor not found or already cleared' });

    const msg = [
      `🏁 <b>Referral Completed!</b>`,
      ``,
      `🪪 <b>Worker ID:</b> <code>${row.workerId}</code>`,
      `👤 <b>Worker:</b> ${row.workerName || 'Unknown'}`,
      `🔗 <b>Ref Code:</b> <code>${row.referralCode}</code>`,
      ``,
      `📋 <b>Visitor Info:</b>`,
      `🌍 Country: ${row.country}`,
      `📱 Device: ${row.device}`,
      `🌐 Browser: ${row.browser}`,
      `⏱ Time: ${new Date(row.timestamp).toLocaleString()}`,
      ``,
      `📊 <b>Worker Totals:</b>`,
      `  🖱 Clicks: ${row.totalClicks}`,
      `  ✅ Claims: ${row.totalClaims}`,
      `  🏁 Completes: ${row.totalCompletes + 1}`
    ].join('\n');

    await telegram(msg);

    db.run(`UPDATE workers SET totalCompletes = totalCompletes + 1 WHERE workerId = ?`, [row.workerId]);
    db.run(`DELETE FROM visitors WHERE visitorId = ?`, [visitorId]);

    console.log(`✅ Complete — visitor deleted — worker: ${row.workerId}`);
    res.json({ success: true, message: 'Done. Data cleared.' });
  });
});

// Cleanup expired visitors periodically
setInterval(() => {
  const now = Date.now();
  db.run(`DELETE FROM visitors WHERE expiresAt < ?`, [now], function(err) {
    if (err) console.error('Cleanup error:', err.message);
    else if (this.changes > 0) console.log(`[CLEANUP] Removed ${this.changes} expired visitors`);
  });
}, 60000); // Every minute

// TEMP: List all workers (no auth, for debugging)
app.get('/api/debug/workers', (req, res) => {
  db.all(`SELECT workerId, name, isActive, referralLink, referralCode, createdAt FROM workers`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ count: rows.length, workers: rows });
  });
});

// Health check
app.get('/api/health', (req, res) => {
  db.get(`SELECT COUNT(*) as workers FROM workers`, [], (err, wRow) => {
    db.get(`SELECT COUNT(*) as visitors FROM visitors`, [], (err, vRow) => {
      res.json({
        status: 'ok',
        workers: wRow ? wRow.workers : 0,
        visitors: vRow ? vRow.visitors : 0,
        uptime: Math.floor(process.uptime()) + 's',
        apiUrl: API_URL
      });
    });
  });
});

// Config endpoint for frontend
app.get('/api/config', (req, res) => {
  res.json({ apiUrl: API_URL });
});

module.exports = { app, boot };

// ─────────────────────────────────────────────────────────────
//  START
// ─────────────────────────────────────────────────────────────
if (require.main === module) {
  boot().then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 Server running  →  ${API_URL}`);
      console.log(`📋 Admin panel     →  ${API_URL}/admin.html`);
      console.log(`🔗 Worker portal   →  ${API_URL}/worker.html`);
      console.log(`🩺 Health check    →  ${API_URL}/api/health\n`);
    });
  });
}