/**
 * app.js — Cloud MIN · Multi-Region Dashboard
 * ─────────────────────────────────────────────
 * Features:
 *  • bcrypt password hashing (in userModel)
 *  • Input sanitization (XSS & injection prevention)
 *  • Rate limiting: per-IP login attempts via in-memory store
 *  • CSRF protection via csurf token generation
 *  • Full backend validation (username, email, password)
 *  • Session management with session fixation prevention
 *  • Structured error handling with user-friendly messages
 *  • Health check endpoint for load balancer probes
 */

'use strict';
const dns = require('dns').promises;

async function domainHasMX(email) {
  try {
    const domain = email.split('@')[1];
    const records = await dns.resolveMx(domain);
    return records && records.length > 0;
  } catch {
    return false;
  }
}



const express    = require('express');
const bodyParser = require('body-parser');
const os         = require('os');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');
const mongoose   = require('mongoose');
const session    = require('express-session');
const User       = require('./models/userModel');

const app = express();

// ── Middleware ─────────────────────────────────────────────
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// ── View engine ────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ── Environment ────────────────────────────────────────────
const PORT        = process.env.PORT        || 3000;
const SERVER_NAME = process.env.SERVER_NAME || 'Server';
const ENV         = process.env.NODE_ENV    || 'production';

// ── Supported AWS regions ──────────────────────────────────
const SUPPORTED_REGIONS = {
  'ap-south-1': 'ap-south-1',
  'ap-south-2': 'ap-south-2',
};
const DEFAULT_REGION = 'ap-south-1';

function resolveRegion(env, regionEnv) {
  if (env === 'development') return 'Localhost';
  return SUPPORTED_REGIONS[regionEnv] || DEFAULT_REGION;
}
const REGION = resolveRegion(ENV, process.env.REGION);

// ── Read version from package.json ─────────────────────────
let BUILD_VERSION = 'v1.0.0';
try {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
  BUILD_VERSION = 'v' + (pkg.version || '1.0.0');
} catch (_) {}

// ── Server start time ──────────────────────────────────────
const SERVER_START = Date.now();

// ── MongoDB URI ────────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI ||
  'mongodb://kscs7755_db_user:Z7JuEBigSxVt65FG@ac-votpwb1-shard-00-00.jkismd9.mongodb.net:27017,ac-votpwb1-shard-00-01.jkismd9.mongodb.net:27017,ac-votpwb1-shard-00-02.jkismd9.mongodb.net:27017/cloudproject?ssl=true&replicaSet=atlas-qx79as-shard-0&authSource=admin&retryWrites=true&w=majority&appName=Cluster0';

// ── Session middleware ─────────────────────────────────────
app.use(session({
  secret:            process.env.SESSION_SECRET || 'cloudproject-secret-key-change-in-prod',
  resave:            false,
  saveUninitialized: false,
  name:              'sid', // don't expose 'connect.sid' default name
  cookie: {
    secure:   ENV === 'production' && process.env.HTTPS === 'true',
    httpOnly: true,
    sameSite: 'lax',
    maxAge:   24 * 60 * 60 * 1000, // 24 hours
  },
}));

// ── MongoDB connection ─────────────────────────────────────
mongoose.connect(MONGO_URI)
  .then(() => console.log(`[mongo] Connected`))
  .catch(err => console.error('[mongo] Connection failed:', err.message));

mongoose.connection.on('disconnected', () => console.warn('[mongo] Disconnected'));
mongoose.connection.on('reconnected',  () => console.log('[mongo]  Reconnected'));


// ════════════════════════════════════════════════════════════
//  RATE LIMITER
//  In-memory per-IP store. For production use a Redis-backed
//  store (e.g. rate-limiter-flexible or express-rate-limit).
// ════════════════════════════════════════════════════════════
const loginAttempts = new Map(); // key: IP, value: { count, lockedUntil }

const RATE_LIMIT = {
  MAX_ATTEMPTS:  5,       // max failed logins before lockout
  LOCKOUT_MS:    10 * 60 * 1000, // 10-minute lockout
  WINDOW_MS:     15 * 60 * 1000, // 15-minute rolling window
  CLEANUP_EVERY: 60 * 1000,      // clean stale entries every 1 minute
};

// Clean up stale rate limit entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of loginAttempts.entries()) {
    if (now > data.lockedUntil && now > (data.firstAttempt || 0) + RATE_LIMIT.WINDOW_MS) {
      loginAttempts.delete(ip);
    }
  }
}, RATE_LIMIT.CLEANUP_EVERY);

/**
 * Get client IP (respects proxy headers).
 */
function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket?.remoteAddress
    || '0.0.0.0';
}

/**
 * Returns { locked: bool, remainingSeconds: number, attemptsLeft: number }
 */
function checkRateLimit(ip) {
  const now  = Date.now();
  const data = loginAttempts.get(ip) || { count: 0, lockedUntil: 0, firstAttempt: now };

  if (data.lockedUntil && now < data.lockedUntil) {
    return {
      locked:           true,
      remainingSeconds: Math.ceil((data.lockedUntil - now) / 1000),
      attemptsLeft:     0,
    };
  }

  // Reset window if elapsed
  if (now > (data.firstAttempt || 0) + RATE_LIMIT.WINDOW_MS) {
    data.count        = 0;
    data.firstAttempt = now;
    data.lockedUntil  = 0;
    loginAttempts.set(ip, data);
  }

  return {
    locked:       false,
    remainingSeconds: 0,
    attemptsLeft: Math.max(0, RATE_LIMIT.MAX_ATTEMPTS - data.count),
  };
}

/**
 * Record a failed login attempt. Returns updated rate limit state.
 */
function recordFailedAttempt(ip) {
  const now  = Date.now();
  const data = loginAttempts.get(ip) || { count: 0, lockedUntil: 0, firstAttempt: now };

  data.count = (data.count || 0) + 1;

  if (data.count >= RATE_LIMIT.MAX_ATTEMPTS) {
    data.lockedUntil = now + RATE_LIMIT.LOCKOUT_MS;
  }
  loginAttempts.set(ip, data);

  return {
    locked:           data.lockedUntil > now,
    remainingSeconds: Math.ceil(Math.max(0, data.lockedUntil - now) / 1000),
    attemptsLeft:     Math.max(0, RATE_LIMIT.MAX_ATTEMPTS - data.count),
  };
}

/**
 * Clear rate limit record on successful login.
 */
function clearRateLimit(ip) {
  loginAttempts.delete(ip);
}


// ════════════════════════════════════════════════════════════
//  INPUT SANITIZATION
// ════════════════════════════════════════════════════════════

/**
 * Strip HTML/script tags and trim whitespace.
 * Prevents XSS and basic injection via reflected form values.
 */
function sanitizeString(val) {
  if (typeof val !== 'string') return '';
  return val
    .replace(/<[^>]*>/g, '')          // strip HTML tags
    .replace(/[^\x20-\x7E\u00A0-\uFFFF]/g, '') // strip non-printable chars
    .trim();
}


// ════════════════════════════════════════════════════════════
//  VALIDATION RULES (backend — mirrors frontend logic)
// ════════════════════════════════════════════════════════════

const RESTRICTED_USERNAMES = [
  'admin','root','superuser','system','null','undefined',
  'support','help','info','abuse','postmaster','webmaster',
  'hostmaster','moderator','mod',
];

const DISPOSABLE_DOMAINS = [
  'mailinator.com','guerrillamail.com','tempmail.com',
  'throwaway.email','yopmail.com','sharklasers.com',
  'trashmail.com','dispostable.com',
];

/**
 * Validate username for signup.
 * Returns error string or null if valid.
 */
function validateUsername(username) {
  if (!username)             return 'Username is required.';
  if (/\s/.test(username))   return 'Username cannot contain spaces.';
  if (username.length < 3)   return 'Username must be at least 3 characters.';
  if (username.length > 20)  return 'Username cannot exceed 20 characters.';
  if (!/^[a-zA-Z]/.test(username)) return 'Username must start with a letter.';
  if (!/^[a-zA-Z0-9_.]+$/.test(username)) return 'Username can only contain letters, numbers, underscores, and dots.';
  if (RESTRICTED_USERNAMES.includes(username.toLowerCase())) {
    return `"${username}" is a reserved name. Please choose another.`;
  }
  return null;
}

/**
 * Validate email address.
 * Returns error string or null if valid.
 */
function validateEmail(email) {
  if (!email)             return 'Email address is required.';
  if (email.length > 254) return 'Email address is too long.';

  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(email)) return 'Please enter a valid email address.';

// Must have exactly one @
const atParts = email.split('@');
if (atParts.length !== 2) return 'Please enter a valid email address.';

const [localPart, domainPart] = atParts;
if (!localPart || localPart.length > 64) return 'Please enter a valid email address.';

// Domain must contain at least one dot
if (!domainPart.includes('.')) return 'Email domain must contain a dot (e.g. gmail.com).';

// Domain parts cannot be empty (catches abc@.com or abc@gmail.)
const domainSegments = domainPart.split('.');
if (domainSegments.some(seg => seg.length === 0)) return 'Please enter a valid email address.';

// TLD must be at least 2 characters
const tld = domainSegments[domainSegments.length - 1];
if (tld.length < 2) return 'Email must have a valid extension (e.g. .com, .in).';

  const domain = email.split('@')[1].toLowerCase();
  if (DISPOSABLE_DOMAINS.includes(domain)) {
    return 'Disposable email addresses are not accepted. Please use a real email.';
  }
  return null;
}

/**
 * Validate password strength for signup.
 * Returns error string or null if valid.
 */
function validatePassword(password, username, email) {
  if (!password)             return 'Password is required.';
  if (password.length < 8)   return 'Password must be at least 8 characters.';
  if (password.length > 128) return 'Password is too long (max 128 characters).';
  if (/\s/.test(password))   return 'Password cannot contain spaces.';
  if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase letter.';
  if (!/[a-z]/.test(password)) return 'Password must contain at least one lowercase letter.';
  if (!/[0-9]/.test(password)) return 'Password must contain at least one number.';
  if (!/[!@#$%^&*()\-_=+\[\]{};:'",.<>?/\\|`~]/.test(password)) {
    return 'Password must contain at least one special character (e.g. !@#$%).';
  }
  // Cannot match username
  if (username && password.toLowerCase() === username.toLowerCase()) {
    return 'Password cannot be the same as your username.';
  }
  // Cannot match email prefix
  if (email) {
    const prefix = email.split('@')[0];
    if (password.toLowerCase() === email.toLowerCase() || password.toLowerCase() === prefix.toLowerCase()) {
      return 'Password cannot be based on your email address.';
    }
  }
  return null;
}


// ════════════════════════════════════════════════════════════
//  SIMPLE CSRF TOKEN (stateless double-submit cookie)
//  For production use a proper library like csurf or helmet.
// ════════════════════════════════════════════════════════════

/**
 * Generate and attach a CSRF token to the session.
 */
function ensureCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

/**
 * Verify submitted CSRF token matches session token.
 * Returns true if valid.
 */
function verifyCsrf(req) {
  const submitted = req.body._csrf || '';
  const expected  = req.session.csrfToken || '';
  // Use timingSafeEqual to prevent timing attacks
  if (!submitted || !expected || submitted.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(submitted), Buffer.from(expected));
}


// ════════════════════════════════════════════════════════════
//  AUTH GUARD
// ════════════════════════════════════════════════════════════
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/');
}


// ════════════════════════════════════════════════════════════
//  SYSTEM METRICS HELPERS
// ════════════════════════════════════════════════════════════
function getCpuUsage() {
  return new Promise(resolve => {
    const cpus1 = os.cpus();
    setTimeout(() => {
      const cpus2 = os.cpus();
      let idle = 0, total = 0;
      cpus1.forEach((cpu, i) => {
        const cpu2 = cpus2[i];
        for (const type in cpu2.times) total += cpu2.times[type] - cpu.times[type];
        idle += cpu2.times.idle - cpu.times.idle;
      });
      resolve(Math.round((1 - idle / total) * 100));
    }, 200);
  });
}

function getMemUsage() {
  const total = os.totalmem(), free = os.freemem();
  return Math.round(((total - free) / total) * 100);
}

function getDiskUsage() {
  return new Promise(resolve => {
    const { exec } = require('child_process');
    exec("df / | tail -1 | awk '{print $5}'", (err, stdout) => {
      if (err) return resolve(null);
      resolve(parseInt(stdout.trim()) || null);
    });
  });
}

function getNetworkBytes() {
  return new Promise(resolve => {
    fs.readFile('/proc/net/dev', 'utf8', (err, data) => {
      if (err) return resolve(null);
      let rx = 0, tx = 0;
      data.trim().split('\n').slice(2).forEach(line => {
        const p = line.trim().split(/\s+/);
        if (p[0].startsWith('lo')) return;
        rx += parseInt(p[1]) || 0;
        tx += parseInt(p[9]) || 0;
      });
      resolve({ rx, tx });
    });
  });
}

let prevNet = null, prevNetTime = null;


// ════════════════════════════════════════════════════════════
//  ROUTES
// ════════════════════════════════════════════════════════════

// ── GET /api/stats ─────────────────────────────────────────
app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    const [cpu, disk, netNow] = await Promise.all([getCpuUsage(), getDiskUsage(), getNetworkBytes()]);
    const mem = getMemUsage();
    let netPct = null;
    const now = Date.now();
    if (prevNet && netNow) {
      const dt = (now - prevNetTime) / 1000;
      const rxDelta = (netNow.rx - prevNet.rx) / dt;
      const txDelta = (netNow.tx - prevNet.tx) / dt;
      netPct = Math.min(100, Math.round(((rxDelta + txDelta) / 125_000_000) * 100));
    }
    prevNet = netNow; prevNetTime = now;

    const fmt = s => {
      const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
      return [h, m, sec].map(v => String(v).padStart(2, '0')).join(':');
    };

    res.json({
      cpu, mem, disk, net: netPct,
      osUptime:  fmt(Math.floor(os.uptime())),
      appUptime: fmt(Math.floor((Date.now() - SERVER_START) / 1000)),
      hostname:  os.hostname(),
      platform:  os.platform(),
      arch:      os.arch(),
      cpuModel:  os.cpus()[0]?.model || 'Unknown',
      cpuCores:  os.cpus().length,
      totalMem:  Math.round(os.totalmem() / 1024 / 1024 / 1024 * 10) / 10,
      freeMem:   Math.round(os.freemem()  / 1024 / 1024 / 1024 * 10) / 10,
      loadAvg:   os.loadavg().map(v => v.toFixed(2)),
      version:   BUILD_VERSION,
      region:    REGION,
      env:       ENV,
      server:    SERVER_NAME,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── GET / — Login/Signup page ──────────────────────────────
app.get('/', (req, res) => {
  if (req.session?.userId) {
    return res.redirect(`/dashboard/${encodeURIComponent(req.session.username)}`);
  }
  const csrfToken = ensureCsrfToken(req);
  res.render('login', { error: null, success: null, tab: 'login', csrfToken, lockoutSeconds: 0, prefill: '', prefillUsername: '', prefillEmail: '' });
});


// ── POST /signup ───────────────────────────────────────────
app.post('/signup', async (req, res) => {
  // ── CSRF check ──
  if (!verifyCsrf(req)) {
    return res.status(403).render('login', {
      error:   'Invalid request. Please refresh and try again.',
      success: null, tab: 'signup',
      csrfToken: ensureCsrfToken(req),
      lockoutSeconds: 0, prefill: '', prefillUsername: '', prefillEmail: '',
    });
  }

  // ── Sanitize inputs ──
  const username = sanitizeString(req.body.username || '');
  const email    = sanitizeString((req.body.email || '').toLowerCase());
  const password = (req.body.password || ''); // don't trim passwords
  const confirm  = (req.body.confirmPassword || '');

  const csrfToken = ensureCsrfToken(req);

  function renderError(msg, type = 'err') {
    return res.render('login', {
      error: msg, success: null, tab: 'signup',
      errorType: type, csrfToken, lockoutSeconds: 0,
      prefill: '', prefillUsername: username, prefillEmail: email,
    });
  }

  // ── Database connectivity check ──
  if (mongoose.connection.readyState !== 1) {
    return renderError('Database unavailable. Please try again in a moment.');
  }

  // ── Field presence ──
  if (!username) return renderError('Username is required.');
  if (!email)    return renderError('Email address is required.');
  if (!password) return renderError('Password is required.');
  if (!confirm)  return renderError('Please confirm your password.');

  // ── Username validation ──
  const usernameErr = validateUsername(username);
  if (usernameErr) return renderError(usernameErr);

  // ── Email validation ──
  const emailErr = validateEmail(email);
  if (emailErr) return renderError(emailErr);

  // ── Password validation ──
  const passwordErr = validatePassword(password, username, email);
  if (passwordErr) return renderError(passwordErr);

  // ── Confirm password ──
  if (password !== confirm) {
    return renderError('Passwords do not match. Please re-enter them.');
  }

  try {
    // ── Duplicate username check ──
    const existingByUsername = await User.findOne({ username });
    if (existingByUsername) {
      return renderError(`Username "${username}" is already taken. Please choose another.`);
    }

    // ── Duplicate email check ──
    const existingByEmail = await User.findOne({ email });
    if (existingByEmail) {
      return renderError('An account with this email address already exists. Try logging in instead.');
    }

    // ── Create user (password hashed in userModel pre-save hook) ──
    const user = new User({ username, email, password });
    await user.save();

    // ── Auto-login after signup (regenerate session to prevent fixation) ──
    req.session.regenerate(err => {
      if (err) {
        console.error('[signup] Session regeneration failed:', err.message);
        return res.render('login', {
          error: 'Account created but session failed. Please log in.',
          success: null, tab: 'login',
          csrfToken: ensureCsrfToken(req),
          lockoutSeconds: 0, prefill: username, prefillUsername: '', prefillEmail: '',
        });
      }
      req.session.userId   = user._id;
      req.session.username = user.username;
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
      res.redirect(`/dashboard/${encodeURIComponent(user.username)}`);
    });

  } catch (err) {
    console.error('[signup] Error:', err.message);
    // Handle mongoose duplicate key error (race condition)
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern || {})[0] || 'field';
      return renderError(`This ${field} is already registered. Please use a different one.`);
    }
    renderError('Registration failed due to a server error. Please try again.');
  }
});


// ── POST /login ────────────────────────────────────────────
app.post('/login', async (req, res) => {
  const ip        = getClientIp(req);
  const csrfToken = ensureCsrfToken(req);

  // ── CSRF check ──
  if (!verifyCsrf(req)) {
    return res.status(403).render('login', {
      error: 'Invalid request. Please refresh and try again.',
      success: null, tab: 'login',
      csrfToken, lockoutSeconds: 0, prefill: '', prefillUsername: '', prefillEmail: '',
    });
  }

  // ── Rate limit check ──
  const rl = checkRateLimit(ip);
  if (rl.locked) {
    return res.status(429).render('login', {
      error: `Too many failed login attempts. Please wait before trying again.`,
      errorType: 'warn',
      success: null, tab: 'login',
      csrfToken, lockoutSeconds: rl.remainingSeconds,
      prefill: '', prefillUsername: '', prefillEmail: '',
    });
  }

  // ── Sanitize inputs ──
  const identifier = sanitizeString(req.body.username || ''); // accepts username or email
  const password   = (req.body.password || '');

  function renderLoginError(msg, type = 'err') {
    return res.render('login', {
      error: msg, success: null, tab: 'login',
      errorType: type, csrfToken,
      lockoutSeconds: 0, prefill: identifier, prefillUsername: '', prefillEmail: '',
    });
  }

  // ── Presence checks ──
  if (!identifier) {
    return renderLoginError('Username or email is required.');
  }
  if (!password) {
    return renderLoginError('Password is required.');
  }
  if (identifier.length < 3) {
    return renderLoginError('Please enter a valid username or email.');
  }

  // ── Database connectivity ──
  if (mongoose.connection.readyState !== 1) {
    return renderLoginError('Database unavailable. Please try again in a moment.');
  }

  try {
    // ── Find user by username OR email ──
    const isEmail = identifier.includes('@');
    const query   = isEmail
      ? { email: identifier.toLowerCase() }
      : { username: identifier };

    const user = await User.findOne(query);

    if (!user) {
      // Record failed attempt and return generic message (prevent user enumeration)
      const afterFail = recordFailedAttempt(ip);
      if (afterFail.locked) {
        return res.status(429).render('login', {
          error: 'Too many failed attempts. Account temporarily locked.',
          errorType: 'warn',
          success: null, tab: 'login',
          csrfToken, lockoutSeconds: afterFail.remainingSeconds,
          prefill: '', prefillUsername: '', prefillEmail: '',
        });
      }
      const attemptsMsg = afterFail.attemptsLeft > 0
        ? ` ${afterFail.attemptsLeft} attempt${afterFail.attemptsLeft === 1 ? '' : 's'} remaining.`
        : '';
      return renderLoginError(`Invalid username/email or password.${attemptsMsg}`);
    }

    // ── Check if account is active/suspended ──
    if (user.suspended) {
      return renderLoginError('This account has been suspended. Please contact support.');
    }

    // ── Verify password ──
    const match = await user.comparePassword(password);

    if (!match) {
      const afterFail = recordFailedAttempt(ip);
      if (afterFail.locked) {
        return res.status(429).render('login', {
          error: 'Too many failed attempts. Account temporarily locked.',
          errorType: 'warn',
          success: null, tab: 'login',
          csrfToken, lockoutSeconds: afterFail.remainingSeconds,
          prefill: '', prefillUsername: '', prefillEmail: '',
        });
      }
      const attemptsMsg = afterFail.attemptsLeft > 0
        ? ` ${afterFail.attemptsLeft} attempt${afterFail.attemptsLeft === 1 ? '' : 's'} remaining.`
        : '';
      return renderLoginError(`Invalid username/email or password.${attemptsMsg}`);
    }

    // ── Successful login ──
    clearRateLimit(ip); // reset failed attempt counter

    // Regenerate session to prevent session fixation attacks
    req.session.regenerate(err => {
      if (err) {
        console.error('[login] Session regeneration failed:', err.message);
        return renderLoginError('Session error. Please try again.');
      }
      req.session.userId    = user._id;
      req.session.username  = user.username;
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
      res.redirect(`/dashboard/${encodeURIComponent(user.username)}`);
    });

  } catch (err) {
    console.error('[login] Error:', err.message);
    renderLoginError('Something went wrong. Please try again.');
  }
});


// ── GET /logout ────────────────────────────────────────────
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});


// ── GET /dashboard/:user ───────────────────────────────────
app.get('/dashboard/:user', requireAuth, (req, res) => {
  res.render('dashboard', {
    user:    decodeURIComponent(req.params.user),
    server:  SERVER_NAME,
    region:  REGION,
    env:     ENV,
    version: BUILD_VERSION,
  });
});


// ── GET /health ────────────────────────────────────────────
app.get('/health', (req, res) => {
  const states = ['disconnected', 'connected', 'connecting', 'disconnecting'];
  res.status(200).json({
    status:   'ok',
    uptime:   process.uptime(),
    database: states[mongoose.connection.readyState] || 'unknown',
    version:  BUILD_VERSION,
    region:   REGION,
  });
});


// ── Start server ───────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[config] ENV=${ENV} | REGION=${REGION} | SERVER=${SERVER_NAME}`);
  console.log(`${SERVER_NAME} running on http://localhost:${PORT}`);
});
