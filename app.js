const express    = require('express');
const bodyParser = require('body-parser');
const os         = require('os');
const fs         = require('fs');
const path       = require('path');
const mongoose   = require('mongoose');
const session    = require('express-session');
const User = require('./models/userModel');
const app = express();

// ── Middleware ───────────────────────────────────────────
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// ── View engine ──────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ── Session middleware ───────────────────────────────────
app.use(session({
  secret:            process.env.SESSION_SECRET || 'cloudproject-secret-key-change-in-prod',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    secure:   process.env.NODE_ENV === 'production' && process.env.HTTPS === 'true',
    httpOnly: true,
    maxAge:   24 * 60 * 60 * 1000, // 24 hours
  },
}));

// ── Supported AWS regions ────────────────────────────────
const SUPPORTED_REGIONS = {
  'ap-south-1': 'ap-south-1', // AWS Mumbai
  'ap-south-2': 'ap-south-2', // AWS Hyderabad
};

const DEFAULT_REGION = 'ap-south-1';

// ── Environment variables ────────────────────────────────
const PORT        = process.env.PORT        || 3000;
const SERVER_NAME = process.env.SERVER_NAME || 'Server';
const ENV         = process.env.NODE_ENV    || 'production';

const MONGO_URI = process.env.MONGO_URI || 'mongodb://kscs7755_db_user:Z7JuEBigSxVt65FG@ac-votpwb1-shard-00-00.jkismd9.mongodb.net:27017,ac-votpwb1-shard-00-01.jkismd9.mongodb.net:27017,ac-votpwb1-shard-00-02.jkismd9.mongodb.net:27017/cloudproject?ssl=true&replicaSet=atlas-qx79as-shard-0&authSource=admin&retryWrites=true&w=majority&appName=Cluster0';


function resolveRegion(env, regionEnv) {
  if (env === 'development') return 'Localhost';
  return SUPPORTED_REGIONS[regionEnv] || DEFAULT_REGION;
}

const REGION = resolveRegion(ENV, process.env.REGION);

// ── Read version from package.json ───────────────────────
let BUILD_VERSION = 'v1.0.0';
try {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
  BUILD_VERSION = 'v' + (pkg.version || '1.0.0');
} catch (_) {}

// ── Track server start time ──────────────────────────────
const SERVER_START = Date.now();

// ── MongoDB connection ───────────────────────────────────
mongoose.connect(MONGO_URI)
  .then(() => console.log(`[mongo] Connected → ${MONGO_URI}`))
  .catch(err => {
    console.error('[mongo] Connection failed:', err.message);
    // Don't exit — let the app start so /health still works; routes will return 503
  });

mongoose.connection.on('disconnected', () => console.warn('[mongo] Disconnected'));
mongoose.connection.on('reconnected',  () => console.log('[mongo]  Reconnected'));

// ── Auth guard middleware ─────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/');
}

// ── CPU usage helper (compares two samples 200ms apart) ──
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

// ── Memory usage ──────────────────────────────────────────
function getMemUsage() {
  const total = os.totalmem();
  const free  = os.freemem();
  return Math.round(((total - free) / total) * 100);
}

// ── Disk usage (Linux/Mac only via df) ───────────────────
function getDiskUsage() {
  return new Promise(resolve => {
    const { exec } = require('child_process');
    exec("df / | tail -1 | awk '{print $5}'", (err, stdout) => {
      if (err) return resolve(null);
      resolve(parseInt(stdout.trim()) || null);
    });
  });
}

// ── Network bytes helper ─────────────────────────────────
function getNetworkBytes() {
  return new Promise(resolve => {
    fs.readFile('/proc/net/dev', 'utf8', (err, data) => {
      if (err) return resolve(null);
      let rxTotal = 0, txTotal = 0;
      const lines = data.trim().split('\n').slice(2);
      lines.forEach(line => {
        const parts = line.trim().split(/\s+/);
        if (parts[0].startsWith('lo')) return;
        rxTotal += parseInt(parts[1]) || 0;
        txTotal += parseInt(parts[9]) || 0;
      });
      resolve({ rx: rxTotal, tx: txTotal });
    });
  });
}

let prevNet     = null;
let prevNetTime = null;

// ── /api/stats ───────────────────────────────────────────
app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    const [cpu, disk, netNow] = await Promise.all([
      getCpuUsage(),
      getDiskUsage(),
      getNetworkBytes(),
    ]);

    const mem = getMemUsage();

    let netPct = null;
    const now = Date.now();
    if (prevNet && netNow) {
      const dt      = (now - prevNetTime) / 1000;
      const rxDelta = (netNow.rx - prevNet.rx) / dt;
      const txDelta = (netNow.tx - prevNet.tx) / dt;
      const maxBytes = 125_000_000;
      netPct = Math.min(100, Math.round(((rxDelta + txDelta) / maxBytes) * 100));
    }
    prevNet     = netNow;
    prevNetTime = now;

    const osUptimeSec  = Math.floor(os.uptime());
    const appUptimeSec = Math.floor((Date.now() - SERVER_START) / 1000);

    const fmt = s => {
      const h   = Math.floor(s / 3600);
      const m   = Math.floor((s % 3600) / 60);
      const sec = s % 60;
      return [h, m, sec].map(v => String(v).padStart(2, '0')).join(':');
    };

    res.json({
      cpu,
      mem,
      disk,
      net:       netPct,
      osUptime:  fmt(osUptimeSec),
      appUptime: fmt(appUptimeSec),
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

// ── GET / — Login/Signup page ─────────────────────────────
app.get('/', (req, res) => {
  // Already logged in → go straight to dashboard
  if (req.session && req.session.userId) {
    return res.redirect(`/dashboard/${encodeURIComponent(req.session.username)}`);
  }
  res.render('login', { error: null, success: null, tab: 'login' });
});

// ── POST /signup ──────────────────────────────────────────
app.post('/signup', async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = (req.body.password || '').trim();

  if (!username || username.length < 3) {
    return res.render('login', {
      error:   'Username must be at least 3 characters.',
      success: null,
      tab:     'signup',
    });
  }
  if (!password || password.length < 6) {
    return res.render('login', {
      error:   'Password must be at least 6 characters.',
      success: null,
      tab:     'signup',
    });
  }

  // Check if MongoDB is connected
  if (mongoose.connection.readyState !== 1) {
    return res.render('login', {
      error:   'Database unavailable. Please try again later.',
      success: null,
      tab:     'signup',
    });
  }

  try {
    const existing = await User.findOne({ username });
    if (existing) {
      return res.render('login', {
        error:   `Username "${username}" is already taken. Choose another.`,
        success: null,
        tab:     'signup',
      });
    }

    const user = new User({ username, password });
    await user.save();

    // Auto-login after signup
    req.session.userId   = user._id;
    req.session.username = user.username;
    res.redirect(`/dashboard/${encodeURIComponent(user.username)}`);

  } catch (err) {
    console.error('[signup] Error:', err.message);
    res.render('login', {
      error:   'Something went wrong. Please try again.',
      success: null,
      tab:     'signup',
    });
  }
});

// ── POST /login ───────────────────────────────────────────
app.post('/login', async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = (req.body.password || '').trim();

  if (!username || !password) {
    return res.render('login', {
      error:   'Username and password are required.',
      success: null,
      tab:     'login',
    });
  }

  // Check if MongoDB is connected
  if (mongoose.connection.readyState !== 1) {
    return res.render('login', {
      error:   'Database unavailable. Please try again later.',
      success: null,
      tab:     'login',
    });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.render('login', {
        error:   'Invalid username or password.',
        success: null,
        tab:     'login',
      });
    }

    const match = await user.comparePassword(password);
    if (!match) {
      return res.render('login', {
        error:   'Invalid username or password.',
        success: null,
        tab:     'login',
      });
    }

    // Regenerate session to prevent fixation attacks
    req.session.regenerate(err => {
      if (err) {
        return res.render('login', { error: 'Session error. Try again.', success: null, tab: 'login' });
      }
      req.session.userId   = user._id;
      req.session.username = user.username;
      res.redirect(`/dashboard/${encodeURIComponent(user.username)}`);
    });

  } catch (err) {
    console.error('[login] Error:', err.message);
    res.render('login', {
      error:   'Something went wrong. Please try again.',
      success: null,
      tab:     'login',
    });
  }
});

// ── GET /logout ───────────────────────────────────────────
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ── Dashboard ─────────────────────────────────────────────
app.get('/dashboard/:user', requireAuth, (req, res) => {
  res.render('dashboard', {
    user:    decodeURIComponent(req.params.user),
    server:  SERVER_NAME,
    region:  REGION,
    env:     ENV,
    version: BUILD_VERSION,
  });
});

// ── Social auth placeholders ──────────────────────────────
app.get('/auth/google', (req, res) => {
  // TODO: replace with real passport-google-oauth20
  res.redirect('/dashboard/GoogleUser');
});

app.get('/auth/github', (req, res) => {
  // TODO: replace with real passport-github2
  res.redirect('/dashboard/GitHubUser');
});

// ── Health check ──────────────────────────────────────────
app.get('/health', (req, res) => {
  const dbState = ['disconnected', 'connected', 'connecting', 'disconnecting'];
  res.status(200).json({
    status:   'ok',
    uptime:   process.uptime(),
    database: dbState[mongoose.connection.readyState] || 'unknown',
  });
});

// ── Start ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[config] ENV=${ENV} | REGION=${REGION} | SERVER=${SERVER_NAME}`);
  console.log(`${SERVER_NAME} running on http://localhost:${PORT}`);
});
