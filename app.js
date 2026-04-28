const express    = require('express');
const bodyParser = require('body-parser');
const os         = require('os');
const fs         = require('fs');
const path       = require('path');

const app = express();

// middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// set view engine
app.set('view engine', 'ejs');

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

// ── Dynamic region resolution ────────────────────────────
// Rules:
//   1. Local development (NODE_ENV=development) → 'Localhost'
//   2. Production with valid REGION env var     → use that region
//   3. Production with no/invalid REGION        → fallback to DEFAULT_REGION
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

// track server start time for uptime
const SERVER_START = Date.now();

// log resolved config on startup
console.log(`[config] ENV=${ENV} | REGION=${REGION} | SERVER=${SERVER_NAME}`);

// ── CPU usage helper (compares two samples 200ms apart) ──
function getCpuUsage() {
  return new Promise(resolve => {
    const cpus1 = os.cpus();
    setTimeout(() => {
      const cpus2 = os.cpus();
      let idle = 0, total = 0;
      cpus1.forEach((cpu, i) => {
        const cpu2 = cpus2[i];
        for (const type in cpu2.times) {
          total += cpu2.times[type] - cpu.times[type];
        }
        idle += cpu2.times.idle - cpu.times.idle;
      });
      resolve(Math.round((1 - idle / total) * 100));
    }, 200);
  });
}

// ── Memory usage ──
function getMemUsage() {
  const total = os.totalmem();
  const free  = os.freemem();
  return Math.round(((total - free) / total) * 100);
}

// ── Disk usage (Linux/Mac only via df) ──
function getDiskUsage() {
  return new Promise(resolve => {
    const { exec } = require('child_process');
    exec("df / | tail -1 | awk '{print $5}'", (err, stdout) => {
      if (err) return resolve(null);
      resolve(parseInt(stdout.trim()) || null);
    });
  });
}

// ── Network bytes helper ──
function getNetworkBytes() {
  return new Promise(resolve => {
    fs.readFile('/proc/net/dev', 'utf8', (err, data) => {
      if (err) return resolve(null);
      let rxTotal = 0, txTotal = 0;
      const lines = data.trim().split('\n').slice(2);
      lines.forEach(line => {
        const parts = line.trim().split(/\s+/);
        if (parts[0].startsWith('lo')) return; // skip loopback
        rxTotal += parseInt(parts[1]) || 0;
        txTotal += parseInt(parts[9]) || 0;
      });
      resolve({ rx: rxTotal, tx: txTotal });
    });
  });
}

// store previous network sample for delta calculation
let prevNet = null;
let prevNetTime = null;

// ── /api/stats — real system data ──────────────────────
app.get('/api/stats', async (req, res) => {
  try {
    const [cpu, disk, netNow] = await Promise.all([
      getCpuUsage(),
      getDiskUsage(),
      getNetworkBytes()
    ]);

    const mem = getMemUsage();

    // calculate network throughput as % of a 1Gbps baseline
    let netPct = null;
    const now = Date.now();
    if (prevNet && netNow) {
      const dt      = (now - prevNetTime) / 1000; // seconds
      const rxDelta = (netNow.rx - prevNet.rx) / dt; // bytes/s
      const txDelta = (netNow.tx - prevNet.tx) / dt;
      const maxBytes = 125_000_000; // 1 Gbps in bytes/s
      netPct = Math.min(100, Math.round(((rxDelta + txDelta) / maxBytes) * 100));
    }
    prevNet     = netNow;
    prevNetTime = now;

    // system uptime (seconds the OS has been running)
    const osUptimeSec  = Math.floor(os.uptime());
    const appUptimeSec = Math.floor((Date.now() - SERVER_START) / 1000);

    const fmt = s => {
      const h = Math.floor(s / 3600);
      const m = Math.floor((s % 3600) / 60);
      const sec = s % 60;
      return [h, m, sec].map(v => String(v).padStart(2, '0')).join(':');
    };

    res.json({
      cpu,
      mem,
      disk,
      net:        netPct,
      osUptime:   fmt(osUptimeSec),
      appUptime:  fmt(appUptimeSec),
      hostname:   os.hostname(),
      platform:   os.platform(),
      arch:       os.arch(),
      cpuModel:   os.cpus()[0]?.model || 'Unknown',
      cpuCores:   os.cpus().length,
      totalMem:   Math.round(os.totalmem() / 1024 / 1024 / 1024 * 10) / 10, // GB
      freeMem:    Math.round(os.freemem()  / 1024 / 1024 / 1024 * 10) / 10,
      loadAvg:    os.loadavg().map(v => v.toFixed(2)),
      version:    BUILD_VERSION,
      region:     REGION,
      env:        ENV,
      server:     SERVER_NAME,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Login page ──────────────────────────────────────────
app.get('/', (req, res) => {
  res.render('login');
});

// ── Handle login ────────────────────────────────────────
app.post('/login', (req, res) => {
  const username = (req.body.username || '').trim();
  if (!username || username.length < 3) return res.redirect('/');
  res.redirect('/dashboard/' + encodeURIComponent(username));
});

// ── Dashboard ────────────────────────────────────────────
app.get('/dashboard/:user', (req, res) => {
  res.render('dashboard', {
    user:    decodeURIComponent(req.params.user),
    server:  SERVER_NAME,
    region:  REGION,
    env:     ENV,
    version: BUILD_VERSION,
  });
});

// ── Social auth placeholders ─────────────────────────────
app.get('/auth/google', (req, res) => {
  // TODO: replace with real passport-google-oauth20
  res.redirect('/dashboard/GoogleUser');
});

app.get('/auth/github', (req, res) => {
  // TODO: replace with real passport-github2
  res.redirect('/dashboard/GitHubUser');
});

// ── Health check ─────────────────────────────────────────
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', uptime: process.uptime() });
});

// ── Start ────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`${SERVER_NAME} running on http://localhost:${PORT}`);
});
