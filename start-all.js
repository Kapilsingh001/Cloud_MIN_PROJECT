/**
 * start-all.js
 * Spawns 3 independent instances of app.js, each on a different port/region.
 *
 * Usage:  node start-all.js
 *
 * Tabs to open after starting:
 *   http://localhost:3000  →  Localhost    (development)
 *   http://localhost:3001  →  ap-south-1   (Mumbai)
 *   http://localhost:3002  →  ap-south-2   (Hyderabad)
 */

const { spawn } = require('child_process');

const servers = [
  {
    label:   'Localhost   (dev)',
    port:    3000,
    region:  '',               // not used in development mode
    env:     'development',
    server:  'LocalServer',
  },
  {
    label:   'Mumbai      (ap-south-1)',
    port:    3001,
    region:  'ap-south-1',
    env:     'production',
    server:  'Mumbai-Server',
  },
  {
    label:   'Hyderabad   (ap-south-2)',
    port:    3002,
    region:  'ap-south-2',
    env:     'production',
    server:  'Hyderabad-Server',
  },
];

servers.forEach(({ label, port, region, env, server }) => {
  const child = spawn(
    process.execPath,   // same node binary
    ['app.js'],
    {
      env: {
        ...process.env,         // inherit PATH etc.
        PORT:        String(port),
        NODE_ENV:    env,
        REGION:      region,
        SERVER_NAME: server,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    }
  );

  const prefix = `[${label}]`;

  child.stdout.on('data', d => process.stdout.write(`${prefix} ${d}`));
  child.stderr.on('data', d => process.stderr.write(`${prefix} ${d}`));

  child.on('exit', (code) => {
    console.log(`${prefix} exited with code ${code}`);
  });

  console.log(`✅ Started ${label} → http://localhost:${port}`);
});

console.log('\n🌐 Open these in separate tabs:');
console.log('   http://localhost:3000  →  Localhost');
console.log('   http://localhost:3001  →  ap-south-1  (Mumbai)');
console.log('   http://localhost:3002  →  ap-south-2  (Hyderabad)\n');