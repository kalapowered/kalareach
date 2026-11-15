// start-worker.mjs WRANGLER CONFIG PORT STATE_DIR CERT_DIR LOG_FILE
// Starts `wrangler dev` for the probe's Worker as a detached server and exits at once, the way a
// helper keeps a server that outlives its starter: a child in a process group of its own, its
// output in a file, no handle held by the starter.
import { spawn } from 'node:child_process';
import { closeSync, openSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname } from 'node:path';

const [wrangler, config, port, state, certs, logFile] = process.argv.slice(2);
if (!logFile) {
  console.error('usage: start-worker.mjs WRANGLER CONFIG PORT STATE_DIR CERT_DIR LOG_FILE');
  process.exit(2);
}
const version = `probe-${randomUUID()}`;
const output = openSync(logFile, 'a');
const child = spawn(
  wrangler,
  [
    'dev',
    '--config', config,
    '--ip', '127.0.0.1',
    '--port', port,
    '--inspector-port', '0',
    '--persist-to', state,
    '--local-protocol', 'https',
    '--https-key-path', `${certs}/leaf.key`,
    '--https-cert-path', `${certs}/leaf.pem`,
    '--var', `BUILD_VERSION:${version}`,
    '--test-scheduled',
    '--log-level', 'warn',
  ],
  {
    cwd: dirname(config),
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      CI: '1',
      WRANGLER_SEND_METRICS: 'false',
      CLOUDFLARE_INCLUDE_PROCESS_ENV: 'false',
    },
    detached: true,
    stdio: ['ignore', output, output],
  },
);
closeSync(output);
child.unref();
writeFileSync(`${state}/server.json`, JSON.stringify({ group: child.pid, port: Number(port), version }));
console.log(`started group ${child.pid}`);
