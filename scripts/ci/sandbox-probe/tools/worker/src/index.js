// A small Worker for the sandbox probe: a D1 table, a Durable Object that counts requests and
// echoes WebSocket frames, and a request that takes a body. It is written for the probe alone.

export class ProbeCounter {
  constructor(state) {
    this.state = state;
    this.events = [];
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/ws') {
      return this.upgrade();
    }
    if (url.pathname === '/ws-log') {
      return Response.json({ events: this.events });
    }
    const n = ((await this.state.storage.get('n')) ?? 0) + 1;
    await this.state.storage.put('n', n);
    return Response.json({ n });
  }

  upgrade() {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();
    server.addEventListener('message', (event) => {
      if (event.data === 'server-close') {
        this.events.push('server-closes');
        server.close(1000, 'server closing');
        return;
      }
      server.send(event.data);
    });
    server.addEventListener('close', (event) => {
      this.events.push(`client-closed:${event.code}`);
      try {
        server.close(event.code === 1005 ? 1000 : event.code, 'acknowledged');
      } catch {
        // already closed from this side
      }
    });
    return new Response(null, { status: 101, webSocket: client });
  }
}

async function digest(buffer) {
  const hash = await crypto.subtle.digest('SHA-256', buffer);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    switch (url.pathname) {
      case '/health':
        return Response.json({ version: env.BUILD_VERSION ?? 'none' });
      case '/echo': {
        const body = await request.arrayBuffer();
        return Response.json({ bytes: body.byteLength, sha256: await digest(body) });
      }
      case '/notes': {
        if (request.method === 'POST') {
          const text = await request.text();
          await env.PROBE_DB.prepare('INSERT INTO probe_notes (body) VALUES (?)').bind(text).run();
        }
        const row = await env.PROBE_DB.prepare('SELECT COUNT(*) AS n FROM probe_notes').first();
        return Response.json({ notes: row.n });
      }
      case '/counter':
      case '/ws':
      case '/ws-log': {
        const stub = env.PROBE_COUNTER.get(env.PROBE_COUNTER.idFromName('probe'));
        return stub.fetch(request);
      }
      default:
        return new Response('not found', { status: 404 });
    }
  },
};
