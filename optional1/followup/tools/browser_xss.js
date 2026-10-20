#!/usr/bin/env node
/* Headless-Chrome CDP check for XSS execution evidence.
 *
 * Usage:
 *   node browser_xss.js --url <url> --cookie "PHPSESSID=...; security=low" \
 *        --expect XSS001 --out evidence.json [--wait 3000]
 *
 * Emits JSON with dialogs, console calls, exceptions and body text. The page is
 * loaded with the supplied lab session cookie; no data leaves the machine.
 */
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.env.CHROME_PATH ||
  path.join(process.env.LOCALAPPDATA || '', 'Google/Chrome/Application/chrome.exe');

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function getJson(url, timeout = 1000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(url, { signal: ctrl.signal });
    return await r.json();
  } finally { clearTimeout(t); }
}

function parseArgs(argv) {
  const out = { wait: 3000, expect: '', port: 9333 };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    if (k === '--url') out.url = argv[++i];
    else if (k === '--cookie') out.cookie = argv[++i];
    else if (k === '--expect') out.expect = argv[++i];
    else if (k === '--out') out.out = argv[++i];
    else if (k === '--wait') out.wait = Number(argv[++i]);
    else if (k === '--port') out.port = Number(argv[++i]);
  }
  if (!out.url || !out.out) throw new Error('--url and --out are required');
  return out;
}

function parseCookie(header) {
  const cookies = [];
  for (const part of (header || '').split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) {
      cookies.push({ name: part.slice(0, idx).trim(), value: part.slice(idx + 1).trim() });
    }
  }
  return cookies;
}

async function main() {
  const args = parseArgs(process.argv);
  if (!fs.existsSync(CHROME)) throw new Error('Chrome not found: ' + CHROME);
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-xss-'));
  const port = args.port;
  const chrome = spawn(CHROME, [
    '--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`,
    '--no-first-run', '--no-default-browser-check', '--disable-gpu',
    '--disable-extensions', '--disable-background-networking', '--disable-sync',
    'about:blank'
  ], { stdio: 'ignore' });

  let ws;
  try {
    let version = null;
    for (let i = 0; i < 100; i++) {
      try { version = await getJson(`http://127.0.0.1:${port}/json/version`); break; }
      catch (_) { await sleep(150); }
    }
    if (!version) throw new Error('Chrome DevTools endpoint did not start');

    ws = new WebSocket(version.webSocketDebuggerUrl);
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

    let nextId = 1;
    const pending = new Map();
    const dialogs = [];
    const consoleCalls = [];
    const exceptions = [];
    let sessionId = null;

    const send = (method, params = {}, sid = null) => new Promise((res, rej) => {
      const id = nextId++;
      pending.set(id, { res, rej });
      const msg = { id, method, params };
      if (sid) msg.sessionId = sid;
      ws.send(JSON.stringify(msg));
    });

    ws.onmessage = (event) => {
      let msg;
      try { msg = JSON.parse(event.data); } catch (_) { return; }
      if (msg.id && pending.has(msg.id)) {
        const { res, rej } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) rej(new Error(JSON.stringify(msg.error)));
        else res(msg.result);
        return;
      }
      const p = msg.params || {};
      if (msg.method === 'Page.javascriptDialogOpening') {
        dialogs.push({ type: p.type, message: p.message, url: p.url });
        send('Page.handleJavaScriptDialog', { accept: true }, msg.sessionId).catch(() => {});
      } else if (msg.method === 'Runtime.consoleAPICalled') {
        const text = (p.args || []).map(a => {
          if (a.value !== undefined) return String(a.value);
          return a.description || a.type;
        }).join(' ');
        consoleCalls.push({ type: p.type, text });
      } else if (msg.method === 'Runtime.exceptionThrown') {
        exceptions.push(p.exceptionDetails && p.exceptionDetails.text ||
          p.exceptionThrown && p.exceptionThrown.exception && p.exceptionThrown.exception.description || '');
      }
    };

    const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
    const attached = await send('Target.attachToTarget', { targetId, flatten: true });
    sessionId = attached.sessionId;
    await send('Page.enable', {}, sessionId);
    await send('Runtime.enable', {}, sessionId);
    await send('Network.enable', {}, sessionId);

    for (const c of parseCookie(args.cookie)) {
      await send('Network.setCookie', {
        name: c.name, value: c.value, domain: '127.0.0.1', path: '/',
        httpOnly: false, secure: false
      }, sessionId);
    }

    await send('Page.navigate', { url: args.url }, sessionId);
    await sleep(args.wait);

    let body = '';
    try {
      const ev = await send('Runtime.evaluate', {
        expression: 'document.body ? document.body.innerText : ""',
        returnByValue: true
      }, sessionId);
      body = (ev.result && ev.result.value) || '';
    } catch (_) {}

    const marker = args.expect;
    const dialogHit = marker && dialogs.some(d => String(d.message).includes(marker));
    const consoleHit = marker && consoleCalls.some(c => c.text.includes(marker));
    const bodyHit = marker && body.includes(marker);

    const result = {
      url: args.url,
      expected_marker: marker,
      dialogs,
      console: consoleCalls,
      exceptions,
      body_has_marker: !!bodyHit,
      body_excerpt: body.slice(0, 800),
      success: !!(dialogHit || consoleHit),
      evidence: { dialog_hit: !!dialogHit, console_hit: !!consoleHit, body_hit: !!bodyHit }
    };
    fs.writeFileSync(args.out, JSON.stringify(result, null, 2), 'utf-8');
    console.log(JSON.stringify(result, null, 2));
  } finally {
    try { if (ws) ws.close(); } catch (_) {}
    try { chrome.kill(); } catch (_) {}
    spawnSync('taskkill', ['/pid', String(chrome.pid), '/T', '/F'], { stdio: 'ignore' });
    try { fs.rmSync(profile, { recursive: true, force: true }); } catch (_) {}
  }
}

main().catch(err => { console.error(String(err)); process.exit(1); });
