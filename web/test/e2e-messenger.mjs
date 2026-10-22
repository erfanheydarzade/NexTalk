// Browser end-to-end test for web/nextalk-messenger.html (headless Chromium).
// Needs: web/wasm/nextalk.wasm (bash cmd/nextalk-wasm/build.sh) and the
// extension package (cd example-transports && node build-all.mjs --wasm-only).
//   npm i && npx playwright install chromium && node e2e-messenger.mjs
// Set CHROMIUM_PATH to use an existing browser binary.
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(here, '..');
const extFile = path.resolve(webRoot, '..', 'example-transports', 'dist', 'relay-example-wasm.ntx');
for (const f of [path.join(webRoot, 'wasm', 'nextalk.wasm'), extFile]) {
  if (!fs.existsSync(f)) { console.error('missing prerequisite: ' + f); process.exit(2); }
}

let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + m); };

const mime = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const srv = http.createServer((q, r) => {
  const p = path.join(webRoot, decodeURIComponent(q.url.split('?')[0]));
  if (!p.startsWith(webRoot)) { r.writeHead(403); return r.end(); }
  fs.readFile(p, (e, d) => {
    if (e) { r.writeHead(404); return r.end(); }
    r.writeHead(200, { 'content-type': mime[path.extname(p)] || 'application/octet-stream' });
    r.end(d);
  });
});
await new Promise(r => srv.listen(0, r));
const port = srv.address().port;

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || undefined,
  args: ['--no-sandbox'],
});
const ctx = await browser.newContext();
const pg = await ctx.newPage();
const errs = [];
pg.on('pageerror', e => errs.push(e.message));
pg.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });
pg.on('dialog', d => d.accept());
await pg.addInitScript(() => {
  document.addEventListener('securitypolicyviolation', e => {
    (window.__csp = window.__csp || []).push(e.violatedDirective + ' ' + (e.blockedURI || 'inline'));
  });
});
const boot = async () => {
  await pg.waitForFunction(() => window.NexTalk && NexTalk.transport, null, { timeout: 90000 });
  await pg.waitForTimeout(1500);
};
const dump = () => pg.evaluate(() => {
  const o = {};
  for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); o[k] = localStorage.getItem(k); }
  return o;
});
const unlock = async pw => {
  await pg.waitForSelector('input[type=password]', { state: 'visible', timeout: 10000 });
  await pg.fill('input[type=password]', pw);
  await pg.click('#mOk');
  await pg.waitForTimeout(2500);
};

await pg.goto(`http://localhost:${port}/nextalk-messenger.html`);
await boot();

// ---- page hygiene -------------------------------------------------------
ok(await pg.evaluate(() => !document.querySelector('script[src*="tailwind"], link[href*="googleapis"]')), 'no third-party script/font tags');
ok((await pg.evaluate(() => window.__csp || [])).length === 0, 'no CSP violations while loading');
ok(errs.length === 0, 'no console/page errors on load ' + JSON.stringify(errs.slice(0, 2)));

// ---- identity + extension host ------------------------------------------
await pg.evaluate(() => window.ntApp.init());
await pg.waitForFunction(() => window.ntApp.state.myId, null, { timeout: 30000 });
const id = await pg.evaluate(() => window.ntApp.state.myId);
ok(!!id, 'identity created');

await pg.setInputFiles('#extFile', extFile);
await pg.waitForTimeout(800);
ok((await pg.evaluate(() => NexTalk.transport.list().transports.map(t => t.id))).includes('relay-example-wasm'), 'extension installed via file picker');
await pg.evaluate(() => NexTalk.transport.enable('relay-example-wasm'));
const reg = await pg.evaluate(async () => {
  try { await NexTalk.transport.register('relay-example-wasm', { router: 'https://router.invalid' }); return 'ok'; }
  catch (e) { return e.message; }
});
ok(!/no WebAssembly host/.test(reg), 'extension host is registered (register reached the network: ' + reg.slice(0, 50) + ')');

// ---- vault: encrypted at rest, restored after reload --------------------
const MARK = 'SECRET-' + Math.random().toString(36).slice(2);
const peer = 'PEER' + 'x'.repeat(40);
await pg.evaluate(([p, m]) => {
  window.ntApp.state.peers[p] = { name: p, messages: [], unread: 0 };
  window.ntApp.push(p, { me: true, text: m });
}, [peer, MARK]);
await pg.evaluate(() => document.querySelector('#vEnable').click());
await pg.waitForSelector('#mOk', { state: 'visible', timeout: 5000 });
await pg.fill('input[type=password]', 'correct horse battery');
await pg.click('#mOk');
await pg.waitForTimeout(2500);
const ls = await dump();
const vault = ls.nextalk_vault_v1 ? JSON.parse(ls.nextalk_vault_v1) : null;
ok(!!vault, 'vault written');
ok(vault && vault.it === 600000, 'vault PBKDF2 iterations = 600000');
ok(!JSON.stringify(ls).includes(MARK), 'chat text is not in localStorage');
ok(!('nextalk_peers_v1' in ls) && !('nextalk_ext_v1' in ls), 'no legacy plaintext keys');
ok(vault && !ls.nextalk_vault_v1.includes('relay-example-wasm'), 'extension state not readable in vault blob');

await pg.reload();
await boot();
await unlock('wrong password');
ok(await pg.evaluate(() => !window.ntApp.state.myId), 'wrong password does not unlock');
await unlock('correct horse battery');
ok(await pg.evaluate(() => !!window.ntApp.state.myId), 'correct password restores identity');
ok(await pg.evaluate(m => JSON.stringify(window.ntApp.state.peers).includes(m), MARK), 'chat history restored from vault');
ok((await pg.evaluate(() => NexTalk.transport.list().transports.map(t => t.id))).includes('relay-example-wasm'), 'extension restored from vault');

// ---- injection ------------------------------------------------------------
await pg.evaluate(() => {
  window.__x = 0;
  const n = '<img src=x onerror=window.__x=1>';
  window.ntApp.setPeers({ [n]: { name: n, messages: [{ me: false, from: n, text: n, ts: Date.now() }], unread: 0 } });
});
await pg.waitForTimeout(500);
ok(await pg.evaluate(() => window.__x === 0 && document.querySelectorAll('#peerList img').length === 0), 'hostile peer name/id cannot inject markup');
await pg.evaluate(() => { const s = document.createElement('script'); s.textContent = 'window.__pwn=1'; document.head.appendChild(s); });
ok(await pg.evaluate(() => window.__pwn === undefined), 'CSP blocks an injected inline script');
ok(await pg.evaluate(async () => { try { await fetch('http://evil.example/x'); return false; } catch (e) { return true; } }), 'CSP blocks plain-http request to a public host');
await pg.evaluate(() => { document.querySelector('#workerUrl').value = 'http://evil.example'; document.querySelector('#btnConnectWorker').click(); });
await pg.waitForTimeout(400);
ok(await pg.evaluate(() => /refusing http:/.test(document.documentElement.textContent)), 'http:// relay on a public host is refused');

// ---- auto-poll schedule (fake clock, stubbed relay.listen) ---------------
await pg.clock.install();
await pg.evaluate(() => {
  window.__polls = 0; window.__mode = 'ok';
  NexTalk.relay.listen = () => { window.__polls++; return Promise.resolve(window.__mode === 'ok' ? { events: [] } : { error: 'boom' }); };
  const s = window.ntApp.state; s.connected = true; s.auto = true; window.ntApp.schedulePoll();
});
await pg.clock.runFor(4100);
ok(await pg.evaluate(() => window.__polls) === 1, 'auto-poll fires after ~4s while visible');
await pg.clock.runFor(4100);
ok(await pg.evaluate(() => window.__polls) === 2, 'auto-poll keeps running');
await pg.evaluate(() => { window.__mode = 'err'; });
await pg.clock.runFor(4100);               // 3rd poll fails -> next delay 8s
const afterFail = await pg.evaluate(() => window.__polls);
await pg.clock.runFor(4100);
ok(await pg.evaluate(() => window.__polls) === afterFail, 'back-off: no poll 4s after a failure');
await pg.clock.runFor(4100);
ok(await pg.evaluate(() => window.__polls) === afterFail + 1, 'back-off: polls again after ~8s');
await pg.evaluate(() => { window.ntApp.state.auto = false; window.ntApp.schedulePoll(); });
const frozen = await pg.evaluate(() => window.__polls);
await pg.clock.runFor(60000);
ok(await pg.evaluate(() => window.__polls) === frozen, 'turning Auto-check off stops polling');

srv.close();
await browser.close();
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
