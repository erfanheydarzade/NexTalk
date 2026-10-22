// Headless smoke test for the browser bridge (needs a built bridge):
//   GOOS=js GOARCH=wasm go build -o web/wasm/nextalk.wasm ./cmd/nextalk-wasm
//   cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/wasm/
//   node web/test/transport-smoke.mjs
// Installs the test queue .ntx, then moves a message between two identities.
import fs from 'node:fs'; import vm from 'node:vm'; import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import zlib from 'node:zlib';
import { buildQueueModule } from './queue-module.mjs';
const require = createRequire(import.meta.url);
const wasmDir = new URL('../wasm/', import.meta.url).pathname;
if (!fs.existsSync(wasmDir + 'nextalk.wasm')) { console.error('build nextalk.wasm first (see header)'); process.exit(2); }

// minimal stored-zip writer (no deps)
const crc = (b) => { let c, t = [], r = 0xffffffff; for (let n = 0; n < 256; n++) { c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } for (const x of b) r = t[(r ^ x) & 255] ^ (r >>> 8); return (r ^ 0xffffffff) >>> 0; };
function zip(files) { const parts = [], cd = []; let off = 0;
  for (const [name, data] of files) { const n = Buffer.from(name), c = crc(data); const h = Buffer.alloc(30); h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt32LE(c, 14); h.writeUInt32LE(data.length, 18); h.writeUInt32LE(data.length, 22); h.writeUInt16LE(n.length, 26);
    parts.push(h, n, Buffer.from(data)); const d = Buffer.alloc(46); d.writeUInt32LE(0x02014b50, 0); d.writeUInt16LE(20, 4); d.writeUInt16LE(20, 6); d.writeUInt32LE(c, 16); d.writeUInt32LE(data.length, 20); d.writeUInt32LE(data.length, 24); d.writeUInt16LE(n.length, 28); d.writeUInt32LE(off, 42); cd.push(d, n); off += 30 + n.length + data.length; }
  const cdb = Buffer.concat(cd), e = Buffer.alloc(22); e.writeUInt32LE(0x06054b50, 0); e.writeUInt16LE(files.length, 8); e.writeUInt16LE(files.length, 10); e.writeUInt32LE(cdb.length, 12); e.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, cdb, e]); }

globalThis.require = require; globalThis.fs = fs;
vm.runInThisContext(fs.readFileSync(wasmDir + 'wasm_exec.js', 'utf8'));
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(fs.readFileSync(wasmDir + 'nextalk.wasm'), go.importObject);
go.run(instance); await new Promise((r) => setTimeout(r, 200));
const NT = globalThis.NexTalk;
assert.equal(NT.version().api, '3');
require('../wasm/ntx-host.js').register(NT);

const manifest = JSON.stringify({ id: 'smoke-queue', name: 'Smoke Queue', version: '0.0.1', api_version: '1', entry: 'queue.wasm', capabilities: ['message'], permissions: [] });
const ntx = zip([['manifest.json', Buffer.from(manifest)], ['queue.wasm', Buffer.from(buildQueueModule())]]).toString('base64');
assert.equal(NT.transport.inspect(ntx).id, 'smoke-queue');
assert.equal(NT.transport.install(ntx).id, 'smoke-queue');
assert.equal(NT.transport.list().transports[0].enabled, false, 'disabled by default');
assert.ok(NT.transport.install(zip([['manifest.json', Buffer.from(manifest.replace('queue.wasm', 'bridge'))], ['bridge', Buffer.from('x')]]).toString('base64')).error, 'process entry rejected');
assert.deepEqual(NT.transport.enable('smoke-queue'), { ok: true });

// Two identities in one page: swap with exportIdentity/importIdentity.
const A = NT.init().id; const aInit = NT.exportIdentity();
const B = NT.init().id; const bInit = NT.exportIdentity();
NT.importIdentity(aInit);
const offer = NT.createOffer(B).offer;                 // A -> B
const aPending = NT.exportIdentity();
NT.importIdentity(bInit);
const acc = NT.acceptOffer(offer); assert.ok(!acc.error, acc.error);   // B accepts
const bReady = NT.exportIdentity();
NT.importIdentity(aPending);
assert.equal(NT.finishHandshake(acc.answer).peerId, B);
const aReady = NT.exportIdentity();

const att = { mailbox: '0a'.repeat(16), secret: '0b'.repeat(32), shard: 'https://shard.test' };
assert.deepEqual(await NT.transport.attach('smoke-queue', att), { ok: true });   // owned by A
await NT.transport.sendMessage('smoke-queue', B, 'hello via transport', {});

NT.importIdentity(bReady);
const { events } = await NT.transport.poll('smoke-queue', { mailbox: att.mailbox });
const msg = events.find((e) => e.type === 'message' && e.message === 'hello via transport');
assert.ok(msg, JSON.stringify(events)); assert.equal(msg.sender, A);
// export/import: tampering is rejected
const exp = JSON.parse(NT.transport.export());
exp.transports[0].hash = '00'.repeat(32);
assert.ok(NT.transport.import(JSON.stringify(exp)).error, 'tampered import rejected');
console.log('smoke: ok');
