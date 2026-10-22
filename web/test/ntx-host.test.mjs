// Node test for web/wasm/ntx-host.js (ABI v1 marshalling) — no Go needed:
//   node web/test/ntx-host.test.mjs
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { buildQueueModule, buildForeignImportModule } from './queue-module.mjs';

const host = createRequire(import.meta.url)('../wasm/ntx-host.js');

const parseBlob = (b) => { // same rules as ntxhost.ParsePollBlob
  const out = []; let pos = 0;
  while (pos < b.length) {
    assert.ok(pos + 4 <= b.length, 'truncated');
    const n = (b[pos] << 24 | b[pos + 1] << 16 | b[pos + 2] << 8 | b[pos + 3]) >>> 0; pos += 4;
    assert.ok(n > 0 && n <= 40 * 1024 && pos + n <= b.length, 'frame out of bounds');
    out.push(b.slice(pos, pos + n)); pos += n;
  }
  return out;
};

const h = await host.instantiate('queue', buildQueueModule(), new Uint8Array(0));
assert.equal(h.caps, 'message');

const f1 = Uint8Array.from([3, ...Buffer.from('first')]);
const f2 = Uint8Array.from([3, ...Buffer.from('second')]);
const pub = new Uint8Array(32).fill(0xc);
const mbox = new Uint8Array(16).fill(0xa), sec = new Uint8Array(32).fill(0xb);

assert.equal(h.send(f1, pub), 1, 'send before start must report not-started (rc 1)');
assert.equal(h.start(), 0);
assert.equal(h.attach(mbox, sec), 0);
assert.equal(h.attach(new Uint8Array(3), sec), 2, 'bad attach size');
assert.equal(h.send(f1, pub), 0);
assert.equal(h.send(f2, pub), 0);
assert.equal(h.send(new Uint8Array(0), pub), 2, 'empty frame');
assert.equal(h.send(new Uint8Array(40 * 1024 + 1), pub), 2, 'oversize frame');

const got = parseBlob(h.poll(10, mbox));
assert.equal(got.length, 2);
assert.deepEqual([...got[0]], [...f1]);
assert.deepEqual([...got[1]], [...f2]);
assert.equal(h.poll(10, mbox).length, 0, 'queue must drain');
assert.equal(h.poll(10, null).length, 0);

// recipient bytes must not clobber the frame (alloc path, repeated calls)
for (let i = 0; i < 50; i++) assert.equal(h.send(f1, pub), 0), assert.deepEqual([...parseBlob(h.poll(1, null))[0]], [...f1]);

assert.equal(h.detach(mbox), 0);
assert.equal(h.status(), 1);
assert.equal(h.stop(), 0);
assert.equal(h.status(), 0);
assert.equal(h.send(f1, pub), 1, 'send after stop');
h.destroy();
assert.throws(() => h.start(), /destroyed/);

await assert.rejects(host.instantiate('x', new Uint8Array([0, 0x61, 0x73, 0x6d]), new Uint8Array(0)), 'truncated module');
await assert.rejects(host.instantiate('x', buildForeignImportModule(), new Uint8Array(0)), /LinkError|import|steal/i, 'foreign import must be refused');

// register() wires the host into a NexTalk-shaped object and surfaces errors
let seen = null;
host.register({ transport: { _registerHost: (x) => { seen = x; return { ok: true }; } } });
assert.equal(seen, host);
assert.throws(() => host.register({}), /API revision 3/);
console.log('ntx-host: all checks passed');
