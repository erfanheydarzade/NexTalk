// ABI v1 conformance check for a .wasm transport — mirrors what the NexTalk
// hosts (wazero natively, ntx-host.js in the browser) require, so a module
// that passes here will load there. Pure Node, no dependencies.
//
//   node tools/verify-wasm.mjs <module.wasm> [--caps message,binary-transfer] [--loopback]
import fs from 'node:fs';
import { KNOWN_CAPABILITIES } from './ntx.mjs';

const MAX_FRAME = 40 * 1024;

export async function verifyWasm(bytes, { manifestCaps = null, loopback = false } = {}) {
  const fails = [], ok = (c, m) => { if (!c) fails.push(m); return c; };
  if (!ok(WebAssembly.validate(bytes), 'module does not validate')) return fails;
  const mod = new WebAssembly.Module(bytes);
  // Sandbox: only the optional ntx.log import is allowed (no WASI, sockets, fs).
  for (const i of WebAssembly.Module.imports(mod)) ok(i.module === 'ntx' && i.name === 'log' && i.kind === 'function', `forbidden import ${i.module}.${i.name}`);
  const names = WebAssembly.Module.exports(mod).map((e) => e.name);
  for (const n of ['memory', 'ntx_init', 'ntx_caps', 'ntx_start', 'ntx_stop', 'ntx_send', 'ntx_attach', 'ntx_detach', 'ntx_poll', 'ntx_status']) ok(names.includes(n), `missing export ${n}`);
  if (fails.length) return fails;

  let mem; const inst = new WebAssembly.Instance(mod, { ntx: { log() {} } }); const ex = inst.exports; mem = ex.memory;
  let scratch = 0; const SCR = 1 << 20;
  const put = (d) => {
    if (ex.ntx_alloc) { const p = ex.ntx_alloc(d.length) >>> 0; new Uint8Array(mem.buffer).set(d, p); return p; }
    const at = SCR + scratch; if (at + d.length > mem.buffer.byteLength) mem.grow(16);
    new Uint8Array(mem.buffer).set(d, at); scratch += (d.length + 7) & ~7; return at;
  };
  const blob = (packed) => { const u = BigInt.asUintN(64, packed); const p = Number(u >> 32n), l = Number(u & 0xffffffffn); return new Uint8Array(mem.buffer).slice(p, p + l); };
  const frames = (b) => { const o = []; let i = 0; while (i < b.length) { if (i + 4 > b.length) { ok(false, 'poll blob truncated'); break; } const n = (b[i] << 24 | b[i + 1] << 16 | b[i + 2] << 8 | b[i + 3]) >>> 0; i += 4; if (!ok(n > 0 && n <= MAX_FRAME && i + n <= b.length, 'poll frame out of bounds')) break; o.push(b.slice(i, i + n)); i += n; } return o; };

  scratch = 0; ok(ex.ntx_init(put(new Uint8Array(0)), 0) === 0, 'ntx_init must return 0');
  const caps = new TextDecoder().decode(blob(ex.ntx_caps())).split(',').map((s) => s.trim()).filter(Boolean);
  ok(caps.length > 0, 'ntx_caps is empty');
  for (const c of caps) { ok(KNOWN_CAPABILITIES.includes(c), `unknown capability ${c}`); if (manifestCaps) ok(manifestCaps.includes(c), `module claims "${c}" which the manifest does not declare (the host refuses this)`); }
  ok(ex.ntx_status() === 0, 'status must be 0 before start');
  const frame = Uint8Array.from([3, ...Buffer.from('conformance')]), pub = new Uint8Array(32).fill(7), mb = new Uint8Array(16).fill(1), sec = new Uint8Array(32).fill(2);
  scratch = 0; const fp = put(frame), rp = put(pub);
  ok(ex.ntx_send(fp, frame.length, rp, pub.length) === 1, 'send before start must return 1');
  ok(ex.ntx_start() === 0, 'ntx_start must return 0'); ok(ex.ntx_status() === 1, 'status must be 1 after start');
  scratch = 0; { const m = put(mb), s = put(sec); ok(ex.ntx_attach(m, s, 0, 0, 0, 0) === 0, 'attach must return 0'); }
  scratch = 0; { const f = put(frame), r = put(pub); const rc = ex.ntx_send(f, frame.length, r, pub.length); ok(rc === 0 || rc === 3, `send returned ${rc} (want 0 or 3)`); }
  scratch = 0; { const m = put(mb); const got = frames(blob(ex.ntx_poll(10, m, 1)));
    if (loopback) { ok(got.length === 1 && Buffer.from(got[0]).equals(Buffer.from(frame)), `loopback poll returned ${got.length} frame(s), want the one sent`); ok(frames(blob(ex.ntx_poll(10, m, 1))).length === 0, 'poll must drain'); } }
  scratch = 0; ok(ex.ntx_detach(put(mb)) === 0, 'detach must return 0');
  ok(ex.ntx_stop() === 0, 'ntx_stop must return 0'); ok(ex.ntx_status() === 0, 'status must be 0 after stop');
  return fails;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const a = process.argv.slice(2), file = a.find((x) => !x.startsWith('--'));
  const capsIdx = a.indexOf('--caps');
  const fails = await verifyWasm(fs.readFileSync(file), { manifestCaps: capsIdx >= 0 ? a[capsIdx + 1].split(',') : null, loopback: a.includes('--loopback') });
  if (fails.length) { console.error('FAIL ' + file + '\n  - ' + fails.join('\n  - ')); process.exit(1); }
  console.log('ok   ' + file + ' (ABI v1)');
}
