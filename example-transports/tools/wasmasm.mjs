// Zero-toolchain WASM assembler + an ABI v1 in-memory queue transport.
// (Same module the NexTalk bridge tests use; no wat2wasm/tinygo needed.)
// Shared FIFO regardless of mailbox/recipient, like the Go test module:
//   queue at 0x4000.., poll output at 0x8000.., ntx_alloc bump heap at 0x1000..
const uleb = (n) => { n = BigInt(n); const o = []; do { let b = Number(n & 0x7fn); n >>= 7n; if (n) b |= 0x80; o.push(b); } while (n); return o; };
const sleb = (n) => { n = BigInt(n); const o = []; for (;;) { const b = Number(n & 0x7fn); n >>= 7n; const sign = (b & 0x40) !== 0; if ((n === 0n && !sign) || (n === -1n && sign)) { o.push(b); return o; } o.push(b | 0x80); } };
const str = (s) => [...uleb(s.length), ...Buffer.from(s)];
const vec = (items) => [...uleb(items.length), ...items.flat()];
const sec = (id, body) => [id, ...uleb(body.length), ...body];
const I32 = 0x7f, I64 = 0x7e;
let CAPS = 'message'; // set per build (module-level so the ntx_caps body sees it)

const op = {
  i32c: (v) => [0x41, ...sleb(v)], i64c: (v) => [0x42, ...sleb(v)],
  get: (i) => [0x20, ...uleb(i)], set: (i) => [0x21, ...uleb(i)],
  gget: (i) => [0x23, ...uleb(i)], gset: (i) => [0x24, ...uleb(i)],
  add: [0x6a], sub: [0x6b], and: [0x71], shru: [0x76], gtu: [0x4b],
  store8: (off) => [0x3a, 0x00, ...uleb(off)],
  ifv: [0x04, 0x40], end: [0x0b], ret: [0x0f],
  ext: [0xad], shl64: [0x86], or64: [0x84],
  memcopy: [0xfc, 0x0a, 0x00, 0x00],
};
const body = (nlocals, ...ops) => { const b = [...(nlocals ? vec([[nlocals, I32]]) : [0]), ...ops.flat(), 0x0b]; return [...uleb(b.length), ...b]; };

// G0 running, G1 qlen, G2 bump
const Q = 0x4000, OUT = 0x8000;
const fns = [
  // [typeIdx, exportName, body]
  [1, 'ntx_init', body(0, op.i32c(0))],
  [2, 'ntx_caps', body(0, op.i64c((0x100n << 32n) | BigInt(Buffer.byteLength(CAPS))))],
  [0, 'ntx_start', body(0, op.i32c(1), op.gset(0), op.i32c(0))],
  [0, 'ntx_stop', body(0, op.i32c(0), op.gset(0), op.i32c(0))],
  [0, 'ntx_status', body(0, op.gget(0))],
  [5, 'ntx_alloc', body(1, // local1 = p
    op.gget(2), op.set(1),
    op.get(1), op.get(0), op.add, op.i32c(0x3f00), op.gtu, op.ifv, op.i32c(0x1000), op.set(1), op.end,
    op.get(1), op.get(0), op.add, op.i32c(7), op.add, op.i32c(-8), op.and, op.gset(2),
    op.get(1))],
  [3, 'ntx_send', body(1, // params fp,fl,rp,rl ; local4 = dst
    op.gget(0), [0x45], op.ifv, op.i32c(1), op.ret, op.end,
    op.gget(1), op.get(1), op.add, op.i32c(4), op.add, op.i32c(0x4000), op.gtu, op.ifv, op.i32c(3), op.ret, op.end,
    op.i32c(Q), op.gget(1), op.add, op.set(4),
    op.get(4), op.get(1), op.i32c(24), op.shru, op.store8(0),
    op.get(4), op.get(1), op.i32c(16), op.shru, op.store8(1),
    op.get(4), op.get(1), op.i32c(8), op.shru, op.store8(2),
    op.get(4), op.get(1), op.store8(3),
    op.get(4), op.i32c(4), op.add, op.get(0), op.get(1), op.memcopy,
    op.gget(1), op.get(1), op.add, op.i32c(4), op.add, op.gset(1),
    op.i32c(0))],
  [4, 'ntx_attach', body(0, op.i32c(0))],
  [5, 'ntx_detach', body(0, op.i32c(0))],
  [6, 'ntx_poll', body(0, // n = qlen
    op.i32c(OUT), op.i32c(Q), op.gget(1), op.memcopy,
    op.i32c(OUT), op.ext, op.i64c(32), op.shl64, op.gget(1), op.ext, op.or64,
    op.i32c(0), op.gset(1))],
];
const types = [
  [0x60, ...vec([]), ...vec([[I32]])],                         // 0 ()->i32
  [0x60, ...vec([[I32], [I32]]), ...vec([[I32]])],             // 1 (i32,i32)->i32
  [0x60, ...vec([]), ...vec([[I64]])],                         // 2 ()->i64
  [0x60, ...vec([[I32], [I32], [I32], [I32]]), ...vec([[I32]])],// 3
  [0x60, ...vec(Array(6).fill([I32])), ...vec([[I32]])],       // 4
  [0x60, ...vec([[I32]]), ...vec([[I32]])],                    // 5 (i32)->i32
  [0x60, ...vec([[I32], [I32], [I32]]), ...vec([[I64]])],      // 6 (i32,i32,i32)->i64
];
// ntx_poll must return i64: body above leaves i64 then runs `i32.const 0; global.set 1`? No:
// the stack must hold the i64 at `end`, so reorder: compute i64, then reset qlen via a block-free trick.
fns[fns.length - 1][2] = body(0,
  op.i32c(OUT), op.i32c(Q), op.gget(1), op.memcopy,
  op.i32c(OUT), op.ext, op.i64c(32), op.shl64, op.gget(1), op.ext, op.or64,
  op.i32c(0), op.gset(1)); // i64 stays on the stack beneath; gset consumes only its i32

/** capsCsv is written into the module data segment (what ntx_caps returns; max 32 bytes). */
export function buildQueueModule(capsCsv = 'message') {
  if (Buffer.byteLength(capsCsv) > 32) throw new Error('caps string too long');
  CAPS = capsCsv; fns[1][2] = body(0, op.i64c((0x100n << 32n) | BigInt(Buffer.byteLength(CAPS))));
  const exports = [
    ...fns.map(([, name], i) => [...str(name), 0x00, ...uleb(i)]),
    [...str('memory'), 0x02, 0x00],
  ];
  const bytes = [
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...sec(1, vec(types)),
    ...sec(3, vec(fns.map(([t]) => uleb(t)))),
    ...sec(5, vec([[0x00, 0x02]])),                              // memory: min 2 pages
    ...sec(6, vec([[I32, 0x01, ...op.i32c(0), 0x0b], [I32, 0x01, ...op.i32c(0), 0x0b], [I32, 0x01, ...op.i32c(0x1000), 0x0b]])),
    ...sec(7, vec(exports)),
    ...sec(10, vec(fns.map(([, , b]) => b))),
    ...sec(11, vec([[0x00, ...op.i32c(0x100), 0x0b, ...vec([[...Buffer.from(capsCsv)].map((c) => [c])].flat())]])),
  ];
  return new Uint8Array(bytes);
}
