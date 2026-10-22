// .ntx packaging + manifest validation (mirrors internal/transport/manifest.go).
// Zero dependencies. Packages are REPRODUCIBLE: fixed timestamps, sorted
// members, normalised manifest JSON — the same inputs always give the same
// sha256, which is exactly what NexTalk pins at install.
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const KNOWN_CAPABILITIES = ['message', 'binary-transfer', 'presence', 'local-network', 'p2p'];
export const KNOWN_PERMISSIONS = ['network', 'storage'];
const ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

/** Throws on anything NexTalk's ParseManifest would refuse (fail closed). */
export function validateManifest(m, { wasm = false } = {}) {
  const bad = (msg) => { throw new Error('manifest: ' + msg); };
  if (typeof m !== 'object' || m === null) bad('not an object');
  if (!ID_RE.test(m.id || '')) bad(`bad id ${JSON.stringify(m.id)}`);
  if (!m.name) bad('empty name');
  if (!m.version) bad('empty version');
  if (m.api_version !== '1') bad(`unsupported api_version ${JSON.stringify(m.api_version)}`);
  if (!m.entry || !/^[A-Za-z0-9._-]+$/.test(m.entry) || m.entry === '.' || m.entry === '..') bad(`bad entry ${JSON.stringify(m.entry)}`);
  if (!Array.isArray(m.capabilities) || m.capabilities.length === 0) bad('no capabilities');
  for (const c of m.capabilities) if (!KNOWN_CAPABILITIES.includes(c)) bad(`unknown capability ${JSON.stringify(c)}`);
  for (const p of m.permissions || []) if (!KNOWN_PERMISSIONS.includes(p)) bad(`unknown permission ${JSON.stringify(p)}`);
  if (wasm && !m.entry.toLowerCase().endsWith('.wasm')) bad(`browser packages need a .wasm entry, got ${JSON.stringify(m.entry)}`);
  return m;
}

const crcTable = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = (b) => { let c = 0xffffffff; for (const x of b) c = crcTable[(c ^ x) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };

/** files: [[name, Buffer|Uint8Array]]; returns a Buffer (zip, deflate, fixed 1980-01-01 timestamps). */
export function zip(files) {
  const parts = [], central = []; let off = 0;
  const DOS_TIME = 0, DOS_DATE = (0 << 9) | (1 << 5) | 1; // 1980-01-01 00:00
  for (const [name, data0] of [...files].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const data = Buffer.from(data0), n = Buffer.from(name, 'utf8'), crc = crc32(data), def = zlib.deflateRawSync(data, { level: 9 });
    const [method, body] = def.length < data.length ? [8, def] : [0, data];
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0800, 6); lh.writeUInt16LE(method, 8);
    lh.writeUInt16LE(DOS_TIME, 10); lh.writeUInt16LE(DOS_DATE, 12); lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(n.length, 26);
    parts.push(lh, n, body);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(0x031e, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0800, 8); ch.writeUInt16LE(method, 10);
    ch.writeUInt16LE(DOS_TIME, 12); ch.writeUInt16LE(DOS_DATE, 14); ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(n.length, 28);
    ch.writeUInt32LE((0o100644 << 16) >>> 0, 38); ch.writeUInt32LE(off, 42);
    central.push(ch, n); off += 30 + n.length + body.length;
  }
  const cd = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, cd, end]);
}

export const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');

/** Validate + write <outDir>/<id>-<suffix>.ntx; returns { file, hash, manifest }. */
export function writeNtx(outDir, manifest, entryBytes, { wasm = false, suffix = '' } = {}) {
  validateManifest(manifest, { wasm });
  if (wasm && !(entryBytes.length >= 8 && entryBytes[0] === 0 && entryBytes[1] === 0x61 && entryBytes[2] === 0x73 && entryBytes[3] === 0x6d)) throw new Error('entry is not a WebAssembly module');
  const mf = Buffer.from(JSON.stringify(manifest, null, 2) + '\n');
  const pkg = zip([['manifest.json', mf], [manifest.entry, entryBytes]]);
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, `${manifest.id}${suffix}.ntx`);
  fs.writeFileSync(file, pkg);
  return { file, hash: sha256(pkg), manifest };
}
