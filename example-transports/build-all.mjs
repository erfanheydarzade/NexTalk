#!/usr/bin/env node
// Build EVERY extension in this repo into dist/*.ntx — automatically.
//
// Discovery (no registry to maintain): every directory that contains a
// manifest.json and/or a wasm/ subdirectory is an extension.
//
//   <ext>/manifest.json + go.mod   native (process-model) package, built with `go build`
//   <ext>/wasm/manifest.json       browser package: needs <ext>/wasm/build.mjs, run as
//   <ext>/wasm/build.mjs               node build.mjs <outDir>   -> must write <outDir>/<manifest.entry>
//   <ext>/wasm/<entry>.wasm        ...or just commit a prebuilt module next to the manifest
//
// Every browser package is validated (manifest rules identical to NexTalk's) and
// ABI-v1-verified before it is written. Output is reproducible; dist/SHA256SUMS lists the pins.
//
//   node build-all.mjs                 # all extensions, native for this machine + all wasm
//   node build-all.mjs --wasm-only     # no Go required
//   node build-all.mjs --all-targets   # native: linux/darwin/windows x amd64/arm64
//   node build-all.mjs relay-example   # only the named extension(s)
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeNtx, validateManifest } from './tools/ntx.mjs';
import { verifyWasm } from './tools/verify-wasm.mjs';

const root = path.dirname(fileURLToPath(import.meta.url)), dist = path.join(root, 'dist');
const args = process.argv.slice(2), flag = (f) => args.includes(f), only = args.filter((a) => !a.startsWith('--'));
const readJSON = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const run = (cmd, a, opts = {}) => spawnSync(cmd, a, { stdio: 'inherit', ...opts });
const hasGo = !flag('--wasm-only') && spawnSync('go', ['version'], { stdio: 'ignore' }).status === 0;

const exts = fs.readdirSync(root, { withFileTypes: true })
  .filter((d) => d.isDirectory() && !['dist', 'node_modules', 'tools'].includes(d.name) && !d.name.startsWith('.'))
  .map((d) => d.name).filter((n) => fs.existsSync(path.join(root, n, 'manifest.json')) || fs.existsSync(path.join(root, n, 'wasm', 'manifest.json')))
  .filter((n) => only.length === 0 || only.includes(n)).sort();
if (!exts.length) { console.error('no extensions found'); process.exit(1); }

fs.rmSync(dist, { recursive: true, force: true }); fs.mkdirSync(dist, { recursive: true });
const sums = []; let failed = 0;
const fail = (m) => { failed++; console.error('FAIL ' + m); };

for (const name of exts) {
  const dir = path.join(root, name);
  console.log(`\n== ${name}`);

  // ---- browser (WASM) package ----
  const wdir = path.join(dir, 'wasm');
  if (fs.existsSync(path.join(wdir, 'manifest.json'))) {
    try {
      const manifest = validateManifest(readJSON(path.join(wdir, 'manifest.json')), { wasm: true });
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ntx-'));
      const entryPath = path.join(tmp, manifest.entry);
      if (fs.existsSync(path.join(wdir, 'build.mjs'))) {
        const r = run(process.execPath, [path.join(wdir, 'build.mjs'), tmp], { cwd: wdir });
        if (r.status !== 0) throw new Error('wasm/build.mjs failed');
      } else if (fs.existsSync(path.join(wdir, manifest.entry))) fs.copyFileSync(path.join(wdir, manifest.entry), entryPath);
      if (!fs.existsSync(entryPath)) throw new Error(`wasm/build.mjs must write ${manifest.entry} into its output dir`);
      const bytes = fs.readFileSync(entryPath);
      const extra = fs.existsSync(path.join(wdir, 'verify.json')) ? readJSON(path.join(wdir, 'verify.json')) : {};
      const fails = await verifyWasm(bytes, { manifestCaps: manifest.capabilities, loopback: !!extra.loopback });
      if (fails.length) throw new Error('ABI v1 verification:\n  - ' + fails.join('\n  - '));
      const res = writeNtx(dist, manifest, bytes, { wasm: true });
      sums.push(`${res.hash}  ${path.basename(res.file)}`); console.log(`ok   ${path.relative(root, res.file)}  sha256 ${res.hash.slice(0, 16)}…  (browser, ${bytes.length} B wasm)`);
    } catch (e) { fail(`${name} (wasm): ${e.message}`); }
  }

  // ---- native (process-model) package ----
  if (fs.existsSync(path.join(dir, 'manifest.json')) && fs.existsSync(path.join(dir, 'go.mod'))) {
    if (!hasGo) { console.log('skip native build (no Go toolchain, or --wasm-only)'); continue; }
    const base = readJSON(path.join(dir, 'manifest.json'));
    const t = run('go', ['test', './...'], { cwd: dir }); if (t.status !== 0) { fail(`${name}: go test`); continue; }
    const targets = flag('--all-targets') ? [['linux', 'amd64'], ['linux', 'arm64'], ['darwin', 'amd64'], ['darwin', 'arm64'], ['windows', 'amd64'], ['windows', 'arm64']] : [[os.platform() === 'win32' ? 'windows' : os.platform(), os.arch() === 'x64' ? 'amd64' : os.arch()]];
    for (const [goos, goarch] of targets) {
      try {
        const entry = base.entry.replace(/\.exe$/, '') + (goos === 'windows' ? '.exe' : '');
        const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ntx-')), bin = path.join(tmp, entry);
        const b = run('go', ['build', '-trimpath', '-ldflags', '-s -w', '-o', bin, '.'], { cwd: dir, env: { ...process.env, GOOS: goos, GOARCH: goarch, CGO_ENABLED: '0' } });
        if (b.status !== 0) throw new Error('go build failed');
        const res = writeNtx(dist, { ...base, entry }, fs.readFileSync(bin), { suffix: flag('--all-targets') ? `-${goos}-${goarch}` : '' });
        sums.push(`${res.hash}  ${path.basename(res.file)}`); console.log(`ok   ${path.relative(root, res.file)}  sha256 ${res.hash.slice(0, 16)}…  (${goos}/${goarch})`);
      } catch (e) { fail(`${name} (${goos}/${goarch}): ${e.message}`); }
    }
  }
}
fs.writeFileSync(path.join(dist, 'SHA256SUMS'), sums.sort().join('\n') + '\n');
console.log(`\n${sums.length} package(s) in dist/ ${failed ? `— ${failed} FAILED` : '— all ok'}`);
process.exit(failed ? 1 : 0);
