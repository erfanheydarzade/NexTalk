#!/usr/bin/env node
// Writes a Content-Security-Policy <meta> into web/nextalk-messenger.html whose
// script-src pins the SHA-256 of every inline <script>, so no injected script
// can run. Re-run after ANY edit to an inline script.
//   node tools/seal-csp.mjs          rewrite the file
//   node tools/seal-csp.mjs --check  exit 1 if the CSP is missing/stale (CI)
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const file = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'nextalk-messenger.html');
const check = process.argv.includes('--check');
let html = fs.readFileSync(file, 'utf8');

const hashes = [];
for (const m of html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
  hashes.push("'sha256-" + crypto.createHash('sha256').update(m[1], 'utf8').digest('base64') + "'");
}
const csp = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval' " + hashes.join(' '),
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  // Relay URL is user-supplied: https anywhere, plain http only for loopback.
  "connect-src 'self' https: http://localhost:* http://127.0.0.1:*",
  "base-uri 'none'", "form-action 'none'", "object-src 'none'",
].join('; ');
const meta = `<meta http-equiv="Content-Security-Policy" content="${csp}" />`;

const re = /<meta http-equiv="Content-Security-Policy"[^>]*>|<!--CSP-->/;
if (!re.test(html)) { console.error('no CSP marker/meta found'); process.exit(1); }
const next = html.replace(re, meta);
if (check) {
  if (next !== html) { console.error('CSP is stale: run node web/tools/seal-csp.mjs'); process.exit(1); }
  console.log(`CSP up to date (${hashes.length} inline scripts pinned)`);
} else {
  fs.writeFileSync(file, next);
  console.log(`CSP written (${hashes.length} inline scripts pinned)`);
}
