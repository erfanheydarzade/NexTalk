// Builds relay-example.wasm with NO toolchain (no tinygo, wat2wasm or Go):
// the ABI v1 queue module is assembled by tools/wasmasm.mjs.
//   node build.mjs <outDir>      (build-all.mjs calls it this way)
//
// Semantics: a process-wide FIFO — send() appends, poll() drains, whatever the
// recipient or mailbox. That is a loopback queue: perfect for demos, tests and
// two identities in one tab, and a starting point for transports that need
// more (copy this directory; to write the module in another language see
// "Writing a WASM transport" in README.md).
import fs from 'node:fs';
import path from 'node:path';
import { buildQueueModule } from '../../tools/wasmasm.mjs';
import { fileURLToPath } from 'node:url';

const out = process.argv[2] || path.dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(fs.readFileSync(new URL('./manifest.json', import.meta.url), 'utf8'));
fs.mkdirSync(out, { recursive: true });
fs.writeFileSync(path.join(out, manifest.entry), buildQueueModule(manifest.capabilities.join(',')));
