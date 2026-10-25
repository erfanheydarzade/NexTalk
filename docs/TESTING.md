# Testing NexTalk

Everything below was run against this tree. Commands assume the repo root.

## 0. Prerequisites
Go 1.25+, Node 22+. For the browser test: `npm` and permission to download Chromium.

## 1. Go: format, vet, unit + integration tests
```bash
gofmt -l .                 # must print nothing
go vet ./...
go test ./...              # includes the real WASM extension round trip under wazero
GOOS=js GOARCH=wasm go vet ./internal/wasmbridge/... ./cmd/nextalk-wasm/...
```
`internal/transport` tests build the shipped extension with Node, so Node must be on PATH
(they skip, not fail, if it is missing).

## 2. Build the browser client
```bash
bash cmd/nextalk-wasm/build.sh          # -> web/wasm/nextalk.wasm + wasm_exec.js
```

## 3. Build the WebAssembly relay extension (.ntx)
```bash
cd example-transports && node build-all.mjs --wasm-only
cat dist/SHA256SUMS                      # identical on every build (reproducible)
```

## 4. Node tests
```bash
cd web/test
node --test ntx-host.test.mjs            # host sandbox / ABI checks
node transport-smoke.mjs                 # two identities, message through the WASM extension -> "smoke: ok"
```

## 5. Browser end-to-end test (headless Chromium)
```bash
cd web/test && npm install && npx playwright install chromium
node e2e-messenger.mjs                   # expect: "25 passed, 0 failed"
```
It checks: API revision 3 compatibility, no third-party tags, CSP enforcement, extension install + host registration,
encrypted vault (600k PBKDF2) incl. wrong-password rejection and restore after reload,
no plaintext chat/extension state in localStorage, markup injection, http:// relay refusal,
and the auto-poll schedule (4s, back-off after failure, stops when Auto-check is off).

## 6. Manual test of the messenger page
```bash
cd web && python3 -m http.server 8000     # NOT file:// - WebAssembly needs http(s)
# open http://localhost:8000/nextalk-messenger.html
```
1. Wait for the **wasm** status dot to turn green; create an identity.
2. Find the **Remember this device** card, set a password, reload, unlock - your chats return (automated in step 5).
3. **Extensions** tab: choose `example-transports/dist/relay-example-wasm.ntx`, read the
   permissions/hash in the confirm dialog (compare with `dist/SHA256SUMS`), install, enable.
4. Two-person test over a real relay: open the page in two different browsers, create an identity in each,
   enter your Router URL (https, or http only for localhost), press **connect + register**, add each other and send a message.
   **Not verified here:** the Router/shard server is not part of this repository, so this path was only
   exercised up to the network call (see `docs/AUDIT-2026-10.md`). Two-identity message flow through the WASM
   extension is covered by `web/test/transport-smoke.mjs`.
5. Leave **Auto-check** on: with a relay connected, new messages should arrive without pressing anything (schedule verified with a stubbed relay in step 5 of the automated tests).

## 7. CI
* `ci.yml` - gofmt, vet, build, tests, CSP seal check.
* `wasm-extensions.yml` - builds `.ntx` (twice, must match), ABI check, `nextalk.wasm`, runs all of the above
  including the browser test, uploads `nextalk-extensions` and `nextalk-web-bundle` artifacts.
* `release.yml` - ships CLI archives, the WASM bundle, `nextalk-messenger_<tag>.html` and `relay-example-wasm_<tag>.ntx`.

## 8. After editing the page
Any change to an inline `<script>` in `web/nextalk-messenger.html` changes its hash:
```bash
node web/tools/seal-csp.mjs          # rewrites the CSP;  --check verifies (CI runs it)
```
