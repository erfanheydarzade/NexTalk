#!/usr/bin/env bash
# Builds cmd/nextalk-wasm into a browser-loadable nextalk.wasm, plus the
# matching wasm_exec.js glue from the local Go install.
#
# Usage:
#   ./cmd/nextalk-wasm/build.sh [output-dir]
#
# Output (default output-dir: ./web/wasm):
#   nextalk.wasm
#   wasm_exec.js
set -euo pipefail

cd "$(dirname "$0")/../.."   # repo root

OUT_DIR="${1:-web/wasm}"
mkdir -p "$OUT_DIR"

# Optional: NEXTALK_VERSION=v1.2.3 ./build.sh — stamps NexTalk.version()'s
# "version" field. Defaults to a short git describe, falling back to "dev"
# outside a git checkout (e.g. a release tarball with .git stripped).
VERSION="${NEXTALK_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"

echo "[*] Building nextalk.wasm (version: $VERSION) ..."
GOOS=js GOARCH=wasm go build \
  -ldflags "-X github.com/erfanheydarzade/NexTalk/internal/wasmbridge.buildVersion=$VERSION" \
  -o "$OUT_DIR/nextalk.wasm" ./cmd/nextalk-wasm

GOROOT="$(go env GOROOT)"
WASM_EXEC=""
for candidate in \
  "$GOROOT/lib/wasm/wasm_exec.js" \
  "$GOROOT/misc/wasm/wasm_exec.js"
do
  if [ -f "$candidate" ]; then
    WASM_EXEC="$candidate"
    break
  fi
done

if [ -z "$WASM_EXEC" ]; then
  echo "[!] Could not find wasm_exec.js under \$GOROOT ($GOROOT)." >&2
  echo "    Copy it manually from your Go installation into $OUT_DIR." >&2
  exit 1
fi

cp "$WASM_EXEC" "$OUT_DIR/wasm_exec.js"

echo "[+] Done. Output in $OUT_DIR/"
echo "    - nextalk.wasm"
echo "    - wasm_exec.js"
