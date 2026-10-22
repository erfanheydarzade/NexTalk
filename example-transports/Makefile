.PHONY: all wasm native test clean
all:            ; node build-all.mjs
wasm:           ; node build-all.mjs --wasm-only      # no Go required
native:         ; node build-all.mjs --all-targets
test:           ; node build-all.mjs --wasm-only && cd relay-example && go test ./...
clean:          ; rm -rf dist
