# Releasing NexTalk

Releases are cut on demand, not on a schedule — there is no weekly/nightly
job. Everything is driven by `.github/workflows/release.yml`.

## Cutting a release (the normal way)

1. Go to **Actions → Release → Run workflow** on GitHub.
2. Fill in:
   - **version** — a semver tag, e.g. `v1.4.0` (or `v1.4.0-rc.1` for a
     pre-release candidate). Must start with `v`.
   - **prerelease** — check this for a beta/RC you don't want showing up
     as "Latest release".
3. Click **Run workflow**.

That single button:

1. Validates the version string and creates+pushes the git tag (skipped
   if the tag already exists — re-running for the same version is safe).
2. Runs `go vet` and `go test ./...` against that tag.
3. Runs [GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`) to
   cross-compile `nextalk` for:

   | OS      | Architectures           |
   |---------|--------------------------|
   | Linux   | amd64, arm64, armv7      |
   | macOS   | amd64, arm64             |
   | Windows | amd64                    |

   packaging each as `.tar.gz` (`.zip` on Windows), plus a
   `checksums.txt`.
4. Builds the WebAssembly bundle via `cmd/nextalk-wasm/build.sh` (the
   same script you'd run locally — see [`wasm.md`](wasm.md)), bundles it
   with `web/index.html`, the docs, and a short "serve this over HTTP"
   README, and uploads it as `nextalk-wasm_<version>.tar.gz`.
5. Publishes one GitHub Release with all of the above attached and a
   changelog generated from commit messages since the previous tag
   (grouped into Features / Fixes / Documentation / Other — see
   `changelog:` in `.goreleaser.yaml` for the exact rules; conventional
   commit prefixes like `feat:`, `fix:`, `docs:` sort into their group,
   everything else lands in "Other").

Writing commits as `feat: ...`, `fix: ...`, `docs: ...` when they matter
for the changelog is enough — no changelog file to hand-maintain.

## Alternative: a plain git tag

If you'd rather not use the Actions UI, the workflow also triggers on a
normal tag push:

```bash
git tag -a v1.4.0 -m "Release v1.4.0"
git push origin v1.4.0
```

This runs the exact same build/publish steps as the button above.

## Version stamping

The tag becomes `nextalk version`'s output (`internal/buildinfo.Version`,
stamped via `-ldflags` in both `.goreleaser.yaml` and, for the wasm
build, `cmd/nextalk-wasm/build.sh`'s `$NEXTALK_VERSION` — see
`NexTalk.version()` in `wasm.md`). A local `go build` outside this
workflow gets `dev` for all three fields.

## Local dry run

To sanity-check the CLI archives without publishing anything:

```bash
go install github.com/goreleaser/goreleaser/v2@latest
goreleaser release --snapshot --clean
```

Output lands in `dist/` (gitignored) and nothing is pushed or uploaded.

## Prerequisites (already in place, noted for completeness)

- The workflow uses the default `GITHUB_TOKEN` — no extra secrets to
  configure.
- `permissions: contents: write` is set at the workflow level so the tag
  push, release creation, and asset upload all succeed without a PAT.
