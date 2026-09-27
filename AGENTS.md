# Agent instructions

## Project

- This repository is the Go module `go.osspkg.com/encrypt`; `go.mod` requires Go 1.26.
- Public packages are `aesgcm` (AES-GCM), `hash` (hash adapter), `pgp` (OpenPGP), and `pki` (X.509/OCSP).
- `pki/internal/xocsp` contains the internal OCSP ASN.1 implementation used by `pki`.
- Keep changes scoped to the package being changed. Public behavior and security-relevant limits should stay documented in Godoc and README where relevant.

## Commands

Run commands from the repository root.

- `go test ./...` runs all Go package tests.
- `make tests` runs the repository's `goppy test` target.
- `make lint` runs `goppy lint`. It can update files through configured formatting and fixes; inspect `git diff` afterward.
- `make build` runs `goppy build --arch=amd64`.
- `make ci` is the CI command from `.github/workflows/ci.yml`. It runs the `pre-commit` chain: install/setup, license, lint, tests, and build. The install step installs `goppy@latest`; the chain is not a read-only validation command.

## Changes and validation

- Keep `go.mod` and `go.sum` in sync when changing dependencies.
- Add or update tests for behavior changes and security fixes. Use `go test ./...` for full-suite validation; use package-scoped `go test` for focused changes.
- The linter configuration is in `.golangci.yml`; prefer fixing findings over adding suppressions. Explain any necessary suppression inline.
- Review the final worktree diff, especially after `make lint` or `make ci`, because these targets may modify files.
- Do not run publishing, deployment, or other external release operations as part of local validation.
