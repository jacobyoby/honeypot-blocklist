# Honeypot blocklist agent rules

## Compiled direction

- Go is the target for Jacob-owned validator, feed, and analysis code.
- Do not add JavaScript, TypeScript, Python, or PHP application code, including
  alternate extensions or extensionless files with those interpreter shebangs.
- `validate.py` and `scripts/overlap.py` are frozen migration sources. Modify
  them only for an incident fix or a parity fixture required to remove them.
- The Go validator is an additive publication gate. Python remains only as the
  parity oracle during the shadow period. Never weaken either gate to make a
  migration pass; remove Python only after recorded parity and rollback.
- Compile continuously: run `go test ./...` after every Go edit. Before review,
  run `gofmt`, `go vet ./...`, `go test -race ./...`, native `go build ./...`,
  and a `linux/amd64` build.

## Data safety

- `blocklist.txt`, `blocklist.json`, `blocklist.csv`, and
  `blocklist.misp.csv` are generated artifacts. Do not hand-edit their content.
- Preserve the documented schema, column order, exclusion rules, and
  cross-format equality unless Jacob explicitly approves a public contract
  change.
- Use fixtures with reserved example addresses. Never put captured
  credentials, private logs, tokens, or unpublished attacker payloads in Git.
- Publishing, delisting, changing inclusion criteria, or pushing a branch is
  an external action and requires the applicable direct authorization.

## Git and review

- Work in a dedicated Git worktree and a task branch. Do not modify another
  agent's checkout.
- Rebase before review when safe. Squash fixup-only commits while preserving
  commits that provide distinct evidence or rollback value.
- Run `make install-hooks` in the task worktree after `make check` passes. This
  activates versioned hooks only for that worktree.
- Do not force-push, merge, tag, or delete worktrees without explicit scope.
- Use `.github/PULL_REQUEST_TEMPLATE.md` and the compiled-migration issue
  template. Every review must include commands and observed results.

## Tools

- Use the CLI for code, builds, tests, debugging, and Git. Use the desktop app
  for visual artifacts and documentation review.
- Use `rg`, `grep`, `awk`, and `sed` directly for exploration. Do not use RTK
  as a wrapper around them.
- Default to the local shell, Go toolchain, Git, and read-only HTTP probes.
  Codex Security may perform read-only review. Use no generic MCP/plugin pack
  unless the current task demonstrates a missing capability.
- Repository work must not uninstall global plugins used by other products.

## Mechanical quality gate

- Prefer the Go standard library. Explain every new production dependency.
- Run `go mod verify`, inspect `go list -m all`, and run the pinned
  `govulncheck` target after dependency changes.
- CI, compiler, formatter, vet, race tests, negative fixtures, and security
  checks enforce mechanical rules; do not substitute prose review for them.
- Prove a known-good fixture passes and a known-bad fixture fails before
  reporting that a validator path works.
- Update current-state documentation with behavior. Preserve dated historical
  measurements and incident records unchanged.
