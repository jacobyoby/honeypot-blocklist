## Scope

- Work item:
- One-sentence change:
- Explicitly out of scope:

## Compiled evidence

- [ ] `gofmt` is clean.
- [ ] `go vet ./...` passes.
- [ ] `go test -race ./...` passes.
- [ ] Native and `linux/amd64` builds pass.
- [ ] Dependency changes are explained and `go mod verify` passes.
- [ ] Dependency-tree, secret, and pinned `govulncheck` gates pass.
- [ ] Versioned hooks are active in the task worktree.

## Behavioral evidence

- [ ] Known-good fixture passes.
- [ ] Known-bad fixture fails for the intended reason.
- [ ] Compiled validation passes on the current publication files.
- [ ] Go/Python stdout and exit-code parity is exact during shadowing.
- [ ] Generated feed files are unchanged, or the authorized change is shown.
- [ ] Documentation and rollback instructions are current.

Deployment/publish status: `not requested` / `authorized separately`
