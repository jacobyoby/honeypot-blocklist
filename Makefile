.PHONY: check compiled-validate dependency-tree format format-check install-hooks legacy-validate noncompiled-guard parity-current quick secret-guard vulncheck

GOVULNCHECK_VERSION := v1.7.0

check: quick
	go test -race ./...
	go build ./...
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...
	go mod verify
	$(MAKE) dependency-tree
	$(MAKE) compiled-validate
	$(MAKE) parity-current
	$(MAKE) vulncheck

quick: format-check noncompiled-guard secret-guard
	go vet ./...
	go test ./...

format-check:
	@files="$$(find . -type f -name '*.go' -not -path './.git/*')"; \
	unformatted="$$(gofmt -l $$files)"; \
	test -z "$$unformatted" || { printf '%s\n' "$$unformatted"; exit 1; }

format:
	@files="$$(find . -type f -name '*.go' -not -path './.git/*')"; \
	gofmt -w $$files

noncompiled-guard:
	@unexpected="$$(git ls-files | \
		grep -Ei '\.(cjs|cts|js|jsx|mjs|mts|phar|php([0-9]+)?|phps|phtml|py|pyi|pyw|ts|tsx)$$' | \
		grep -Ev '^(scripts/overlap\.py|validate\.py)$$' || true)"; \
	test -z "$$unexpected" || { \
		printf '%s\n' 'Unexpected non-compiled application source:' "$$unexpected"; \
		exit 1; \
	}; \
	interpreted="$$(git ls-files | while IFS= read -r path; do \
		if [ "$$path" = scripts/overlap.py ] || [ "$$path" = validate.py ]; then continue; fi; \
		index_first_line="$$(git show ":$$path" 2>/dev/null | sed -n '1p')"; \
		worktree_first_line=; \
		if [ -f "$$path" ]; then IFS= read -r worktree_first_line < "$$path" || true; fi; \
		for first_line in "$$index_first_line" "$$worktree_first_line"; do \
			if printf '%s\n' "$$first_line" | grep -Eiq '^#![[:space:]]*(/usr/bin/env([[:space:]]+-S)?[[:space:]]+|/[^[:space:]]*/)?(bun|deno|node|php|python([0-9.]*)?)([[:space:]]|$$)'; then \
				printf '%s\n' "$$path"; \
				break; \
			fi; \
		done; \
	done)"; \
	test -z "$$interpreted" || { \
		printf '%s\n' 'Unexpected interpreted-language shebang:' "$$interpreted"; \
		exit 1; \
	}

secret-guard:
	@matches="$$( \
		(git grep -aEl -e '(-----BEGIN ([A-Z0-9]+[[:space:]]+)*PRIVATE KEY-----|A(KIA|SIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|xapp-[A-Za-z0-9-]{10,}|https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+)' -- . || true; \
		 git grep --cached -aEl -e '(-----BEGIN ([A-Z0-9]+[[:space:]]+)*PRIVATE KEY-----|A(KIA|SIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|xapp-[A-Za-z0-9-]{10,}|https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+)' -- . || true) | sort -u)"; \
	test -z "$$matches" || { \
		printf '%s\n' 'Secret-like material found in tracked files:' "$$matches"; \
		exit 1; \
	}

dependency-tree:
	go list -m all

compiled-validate:
	go run ./cmd/blocklist-validator .

parity-current:
	@set +e; \
	legacy_output="$$(python3 validate.py . 2>&1)"; \
	legacy_status=$$?; \
	compiled_output="$$(go run ./cmd/blocklist-validator . 2>&1)"; \
	compiled_status=$$?; \
	set -e; \
	if [ "$$legacy_status" -ne "$$compiled_status" ] || [ "$$legacy_output" != "$$compiled_output" ]; then \
		printf '%s\n' "legacy status=$$legacy_status" "$$legacy_output" \
			"compiled status=$$compiled_status" "$$compiled_output"; \
		exit 1; \
	fi; \
	printf '%s\n' 'current-corpus Python/Go parity: exact'

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

install-hooks:
	git config extensions.worktreeConfig true
	git config --worktree core.hooksPath .githooks

legacy-validate:
	python3 validate.py .
