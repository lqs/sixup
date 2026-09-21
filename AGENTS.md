# AGENTS.md

- Do not over-engineer. Write only the code needed now: no speculative abstractions, no extra indirection. A flat main package; keep it that way.
- Write modern Go 1.27: generics, `slices`/`maps`/`cmp`, `errors.Is`/`%w`, `log/slog`, context. Compatibility with older versions is not a concern.
- Do not rush to commit. After changing code, run `go build ./... && go vet ./... && go test ./...` and `GOOS=linux golangci-lint run` (the Linux target is the real one; on macOS the linux-only netlink constants are reported as unused), and wait for the user to confirm before committing.
- Comments, log messages and command-line help are always in English.
