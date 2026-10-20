## What and why

<!-- What does this change, and what problem does it solve? Link the issue: "Fixes #123". -->

## How I tested it

<!-- e.g. new test in internal/analyze, ran kam diff on examples/smoke -->

## Checklist

- [ ] The PR title is a Conventional Commit (`feat:`, `fix:`, `docs:`, `chore:`)
- [ ] `gofmt -l .` prints nothing, and `go vet ./...` and `go test ./...` pass
- [ ] New or changed rules have a test that triggers them and one that shows they don't over-trigger
- [ ] The README is updated if behaviour or flags changed
- [ ] No real account IDs, ARNs or secrets in test data
