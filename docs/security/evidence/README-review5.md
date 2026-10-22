# Review 5 evidence

| File | Tree | Command | Result |
|---|---|---|---|
| `independent-review-5-before.txt` | 0dcf5d3 plus the reviewer's probes | `go test -race -count=1 -p 1 -run TestR5_ -v ./internal/kernel ./internal/httpapi` | 5 FAIL (F1–F5 open) |
| `full-suite-review5-F1-F5.txt` | F1–F5 fixes and migration 0017, before the F6/F9 edits | `go build ./... && go vet ./... && go test -race -count=1 -p 1 -v ./...` | 219 top-level PASS, 0 FAIL, all 13 packages ok (includes the browser journey) |
| `independent-review-5-after.txt` | Final tree of this commit (F6/F9 changes touch only `internal/kernel` and `internal/httpapi`) | `go test -race -count=1 -p 1 -v ./internal/kernel ./internal/httpapi` | 163 top-level PASS, 0 FAIL |

All runs used a disposable local PostgreSQL 16 database with synthetic data. The review findings were fixed by the same AI agent that wrote the code; an independent re-review has not yet been done.
