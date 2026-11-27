// Module boundary marker so `go test ./...` inside caddy-core does not attempt
// to compile maintained upstream patch copies under forks/ directly; active code
// is synced into vendor/ (verified by forks_sync_test.go).
module caddy-core/forks

go 1.24
