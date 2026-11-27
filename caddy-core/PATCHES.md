# vSafeGate Caddy Core Controlled Vendor Patches

All upstream vendor modifications are maintained in `caddy-core/forks/` and synced into
`caddy-core/vendor/` so `GOPROXY=off go build -mod=vendor .` remains 100% offline-reproducible
with zero external network dependency.

Run `./sync_forks.sh` after any upstream `vendor/` refresh, and verify parity via
`go test -mod=vendor ./...` (enforced by `forks_sync_test.go`).

## Active Patches

1. **`caddy/modules/caddyhttp/server.go`** (`github.com/caddyserver/caddy/v2 v2.11.9`)
   - Sets `caddyhttp.ServerHeader = ""` and skips emitting the default `Server: Caddy` header in `ServeHTTP`.
   - Purpose: Full gateway identity hiding (no default Caddy fingerprint header on responses or errors).

2. **`coraza-caddy/coraza.go` & `coraza-caddy/interceptor.go`** (`github.com/corazawaf/coraza-caddy/v2 v2.6.2`)
   - When a Coraza rule triggers an interruption with `it.Action == "drop"` in Phase 1/2 (`coraza.go`) or Phase 3/4 (`interceptor.go`), logs the violation and executes `panic(http.ErrAbortHandler)` without writing any HTTP response headers or status code.
   - `defer tx.ProcessLogging()` and `defer tx.Close()` still run cleanly during panic unwinding, while `net/http` aborts the TCP socket / resets HTTP/2 stream cleanly.

3. **`coraza/internal/corazawaf/waf.go`** (`github.com/corazawaf/coraza/v3 v3.8.1`)
   - Ensures `(*WAF).Close()` calls `w.auditLogWriter.Close()` when `w.auditLogWriterInitialized` is true so Caddy usage-pool destructors release audit log handles cleanly on config reload.

4. **`coraza/internal/auditlog/serial_writer.go`** (`github.com/corazawaf/coraza/v3 v3.8.1`)
   - Replaces uncoordinated per-WAF `os.OpenFile` handles with a refcounted, mutex-protected `sharedFileEntry` registry keyed by `(cleanTarget, FileMode)`.
   - Prevents concurrent sites from writing interleaved JSON lines into `/var/log/caddy/waf-audit.jsonl`, detects log rotation/unlink via `os.SameFile` and reopens transparently, and closes file descriptors only when the final referencing WAF closes.

5. **`coraza/internal/seclang/directives.go`** (`github.com/corazawaf/coraza/v3 v3.8.1`)
   - Allows `SecAuditLogRelevantStatus ^$` / `off` / `none` to clear `AuditLogRelevantStatus = nil` so `RelevantOnly` never logs arbitrary backend 4xx/5xx responses while still logging 100% of WAF-rule-matched transactions (`deny`, `drop`, and `DetectionOnly`).
