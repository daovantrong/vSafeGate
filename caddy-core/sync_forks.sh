#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

pairs=(
  "forks/caddy/modules/caddyhttp/server.go:vendor/github.com/caddyserver/caddy/v2/modules/caddyhttp/server.go"
  "forks/coraza-caddy/coraza.go:vendor/github.com/corazawaf/coraza-caddy/v2/coraza.go"
  "forks/coraza-caddy/interceptor.go:vendor/github.com/corazawaf/coraza-caddy/v2/interceptor.go"
  "forks/coraza/internal/corazawaf/waf.go:vendor/github.com/corazawaf/coraza/v3/internal/corazawaf/waf.go"
  "forks/coraza/internal/auditlog/serial_writer.go:vendor/github.com/corazawaf/coraza/v3/internal/auditlog/serial_writer.go"
  "forks/coraza/internal/seclang/directives.go:vendor/github.com/corazawaf/coraza/v3/internal/seclang/directives.go"
)

for entry in "${pairs[@]}"; do
  src="${entry%%:*}"
  dst="${entry##*:}"
  cp "$src" "$dst"
  echo "Synced $src -> $dst"
done
