package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestForksMatchVendor(t *testing.T) {
	pairs := [][2]string{
		{"forks/caddy/modules/caddyhttp/server.go", "vendor/github.com/caddyserver/caddy/v2/modules/caddyhttp/server.go"},
		{"forks/coraza-caddy/coraza.go", "vendor/github.com/corazawaf/coraza-caddy/v2/coraza.go"},
		{"forks/coraza-caddy/interceptor.go", "vendor/github.com/corazawaf/coraza-caddy/v2/interceptor.go"},
		{"forks/coraza/internal/corazawaf/waf.go", "vendor/github.com/corazawaf/coraza/v3/internal/corazawaf/waf.go"},
		{"forks/coraza/internal/auditlog/serial_writer.go", "vendor/github.com/corazawaf/coraza/v3/internal/auditlog/serial_writer.go"},
		{"forks/coraza/internal/seclang/directives.go", "vendor/github.com/corazawaf/coraza/v3/internal/seclang/directives.go"},
	}

	for _, p := range pairs {
		forkBytes, err := os.ReadFile(filepath.FromSlash(p[0]))
		if err != nil {
			t.Fatalf("read fork %s: %v", p[0], err)
		}
		vendorBytes, err := os.ReadFile(filepath.FromSlash(p[1]))
		if err != nil {
			t.Fatalf("read vendor %s: %v", p[1], err)
		}
		if !bytes.Equal(forkBytes, vendorBytes) {
			t.Fatalf("fork %s drifted from vendor %s; run ./sync_forks.sh", p[0], p[1])
		}
	}
}

func TestCaddyServerHeaderStripped(t *testing.T) {
	if caddyhttp.ServerHeader != "" {
		t.Fatalf("expected caddyhttp.ServerHeader to be empty, got %q", caddyhttp.ServerHeader)
	}
}
