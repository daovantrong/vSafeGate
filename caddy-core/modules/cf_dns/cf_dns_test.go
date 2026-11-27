package cf_dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

type mockCFServer struct {
	mu      sync.Mutex
	records map[string]cfDNSRecord
	nextID  int
	token   string
}

func newMockCFServer(token string) (*mockCFServer, *httptest.Server) {
	m := &mockCFServer{
		records: make(map[string]cfDNSRecord),
		token:   token,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+m.token {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Unauthorized"}]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			name := r.URL.Query().Get("name")
			if name == "example.com" {
				_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zone-123","name":"example.com"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
			return

		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-123/dns_records":
			nameFilter := r.URL.Query().Get("name")
			typeFilter := r.URL.Query().Get("type")
			m.mu.Lock()
			var list []cfDNSRecord
			for _, rec := range m.records {
				if nameFilter != "" && rec.Name != nameFilter {
					continue
				}
				if typeFilter != "" && rec.Type != typeFilter {
					continue
				}
				list = append(list, rec)
			}
			m.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success":     true,
				"result":      list,
				"result_info": map[string]int{"page": 1, "total_pages": 1},
			})
			return

		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-123/dns_records":
			var body cfDNSRecord
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			m.mu.Lock()
			m.nextID++
			body.ID = "rec-" + string(rune('0'+m.nextID))
			m.records[body.ID] = body
			m.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": body})
			return

		case (r.Method == http.MethodPut || r.Method == http.MethodDelete) && strings.HasPrefix(r.URL.Path, "/zones/zone-123/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/zone-123/dns_records/")
			m.mu.Lock()
			defer m.mu.Unlock()
			if _, ok := m.records[id]; !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":81044,"message":"Record does not exist"}]}`))
				return
			}
			if r.Method == http.MethodDelete {
				delete(m.records, id)
				_, _ = w.Write([]byte(`{"success":true,"result":{"id":"` + id + `"}}`))
				return
			}
			var body cfDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&body)
			body.ID = id
			m.records[id] = body
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": body})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	return m, srv
}

func TestCloudflareDNSProvider_LibdnsCRUD(t *testing.T) {
	_, srv := newMockCFServer("secret-cf-token")
	defer srv.Close()

	p := &Provider{
		APIToken: "secret-cf-token",
		BaseURL:  srv.URL,
	}
	if err := p.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	ctx := context.Background()
	zone := "example.com."

	// 1. Append TXT record for ACME DNS-01
	appended, err := p.AppendRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "token-123", TTL: 60 * time.Second},
	})
	if err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	if len(appended) != 1 || appended[0].RR().Name != "_acme-challenge" || appended[0].RR().Data != "token-123" {
		t.Fatalf("unexpected appended records: %+v", appended)
	}

	// 2. GetRecords verifies persistence and relative naming
	all, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	if len(all) != 1 || all[0].RR().Name != "_acme-challenge" {
		t.Fatalf("unexpected GetRecords output: %+v", all)
	}

	// 3. SetRecords updates existing TXT record in place
	setRes, err := p.SetRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "token-456", TTL: 120 * time.Second},
	})
	if err != nil {
		t.Fatalf("SetRecords: %v", err)
	}
	if len(setRes) != 1 || setRes[0].RR().Data != "token-456" {
		t.Fatalf("unexpected SetRecords result: %+v", setRes)
	}

	// 4. DeleteRecords removes matching TXT record
	delRes, err := p.DeleteRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "token-456"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if len(delRes) != 1 {
		t.Fatalf("expected 1 deleted record, got %d", len(delRes))
	}

	after, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords after delete: %v", err)
	}
	if len(after) != 0 {
		t.Fatalf("expected 0 records after delete, got %+v", after)
	}
}

func TestCloudflareDNSProvider_CaddyfileAndValidation(t *testing.T) {
	d := caddyfile.NewTestDispenser(`cloudflare {
		api_token my-test-token
		base_url https://example.invalid/client/v4
	}`)
	var p Provider
	if err := p.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if p.APIToken != "my-test-token" {
		t.Fatalf("expected token my-test-token, got %q", p.APIToken)
	}

	empty := &Provider{}
	if err := empty.Validate(); err == nil {
		t.Fatal("expected Validate error when APIToken empty")
	}
}
