package cf_dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

const defaultCloudflareBaseURL = "https://api.cloudflare.com/client/v4"

func init() {
	caddy.RegisterModule(Provider{})
}

// Provider implements Caddy DNS-01 ACME resolution using Cloudflare API v4
// via Go stdlib net/http and libdns v1.1.1 (zero additional external dependencies).
type Provider struct {
	APIToken   string       `json:"api_token,omitempty"`
	BaseURL    string       `json:"base_url,omitempty"`
	HTTPClient *http.Client `json:"-"`

	zoneCache *sync.Map // normalized zone name -> zone ID
}

// CaddyModule implements caddy.Module.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.cloudflare",
		New: func() caddy.Module { return new(Provider) },
	}
}

// Provision implements caddy.Provisioner.
func (p *Provider) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	p.APIToken = strings.TrimSpace(repl.ReplaceAll(p.APIToken, ""))
	if p.BaseURL == "" {
		p.BaseURL = defaultCloudflareBaseURL
	}
	p.BaseURL = strings.TrimRight(p.BaseURL, "/")
	if p.HTTPClient == nil {
		p.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if p.zoneCache == nil {
		p.zoneCache = &sync.Map{}
	}
	return nil
}

// Validate implements caddy.Validator.
func (p *Provider) Validate() error {
	if strings.TrimSpace(p.APIToken) == "" {
		return errors.New("cloudflare dns provider requires api_token")
	}
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
// Supports:
//   cloudflare <api_token>
// or:
//   cloudflare {
//       api_token <token>
//   }
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			p.APIToken = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "api_token":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.APIToken = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			case "base_url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.BaseURL = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective %q", d.Val())
			}
		}
	}
	return nil
}

type cfEnvelope struct {
	Success    bool             `json:"success"`
	Errors     []cfAPIError     `json:"errors"`
	Result     json.RawMessage  `json:"result"`
	ResultInfo *cfResultInfo    `json:"result_info,omitempty"`
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfResultInfo struct {
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfDNSRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied *bool  `json:"proxied,omitempty"`
}

func (p *Provider) baseURL() string {
	if p.BaseURL != "" {
		return strings.TrimRight(p.BaseURL, "/")
	}
	return defaultCloudflareBaseURL
}

func (p *Provider) client() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (p *Provider) doAPI(ctx context.Context, method, path string, reqBody any) (*cfEnvelope, error) {
	if strings.TrimSpace(p.APIToken) == "" {
		return nil, errors.New("cloudflare api_token is empty")
	}

	var bodyBytes []byte
	if reqBody != nil {
		var err error
		bodyBytes, err = json.Marshal(reqBody)
		if err != nil {
			return nil, err
		}
	}

	fullURL := p.baseURL() + path
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		var bodyReader io.Reader
		if bodyBytes != nil {
			bodyReader = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+p.APIToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "vSafeGate-CF-DNS/1.0")

		resp, err := p.client().Do(req)
		if err != nil {
			lastErr = err
			if attempt < 2 && sleepCtx(ctx, time.Duration(attempt+1)*150*time.Millisecond) {
				continue
			}
			return nil, err
		}

		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("cloudflare API %s %s HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
			wait := time.Duration(attempt+1) * 200 * time.Millisecond
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if sec, convErr := strconv.Atoi(ra); convErr == nil && sec > 0 && sec <= 10 {
					wait = time.Duration(sec) * time.Second
				}
			}
			if attempt < 2 && sleepCtx(ctx, wait) {
				continue
			}
			return nil, lastErr
		}

		var env cfEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, fmt.Errorf("cloudflare API %s %s invalid JSON (HTTP %d): %w", method, path, resp.StatusCode, err)
		}
		if !env.Success || resp.StatusCode >= 400 {
			if len(env.Errors) > 0 {
				return nil, fmt.Errorf("cloudflare API %s %s failed: [%d] %s", method, path, env.Errors[0].Code, env.Errors[0].Message)
			}
			return nil, fmt.Errorf("cloudflare API %s %s failed (HTTP %d)", method, path, resp.StatusCode)
		}
		return &env, nil
	}
	return nil, lastErr
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func normalizeZoneName(zone string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
}

func (p *Provider) getZoneID(ctx context.Context, zone string) (string, error) {
	z := normalizeZoneName(zone)
	if z == "" {
		return "", errors.New("empty zone")
	}
	if p.zoneCache != nil {
		if cached, ok := p.zoneCache.Load(z); ok {
			return cached.(string), nil
		}
	}

	// Walk labels in case a delegated subdomain zone was supplied.
	labels := strings.Split(z, ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		if p.zoneCache != nil {
			if cached, ok := p.zoneCache.Load(candidate); ok {
				p.zoneCache.Store(z, cached)
				return cached.(string), nil
			}
		}

		q := "/zones?name=" + url.QueryEscape(candidate)
		env, err := p.doAPI(ctx, http.MethodGet, q, nil)
		if err != nil {
			return "", err
		}
		var zones []cfZone
		if err := json.Unmarshal(env.Result, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 && zones[0].ID != "" {
			if p.zoneCache != nil {
				p.zoneCache.Store(candidate, zones[0].ID)
				p.zoneCache.Store(z, zones[0].ID)
			}
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare zone not found for %q", zone)
}

func cfRecordToLibdns(r cfDNSRecord, zone string) libdns.Record {
	ttl := time.Duration(r.TTL) * time.Second
	if r.TTL == 1 {
		ttl = 0
	}
	rr := libdns.RR{
		Name: libdns.RelativeName(r.Name, zone),
		TTL:  ttl,
		Type: strings.ToUpper(r.Type),
		Data: r.Content,
	}
	parsed, err := rr.Parse()
	if err != nil {
		return rr
	}
	return parsed
}

func ttlForCloudflare(ttl time.Duration, recType string) int {
	if ttl <= 0 {
		if strings.EqualFold(recType, "TXT") {
			return 60
		}
		return 1 // automatic
	}
	secs := int(ttl.Seconds())
	if secs < 60 {
		return 60
	}
	return secs
}

func fqdnName(name, zone string) string {
	abs := libdns.AbsoluteName(name, zone)
	return strings.TrimSuffix(abs, ".")
}

func (p *Provider) listZoneRecords(ctx context.Context, zoneID, nameFilter, typeFilter string) ([]cfDNSRecord, error) {
	var all []cfDNSRecord
	page := 1
	for {
		params := url.Values{}
		params.Set("per_page", "100")
		params.Set("page", strconv.Itoa(page))
		if nameFilter != "" {
			params.Set("name", nameFilter)
		}
		if typeFilter != "" {
			params.Set("type", strings.ToUpper(typeFilter))
		}
		env, err := p.doAPI(ctx, http.MethodGet, fmt.Sprintf("/zones/%s/dns_records?%s", url.PathEscape(zoneID), params.Encode()), nil)
		if err != nil {
			return nil, err
		}
		var recs []cfDNSRecord
		if err := json.Unmarshal(env.Result, &recs); err != nil {
			return nil, err
		}
		all = append(all, recs...)
		if env.ResultInfo == nil || env.ResultInfo.TotalPages <= page {
			break
		}
		page++
	}
	return all, nil
}

// GetRecords implements libdns.RecordGetter.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	cfRecs, err := p.listZoneRecords(ctx, zoneID, "", "")
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, 0, len(cfRecs))
	for _, r := range cfRecs {
		out = append(out, cfRecordToLibdns(r, zone))
	}
	return out, nil
}

// AppendRecords implements libdns.RecordAppender.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	created := make([]libdns.Record, 0, len(recs))
	for _, rec := range recs {
		rr := rec.RR()
		payload := cfDNSRecord{
			Type:    strings.ToUpper(rr.Type),
			Name:    fqdnName(rr.Name, zone),
			Content: rr.Data,
			TTL:     ttlForCloudflare(rr.TTL, rr.Type),
		}
		env, err := p.doAPI(ctx, http.MethodPost, fmt.Sprintf("/zones/%s/dns_records", url.PathEscape(zoneID)), payload)
		if err != nil {
			return created, err
		}
		var res cfDNSRecord
		if err := json.Unmarshal(env.Result, &res); err != nil {
			return created, err
		}
		created = append(created, cfRecordToLibdns(res, zone))
	}
	return created, nil
}

// SetRecords implements libdns.RecordSetter.
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	updated := make([]libdns.Record, 0, len(recs))
	for _, rec := range recs {
		rr := rec.RR()
		fqdn := fqdnName(rr.Name, zone)
		recType := strings.ToUpper(rr.Type)

		existing, err := p.listZoneRecords(ctx, zoneID, fqdn, recType)
		if err != nil {
			return updated, err
		}
		payload := cfDNSRecord{
			Type:    recType,
			Name:    fqdn,
			Content: rr.Data,
			TTL:     ttlForCloudflare(rr.TTL, recType),
		}

		if len(existing) == 0 {
			env, err := p.doAPI(ctx, http.MethodPost, fmt.Sprintf("/zones/%s/dns_records", url.PathEscape(zoneID)), payload)
			if err != nil {
				return updated, err
			}
			var res cfDNSRecord
			if err := json.Unmarshal(env.Result, &res); err != nil {
				return updated, err
			}
			updated = append(updated, cfRecordToLibdns(res, zone))
			continue
		}

		// Update first matching record, delete any duplicates for exact RRset replacement semantics.
		env, err := p.doAPI(ctx, http.MethodPut, fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(zoneID), url.PathEscape(existing[0].ID)), payload)
		if err != nil {
			return updated, err
		}
		var res cfDNSRecord
		if err := json.Unmarshal(env.Result, &res); err != nil {
			return updated, err
		}
		updated = append(updated, cfRecordToLibdns(res, zone))

		for _, dup := range existing[1:] {
			if _, derr := p.doAPI(ctx, http.MethodDelete, fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(zoneID), url.PathEscape(dup.ID)), nil); derr != nil {
				return updated, derr
			}
		}
	}
	return updated, nil
}

// DeleteRecords implements libdns.RecordDeleter.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	deleted := make([]libdns.Record, 0, len(recs))
	for _, rec := range recs {
		rr := rec.RR()
		fqdn := fqdnName(rr.Name, zone)
		recType := strings.ToUpper(rr.Type)

		existing, err := p.listZoneRecords(ctx, zoneID, fqdn, recType)
		if err != nil {
			return deleted, err
		}
		for _, item := range existing {
			if rr.Data != "" && item.Content != rr.Data {
				continue
			}
			if _, derr := p.doAPI(ctx, http.MethodDelete, fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(zoneID), url.PathEscape(item.ID)), nil); derr != nil {
				return deleted, derr
			}
			deleted = append(deleted, cfRecordToLibdns(item, zone))
		}
	}
	return deleted, nil
}

var (
	_ caddy.Module          = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
	_ caddy.Validator       = (*Provider)(nil)
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
