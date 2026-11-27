package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultCFAPIBase = "https://api.cloudflare.com/client/v4"

var defaultCloudflareIPv4 = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

var defaultCloudflareIPv6 = []string{
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

type CFZone struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Status     string   `json:"status"`
	NameServer []string `json:"name_servers,omitempty"`
}

type CFDNSRecord struct {
	ID      string `json:"id,omitempty"`
	ZoneID  string `json:"zone_id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment,omitempty"`
}

type CloudflareClient struct {
	APIToken   string
	BaseURL    string
	HTTPClient *http.Client
}

func newCloudflareClient(token string) *CloudflareClient {
	return &CloudflareClient{
		APIToken: strings.TrimSpace(token),
		BaseURL:  defaultCFAPIBase,
		HTTPClient: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

type cfAPIEnvelope struct {
	Success    bool            `json:"success"`
	Errors     []cfAPIErrorMsg `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info,omitempty"`
}

type cfAPIErrorMsg struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *CloudflareClient) baseURL() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return defaultCFAPIBase
}

func (c *CloudflareClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (c *CloudflareClient) do(ctx context.Context, method, path string, body any, auth bool) (*cfAPIEnvelope, error) {
	if auth && strings.TrimSpace(c.APIToken) == "" {
		return nil, errors.New("Cloudflare API Token chưa được cấu hình")
	}

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, reader)
	if err != nil {
		return nil, err
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.APIToken))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vSafeGate/"+AppVersion)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}

	var env cfAPIEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("cloudflare HTTP %d invalid JSON: %w", resp.StatusCode, err)
	}
	if !env.Success || resp.StatusCode >= 400 {
		if len(env.Errors) > 0 {
			return nil, fmt.Errorf("cloudflare [%d] %s", env.Errors[0].Code, env.Errors[0].Message)
		}
		return nil, fmt.Errorf("cloudflare HTTP %d", resp.StatusCode)
	}
	return &env, nil
}

func (c *CloudflareClient) VerifyToken(ctx context.Context) (string, error) {
	env, err := c.do(ctx, http.MethodGet, "/user/tokens/verify", nil, true)
	if err != nil {
		return "", err
	}
	var res struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(env.Result, &res); err != nil {
		return "", err
	}
	if res.Status != "active" && res.Status != "" {
		return res.Status, fmt.Errorf("token status is %s", res.Status)
	}
	return res.Status, nil
}

func (c *CloudflareClient) ListZones(ctx context.Context) ([]CFZone, error) {
	var all []CFZone
	page := 1
	for {
		path := fmt.Sprintf("/zones?per_page=50&page=%d", page)
		env, err := c.do(ctx, http.MethodGet, path, nil, true)
		if err != nil {
			return nil, err
		}
		var chunk []CFZone
		if err := json.Unmarshal(env.Result, &chunk); err != nil {
			return nil, err
		}
		all = append(all, chunk...)
		if env.ResultInfo == nil || env.ResultInfo.TotalPages <= page {
			break
		}
		page++
	}
	return all, nil
}

func (c *CloudflareClient) ListDNSRecords(ctx context.Context, zoneID string) ([]CFDNSRecord, error) {
	if strings.TrimSpace(zoneID) == "" {
		return nil, errors.New("zone_id required")
	}
	var all []CFDNSRecord
	page := 1
	for {
		path := fmt.Sprintf("/zones/%s/dns_records?per_page=100&page=%d", url.PathEscape(zoneID), page)
		env, err := c.do(ctx, http.MethodGet, path, nil, true)
		if err != nil {
			return nil, err
		}
		var chunk []CFDNSRecord
		if err := json.Unmarshal(env.Result, &chunk); err != nil {
			return nil, err
		}
		all = append(all, chunk...)
		if env.ResultInfo == nil || env.ResultInfo.TotalPages <= page {
			break
		}
		page++
	}
	return all, nil
}

func (c *CloudflareClient) CreateDNSRecord(ctx context.Context, zoneID string, rec CFDNSRecord) (*CFDNSRecord, error) {
	if strings.TrimSpace(zoneID) == "" {
		return nil, errors.New("zone_id required")
	}
	rec.Type = strings.ToUpper(strings.TrimSpace(rec.Type))
	if rec.TTL <= 0 {
		rec.TTL = 1
	}
	if err := validateCFRecord(rec); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/zones/%s/dns_records", url.PathEscape(zoneID))
	env, err := c.do(ctx, http.MethodPost, path, rec, true)
	if err != nil {
		return nil, err
	}
	var out CFDNSRecord
	if err := json.Unmarshal(env.Result, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *CloudflareClient) UpdateDNSRecord(ctx context.Context, zoneID, recordID string, rec CFDNSRecord) (*CFDNSRecord, error) {
	if strings.TrimSpace(zoneID) == "" || strings.TrimSpace(recordID) == "" {
		return nil, errors.New("zone_id and record_id required")
	}
	rec.Type = strings.ToUpper(strings.TrimSpace(rec.Type))
	if rec.TTL <= 0 {
		rec.TTL = 1
	}
	if err := validateCFRecord(rec); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(zoneID), url.PathEscape(recordID))
	env, err := c.do(ctx, http.MethodPut, path, rec, true)
	if err != nil {
		return nil, err
	}
	var out CFDNSRecord
	if err := json.Unmarshal(env.Result, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *CloudflareClient) PatchDNSRecordProxied(ctx context.Context, zoneID, recordID string, proxied bool) (*CFDNSRecord, error) {
	if strings.TrimSpace(zoneID) == "" || strings.TrimSpace(recordID) == "" {
		return nil, errors.New("zone_id and record_id required")
	}
	path := fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(zoneID), url.PathEscape(recordID))
	env, err := c.do(ctx, http.MethodPatch, path, map[string]any{"proxied": proxied}, true)
	if err != nil {
		return nil, err
	}
	var out CFDNSRecord
	if err := json.Unmarshal(env.Result, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *CloudflareClient) DeleteDNSRecord(ctx context.Context, zoneID, recordID string) error {
	if strings.TrimSpace(zoneID) == "" || strings.TrimSpace(recordID) == "" {
		return errors.New("zone_id and record_id required")
	}
	path := fmt.Sprintf("/zones/%s/dns_records/%s", url.PathEscape(zoneID), url.PathEscape(recordID))
	_, err := c.do(ctx, http.MethodDelete, path, nil, true)
	return err
}

func (c *CloudflareClient) SetZoneSecurityLevel(ctx context.Context, zoneID, level string) error {
	if strings.TrimSpace(zoneID) == "" {
		return errors.New("zone_id required")
	}
	path := fmt.Sprintf("/zones/%s/settings/security_level", url.PathEscape(zoneID))
	_, err := c.do(ctx, http.MethodPatch, path, map[string]string{"value": level}, true)
	return err
}

func (c *CloudflareClient) FetchCloudflareIPs(ctx context.Context) (ipv4, ipv6 []string, err error) {
	env, err := c.do(ctx, http.MethodGet, "/ips", nil, false)
	if err != nil {
		return nil, nil, err
	}
	var res struct {
		IPv4CIDRs []string `json:"ipv4_cidrs"`
		IPv6CIDRs []string `json:"ipv6_cidrs"`
	}
	if err := json.Unmarshal(env.Result, &res); err != nil {
		return nil, nil, err
	}
	for _, s := range res.IPv4CIDRs {
		if pfx, perr := netip.ParsePrefix(strings.TrimSpace(s)); perr == nil {
			ipv4 = append(ipv4, pfx.Masked().String())
		}
	}
	for _, s := range res.IPv6CIDRs {
		if pfx, perr := netip.ParsePrefix(strings.TrimSpace(s)); perr == nil {
			ipv6 = append(ipv6, pfx.Masked().String())
		}
	}
	if len(ipv4) == 0 {
		return nil, nil, errors.New("cloudflare returned empty ipv4_cidrs")
	}
	return ipv4, ipv6, nil
}

func validateCFRecord(rec CFDNSRecord) error {
	rec.Type = strings.ToUpper(strings.TrimSpace(rec.Type))
	switch rec.Type {
	case "A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS":
	default:
		return fmt.Errorf("loại bản ghi DNS không được hỗ trợ: %q", rec.Type)
	}
	if strings.TrimSpace(rec.Name) == "" || strings.TrimSpace(rec.Content) == "" {
		return errors.New("tên bản ghi và giá trị content là bắt buộc")
	}
	if rec.Proxied && rec.Type != "A" && rec.Type != "AAAA" && rec.Type != "CNAME" {
		return errors.New("chỉ bản ghi A, AAAA hoặc CNAME mới hỗ trợ bật Cloudflare Proxy (mây cam)")
	}
	return nil
}

func maskAPIToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	if len(token) <= 8 {
		return "********"
	}
	return token[:4] + "..." + token[len(token)-4:]
}

func cfIPCachePath() string {
	if os.Getenv("ENV") == "dev" {
		return "./cf_ips.json"
	}
	return "/var/lib/vsafegate/cf_ips.json"
}

func (s *AppState) syncCloudflareIPsWithBase(ctx context.Context, baseURL string) error {
	client := newCloudflareClient("")
	if baseURL != "" {
		client.BaseURL = baseURL
	}
	v4, v6, err := client.FetchCloudflareIPs(ctx)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.config.Cloudflare.CachedIPv4 = v4
	s.config.Cloudflare.CachedIPv6 = v6
	s.config.Cloudflare.LastIPSyncAt = time.Now().UTC()
	s.config.Cloudflare.IPSyncSource = "cloudflare_api"
	s.mu.Unlock()
	s.saveConfig()

	cacheData, _ := json.MarshalIndent(map[string]any{
		"ipv4_cidrs": v4,
		"ipv6_cidrs": v6,
		"synced_at":  time.Now().UTC(),
	}, "", "  ")
	cachePath := cfIPCachePath()
	_ = os.MkdirAll(filepath.Dir(cachePath), 0750)
	_ = os.WriteFile(cachePath, cacheData, 0600)

	if s.reloadManager != nil {
		s.reloadManager.Trigger()
	}
	return nil
}

func effectiveCloudflareCIDRs(cfg CloudflareConfig) (v4, v6 []string) {
	if len(cfg.CachedIPv4) > 0 {
		v4 = cfg.CachedIPv4
	} else {
		v4 = defaultCloudflareIPv4
	}
	if len(cfg.CachedIPv6) > 0 {
		v6 = cfg.CachedIPv6
	} else {
		v6 = defaultCloudflareIPv6
	}
	return v4, v6
}

// ---------- Custom TLS Certificate Upload & Validation ----------

var reSafeCertID = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func (s *AppState) certsBaseDir() string {
	if s.certsDir != "" {
		return s.certsDir
	}
	if os.Getenv("ENV") == "dev" {
		return "./certs"
	}
	return "/etc/vsafegate/certs"
}

type UploadedCertMeta struct {
	CertPath string   `json:"cert_path"`
	KeyPath  string   `json:"key_path"`
	Subject  string   `json:"subject"`
	Issuer   string   `json:"issuer"`
	DNSNames []string `json:"dns_names"`
	NotAfter string   `json:"not_after"`
}

func saveValidatedCertFiles(baseDir, fileID, certPEM, keyPEM string) (*UploadedCertMeta, error) {
	fileID = strings.TrimSpace(fileID)
	if fileID == "" || !reSafeCertID.MatchString(fileID) || strings.Contains(fileID, "..") {
		return nil, errors.New("cert ID không hợp lệ")
	}
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	if certPEM == "" || keyPEM == "" {
		return nil, errors.New("cần đầy đủ nội dung Certificate PEM và Private Key PEM")
	}

	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("chứng chỉ và khóa riêng không khớp hoặc không hợp lệ: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("không tìm thấy chứng chỉ X.509 trong PEM")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("lỗi phân tích X.509: %w", err)
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, fmt.Errorf("chứng chỉ đã hết hạn vào %s", leaf.NotAfter.Format(time.RFC3339))
	}

	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("không thể tạo thư mục lưu cert: %w", err)
	}
	certPath := filepath.Join(baseDir, fileID+".crt")
	keyPath := filepath.Join(baseDir, fileID+".key")

	if err := os.WriteFile(certPath, []byte(certPEM+"\n"), 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM+"\n"), 0600); err != nil {
		_ = os.Remove(certPath)
		return nil, err
	}

	issuer := leaf.Issuer.CommonName
	if issuer == "" && len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	}

	return &UploadedCertMeta{
		CertPath: certPath,
		KeyPath:  keyPath,
		Subject:  leaf.Subject.CommonName,
		Issuer:   issuer,
		DNSNames: leaf.DNSNames,
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
	}, nil
}

func (s *AppState) saveUploadedSiteCert(siteID, certPEM, keyPEM string) (*UploadedCertMeta, error) {
	meta, err := saveValidatedCertFiles(s.certsBaseDir(), siteID, certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	found := false
	s.mu.Lock()
	for i := range s.config.Sites {
		if s.config.Sites[i].ID == siteID {
			s.config.Sites[i].SSL = true
			s.config.Sites[i].CertMode = "uploaded"
			s.config.Sites[i].CustomCertPath = meta.CertPath
			s.config.Sites[i].CustomKeyPath = meta.KeyPath
			s.config.Sites[i].CustomCertExpiry = meta.NotAfter
			s.config.Sites[i].CustomCertIssuer = meta.Issuer
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		_ = os.Remove(meta.CertPath)
		_ = os.Remove(meta.KeyPath)
		return nil, errors.New("không tìm thấy site với site_id đã chọn")
	}

	s.saveConfig()
	if s.reloadManager != nil {
		s.reloadManager.Trigger()
	}
	return meta, nil
}

func (s *AppState) saveUploadedOriginCA(siteID, caPEM string) (string, error) {
	siteID = strings.TrimSpace(siteID)
	if siteID == "" || !reSafeCertID.MatchString(siteID) || strings.Contains(siteID, "..") {
		return "", errors.New("site_id không hợp lệ")
	}
	caPEM = strings.TrimSpace(caPEM)
	if caPEM == "" {
		return "", errors.New("nội dung Origin CA PEM không được để trống")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return "", errors.New("Origin CA PEM không chứa chứng chỉ X.509 hợp lệ")
	}

	baseDir := s.certsBaseDir()
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return "", fmt.Errorf("không thể tạo thư mục lưu cert: %w", err)
	}
	caPath := filepath.Join(baseDir, siteID+"-origin-ca.crt")
	if err := os.WriteFile(caPath, []byte(caPEM+"\n"), 0600); err != nil {
		return "", err
	}
	return caPath, nil
}

// ---------- Auto-Orange-Cloud Failover Controller ----------

type siteFailoverTracker struct {
	overloadSince  time.Time
	calmSince      time.Time
	lastActionTime time.Time
}

type shieldRateSample struct {
	rps       float64
	dropPS    float64
	updatedAt time.Time
}

type AutoProxyController struct {
	state       *AppState
	mu          sync.Mutex
	trackers    map[string]*siteFailoverTracker
	siteSamples map[string]*shieldRateSample
	hostSamples map[string]*shieldRateSample
	baseURL     string // optional override for testing
	nowFn       func() time.Time
	httpClient  *http.Client

	wafEventCount atomic.Int64
	lastTickTime  time.Time
	lastWAFCount  int64
}

func newAutoProxyController(s *AppState) *AutoProxyController {
	return &AutoProxyController{
		state:       s,
		trackers:    make(map[string]*siteFailoverTracker),
		siteSamples: make(map[string]*shieldRateSample),
		hostSamples: make(map[string]*shieldRateSample),
		nowFn:       time.Now,
	}
}

func (c *AutoProxyController) recordWAFEvent() {
	c.wafEventCount.Add(1)
}

func (c *AutoProxyController) RecordShieldStats(siteID, host string, rps, dropPS float64) {
	if c == nil {
		return
	}
	now := c.now()
	sample := &shieldRateSample{
		rps:       rps,
		dropPS:    dropPS,
		updatedAt: now,
	}
	normHost := strings.ToLower(strings.TrimSpace(host))
	if idx := strings.IndexByte(normHost, ':'); idx > 0 {
		normHost = normHost[:idx]
	}

	c.mu.Lock()
	if c.siteSamples == nil {
		c.siteSamples = make(map[string]*shieldRateSample)
	}
	if c.hostSamples == nil {
		c.hostSamples = make(map[string]*shieldRateSample)
	}
	if strings.TrimSpace(siteID) != "" {
		c.siteSamples[strings.TrimSpace(siteID)] = sample
	}
	if normHost != "" {
		c.hostSamples[normHost] = sample
	}
	c.mu.Unlock()
}

func (c *AutoProxyController) metricsForSite(site Site, now time.Time, fallbackDropPS float64) (rps, dropPS float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	const staleAfter = 15 * time.Second
	if site.ID != "" {
		if s, ok := c.siteSamples[site.ID]; ok && now.Sub(s.updatedAt) <= staleAfter {
			rps = s.rps
			dropPS = s.dropPS
		}
	}
	if rps == 0 && dropPS == 0 && site.Domain != "" {
		dom := strings.ToLower(strings.TrimSpace(site.Domain))
		if idx := strings.IndexByte(dom, ':'); idx > 0 {
			dom = dom[:idx]
		}
		if s, ok := c.hostSamples[dom]; ok && now.Sub(s.updatedAt) <= staleAfter {
			rps = s.rps
			dropPS = s.dropPS
		} else if strings.HasPrefix(dom, "*.") {
			suffix := dom[1:]
			for h, hs := range c.hostSamples {
				if strings.HasSuffix(h, suffix) && now.Sub(hs.updatedAt) <= staleAfter {
					rps += hs.rps
					dropPS += hs.dropPS
				}
			}
		}
	}
	if fallbackDropPS > 0 {
		dropPS += fallbackDropPS
	}
	return rps, dropPS
}

func (c *AutoProxyController) now() time.Time {
	if c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now()
}

func (c *AutoProxyController) Start() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		c.lastTickTime = c.now()
		c.lastWAFCount = c.wafEventCount.Load()

		for range ticker.C {
			now := c.now()
			elapsed := now.Sub(c.lastTickTime).Seconds()
			if elapsed <= 0 {
				elapsed = 5
			}
			curWAF := c.wafEventCount.Load()
			deltaWAF := curWAF - c.lastWAFCount
			c.lastWAFCount = curWAF
			c.lastTickTime = now

			dropPS := float64(deltaWAF) / elapsed
			c.EvaluateFromTelemetry(context.Background(), dropPS)
		}
	}()
}

// EvaluateFromTelemetry evaluates each AutoProxyEnabled site using real per-site/host
// RPS and DropPS reported by vsafegate_shield plus WAF/shield drop delta.
func (c *AutoProxyController) EvaluateFromTelemetry(ctx context.Context, fallbackDropPS float64) {
	c.evaluateSites(ctx, func(site Site, now time.Time) (float64, float64) {
		return c.metricsForSite(site, now, fallbackDropPS)
	})
}

// Evaluate checks all AutoProxyEnabled sites against instantaneous RPS and DropPS metrics
// using hysteresis window and hold-time safeguards, toggling Cloudflare proxied=true/false
// ONLY on HTTP/HTTPS records (A, AAAA, CNAME).
func (c *AutoProxyController) Evaluate(ctx context.Context, rps, dropPS float64) {
	c.evaluateSites(ctx, func(_ Site, _ time.Time) (float64, float64) {
		return rps, dropPS
	})
}

func (c *AutoProxyController) evaluateSites(ctx context.Context, metricsFn func(site Site, now time.Time) (float64, float64)) {
	if c.state == nil {
		return
	}

	c.state.mu.RLock()
	token := strings.TrimSpace(c.state.config.Cloudflare.APIToken)
	sitesCopy := make([]Site, len(c.state.config.Sites))
	copy(sitesCopy, c.state.config.Sites)
	c.state.mu.RUnlock()

	if token == "" {
		return
	}

	client := newCloudflareClient(token)
	if c.baseURL != "" {
		client.BaseURL = c.baseURL
	}
	if c.httpClient != nil {
		client.HTTPClient = c.httpClient
	}

	now := c.now()
	configDirty := false

	for _, site := range sitesCopy {
		if !site.AutoProxyEnabled || site.AutoProxyZoneID == "" || len(site.AutoProxyRecordIDs) == 0 {
			continue
		}
		rps, dropPS := metricsFn(site, now)
		windowSec := site.AutoProxyWindowSec
		if windowSec < 5 {
			windowSec = 15
		}
		holdMinutes := site.AutoProxyHoldMinutes
		if holdMinutes <= 0 {
			holdMinutes = 30
		}

		rpsOver := site.AutoProxyThresholdRPS > 0 && rps >= float64(site.AutoProxyThresholdRPS)
		dropOver := site.AutoProxyThresholdDropPS > 0 && dropPS >= float64(site.AutoProxyThresholdDropPS)
		overloaded := rpsOver || dropOver

		rpsCalm := site.AutoProxyThresholdRPS <= 0 || rps < float64(site.AutoProxyThresholdRPS)*0.5
		dropCalm := site.AutoProxyThresholdDropPS <= 0 || dropPS < float64(site.AutoProxyThresholdDropPS)*0.5
		calm := rpsCalm && dropCalm

		c.mu.Lock()
		tr, ok := c.trackers[site.ID]
		if !ok {
			tr = &siteFailoverTracker{}
			c.trackers[site.ID] = tr
		}

		action := ""
		if !site.AutoProxyActive {
			if overloaded {
				if tr.overloadSince.IsZero() {
					tr.overloadSince = now
				}
				if now.Sub(tr.overloadSince) >= time.Duration(windowSec)*time.Second {
					action = "activate"
					tr.overloadSince = time.Time{}
					tr.calmSince = time.Time{}
				}
			} else {
				tr.overloadSince = time.Time{}
			}
		} else if site.AutoProxyAutoRevert {
			activatedAt := site.AutoProxyActivatedAt
			if activatedAt.IsZero() {
				activatedAt = tr.lastActionTime
			}
			holdElapsed := !activatedAt.IsZero() && now.Sub(activatedAt) >= time.Duration(holdMinutes)*time.Minute
			if calm && holdElapsed {
				if tr.calmSince.IsZero() {
					tr.calmSince = now
				}
				if now.Sub(tr.calmSince) >= time.Duration(windowSec)*time.Second {
					action = "revert"
					tr.calmSince = time.Time{}
				}
			} else {
				tr.calmSince = time.Time{}
			}
		}
		c.mu.Unlock()

		if action == "" {
			continue
		}

		proxiedTarget := action == "activate"
		records, err := client.ListDNSRecords(ctx, site.AutoProxyZoneID)
		if err != nil {
			log.Printf("[AutoProxy] Failed to list DNS records for site %s: %v", site.Domain, err)
			continue
		}
		recByID := make(map[string]CFDNSRecord, len(records))
		for _, r := range records {
			recByID[r.ID] = r
		}

		updatedAny := false
		updatedCount := 0
		for _, recID := range site.AutoProxyRecordIDs {
			rec, exists := recByID[recID]
			if !exists {
				continue
			}
			rt := strings.ToUpper(rec.Type)
			if rt != "A" && rt != "AAAA" && rt != "CNAME" {
				// Safety guard: never toggle MX/TXT/SRV records
				continue
			}
			if _, perr := client.PatchDNSRecordProxied(ctx, site.AutoProxyZoneID, recID, proxiedTarget); perr != nil {
				log.Printf("[AutoProxy] Patch record %s (%s) proxied=%v failed: %v", rec.Name, recID, proxiedTarget, perr)
				continue
			}
			updatedAny = true
			updatedCount++
		}

		if updatedAny && site.AutoProxyUnderAttack {
			secLevel := "medium"
			if proxiedTarget {
				secLevel = "under_attack"
			}
			if serr := client.SetZoneSecurityLevel(ctx, site.AutoProxyZoneID, secLevel); serr != nil {
				log.Printf("[AutoProxy] Set security_level=%s for zone %s failed: %v", secLevel, site.AutoProxyZoneID, serr)
			}
		}

		if updatedAny {
			c.mu.Lock()
			if t := c.trackers[site.ID]; t != nil {
				t.lastActionTime = now
			}
			c.mu.Unlock()

			c.state.mu.Lock()
			for i := range c.state.config.Sites {
				if c.state.config.Sites[i].ID == site.ID {
					c.state.config.Sites[i].AutoProxyActive = proxiedTarget
					if proxiedTarget {
						c.state.config.Sites[i].AutoProxyActivatedAt = now.UTC()
					} else {
						c.state.config.Sites[i].AutoProxyActivatedAt = time.Time{}
					}
					configDirty = true
					break
				}
			}
			c.state.mu.Unlock()
			log.Printf("[AutoProxy] Site %s (%s): switched Cloudflare proxied=%v", site.Domain, action, proxiedTarget)
			if c.state.alertEngine != nil {
				c.state.alertEngine.NotifyAutoProxy(site.Domain, action, site.AutoProxyZoneID, updatedCount, site.AutoProxyUnderAttack)
			}
		}
	}

	if configDirty {
		c.state.saveConfig()
	}
}
