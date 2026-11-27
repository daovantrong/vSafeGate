package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var threatCategoryOrder = []string{
	"SQLi",
	"XSS",
	"LFI/RCE",
	"Scanner/Bot",
	"Rate-Limit",
	"Challenge Fail",
	"SSH",
	"Canary",
}

type TelemetryBucket struct {
	Timestamp      int64              `json:"ts"`
	Requests       uint64             `json:"requests"`
	CleanRequests  uint64             `json:"clean_requests"`
	Status2xx      uint64             `json:"status_2xx"`
	Status3xx      uint64             `json:"status_3xx"`
	Status4xx      uint64             `json:"status_4xx"`
	Status5xx      uint64             `json:"status_5xx"`
	BlockedWAF     uint64             `json:"blocked_waf"`
	KernelDropPkts uint64             `json:"kernel_drop_pkts"`
	KernelDropByts uint64             `json:"kernel_drop_bytes"`
	P50Ms          float64            `json:"p50_ms"`
	P95Ms          float64            `json:"p95_ms"`
	P99Ms          float64            `json:"p99_ms"`
	LatencyBuckets map[string]float64 `json:"latency_buckets,omitempty"`
}

type HostTelemetry struct {
	Host            string             `json:"host"`
	RPS             float64            `json:"rps"`
	ShieldRPS       float64            `json:"shield_rps"`
	ShieldDropPS    float64            `json:"shield_drop_ps"`
	InFlight        int64              `json:"in_flight"`
	Requests        uint64             `json:"requests"`
	Status2xx       uint64             `json:"status_2xx"`
	Status3xx       uint64             `json:"status_3xx"`
	Status4xx       uint64             `json:"status_4xx"`
	Status5xx       uint64             `json:"status_5xx"`
	Errors          uint64             `json:"errors"`
	P50Ms           float64            `json:"p50_ms"`
	P95Ms           float64            `json:"p95_ms"`
	P99Ms           float64            `json:"p99_ms"`
	LastUpdatedAt   time.Time          `json:"last_updated_at"`
	LatencyBuckets  map[string]float64 `json:"-"`
	ShieldUpdatedAt time.Time          `json:"-"`
}

type TopStatItem struct {
	Key       string    `json:"key"`
	Label     string    `json:"label,omitempty"`
	SubLabel  string    `json:"sub_label,omitempty"`
	RuleID    int       `json:"rule_id,omitempty"`
	Count     uint64    `json:"count"`
	LastSeen  time.Time `json:"last_seen"`
	IsBanned  bool      `json:"is_banned,omitempty"`
	ExemptURI string    `json:"exempt_uri,omitempty"`
}

type CertExpiryStatus struct {
	Domain        string    `json:"domain"`
	Source        string    `json:"source"` // "uploaded" or "acme"
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining float64   `json:"days_remaining"`
	ExpiringSoon  bool      `json:"expiring_soon"`
	Expired       bool      `json:"expired"`
	FilePath      string    `json:"file_path,omitempty"`
}

type UpstreamHealthStatus struct {
	Source      string `json:"source"` // "l7" or "l4"
	Target      string `json:"target"` // site domain or service name
	Address     string `json:"address"`
	NumRequests int    `json:"num_requests"`
	Fails       int    `json:"fails"`
	Healthy     bool   `json:"healthy"`
}

type TelemetryQueryResult struct {
	Range            string                    `json:"range"`
	GeneratedAt      time.Time                 `json:"generated_at"`
	Buckets          []TelemetryBucket         `json:"buckets"`
	PerHost          map[string]*HostTelemetry `json:"per_host"`
	Categories       map[string]uint64         `json:"categories"`
	CurrentRPS       float64                   `json:"current_rps"`
	CurrentDropPS    float64                   `json:"current_drop_ps"`
	InFlight         int64                     `json:"in_flight"`
	P50Ms            float64                   `json:"p50_ms"`
	P95Ms            float64                   `json:"p95_ms"`
	P99Ms            float64                   `json:"p99_ms"`
	Status2xx        uint64                    `json:"status_2xx"`
	Status3xx        uint64                    `json:"status_3xx"`
	Status4xx        uint64                    `json:"status_4xx"`
	Status5xx        uint64                    `json:"status_5xx"`
	TotalKernelPkts  uint64                    `json:"kernel_drop_pkts_total"`
	TotalKernelBytes uint64                    `json:"kernel_drop_bytes_total"`
	TopAttackers     []TopStatItem             `json:"top_attackers"`
	TopCountries     []TopStatItem             `json:"top_countries"`
	TopDomains       []TopStatItem             `json:"top_domains"`
	TopRules         []TopStatItem             `json:"top_rules"`
}

type TelemetrySummary struct {
	GeneratedAt      time.Time                 `json:"generated_at"`
	CurrentRPS       float64                   `json:"current_rps"`
	CurrentDropPS    float64                   `json:"current_drop_ps"`
	InFlight         int64                     `json:"in_flight"`
	P50Ms            float64                   `json:"p50_ms"`
	P95Ms            float64                   `json:"p95_ms"`
	P99Ms            float64                   `json:"p99_ms"`
	Status2xx        uint64                    `json:"status_2xx"`
	Status3xx        uint64                    `json:"status_3xx"`
	Status4xx        uint64                    `json:"status_4xx"`
	Status5xx        uint64                    `json:"status_5xx"`
	TotalKernelPkts  uint64                    `json:"kernel_drop_pkts_total"`
	TotalKernelBytes uint64                    `json:"kernel_drop_bytes_total"`
	Categories       map[string]uint64         `json:"categories"`
	PerHost          map[string]*HostTelemetry `json:"per_host"`
	TopAttackers     []TopStatItem             `json:"top_attackers"`
	TopCountries     []TopStatItem             `json:"top_countries"`
	TopDomains       []TopStatItem             `json:"top_domains"`
	TopRules         []TopStatItem             `json:"top_rules"`
	ExpiringCerts    []CertExpiryStatus        `json:"expiring_certs,omitempty"`
	UnhealthyTargets []UpstreamHealthStatus    `json:"unhealthy_upstreams,omitempty"`
}

type persistedTelemetryState struct {
	Version          int                       `json:"version"`
	SavedAt          time.Time                 `json:"saved_at"`
	MinuteBuckets    []TelemetryBucket         `json:"minute_buckets"`
	HourBuckets      []TelemetryBucket         `json:"hour_buckets"`
	Categories       map[string]uint64         `json:"categories"`
	Status2xx        uint64                    `json:"status_2xx"`
	Status3xx        uint64                    `json:"status_3xx"`
	Status4xx        uint64                    `json:"status_4xx"`
	Status5xx        uint64                    `json:"status_5xx"`
	TotalKernelPkts  uint64                    `json:"total_kernel_pkts"`
	TotalKernelBytes uint64                    `json:"total_kernel_bytes"`
	TopAttackers     map[string]*TopStatItem   `json:"top_attackers"`
	TopCountries     map[string]*TopStatItem   `json:"top_countries"`
	TopDomains       map[string]*TopStatItem   `json:"top_domains"`
	TopRules         map[string]*TopStatItem   `json:"top_rules"`
	PerHost          map[string]*HostTelemetry `json:"per_host"`
}

type prometheusScrapeSnapshot struct {
	RequestsByHost    map[string]uint64
	InFlightByHost    map[string]int64
	ErrorsByHost      map[string]uint64
	StatusByHost      map[string][4]uint64 // [2xx, 3xx, 4xx, 5xx]
	BucketsByHost     map[string]map[string]float64
	TotalRequests     uint64
	TotalInFlight     int64
	TotalErrors       uint64
	TotalStatus       [4]uint64
	TotalBuckets      map[string]float64
}

type kernelCounterPair struct {
	Pkts  uint64
	Bytes uint64
}

type geoIPCidrEntry struct {
	pfx     netip.Prefix
	country string
}

type geoIPZoneLookup struct {
	mu         sync.RWMutex
	dir        string
	loadedAt   time.Time
	bucketsV4  [256][]geoIPCidrEntry
	wideV4     []geoIPCidrEntry
	ipCache    map[string]string
}

func newGeoIPZoneLookup(dir string) *geoIPZoneLookup {
	return &geoIPZoneLookup{
		dir:     dir,
		ipCache: make(map[string]string),
	}
}

func (g *geoIPZoneLookup) Invalidate() {
	g.mu.Lock()
	g.loadedAt = time.Time{}
	g.ipCache = make(map[string]string)
	g.mu.Unlock()
}

func (g *geoIPZoneLookup) Lookup(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" || ipStr == "*" {
		return ""
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return "Unknown"
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return "LAN"
	}

	norm := addr.String()
	g.mu.RLock()
	if c, ok := g.ipCache[norm]; ok {
		g.mu.RUnlock()
		return c
	}
	needsReload := g.loadedAt.IsZero() || time.Since(g.loadedAt) > 5*time.Minute
	g.mu.RUnlock()

	if needsReload {
		g.reload()
	}

	country := "Unknown"
	if addr.Is4() {
		b := addr.As4()
		g.mu.RLock()
		for _, e := range g.bucketsV4[b[0]] {
			if e.pfx.Contains(addr) {
				country = e.country
				break
			}
		}
		if country == "Unknown" {
			for _, e := range g.wideV4 {
				if e.pfx.Contains(addr) {
					country = e.country
					break
				}
			}
		}
		g.mu.RUnlock()
	}

	g.mu.Lock()
	if len(g.ipCache) > 4096 {
		g.ipCache = make(map[string]string)
	}
	g.ipCache[norm] = country
	g.mu.Unlock()
	return country
}

func (g *geoIPZoneLookup) reload() {
	dir := g.dir
	if dir == "" {
		dir = "/etc/vsafegate/geoip"
	}
	entries, err := os.ReadDir(dir)
	var buckets [256][]geoIPCidrEntry
	var wide []geoIPCidrEntry

	if err == nil {
		for _, de := range entries {
			if de.IsDir() || !strings.HasSuffix(de.Name(), ".zone") {
				continue
			}
			code := strings.ToUpper(strings.TrimSuffix(de.Name(), ".zone"))
			if len(code) != 2 {
				continue
			}
			data, rerr := os.ReadFile(filepath.Join(dir, de.Name()))
			if rerr != nil {
				continue
			}
			sc := bufio.NewScanner(strings.NewReader(string(data)))
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				pfx, perr := netip.ParsePrefix(line)
				if perr != nil || !pfx.Addr().Is4() {
					continue
				}
				ent := geoIPCidrEntry{pfx: pfx.Masked(), country: code}
				if pfx.Bits() >= 8 {
					b := ent.pfx.Addr().As4()
					buckets[b[0]] = append(buckets[b[0]], ent)
				} else {
					wide = append(wide, ent)
				}
			}
		}
	}

	g.mu.Lock()
	g.bucketsV4 = buckets
	g.wideV4 = wide
	g.loadedAt = time.Now()
	g.ipCache = make(map[string]string)
	g.mu.Unlock()
}

type TelemetryStore struct {
	mu               sync.RWMutex
	state            *AppState
	filePath         string
	metricsURL       string
	upstreamsURL     string
	httpClient       *http.Client
	runner           firewallRunner
	geoipLookup      *geoIPZoneLookup
	nowFn            func() time.Time
	minuteBuckets    []TelemetryBucket
	hourBuckets      []TelemetryBucket
	categories       map[string]uint64
	perHost          map[string]*HostTelemetry
	topAttackers     map[string]*TopStatItem
	topCountries     map[string]*TopStatItem
	topDomains       map[string]*TopStatItem
	topRules         map[string]*TopStatItem
	status2xx        uint64
	status3xx        uint64
	status4xx        uint64
	status5xx        uint64
	totalKernelPkts  uint64
	totalKernelBytes uint64
	currentRPS       float64
	currentDropPS    float64
	inFlight         int64
	p50Ms            float64
	p95Ms            float64
	p99Ms            float64

	// Previous scrape baselines for delta computations
	hasPrevMetrics   bool
	prevMetrics      prometheusScrapeSnapshot
	lastScrapeAt     time.Time
	hasPrevV4Kernel  bool
	prevV4Kernel     kernelCounterPair
	hasPrevV6Kernel  bool
	prevV6Kernel     kernelCounterPair
	lastSavedAt      time.Time
	lastCertCheckAt  time.Time
	cachedCertStatus []CertExpiryStatus
	cachedUpstreams  []UpstreamHealthStatus

	stopCh   chan struct{}
	doneCh   chan struct{}
	started  bool
	stopOnce sync.Once
}

func (s *AppState) effectiveTelemetryPath() string {
	if s != nil && strings.TrimSpace(s.telemetryPath) != "" {
		return strings.TrimSpace(s.telemetryPath)
	}
	if s != nil && s.configPath != "" && s.configPath != "/etc/vsafegate/config.json" && s.configPath != "./config.json" {
		return filepath.Join(filepath.Dir(s.configPath), "telemetry.json")
	}
	if os.Getenv("ENV") == "dev" {
		return "./telemetry.json"
	}
	return "/var/lib/vsafegate/telemetry.json"
}

func (s *AppState) effectiveCaddyDataDir() string {
	if s != nil && strings.TrimSpace(s.caddyDataDir) != "" {
		return strings.TrimSpace(s.caddyDataDir)
	}
	if os.Getenv("ENV") == "dev" {
		return "./caddy-data"
	}
	return "/etc/vsafegate/caddy-data"
}

func NewTelemetryStore(s *AppState, filePath string) *TelemetryStore {
	if strings.TrimSpace(filePath) == "" {
		if s != nil {
			filePath = s.effectiveTelemetryPath()
		} else {
			filePath = "/var/lib/vsafegate/telemetry.json"
		}
	}
	var runner firewallRunner
	if runtime.GOOS == "linux" {
		runner = osFirewallRunner{}
	}
	ts := &TelemetryStore{
		state:        s,
		filePath:     filePath,
		metricsURL:   "http://127.0.0.1:2019/metrics",
		upstreamsURL: "http://127.0.0.1:2019/reverse_proxy/upstreams",
		httpClient:   &http.Client{Timeout: 3 * time.Second},
		runner:       runner,
		geoipLookup:  newGeoIPZoneLookup("/etc/vsafegate/geoip"),
		nowFn:        time.Now,
		categories:   initCategoriesMap(),
		perHost:      make(map[string]*HostTelemetry),
		topAttackers: make(map[string]*TopStatItem),
		topCountries: make(map[string]*TopStatItem),
		topDomains:   make(map[string]*TopStatItem),
		topRules:     make(map[string]*TopStatItem),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}
	ts.load()
	return ts
}

func initCategoriesMap() map[string]uint64 {
	m := make(map[string]uint64, len(threatCategoryOrder))
	for _, cat := range threatCategoryOrder {
		m[cat] = 0
	}
	return m
}

func (t *TelemetryStore) InvalidateGeoIPCache() {
	if t != nil && t.geoipLookup != nil {
		t.geoipLookup.Invalidate()
	}
}

func (t *TelemetryStore) now() time.Time {
	if t != nil && t.nowFn != nil {
		return t.nowFn()
	}
	return time.Now()
}

func (t *TelemetryStore) Start() {
	t.mu.Lock()
	if t.started {
		t.mu.Unlock()
		return
	}
	t.started = true
	t.mu.Unlock()

	go func() {
		defer close(t.doneCh)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-t.stopCh:
				_ = t.Save()
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				t.CollectOnce(ctx)
				cancel()
			}
		}
	}()
}

func (t *TelemetryStore) Stop() {
	if t == nil {
		return
	}
	t.mu.Lock()
	started := t.started
	t.mu.Unlock()
	if !started {
		_ = t.Save()
		return
	}
	t.stopOnce.Do(func() {
		close(t.stopCh)
	})
	<-t.doneCh
}

func (t *TelemetryStore) load() {
	data, err := os.ReadFile(t.filePath)
	if err != nil {
		return
	}
	var st persistedTelemetryState
	if err := json.Unmarshal(data, &st); err != nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now().UTC()
	t.minuteBuckets = pruneBuckets(st.MinuteBuckets, now.Add(-24*time.Hour))
	t.hourBuckets = pruneBuckets(st.HourBuckets, now.Add(-30*24*time.Hour))
	if st.Categories != nil {
		for k, v := range st.Categories {
			t.categories[k] = v
		}
	}
	t.status2xx = st.Status2xx
	t.status3xx = st.Status3xx
	t.status4xx = st.Status4xx
	t.status5xx = st.Status5xx
	t.totalKernelPkts = st.TotalKernelPkts
	t.totalKernelBytes = st.TotalKernelBytes
	if st.TopAttackers != nil {
		t.topAttackers = st.TopAttackers
	}
	if st.TopCountries != nil {
		t.topCountries = st.TopCountries
	}
	if st.TopDomains != nil {
		t.topDomains = st.TopDomains
	}
	if st.TopRules != nil {
		t.topRules = st.TopRules
	}
	if st.PerHost != nil {
		t.perHost = st.PerHost
	}
}

func (t *TelemetryStore) Save() error {
	if t == nil || strings.TrimSpace(t.filePath) == "" {
		return nil
	}

	t.mu.RLock()
	st := persistedTelemetryState{
		Version:          1,
		SavedAt:          t.now().UTC(),
		MinuteBuckets:    append([]TelemetryBucket(nil), t.minuteBuckets...),
		HourBuckets:      append([]TelemetryBucket(nil), t.hourBuckets...),
		Categories:       copyUint64Map(t.categories),
		Status2xx:        t.status2xx,
		Status3xx:        t.status3xx,
		Status4xx:        t.status4xx,
		Status5xx:        t.status5xx,
		TotalKernelPkts:  t.totalKernelPkts,
		TotalKernelBytes: t.totalKernelBytes,
		TopAttackers:     copyTopMap(t.topAttackers),
		TopCountries:     copyTopMap(t.topCountries),
		TopDomains:       copyTopMap(t.topDomains),
		TopRules:         copyTopMap(t.topRules),
		PerHost:          copyHostTelemetryMap(t.perHost),
	}
	t.mu.RUnlock()

	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(t.filePath), 0750); err != nil {
		return err
	}
	tmp := t.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, t.filePath); err != nil {
		return err
	}
	return os.Chmod(t.filePath, 0600)
}

func copyUint64Map(src map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func copyFloatMap(src map[string]float64) map[string]float64 {
	if src == nil {
		return nil
	}
	out := make(map[string]float64, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func copyTopMap(src map[string]*TopStatItem) map[string]*TopStatItem {
	out := make(map[string]*TopStatItem, len(src))
	for k, v := range src {
		if v != nil {
			cp := *v
			out[k] = &cp
		}
	}
	return out
}

func copyHostTelemetryMap(src map[string]*HostTelemetry) map[string]*HostTelemetry {
	out := make(map[string]*HostTelemetry, len(src))
	for k, v := range src {
		if v != nil {
			cp := *v
			cp.LatencyBuckets = copyFloatMap(v.LatencyBuckets)
			out[k] = &cp
		}
	}
	return out
}

func pruneBuckets(buckets []TelemetryBucket, cutoff time.Time) []TelemetryBucket {
	cutoffUnix := cutoff.Unix()
	idx := 0
	for idx < len(buckets) && buckets[idx].Timestamp < cutoffUnix {
		idx++
	}
	if idx == 0 {
		return buckets
	}
	out := make([]TelemetryBucket, len(buckets)-idx)
	copy(out, buckets[idx:])
	return out
}

func (t *TelemetryStore) getOrCreateMinuteBucketLocked(now time.Time) *TelemetryBucket {
	ts := now.UTC().Truncate(time.Minute).Unix()
	if n := len(t.minuteBuckets); n > 0 && t.minuteBuckets[n-1].Timestamp == ts {
		return &t.minuteBuckets[n-1]
	}
	t.minuteBuckets = pruneBuckets(t.minuteBuckets, now.UTC().Add(-24*time.Hour))
	t.minuteBuckets = append(t.minuteBuckets, TelemetryBucket{Timestamp: ts})
	if len(t.minuteBuckets) > 1440 {
		t.minuteBuckets = t.minuteBuckets[len(t.minuteBuckets)-1440:]
	}
	return &t.minuteBuckets[len(t.minuteBuckets)-1]
}

func (t *TelemetryStore) getOrCreateHourBucketLocked(now time.Time) *TelemetryBucket {
	ts := now.UTC().Truncate(time.Hour).Unix()
	if n := len(t.hourBuckets); n > 0 && t.hourBuckets[n-1].Timestamp == ts {
		return &t.hourBuckets[n-1]
	}
	t.hourBuckets = pruneBuckets(t.hourBuckets, now.UTC().Add(-30*24*time.Hour))
	t.hourBuckets = append(t.hourBuckets, TelemetryBucket{Timestamp: ts})
	if len(t.hourBuckets) > 720 {
		t.hourBuckets = t.hourBuckets[len(t.hourBuckets)-720:]
	}
	return &t.hourBuckets[len(t.hourBuckets)-1]
}

func categorizeThreat(entry AttackLog) string {
	nameLow := strings.ToLower(entry.RuleName + " " + entry.URI + " " + entry.Action)
	id := entry.RuleID

	if strings.Contains(nameLow, "[ssh guard]") || strings.Contains(nameLow, "ssh ") || strings.HasPrefix(nameLow, "ssh") {
		return "SSH"
	}
	if strings.Contains(nameLow, "[port scan canary]") || strings.Contains(nameLow, "canary") {
		return "Canary"
	}
	if strings.EqualFold(entry.Action, "CHALLENGE_POW") || strings.Contains(nameLow, "challenge") || strings.Contains(nameLow, "invalid_proof") {
		return "Challenge Fail"
	}
	if strings.EqualFold(entry.Action, "RATE_LIMIT_429") || strings.EqualFold(entry.Action, "SHIELD L7 BAN") || strings.EqualFold(entry.Action, "L7_BAN_ABORT") ||
		strings.Contains(nameLow, "rate limit") || strings.Contains(nameLow, "concurrent stream flood") || strings.Contains(nameLow, "http flood") {
		return "Rate-Limit"
	}
	if (id >= 942000 && id < 943000) || id == 1003 || strings.Contains(nameLow, "sql") || strings.Contains(nameLow, "nosql") {
		return "SQLi"
	}
	if (id >= 941000 && id < 942000) || id == 1004 || strings.Contains(nameLow, "xss") || strings.Contains(nameLow, "cross-site scripting") || strings.Contains(nameLow, "javascript") {
		return "XSS"
	}
	if (id >= 930000 && id < 935000) || strings.Contains(nameLow, "lfi") || strings.Contains(nameLow, "rce") || strings.Contains(nameLow, "traversal") ||
		strings.Contains(nameLow, "command") || strings.Contains(nameLow, "shell") || strings.Contains(nameLow, ".env") || strings.Contains(nameLow, "/etc/passwd") {
		return "LFI/RCE"
	}
	if (id >= 913000 && id < 922000) || id == 1002 || strings.Contains(nameLow, "scanner") || strings.Contains(nameLow, "bot") ||
		strings.Contains(nameLow, "sqlmap") || strings.Contains(nameLow, "nikto") || strings.Contains(nameLow, "nuclei") {
		return "Scanner/Bot"
	}
	if strings.Contains(nameLow, "shield") {
		return "Rate-Limit"
	}
	return "Scanner/Bot"
}

func bumpTopStat(m map[string]*TopStatItem, key string, item TopStatItem, capSize int) {
	if key == "" {
		return
	}
	cur, ok := m[key]
	if ok && cur != nil {
		cur.Count++
		if item.LastSeen.After(cur.LastSeen) {
			cur.LastSeen = item.LastSeen
		}
		if item.Label != "" {
			cur.Label = item.Label
		}
		if item.SubLabel != "" {
			cur.SubLabel = item.SubLabel
		}
		if item.ExemptURI != "" {
			cur.ExemptURI = item.ExemptURI
		}
		return
	}
	if len(m) >= capSize {
		var minKey string
		var minCount uint64 = math.MaxUint64
		for k, v := range m {
			if v == nil || v.Count < minCount {
				minCount = 0
				if v != nil {
					minCount = v.Count
				}
				minKey = k
			}
		}
		if minKey != "" {
			delete(m, minKey)
		}
	}
	cp := item
	cp.Key = key
	cp.Count = 1
	m[key] = &cp
}

func (t *TelemetryStore) RecordShieldStats(siteID, host string, rps, dropPS float64) {
	if t == nil {
		return
	}
	now := t.now().UTC()
	normHost := normalizeHostName(host)
	if normHost == "" {
		normHost = "_unknown"
	}

	t.mu.Lock()
	ht := t.perHost[normHost]
	if ht == nil {
		ht = &HostTelemetry{Host: normHost}
		t.perHost[normHost] = ht
	}
	ht.ShieldRPS = rps
	ht.ShieldDropPS = dropPS
	ht.ShieldUpdatedAt = now
	ht.LastUpdatedAt = now

	var totalDropPS float64
	for _, h := range t.perHost {
		if now.Sub(h.ShieldUpdatedAt) <= 15*time.Second {
			totalDropPS += h.ShieldDropPS
		}
	}
	t.currentDropPS = totalDropPS
	t.mu.Unlock()
}

func (t *TelemetryStore) RecordThreatEvent(entry AttackLog) {
	if t == nil {
		return
	}
	ts := entry.Timestamp
	if ts.IsZero() {
		ts = t.now().UTC()
	}
	cat := categorizeThreat(entry)
	clientIP := strings.TrimSpace(entry.ClientIP)
	if addr, err := netip.ParseAddr(clientIP); err == nil {
		clientIP = addr.Unmap().String()
	}
	country := ""
	if clientIP != "" && clientIP != "*" && t.geoipLookup != nil {
		country = t.geoipLookup.Lookup(clientIP)
	}
	host := normalizeHostName(entry.Host)

	t.mu.Lock()
	mb := t.getOrCreateMinuteBucketLocked(ts)
	mb.BlockedWAF++
	hb := t.getOrCreateHourBucketLocked(ts)
	hb.BlockedWAF++

	if t.categories == nil {
		t.categories = initCategoriesMap()
	}
	t.categories[cat]++

	if clientIP != "" && clientIP != "*" {
		bumpTopStat(t.topAttackers, clientIP, TopStatItem{
			Label:    entry.RuleName,
			SubLabel: country,
			LastSeen: ts,
		}, 500)
	}
	if country != "" {
		bumpTopStat(t.topCountries, country, TopStatItem{
			Label:    country,
			LastSeen: ts,
		}, 256)
	}
	if host != "" && host != "n/a" && host != ":0" {
		bumpTopStat(t.topDomains, host, TopStatItem{
			Label:    host,
			LastSeen: ts,
		}, 256)
	}
	if entry.RuleID > 0 || entry.RuleName != "" {
		rKey := fmt.Sprintf("%d:%s", entry.RuleID, entry.RuleName)
		cleanURI, _, _ := strings.Cut(entry.URI, "?")
		bumpTopStat(t.topRules, rKey, TopStatItem{
			Label:     entry.RuleName,
			SubLabel:  host,
			RuleID:    entry.RuleID,
			LastSeen:  ts,
			ExemptURI: cleanURI,
		}, 256)
	}
	t.mu.Unlock()
}

func normalizeHostName(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return ""
	}
	if idx := strings.LastIndex(h, ":"); idx > 0 && !strings.Contains(h, "]") {
		h = h[:idx]
	}
	return h
}

func parsePrometheusLabels(raw string) map[string]string {
	labels := make(map[string]string)
	i := 0
	n := len(raw)
	for i < n {
		for i < n && (raw[i] == ' ' || raw[i] == ',' || raw[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}
		eq := strings.IndexByte(raw[i:], '=')
		if eq <= 0 {
			break
		}
		key := strings.TrimSpace(raw[i : i+eq])
		i += eq + 1
		if i >= n || raw[i] != '"' {
			break
		}
		i++ // skip opening quote
		var val strings.Builder
		for i < n {
			ch := raw[i]
			if ch == '\\' && i+1 < n {
				i++
				switch raw[i] {
				case 'n':
					val.WriteByte('\n')
				case '\\':
					val.WriteByte('\\')
				case '"':
					val.WriteByte('"')
				default:
					val.WriteByte(raw[i])
				}
				i++
				continue
			}
			if ch == '"' {
				i++
				break
			}
			val.WriteByte(ch)
			i++
		}
		labels[key] = val.String()
	}
	return labels
}

func parsePrometheusMetrics(text string) prometheusScrapeSnapshot {
	snap := prometheusScrapeSnapshot{
		RequestsByHost: make(map[string]uint64),
		InFlightByHost: make(map[string]int64),
		ErrorsByHost:   make(map[string]uint64),
		StatusByHost:   make(map[string][4]uint64),
		BucketsByHost:  make(map[string]map[string]float64),
		TotalBuckets:   make(map[string]float64),
	}

	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		var name, labelStr, valPart string
		if lb := strings.IndexByte(line, '{'); lb > 0 {
			name = line[:lb]
			// Find closing '}' respecting quoted strings
			inQuote := false
			rb := -1
			for i := lb + 1; i < len(line); i++ {
				if line[i] == '\\' && inQuote {
					i++
					continue
				}
				if line[i] == '"' {
					inQuote = !inQuote
					continue
				}
				if !inQuote && line[i] == '}' {
					rb = i
					break
				}
			}
			if rb < 0 {
				continue
			}
			labelStr = line[lb+1 : rb]
			valPart = strings.TrimSpace(line[rb+1:])
		} else {
			sp := strings.IndexAny(line, " \t")
			if sp <= 0 {
				continue
			}
			name = line[:sp]
			valPart = strings.TrimSpace(line[sp+1:])
		}

		if !strings.HasPrefix(name, "caddy_http_") {
			continue
		}
		fields := strings.Fields(valPart)
		if len(fields) == 0 {
			continue
		}
		val, err := strconv.ParseFloat(fields[0], 64)
		if err != nil || math.IsNaN(val) || math.IsInf(val, 0) || val < 0 {
			continue
		}
		labels := parsePrometheusLabels(labelStr)
		host := normalizeHostName(labels["host"])
		if host == "" {
			host = "_default"
		}

		switch name {
		case "caddy_http_requests_total":
			u := uint64(math.Round(val))
			snap.RequestsByHost[host] += u
			snap.TotalRequests += u

		case "caddy_http_requests_in_flight":
			iv := int64(math.Round(val))
			snap.InFlightByHost[host] += iv
			snap.TotalInFlight += iv

		case "caddy_http_request_errors_total":
			u := uint64(math.Round(val))
			snap.ErrorsByHost[host] += u
			snap.TotalErrors += u

		case "caddy_http_request_duration_seconds_count":
			code := strings.TrimSpace(labels["code"])
			u := uint64(math.Round(val))
			idx := -1
			if len(code) > 0 {
				switch code[0] {
				case '2':
					idx = 0
				case '3':
					idx = 1
				case '4':
					idx = 2
				case '5':
					idx = 3
				}
			}
			if idx >= 0 {
				st := snap.StatusByHost[host]
				st[idx] += u
				snap.StatusByHost[host] = st
				snap.TotalStatus[idx] += u
			}

		case "caddy_http_request_duration_seconds_bucket":
			le := strings.TrimSpace(labels["le"])
			if le == "" {
				continue
			}
			hb := snap.BucketsByHost[host]
			if hb == nil {
				hb = make(map[string]float64)
				snap.BucketsByHost[host] = hb
			}
			hb[le] += val
			snap.TotalBuckets[le] += val
		}
	}
	return snap
}

func computeHistogramQuantileMs(buckets map[string]float64, q float64) float64 {
	if len(buckets) == 0 || q <= 0 || q >= 1 {
		return 0
	}
	type lePair struct {
		bound float64
		count float64
		isInf bool
	}
	var finite []lePair
	infCount := 0.0
	hasInf := false
	for k, c := range buckets {
		if k == "+Inf" || k == "+inf" || k == "Inf" {
			infCount = c
			hasInf = true
			continue
		}
		b, err := strconv.ParseFloat(k, 64)
		if err != nil || math.IsNaN(b) || b <= 0 {
			continue
		}
		finite = append(finite, lePair{bound: b, count: c})
	}
	if len(finite) == 0 {
		return 0
	}
	sort.Slice(finite, func(i, j int) bool { return finite[i].bound < finite[j].bound })
	total := infCount
	if !hasInf || total < finite[len(finite)-1].count {
		total = finite[len(finite)-1].count
	}
	if total <= 0 {
		return 0
	}

	rank := q * total
	for i, b := range finite {
		if b.count >= rank {
			var prevBound, prevCount float64
			if i > 0 {
				prevBound = finite[i-1].bound
				prevCount = finite[i-1].count
			}
			delta := b.count - prevCount
			if delta <= 0 {
				return math.Round(b.bound*1000*100) / 100
			}
			frac := (rank - prevCount) / delta
			valSec := prevBound + (b.bound-prevBound)*frac
			return math.Round(valSec*1000*100) / 100
		}
	}
	lastSec := finite[len(finite)-1].bound
	return math.Round(lastSec*1000*100) / 100
}

func parseIptablesCountField(raw string) (uint64, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	mult := uint64(1)
	last := s[len(s)-1]
	switch last {
	case 'K', 'k':
		mult = 1000
		s = s[:len(s)-1]
	case 'M', 'm':
		mult = 1000 * 1000
		s = s[:len(s)-1]
	case 'G', 'g':
		mult = 1000 * 1000 * 1000
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v * mult, true
}

func parseIptablesDropCounters(output string) kernelCounterPair {
	var total kernelCounterPair
	sc := bufio.NewScanner(strings.NewReader(output))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "Chain ") || strings.HasPrefix(line, "pkts ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if !strings.EqualFold(fields[2], "DROP") {
			continue
		}
		pkts, ok1 := parseIptablesCountField(fields[0])
		bytesCnt, ok2 := parseIptablesCountField(fields[1])
		if ok1 && ok2 {
			total.Pkts += pkts
			total.Bytes += bytesCnt
		}
	}
	return total
}

func scrapeKernelDropCountersWith(r firewallRunner) (v4, v6 kernelCounterPair, hasV4, hasV6 bool) {
	if r == nil {
		return
	}
	if out, err := r.Output("iptables", "-L", "VSAFEGATE_INPUT", "-vxn"); err == nil {
		v4 = parseIptablesDropCounters(string(out))
		hasV4 = true
	}
	if out6, err := r.Output("ip6tables", "-L", "VSAFEGATE6_INPUT", "-vxn"); err == nil {
		v6 = parseIptablesDropCounters(string(out6))
		hasV6 = true
	}
	return
}

func deltaUint64WithReset(cur, prev uint64, hasPrev bool) uint64 {
	if !hasPrev {
		return 0
	}
	if cur >= prev {
		return cur - prev
	}
	// Counter reset (process restart / chain flush)
	return cur
}

func mergeBuckets(dst, delta map[string]float64) map[string]float64 {
	if dst == nil {
		dst = make(map[string]float64, len(delta))
	}
	for k, v := range delta {
		if v > 0 {
			dst[k] += v
		}
	}
	return dst
}

func diffBuckets(cur, prev map[string]float64, reset bool) map[string]float64 {
	delta := make(map[string]float64, len(cur))
	for k, cv := range cur {
		if reset {
			delta[k] = cv
			continue
		}
		pv := prev[k]
		if cv >= pv {
			delta[k] = cv - pv
		} else {
			delta[k] = cv
		}
	}
	return delta
}

func (t *TelemetryStore) CollectOnce(ctx context.Context) {
	if t == nil {
		return
	}
	now := t.now().UTC()

	// 1. Scrape Caddy Prometheus metrics (non-blocking if Caddy isn't running)
	var scrapedProm *prometheusScrapeSnapshot
	if t.metricsURL != "" && t.httpClient != nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.metricsURL, nil)
		if err == nil {
			if resp, rerr := t.httpClient.Do(req); rerr == nil {
				body, berr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK && berr == nil {
					s := parsePrometheusMetrics(string(body))
					scrapedProm = &s
				}
			}
		}
	}

	// 2. Scrape kernel DROP counters
	v4Drop, v6Drop, hasV4, hasV6 := scrapeKernelDropCountersWith(t.runner)

	// 3. Scrape L7 reverse_proxy upstream status
	l7Upstreams := t.scrapeCaddyUpstreams(ctx)

	// 4. Periodic TLS certificate expiry scan (every 10 minutes or first run)
	var certs []CertExpiryStatus
	checkCerts := false
	t.mu.RLock()
	if t.lastCertCheckAt.IsZero() || now.Sub(t.lastCertCheckAt) >= 10*time.Minute {
		checkCerts = true
	}
	t.mu.RUnlock()
	if checkCerts && t.state != nil {
		t.state.mu.RLock()
		cfgSnap := t.state.config
		cfgSnap.Sites = append([]Site(nil), t.state.config.Sites...)
		warnDays := cfgSnap.SMTP.CertExpiryWarnDays
		t.state.mu.RUnlock()
		if warnDays <= 0 {
			warnDays = 14
		}
		certs = CheckExpiringCertificates(cfgSnap, t.state.certsBaseDir(), t.state.effectiveCaddyDataDir(), warnDays, now)
		t.state.checkMgmtCertRenewalFallback(now)
	}

	// 5. Commit deltas atomically into TelemetryStore buckets
	var totalDropPS float64
	t.mu.Lock()
	elapsed := now.Sub(t.lastScrapeAt).Seconds()
	if elapsed <= 0 || !t.hasPrevMetrics {
		elapsed = 10.0
	}

	mb := t.getOrCreateMinuteBucketLocked(now)
	hb := t.getOrCreateHourBucketLocked(now)

	var kernelDropDeltaPkts, kernelDropDeltaBytes uint64
	if hasV4 {
		kernelDropDeltaPkts += deltaUint64WithReset(v4Drop.Pkts, t.prevV4Kernel.Pkts, t.hasPrevV4Kernel)
		kernelDropDeltaBytes += deltaUint64WithReset(v4Drop.Bytes, t.prevV4Kernel.Bytes, t.hasPrevV4Kernel)
		if !t.hasPrevV4Kernel && t.totalKernelPkts == 0 {
			kernelDropDeltaPkts += v4Drop.Pkts
			kernelDropDeltaBytes += v4Drop.Bytes
		}
		t.prevV4Kernel = v4Drop
		t.hasPrevV4Kernel = true
	}
	if hasV6 {
		kernelDropDeltaPkts += deltaUint64WithReset(v6Drop.Pkts, t.prevV6Kernel.Pkts, t.hasPrevV6Kernel)
		kernelDropDeltaBytes += deltaUint64WithReset(v6Drop.Bytes, t.prevV6Kernel.Bytes, t.hasPrevV6Kernel)
		if !t.hasPrevV6Kernel && t.totalKernelPkts == 0 {
			kernelDropDeltaPkts += v6Drop.Pkts
			kernelDropDeltaBytes += v6Drop.Bytes
		}
		t.prevV6Kernel = v6Drop
		t.hasPrevV6Kernel = true
	}
	if kernelDropDeltaPkts > 0 || kernelDropDeltaBytes > 0 {
		t.totalKernelPkts += kernelDropDeltaPkts
		t.totalKernelBytes += kernelDropDeltaBytes
		mb.KernelDropPkts += kernelDropDeltaPkts
		mb.KernelDropByts += kernelDropDeltaBytes
		hb.KernelDropPkts += kernelDropDeltaPkts
		hb.KernelDropByts += kernelDropDeltaBytes
	}

	if scrapedProm != nil {
		hadPersistedStatus := (t.status2xx + t.status3xx + t.status4xx + t.status5xx) > 0
		reset := !t.hasPrevMetrics || scrapedProm.TotalRequests < t.prevMetrics.TotalRequests
		var dReqs, d2, d3, d4, d5 uint64
		if !t.hasPrevMetrics {
			if !hadPersistedStatus {
				dReqs = scrapedProm.TotalRequests
				d2 = scrapedProm.TotalStatus[0]
				d3 = scrapedProm.TotalStatus[1]
				d4 = scrapedProm.TotalStatus[2]
				d5 = scrapedProm.TotalStatus[3]
			}
		} else {
			dReqs = deltaUint64WithReset(scrapedProm.TotalRequests, t.prevMetrics.TotalRequests, true)
			d2 = deltaUint64WithReset(scrapedProm.TotalStatus[0], t.prevMetrics.TotalStatus[0], true)
			d3 = deltaUint64WithReset(scrapedProm.TotalStatus[1], t.prevMetrics.TotalStatus[1], true)
			d4 = deltaUint64WithReset(scrapedProm.TotalStatus[2], t.prevMetrics.TotalStatus[2], true)
			d5 = deltaUint64WithReset(scrapedProm.TotalStatus[3], t.prevMetrics.TotalStatus[3], true)
		}

		t.status2xx += d2
		t.status3xx += d3
		t.status4xx += d4
		t.status5xx += d5
		t.inFlight = scrapedProm.TotalInFlight
		if t.hasPrevMetrics {
			t.currentRPS = math.Round((float64(dReqs)/elapsed)*100) / 100
		}

		deltaHist := diffBuckets(scrapedProm.TotalBuckets, t.prevMetrics.TotalBuckets, !t.hasPrevMetrics || reset)
		mb.Requests += dReqs
		mb.Status2xx += d2
		mb.Status3xx += d3
		mb.Status4xx += d4
		mb.Status5xx += d5
		mb.CleanRequests += d2 + d3
		mb.LatencyBuckets = mergeBuckets(mb.LatencyBuckets, deltaHist)
		mb.P50Ms = computeHistogramQuantileMs(mb.LatencyBuckets, 0.50)
		mb.P95Ms = computeHistogramQuantileMs(mb.LatencyBuckets, 0.95)
		mb.P99Ms = computeHistogramQuantileMs(mb.LatencyBuckets, 0.99)

		hb.Requests += dReqs
		hb.Status2xx += d2
		hb.Status3xx += d3
		hb.Status4xx += d4
		hb.Status5xx += d5
		hb.CleanRequests += d2 + d3
		hb.LatencyBuckets = mergeBuckets(hb.LatencyBuckets, deltaHist)
		hb.P50Ms = computeHistogramQuantileMs(hb.LatencyBuckets, 0.50)
		hb.P95Ms = computeHistogramQuantileMs(hb.LatencyBuckets, 0.95)
		hb.P99Ms = computeHistogramQuantileMs(hb.LatencyBuckets, 0.99)

		if len(deltaHist) > 0 {
			if p50 := computeHistogramQuantileMs(deltaHist, 0.50); p50 > 0 {
				t.p50Ms = p50
				t.p95Ms = computeHistogramQuantileMs(deltaHist, 0.95)
				t.p99Ms = computeHistogramQuantileMs(deltaHist, 0.99)
			}
		}

		// Per-host breakdown
		for host, reqTotal := range scrapedProm.RequestsByHost {
			ht := t.perHost[host]
			if ht == nil {
				ht = &HostTelemetry{Host: host}
				t.perHost[host] = ht
			}
			prevHReqs := t.prevMetrics.RequestsByHost[host]
			var hDelta uint64
			if t.hasPrevMetrics {
				hDelta = deltaUint64WithReset(reqTotal, prevHReqs, true)
				ht.RPS = math.Round((float64(hDelta)/elapsed)*100) / 100
			} else if !hadPersistedStatus {
				hDelta = reqTotal
			}
			prevSt := t.prevMetrics.StatusByHost[host]
			curSt := scrapedProm.StatusByHost[host]
			if t.hasPrevMetrics {
				ht.Requests += hDelta
				ht.Status2xx += deltaUint64WithReset(curSt[0], prevSt[0], true)
				ht.Status3xx += deltaUint64WithReset(curSt[1], prevSt[1], true)
				ht.Status4xx += deltaUint64WithReset(curSt[2], prevSt[2], true)
				ht.Status5xx += deltaUint64WithReset(curSt[3], prevSt[3], true)
			} else if !hadPersistedStatus {
				ht.Requests += hDelta
				ht.Status2xx += curSt[0]
				ht.Status3xx += curSt[1]
				ht.Status4xx += curSt[2]
				ht.Status5xx += curSt[3]
			}
			ht.InFlight = scrapedProm.InFlightByHost[host]
			hBuckets := diffBuckets(scrapedProm.BucketsByHost[host], t.prevMetrics.BucketsByHost[host], !t.hasPrevMetrics || reset)
			if p50 := computeHistogramQuantileMs(hBuckets, 0.50); p50 > 0 {
				ht.P50Ms = p50
				ht.P95Ms = computeHistogramQuantileMs(hBuckets, 0.95)
				ht.P99Ms = computeHistogramQuantileMs(hBuckets, 0.99)
			}
			ht.LastUpdatedAt = now
		}

		t.prevMetrics = *scrapedProm
		t.hasPrevMetrics = true
		t.lastScrapeAt = now
	}

	// Combine shield drop/s + kernel drop/s
	var shieldDropSum float64
	for _, h := range t.perHost {
		if now.Sub(h.ShieldUpdatedAt) <= 15*time.Second {
			shieldDropSum += h.ShieldDropPS
		}
	}
	kernelDropPS := float64(kernelDropDeltaPkts) / elapsed
	totalDropPS = shieldDropSum + kernelDropPS
	t.currentDropPS = math.Round(totalDropPS*100) / 100

	// Combine L7 + L4 unhealthy upstreams
	var unhealthy []UpstreamHealthStatus
	for _, u := range l7Upstreams {
		if !u.Healthy {
			unhealthy = append(unhealthy, u)
		}
	}
	for _, l4u := range l4Manager.BackendHealthSnapshot() {
		if !l4u.Healthy {
			unhealthy = append(unhealthy, UpstreamHealthStatus{
				Source:  "l4",
				Target:  fmt.Sprintf("%s (%s:%d)", l4u.ServiceName, strings.ToUpper(l4u.Protocol), l4u.ListenPort),
				Address: l4u.Address,
				Healthy: false,
			})
		}
	}
	t.cachedUpstreams = unhealthy

	if checkCerts {
		t.lastCertCheckAt = now
		t.cachedCertStatus = certs
	}

	shouldSave := t.lastSavedAt.IsZero() || now.Sub(t.lastSavedAt) >= time.Minute
	if shouldSave {
		t.lastSavedAt = now
	}
	t.mu.Unlock()

	if shouldSave {
		_ = t.Save()
	}

	// 6. Evaluate Alerts outside TelemetryStore lock
	if t.state != nil && t.state.alertEngine != nil {
		t.state.alertEngine.CheckTelemetrySignals(totalDropPS, unhealthy, certs)
	}
}

func (t *TelemetryStore) scrapeCaddyUpstreams(ctx context.Context) []UpstreamHealthStatus {
	if t.upstreamsURL == "" || t.httpClient == nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.upstreamsURL, nil)
	if err != nil {
		return nil
	}
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var raw []struct {
		Address     string `json:"address"`
		NumRequests int    `json:"num_requests"`
		Fails       int    `json:"fails"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&raw); err != nil {
		return nil
	}
	out := make([]UpstreamHealthStatus, 0, len(raw))
	for _, item := range raw {
		out = append(out, UpstreamHealthStatus{
			Source:      "l7",
			Target:      "Caddy Reverse Proxy",
			Address:     item.Address,
			NumRequests: item.NumRequests,
			Fails:       item.Fails,
			Healthy:     item.Fails == 0,
		})
	}
	return out
}

func CheckExpiringCertificates(cfg Config, certsDir, caddyDataDir string, warnDays int, now time.Time) []CertExpiryStatus {
	if warnDays <= 0 {
		warnDays = 14
	}
	threshold := time.Duration(warnDays) * 24 * time.Hour
	var results []CertExpiryStatus
	seen := make(map[string]struct{})

	checkPEMFile := func(domain, source, path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		for len(data) > 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			data = rest
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil || cert.IsCA {
				continue
			}
			rem := cert.NotAfter.Sub(now)
			dom := domain
			if dom == "" {
				dom = cert.Subject.CommonName
				if dom == "" && len(cert.DNSNames) > 0 {
					dom = cert.DNSNames[0]
				}
			}
			key := source + "|" + dom + "|" + path
			if _, dup := seen[key]; dup {
				return
			}
			seen[key] = struct{}{}
			results = append(results, CertExpiryStatus{
				Domain:        dom,
				Source:        source,
				Subject:       cert.Subject.CommonName,
				Issuer:        cert.Issuer.CommonName,
				NotAfter:      cert.NotAfter.UTC(),
				DaysRemaining: math.Round((rem.Hours()/24.0)*10) / 10,
				ExpiringSoon:  rem <= threshold,
				Expired:       now.After(cert.NotAfter),
				FilePath:      path,
			})
			return
		}
	}

	// 1. Uploaded custom site certs
	for _, site := range cfg.Sites {
		if !site.SSL {
			continue
		}
		if site.CustomCertPath != "" {
			checkPEMFile(site.Domain, "uploaded", site.CustomCertPath)
		} else if site.CustomCertExpiry != "" {
			if exp, err := time.Parse(time.RFC3339, site.CustomCertExpiry); err == nil {
				rem := exp.Sub(now)
				results = append(results, CertExpiryStatus{
					Domain:        site.Domain,
					Source:        "uploaded",
					Issuer:        site.CustomCertIssuer,
					NotAfter:      exp.UTC(),
					DaysRemaining: math.Round((rem.Hours()/24.0)*10) / 10,
					ExpiringSoon:  rem <= threshold,
					Expired:       now.After(exp),
				})
			}
		}
	}

	// 2. Caddy ACME certs inside caddyDataDir/caddy/certificates
	if caddyDataDir != "" {
		acmeDir := filepath.Join(caddyDataDir, "caddy", "certificates")
		_ = filepath.WalkDir(acmeDir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if strings.HasSuffix(strings.ToLower(d.Name()), ".crt") || strings.HasSuffix(strings.ToLower(d.Name()), ".pem") {
				checkPEMFile("", "acme", path)
			}
			return nil
		})
	}
	_ = certsDir
	return results
}

func sortTopItems(m map[string]*TopStatItem, limit int, bannedLookup map[string]bool) []TopStatItem {
	items := make([]TopStatItem, 0, len(m))
	for _, v := range m {
		if v == nil || v.Count == 0 {
			continue
		}
		cp := *v
		if bannedLookup != nil && bannedLookup[cp.Key] {
			cp.IsBanned = true
		}
		items = append(items, cp)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].LastSeen.After(items[j].LastSeen)
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

func (t *TelemetryStore) Query(rangeStr string) TelemetryQueryResult {
	r := strings.ToLower(strings.TrimSpace(rangeStr))
	if r != "1h" && r != "24h" && r != "7d" && r != "30d" {
		r = "24h"
	}

	var bannedLookup map[string]bool
	if t.state != nil {
		t.state.mu.RLock()
		bannedLookup = make(map[string]bool, len(t.state.bannedMap)+len(t.state.config.ShieldBannedIPs))
		for ip := range t.state.bannedMap {
			bannedLookup[ip] = true
		}
		for _, sb := range t.state.config.ShieldBannedIPs {
			bannedLookup[sb.IP] = true
		}
		t.state.mu.RUnlock()
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	now := t.now().UTC()
	var selected []TelemetryBucket
	switch r {
	case "1h":
		cutoff := now.Add(-1 * time.Hour).Unix()
		for _, b := range t.minuteBuckets {
			if b.Timestamp >= cutoff {
				cp := b
				cp.LatencyBuckets = nil
				selected = append(selected, cp)
			}
		}
	case "24h":
		cutoff := now.Add(-24 * time.Hour).Unix()
		for _, b := range t.minuteBuckets {
			if b.Timestamp >= cutoff {
				cp := b
				cp.LatencyBuckets = nil
				selected = append(selected, cp)
			}
		}
	case "7d":
		cutoff := now.Add(-7 * 24 * time.Hour).Unix()
		for _, b := range t.hourBuckets {
			if b.Timestamp >= cutoff {
				cp := b
				cp.LatencyBuckets = nil
				selected = append(selected, cp)
			}
		}
	case "30d":
		cutoff := now.Add(-30 * 24 * time.Hour).Unix()
		for _, b := range t.hourBuckets {
			if b.Timestamp >= cutoff {
				cp := b
				cp.LatencyBuckets = nil
				selected = append(selected, cp)
			}
		}
	}

	return TelemetryQueryResult{
		Range:            r,
		GeneratedAt:      now,
		Buckets:          selected,
		PerHost:          copyHostTelemetryMap(t.perHost),
		Categories:       copyUint64Map(t.categories),
		CurrentRPS:       t.currentRPS,
		CurrentDropPS:    t.currentDropPS,
		InFlight:         t.inFlight,
		P50Ms:            t.p50Ms,
		P95Ms:            t.p95Ms,
		P99Ms:            t.p99Ms,
		Status2xx:        t.status2xx,
		Status3xx:        t.status3xx,
		Status4xx:        t.status4xx,
		Status5xx:        t.status5xx,
		TotalKernelPkts:  t.totalKernelPkts,
		TotalKernelBytes: t.totalKernelBytes,
		TopAttackers:     sortTopItems(t.topAttackers, 10, bannedLookup),
		TopCountries:     sortTopItems(t.topCountries, 10, nil),
		TopDomains:       sortTopItems(t.topDomains, 10, nil),
		TopRules:         sortTopItems(t.topRules, 10, nil),
	}
}

func (t *TelemetryStore) Summary() TelemetrySummary {
	q := t.Query("24h")
	t.mu.RLock()
	var expiring []CertExpiryStatus
	for _, c := range t.cachedCertStatus {
		if c.ExpiringSoon {
			expiring = append(expiring, c)
		}
	}
	unhealthy := append([]UpstreamHealthStatus(nil), t.cachedUpstreams...)
	t.mu.RUnlock()

	return TelemetrySummary{
		GeneratedAt:      q.GeneratedAt,
		CurrentRPS:       q.CurrentRPS,
		CurrentDropPS:    q.CurrentDropPS,
		InFlight:         q.InFlight,
		P50Ms:            q.P50Ms,
		P95Ms:            q.P95Ms,
		P99Ms:            q.P99Ms,
		Status2xx:        q.Status2xx,
		Status3xx:        q.Status3xx,
		Status4xx:        q.Status4xx,
		Status5xx:        q.Status5xx,
		TotalKernelPkts:  q.TotalKernelPkts,
		TotalKernelBytes: q.TotalKernelBytes,
		Categories:       q.Categories,
		PerHost:          q.PerHost,
		TopAttackers:     q.TopAttackers,
		TopCountries:     q.TopCountries,
		TopDomains:       q.TopDomains,
		TopRules:         q.TopRules,
		ExpiringCerts:    expiring,
		UnhealthyTargets: unhealthy,
	}
}

// ---------- SSE Broker for Live Attack Stream (/api/soc/stream) ----------

type socSSEMessage struct {
	Event string
	Data  []byte
}

type SSEBroker struct {
	mu      sync.RWMutex
	clients map[chan socSSEMessage]struct{}
}

func NewSSEBroker() *SSEBroker {
	return &SSEBroker{
		clients: make(map[chan socSSEMessage]struct{}),
	}
}

func (b *SSEBroker) Subscribe() chan socSSEMessage {
	ch := make(chan socSSEMessage, 64)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *SSEBroker) Unsubscribe(ch chan socSSEMessage) {
	b.mu.Lock()
	if _, ok := b.clients[ch]; ok {
		delete(b.clients, ch)
		close(ch)
	}
	b.mu.Unlock()
}

func (b *SSEBroker) ClientCount() int {
	b.mu.RLock()
	n := len(b.clients)
	b.mu.RUnlock()
	return n
}

func (b *SSEBroker) Publish(eventName string, payload any) {
	if b == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	msg := socSSEMessage{Event: eventName, Data: data}
	b.mu.RLock()
	for ch := range b.clients {
		select {
		case ch <- msg:
		default:
		}
	}
	b.mu.RUnlock()
}
