package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const defaultSharedThreatHubURL = "https://vsafegate.trong.pro"

func hashHardwareID(prefix, raw string) string {
	sum := sha256.Sum256([]byte(prefix + strings.ToLower(strings.TrimSpace(raw))))
	return "vsg_" + hex.EncodeToString(sum[:])[:24]
}

func isValidHardwareToken(s string) bool {
	s = strings.ToLower(strings.TrimSpace(strings.TrimRight(s, "\x00")))
	if s == "" || len(s) < 6 {
		return false
	}
	switch s {
	case "not specified", "to be filled by o.e.m.", "default string", "none", "unknown",
		"00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff":
		return false
	}
	return true
}

func computeHardwareServerID(persistPath string) string {
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil && isValidHardwareToken(string(b)) {
			return hashHardwareID("vsg-dmi-v1:", string(b))
		}
		if b, err := os.ReadFile("/proc/device-tree/serial-number"); err == nil && isValidHardwareToken(string(b)) {
			return hashHardwareID("vsg-dt-v1:", string(b))
		}
		if b, err := os.ReadFile("/etc/machine-id"); err == nil && isValidHardwareToken(string(b)) {
			return hashHardwareID("vsg-mid-v1:", string(b))
		}
	}
	if persistPath != "" {
		if b, err := os.ReadFile(persistPath); err == nil {
			id := strings.TrimSpace(string(b))
			if strings.HasPrefix(id, "vsg_") && len(id) == 28 {
				return id
			}
		}
	}
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	id := "vsg_" + hex.EncodeToString(rnd[:])
	if persistPath != "" {
		_ = os.MkdirAll(filepath.Dir(persistPath), 0750)
		_ = os.WriteFile(persistPath, []byte(id+"\n"), 0600)
	}
	return id
}

func (s *AppState) getOrComputeServerID() string {
	if s == nil {
		return computeHardwareServerID("")
	}
	s.mu.RLock()
	cached := s.config.SharedThreat.ServerID
	cfgPath := s.configPath
	s.mu.RUnlock()
	if strings.HasPrefix(cached, "vsg_") && len(cached) == 28 {
		return cached
	}
	persistPath := ""
	if cfgPath != "" {
		persistPath = filepath.Join(filepath.Dir(cfgPath), ".server_id")
	}
	id := computeHardwareServerID(persistPath)
	s.mu.Lock()
	if s.config.SharedThreat.ServerID == "" {
		s.config.SharedThreat.ServerID = id
	} else {
		id = s.config.SharedThreat.ServerID
	}
	s.mu.Unlock()
	return id
}

func validateSharedThreatConfig(cfg *SharedThreatConfig) error {
	if cfg == nil {
		return errors.New("shared_threat config is required")
	}
	cfg.HubURL = strings.TrimRight(strings.TrimSpace(cfg.HubURL), "/")
	if cfg.HubURL == "" {
		cfg.HubURL = defaultSharedThreatHubURL
	}
	cfg.APIKey = strings.TrimSpace(cfg.APIKey)
	cfg.NodeName = strings.TrimSpace(cfg.NodeName)
	if cfg.SyncIntervalMin <= 0 {
		cfg.SyncIntervalMin = 15
	}
	if cfg.SyncIntervalMin > 1440 {
		cfg.SyncIntervalMin = 1440
	}

	if cfg.Enabled {
		u, err := url.Parse(cfg.HubURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.TrimSpace(u.Host) == "" {
			return errors.New("hub_url không hợp lệ (phải là URL http:// hoặc https://)")
		}
		if cfg.APIKey == "" {
			return errors.New("api_key không được để trống khi bật Đồng Bộ IP Chặn Chung")
		}
	}
	return nil
}

func (s *AppState) effectiveSharedNodeName(cfg SharedThreatConfig) string {
	if n := strings.TrimSpace(cfg.NodeName); n != "" {
		return n
	}
	if n := strings.TrimSpace(s.config.MgmtDomain); n != "" {
		return n
	}
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		return strings.TrimSpace(h)
	}
	return "vsafegate-node"
}

func (s *AppState) ReportBlockedIPAsync(ip, reason, layer string, ttlHours int) {
	if s == nil {
		return
	}
	s.mu.RLock()
	cfg := s.config.SharedThreat
	isWL := s.isWhitelistedLocked(ip)
	isTrusted := isTrustedProxyOrCloudflareIP(ip, s.config)
	nodeName := s.effectiveSharedNodeName(cfg)
	s.mu.RUnlock()

	if !cfg.Enabled || !cfg.PushOnBan || strings.TrimSpace(cfg.APIKey) == "" {
		return
	}
	serverID := s.getOrComputeServerID()
	norm, err := normalizeBanTarget(ip)
	if err != nil || isPrivateOrReservedIP(norm) || isWL || isTrusted {
		return
	}
	hubURL := strings.TrimRight(strings.TrimSpace(cfg.HubURL), "/")
	if hubURL == "" {
		hubURL = defaultSharedThreatHubURL
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		payload := map[string]any{
			"ip":        norm,
			"reason":    reason,
			"layer":     layer,
			"node":      nodeName,
			"server_id": serverID,
			"ttl_hours": ttlHours,
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, hubURL+"/api/report.php", bytes.NewReader(raw))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-vSafeGate-Key", cfg.APIKey)
		req.Header.Set("User-Agent", "vSafeGate/"+AppVersion)

		resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
		if err != nil {
			log.Printf("[SharedThreat] Report IP %s failed: %v", norm, err)
			return
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			log.Printf("[SharedThreat] Report IP %s returned HTTP %d", norm, resp.StatusCode)
		}
	}()
}

func (s *AppState) SyncSharedThreatList(ctx context.Context) (int, error) {
	if s == nil {
		return 0, errors.New("state unavailable")
	}
	s.mu.RLock()
	cfg := s.config.SharedThreat
	cfgSnap := s.config
	s.mu.RUnlock()

	if !cfg.Enabled || !cfg.SyncEnabled {
		return 0, nil
	}
	hubURL := strings.TrimRight(strings.TrimSpace(cfg.HubURL), "/")
	if hubURL == "" {
		hubURL = defaultSharedThreatHubURL
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return 0, errors.New("chưa cấu hình Shared Threat API Key")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hubURL+"/api/feed.php?format=txt", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-vSafeGate-Key", cfg.APIKey)
	req.Header.Set("User-Agent", "vSafeGate/"+AppVersion)

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		s.recordSharedSyncStatus(0, err.Error())
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		errMsg := fmt.Errorf("hub HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		s.recordSharedSyncStatus(0, errMsg.Error())
		return 0, errMsg
	}

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		s.recordSharedSyncStatus(0, err.Error())
		return 0, err
	}

	lines := strings.Split(string(rawBody), "\n")
	validTargets := make([]string, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))

	s.mu.RLock()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		norm, nerr := normalizeBanTarget(line)
		if nerr != nil || !isIPv4Target(norm) || isPrivateOrReservedIP(norm) {
			continue
		}
		if s.isWhitelistedLocked(norm) || isTrustedProxyOrCloudflareIP(norm, cfgSnap) {
			continue
		}
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		validTargets = append(validTargets, norm)
	}
	s.mu.RUnlock()

	if runtime.GOOS == "linux" {
		r := osFirewallRunner{}
		if _, err := r.LookPath("ipset"); err == nil {
			needFirewallSync := !ipsetExists(r, "vsafegate-shared")
			_ = r.Run("ipset", "create", "vsafegate-shared", "hash:net", "maxelem", "131072", "-exist")
			_ = r.Run("ipset", "create", "vsafegate-shared-tmp", "hash:net", "maxelem", "131072", "-exist")
			var script strings.Builder
			script.WriteString("flush vsafegate-shared-tmp\n")
			for _, t := range validTargets {
				script.WriteString("add vsafegate-shared-tmp ")
				script.WriteString(t)
				script.WriteString(" -exist\n")
			}
			if err := r.RunStdin(script.String(), "ipset", "restore"); err != nil {
				s.recordSharedSyncStatus(0, err.Error())
				return 0, err
			}
			if err := r.Run("ipset", "swap", "vsafegate-shared-tmp", "vsafegate-shared"); err != nil {
				s.recordSharedSyncStatus(0, err.Error())
				return 0, err
			}
			_ = r.Run("ipset", "destroy", "vsafegate-shared-tmp")
			if needFirewallSync {
				s.triggerFirewallSync()
			}
		}
	}

	s.recordSharedSyncStatus(len(validTargets), "")
	return len(validTargets), nil
}

// PushExistingBannedIPs uploads active public BannedIPs from local config to the central hub.
func (s *AppState) PushExistingBannedIPs(ctx context.Context) (int, error) {
	if s == nil {
		return 0, errors.New("state unavailable")
	}
	s.mu.RLock()
	cfg := s.config.SharedThreat
	cfgSnap := s.config
	banned := append([]BannedIPEntry(nil), s.config.BannedIPs...)
	nodeName := s.effectiveSharedNodeName(cfg)
	s.mu.RUnlock()

	if !cfg.Enabled || !cfg.PushOnBan {
		return 0, nil
	}
	hubURL := strings.TrimRight(strings.TrimSpace(cfg.HubURL), "/")
	if hubURL == "" {
		hubURL = defaultSharedThreatHubURL
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return 0, errors.New("chưa cấu hình Shared Threat API Key")
	}

	serverID := s.getOrComputeServerID()
	now := time.Now()
	client := &http.Client{Timeout: 8 * time.Second}
	pushed := 0
	for _, entry := range banned {
		if !entry.ExpiresAt.IsZero() && entry.ExpiresAt.Before(now) {
			continue
		}
		norm, err := normalizeBanTarget(entry.IP)
		if err != nil || isPrivateOrReservedIP(norm) || isTrustedProxyOrCloudflareIP(norm, cfgSnap) {
			continue
		}
		s.mu.RLock()
		isWL := s.isWhitelistedLocked(norm)
		s.mu.RUnlock()
		if isWL {
			continue
		}
		ttlHours := 0
		if !entry.ExpiresAt.IsZero() {
			rem := int(entry.ExpiresAt.Sub(now).Hours())
			if rem < 1 {
				rem = 1
			}
			ttlHours = rem
		}
		raw, err := json.Marshal(map[string]any{
			"ip":        norm,
			"reason":    entry.Reason,
			"layer":     "Kernel ipset",
			"node":      nodeName,
			"server_id": serverID,
			"ttl_hours": ttlHours,
		})
		if err != nil {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, hubURL+"/api/report.php", bytes.NewReader(raw))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-vSafeGate-Key", cfg.APIKey)
		req.Header.Set("User-Agent", "vSafeGate/"+AppVersion)

		resp, err := client.Do(req)
		if err != nil {
			return pushed, err
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return pushed, fmt.Errorf("hub HTTP %d", resp.StatusCode)
		}
		pushed++
	}
	return pushed, nil
}

func (s *AppState) recordSharedSyncStatus(count int, errMsg string) {
	s.mu.Lock()
	s.config.SharedThreat.LastSyncAt = time.Now().UTC()
	if errMsg == "" {
		s.config.SharedThreat.LastSyncCount = count
		s.config.SharedThreat.LastSyncError = ""
	} else {
		s.config.SharedThreat.LastSyncError = errMsg
	}
	s.mu.Unlock()
	s.saveConfig()
}

func (s *AppState) startSharedThreatSyncLoop(stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		var lastHeartbeat time.Time
		for {
			s.mu.RLock()
			cfg := s.config.SharedThreat
			s.mu.RUnlock()

			if cfg.Enabled && strings.TrimSpace(cfg.APIKey) != "" {
				if lastHeartbeat.IsZero() || time.Since(lastHeartbeat) >= 2*time.Minute {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					if err := s.SendHubHeartbeat(ctx); err != nil {
						log.Printf("[SharedThreat] Heartbeat failed: %v", err)
					} else {
						lastHeartbeat = time.Now()
					}
					cancel()
				}
			}

			if cfg.Enabled && cfg.SyncEnabled && strings.TrimSpace(cfg.APIKey) != "" {
				interval := time.Duration(cfg.SyncIntervalMin) * time.Minute
				if interval <= 0 {
					interval = 15 * time.Minute
				}
				if cfg.LastSyncAt.IsZero() || time.Since(cfg.LastSyncAt) >= interval {
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					if cnt, err := s.SyncSharedThreatList(ctx); err != nil {
						log.Printf("[SharedThreat] Periodic sync failed: %v", err)
					} else {
						log.Printf("[SharedThreat] Synced %d shared IP(s) from %s", cnt, cfg.HubURL)
					}
					cancel()
				}
			}

			select {
			case <-ticker.C:
			case <-stopCh:
				return
			}
		}
	}()
}

func (s *AppState) SendHubHeartbeat(ctx context.Context) error {
	if s == nil {
		return errors.New("state unavailable")
	}
	serverID := s.getOrComputeServerID()
	s.mu.RLock()
	cfg := s.config.SharedThreat
	activeBans := len(s.config.BannedIPs)
	nodeName := s.effectiveSharedNodeName(cfg)
	s.mu.RUnlock()

	if !cfg.Enabled || strings.TrimSpace(cfg.APIKey) == "" {
		return nil
	}
	hubURL := strings.TrimRight(strings.TrimSpace(cfg.HubURL), "/")
	if hubURL == "" {
		hubURL = defaultSharedThreatHubURL
	}
	var threatsBlocked int64
	if s.telemetry != nil {
		sum := s.telemetry.Summary()
		for _, v := range sum.Categories {
			threatsBlocked += int64(v)
		}
		threatsBlocked += int64(sum.TotalKernelPkts)
	}
	if threatsBlocked == 0 && s.logManager != nil {
		threatsBlocked = int64(s.logManager.TotalCount())
	}

	raw, err := json.Marshal(map[string]any{
		"server_id":       serverID,
		"node":            nodeName,
		"version":         AppVersion,
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
		"active_bans":     activeBans,
		"threats_blocked": threatsBlocked,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hubURL+"/api/heartbeat.php", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-vSafeGate-Key", cfg.APIKey)
	req.Header.Set("User-Agent", "vSafeGate/"+AppVersion)

	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("heartbeat HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
