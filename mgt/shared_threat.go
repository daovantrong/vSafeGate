package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

const defaultSharedThreatHubURL = "https://vsafegate.trong.pro"

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
		for {
			s.mu.RLock()
			cfg := s.config.SharedThreat
			s.mu.RUnlock()

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
