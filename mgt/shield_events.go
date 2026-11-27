package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type ShieldEvent struct {
	Type               string  `json:"type"` // "challenge", "drop", "ban", "stats"
	Timestamp          int64   `json:"ts"`
	Host               string  `json:"host,omitempty"`
	SiteID             string  `json:"site_id,omitempty"`
	ClientIP           string  `json:"client_ip,omitempty"`
	PeerIP             string  `json:"peer_ip,omitempty"`
	BehindTrustedProxy bool    `json:"behind_trusted_proxy,omitempty"`
	URI                string  `json:"uri,omitempty"`
	Method             string  `json:"method,omitempty"`
	UserAgent          string  `json:"user_agent,omitempty"`
	Reason             string  `json:"reason,omitempty"`
	Action             string  `json:"action,omitempty"`
	RPS                float64 `json:"rps,omitempty"`
	DropPS             float64 `json:"drop_ps,omitempty"`
}

func (s *AppState) effectiveEventsSocketPath() string {
	if s != nil && strings.TrimSpace(s.eventsSocketPath) != "" {
		return strings.TrimSpace(s.eventsSocketPath)
	}
	if os.Getenv("ENV") == "dev" {
		return filepath.Join(os.TempDir(), "vsafegate-events.sock")
	}
	if runtime.GOOS == "linux" {
		return "/run/vsafegate/events.sock"
	}
	return ""
}

func (s *AppState) startShieldEventReceiver() error {
	sockPath := s.effectiveEventsSocketPath()
	if sockPath == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(sockPath), 0750); err != nil {
		return err
	}
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	_ = os.Chmod(sockPath, 0600)

	s.shieldSockMu.Lock()
	if s.shieldSockListener != nil {
		_ = s.shieldSockListener.Close()
	}
	s.shieldSockListener = ln
	s.shieldSockMu.Unlock()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serveShieldEventConn(conn)
		}
	}()

	log.Printf("[Shield Receiver] Listening for L7 Shield events on %s", sockPath)
	return nil
}

func (s *AppState) stopShieldEventReceiver() {
	s.shieldSockMu.Lock()
	ln := s.shieldSockListener
	s.shieldSockListener = nil
	s.shieldSockMu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

func (s *AppState) serveShieldEventConn(conn net.Conn) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 4096), 64*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev ShieldEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		s.handleShieldEvent(ev)
	}
}

func normalizeEventIP(raw string) string {
	str := strings.TrimSpace(raw)
	if str == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(str); err == nil {
		str = host
	}
	str, _, _ = strings.Cut(str, "%")
	if addr, err := netip.ParseAddr(strings.TrimSpace(str)); err == nil {
		return addr.Unmap().String()
	}
	return ""
}

func (s *AppState) shouldLogShieldSample(key string, now time.Time, window time.Duration) bool {
	s.shieldLogSampleMu.Lock()
	defer s.shieldLogSampleMu.Unlock()
	if s.shieldLogSampleAt == nil {
		s.shieldLogSampleAt = make(map[string]time.Time)
	}
	if len(s.shieldLogSampleAt) > 2048 {
		for k, ts := range s.shieldLogSampleAt {
			if now.Sub(ts) > window*2 {
				delete(s.shieldLogSampleAt, k)
			}
		}
	}
	if last, ok := s.shieldLogSampleAt[key]; ok && now.Sub(last) < window {
		return false
	}
	s.shieldLogSampleAt[key] = now
	return true
}

func (s *AppState) handleShieldEvent(ev ShieldEvent) {
	switch ev.Type {
	case "stats":
		if s.autoProxyCtrl != nil {
			s.autoProxyCtrl.RecordShieldStats(ev.SiteID, ev.Host, ev.RPS, ev.DropPS)
		}
		if s.telemetry != nil {
			s.telemetry.RecordShieldStats(ev.SiteID, ev.Host, ev.RPS, ev.DropPS)
		}
		return

	case "ban":
		if s.autoProxyCtrl != nil {
			s.autoProxyCtrl.recordWAFEvent()
		}
		clientIP := normalizeEventIP(ev.ClientIP)
		peerIP := normalizeEventIP(ev.PeerIP)
		if clientIP == "" || isPrivateOrReservedIP(clientIP) {
			return
		}

		s.mu.RLock()
		cfgSnap := s.config
		whitelisted := s.isWhitelistedLocked(clientIP)
		s.mu.RUnlock()

		if whitelisted {
			return
		}
		// Never kernel-ban Cloudflare Edge or Trusted Proxy IPs!
		if isTrustedProxyOrCloudflareIP(clientIP, cfgSnap) {
			log.Printf("[Anti-Self-DoS] Shield ban event ignored for Cloudflare/TrustedProxy IP %s", clientIP)
			return
		}

		reason := strings.TrimSpace(ev.Reason)
		if reason == "" {
			reason = "[Shield] HTTP flood threshold exceeded"
		}

		viaTrustedProxy := ev.BehindTrustedProxy || (peerIP != "" && isTrustedProxyOrCloudflareIP(peerIP, cfgSnap))
		if viaTrustedProxy {
			// Traffic came through Cloudflare/Router NAT -> L7 Shield Banlist ONLY (never touch kernel ipset!)
			s.addShieldL7Ban(clientIP, ev.Host, ev.SiteID, reason, ev.URI, ev.Method, ev.UserAgent)
			return
		}

		// Direct abuser hitting origin directly -> O(1) Kernel ipset ban
		s.banIP(clientIP, reason, -1)
		return

	case "drop", "challenge":
		if s.autoProxyCtrl != nil {
			s.autoProxyCtrl.recordWAFEvent()
		}
		clientIP := normalizeEventIP(ev.ClientIP)
		if clientIP == "" {
			return
		}
		now := time.Now()
		sampleKey := ev.Type + "|" + ev.Host + "|" + clientIP
		if !s.shouldLogShieldSample(sampleKey, now, 10*time.Second) {
			return
		}
		action := ev.Action
		if action == "" {
			if ev.Type == "challenge" {
				action = "CHALLENGE_POW"
			} else {
				action = "RATE_LIMIT_429"
			}
		}
		entry := AttackLog{
			ID:        fmt.Sprintf("shield-%d", now.UnixNano()),
			Timestamp: now,
			ClientIP:  clientIP,
			Host:      ev.Host,
			URI:       ev.URI,
			Method:    ev.Method,
			RuleID:    9950,
			RuleName:  ev.Reason,
			Action:    action,
			UserAgent: ev.UserAgent,
		}
		s.mu.Lock()
		s.addRecentLog(entry)
		s.mu.Unlock()
		s.publishAttackLog(entry)
	}
}

func (s *AppState) addShieldL7Ban(ip, host, siteID, reason, uri, method, ua string) {
	ip = normalizeEventIP(ip)
	if ip == "" || isPrivateOrReservedIP(ip) {
		return
	}

	now := time.Now()
	s.mu.Lock()
	if s.isWhitelistedLocked(ip) || isTrustedProxyOrCloudflareIP(ip, s.config) {
		s.mu.Unlock()
		return
	}

	ttlHours := s.config.DefaultBanTTL
	if ttlHours < 0 {
		ttlHours = 24
	}
	var expiresAt time.Time
	if ttlHours > 0 {
		expiresAt = now.Add(time.Duration(ttlHours) * time.Hour)
	}

	entry := ShieldBanEntry{
		IP:        ip,
		Host:      host,
		SiteID:    siteID,
		Reason:    reason,
		BannedAt:  now,
		ExpiresAt: expiresAt,
	}

	updated := false
	for i := range s.config.ShieldBannedIPs {
		if s.config.ShieldBannedIPs[i].IP == ip {
			s.config.ShieldBannedIPs[i] = entry
			updated = true
			break
		}
	}
	if !updated {
		s.config.ShieldBannedIPs = append(s.config.ShieldBannedIPs, entry)
	}

	logEntry := AttackLog{
		ID:        fmt.Sprintf("l7ban-%d", now.UnixNano()),
		Timestamp: now,
		ClientIP:  ip,
		Host:      host,
		URI:       uri,
		Method:    method,
		RuleID:    9951,
		RuleName:  reason,
		Action:    "SHIELD L7 BAN",
		UserAgent: ua,
	}
	s.addRecentLog(logEntry)
	s.mu.Unlock()

	s.publishAttackLog(logEntry)
	if s.alertEngine != nil {
		s.alertEngine.NotifyIPBan(ip, reason, "L7 Shield", ttlHours)
	}
	s.saveConfig()
	if s.reloadManager != nil {
		s.reloadManager.Trigger()
	}
}

type ShieldBanResponse struct {
	IP               string    `json:"ip"`
	Host             string    `json:"host,omitempty"`
	SiteID           string    `json:"site_id,omitempty"`
	Reason           string    `json:"reason,omitempty"`
	BannedAt         time.Time `json:"banned_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	IsPermanent      bool      `json:"is_permanent"`
	RemainingSeconds int64     `json:"remaining_seconds"`
	RemainingText    string    `json:"remaining_text"`
}

func (s *AppState) getShieldBannedIPList() []ShieldBanResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]ShieldBanResponse, 0, len(s.config.ShieldBannedIPs))
	for _, b := range s.config.ShieldBannedIPs {
		remSec, remText := formatRemainingTime(b.ExpiresAt)
		out = append(out, ShieldBanResponse{
			IP:               b.IP,
			Host:             b.Host,
			SiteID:           b.SiteID,
			Reason:           b.Reason,
			BannedAt:         b.BannedAt,
			ExpiresAt:        b.ExpiresAt,
			IsPermanent:      b.ExpiresAt.IsZero(),
			RemainingSeconds: remSec,
			RemainingText:    remText,
		})
	}
	return out
}

func (s *AppState) unbanShieldIP(ip string) {
	norm := normalizeEventIP(ip)
	if norm == "" {
		norm = strings.TrimSpace(ip)
	}
	if norm == "" {
		return
	}

	s.mu.Lock()
	filtered := make([]ShieldBanEntry, 0, len(s.config.ShieldBannedIPs))
	changed := false
	for _, b := range s.config.ShieldBannedIPs {
		if b.IP == norm {
			changed = true
			continue
		}
		filtered = append(filtered, b)
	}
	s.config.ShieldBannedIPs = filtered
	s.mu.Unlock()

	if changed {
		s.saveConfig()
		if s.reloadManager != nil {
			s.reloadManager.Trigger()
		}
	}
}

func (s *AppState) clearAllShieldBans() {
	s.mu.Lock()
	changed := len(s.config.ShieldBannedIPs) > 0
	s.config.ShieldBannedIPs = nil
	s.mu.Unlock()

	if changed {
		s.saveConfig()
		if s.reloadManager != nil {
			s.reloadManager.Trigger()
		}
	}
}

func (s *AppState) expireShieldBans(now time.Time) {
	s.mu.Lock()
	if len(s.config.ShieldBannedIPs) == 0 {
		s.mu.Unlock()
		return
	}
	kept := make([]ShieldBanEntry, 0, len(s.config.ShieldBannedIPs))
	changed := false
	for _, b := range s.config.ShieldBannedIPs {
		if !b.ExpiresAt.IsZero() && now.After(b.ExpiresAt) {
			changed = true
			continue
		}
		kept = append(kept, b)
	}
	if changed {
		s.config.ShieldBannedIPs = kept
	}
	s.mu.Unlock()

	if changed {
		s.saveConfig()
		if s.reloadManager != nil {
			s.reloadManager.Trigger()
		}
	}
}

// unused sync import guard if refactored later
var _ = sync.Mutex{}
