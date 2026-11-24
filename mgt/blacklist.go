package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func isPrivateOrReservedIP(ipStr string) bool {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" || ipStr == "127.0.0.1" || ipStr == "::1" || ipStr == "localhost" {
		return true
	}
	if strings.Contains(ipStr, "/") {
		ip, _, err := net.ParseCIDR(ipStr)
		if err != nil {
			return true
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
		return false
	}
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return true
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return true
	}
	return false
}

func formatRemainingTime(expiresAt time.Time) (int64, string) {
	if expiresAt.IsZero() {
		return 0, "Vĩnh viễn"
	}
	rem := time.Until(expiresAt)
	if rem <= 0 {
		return 0, "Đã hết hạn"
	}
	totalSec := int64(rem.Seconds())
	hours := int(rem.Hours())
	mins := int(rem.Minutes()) % 60
	if hours > 24 {
		days := hours / 24
		remHours := hours % 24
		return totalSec, fmt.Sprintf("Còn %d ngày %d giờ", days, remHours)
	}
	if hours > 0 {
		return totalSec, fmt.Sprintf("Còn %d giờ %d phút", hours, mins)
	}
	return totalSec, fmt.Sprintf("Còn %d phút", mins)
}

func (s *AppState) addRecentLog(entry AttackLog) {
	if len(s.recentLogs) >= 200 {
		copy(s.recentLogs[1:], s.recentLogs[:199])
		s.recentLogs[0] = entry
	} else {
		s.recentLogs = append([]AttackLog{entry}, s.recentLogs...)
	}
}

func (s *AppState) isWhitelisted(ipStr string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isWhitelistedLocked(ipStr)
}

func (s *AppState) isWhitelistedLocked(ipStr string) bool {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return true
	}
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return true
	}

	for _, w := range s.config.WhitelistIPs {
		target := strings.TrimSpace(w.IP)
		if target == "" {
			continue
		}
		if target == ipStr {
			return true
		}
		if strings.Contains(target, "/") {
			_, ipNet, err := net.ParseCIDR(target)
			if err == nil && ipNet.Contains(parsedIP) {
				return true
			}
		}
	}
	return false
}

func (s *AppState) banIP(ip, reason string, durationHours int) {
	ip = strings.TrimSpace(ip)
	if isPrivateOrReservedIP(ip) {
		return
	}

	s.mu.Lock()
	if s.isWhitelistedLocked(ip) {
		s.mu.Unlock()
		log.Printf("[Whitelist] IP %s thuộc danh sách Cho Phép (Whitelist), bỏ qua chặn!", ip)
		return
	}
	if durationHours < 0 {
		if s.offenseCount == nil {
			s.offenseCount = make(map[string]int)
		}
		s.offenseCount[ip]++
		offenses := s.offenseCount[ip]
		if offenses == 1 {
			durationHours = s.config.DefaultBanTTL
			if durationHours <= 0 {
				durationHours = 24 // 24 hours default
			}
		} else if offenses == 2 {
			durationHours = 72 // Tái phạm lần 2: Cách ly 72 giờ
			reason = fmt.Sprintf("[Tái Phạm Lần 2 - 72h] %s", reason)
		} else {
			durationHours = 0 // Tái phạm lần 3+: Chặn VĨNH VIỄN
			reason = fmt.Sprintf("[Tái Phạm Lần %d - VĨNH VIỄN] %s", offenses, reason)
		}
	}

	now := time.Now()
	var expiresAt time.Time
	if durationHours > 0 {
		expiresAt = now.Add(time.Duration(durationHours) * time.Hour)
	}

	// Immediate Linux Kernel ipset drop (O(1))
	if runtime.GOOS == "linux" {
		exec.Command("ipset", "add", "vsafegate-blacklist", ip, "-exist").Run()
	}

	// Update in-memory Map & Config Slice
	entry := BannedIPEntry{
		IP:            ip,
		Reason:        reason,
		BannedAt:      now,
		ExpiresAt:     expiresAt,
		DurationHours: durationHours,
	}
	s.bannedMap[ip] = &entry

	// Sync config.BannedIPs
	found := false
	for i, b := range s.config.BannedIPs {
		if b.IP == ip {
			s.config.BannedIPs[i] = entry
			found = true
			break
		}
	}
	if !found {
		s.config.BannedIPs = append(s.config.BannedIPs, entry)
	}

	// Also sync legacy config.BlacklistIP
	legacyFound := false
	for _, oldIP := range s.config.BlacklistIP {
		if oldIP == ip {
			legacyFound = true
			break
		}
	}
	if !legacyFound {
		s.config.BlacklistIP = append(s.config.BlacklistIP, ip)
	}

	ttlInfo := "Vĩnh viễn"
	if durationHours > 0 {
		ttlInfo = fmt.Sprintf("TTL: %d giờ", durationHours)
	}
	logAction := fmt.Sprintf("KERNEL DROP (ipset, %s)", ttlInfo)

	logEntry := AttackLog{
		ID:        fmt.Sprintf("ban-%d", time.Now().UnixNano()),
		Timestamp: now,
		ClientIP:  ip,
		Host:      "Firewall/Kernel",
		URI:       reason,
		Method:    "TCP/DROP",
		RuleID:    9999,
		RuleName:  reason,
		Action:    logAction,
		UserAgent: fmt.Sprintf("vSafeGate Auto-Defense (%s)", ttlInfo),
	}

	s.addRecentLog(logEntry)
	s.mu.Unlock()

	// Persistent log to JSONL
	if s.logManager != nil {
		s.logManager.Append(logEntry)
	}

	s.saveConfig()
	if s.reloadManager != nil {
		s.reloadManager.Trigger()
	}
}

func (s *AppState) clearAllBannedIPs(reason string) {
	// Flush kernel ipset
	if runtime.GOOS == "linux" {
		exec.Command("ipset", "flush", "vsafegate-blacklist").Run()
	}

	s.mu.Lock()
	count := len(s.config.BannedIPs)
	s.bannedMap = make(map[string]*BannedIPEntry)
	s.config.BannedIPs = []BannedIPEntry{}
	s.config.BlacklistIP = []string{}

	if reason == "" {
		reason = "[Admin] Xóa toàn bộ danh sách Blacklist"
	}

	logEntry := AttackLog{
		ID:        fmt.Sprintf("clear-bl-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		ClientIP:  "*",
		Host:      "Firewall/Kernel",
		URI:       fmt.Sprintf("%s (Đã gỡ %d IP)", reason, count),
		Method:    "TCP/FLUSH",
		RuleID:    9998,
		RuleName:  reason,
		Action:    "ALL_UNBANNED",
		UserAgent: "vSafeGate Auto-Defense",
	}

	s.addRecentLog(logEntry)
	s.mu.Unlock()

	// Persistent log to JSONL
	if s.logManager != nil {
		s.logManager.Append(logEntry)
	}

	s.saveConfig()
	if s.reloadManager != nil {
		s.reloadManager.Trigger()
	}
}

func (s *AppState) unbanIP(ip, reason string) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}

	// Delete from kernel ipset
	if runtime.GOOS == "linux" {
		exec.Command("ipset", "del", "vsafegate-blacklist", ip).Run()
	}

	s.mu.Lock()
	delete(s.bannedMap, ip)

	filteredBanned := make([]BannedIPEntry, 0, len(s.config.BannedIPs))
	for _, b := range s.config.BannedIPs {
		if b.IP != ip {
			filteredBanned = append(filteredBanned, b)
		}
	}
	s.config.BannedIPs = filteredBanned

	filteredLegacy := make([]string, 0, len(s.config.BlacklistIP))
	for _, b := range s.config.BlacklistIP {
		if b != ip {
			filteredLegacy = append(filteredLegacy, b)
		}
	}
	s.config.BlacklistIP = filteredLegacy

	if reason == "" {
		reason = "[Admin] Mở khóa IP thủ công"
	}

	logEntry := AttackLog{
		ID:        fmt.Sprintf("unban-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		ClientIP:  ip,
		Host:      "Firewall/Kernel",
		URI:       reason,
		Method:    "TCP/UNBAN",
		RuleID:    9998,
		RuleName:  reason,
		Action:    "UNBANNED",
		UserAgent: "vSafeGate Auto-Defense",
	}

	s.addRecentLog(logEntry)
	s.mu.Unlock()

	// Persistent log to JSONL
	if s.logManager != nil {
		s.logManager.Append(logEntry)
	}

	s.saveConfig()
	if s.reloadManager != nil {
		s.reloadManager.Trigger()
	}
}

func (s *AppState) getBannedIPList() []BannedIPResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]BannedIPResponse, 0, len(s.config.BannedIPs))
	for _, b := range s.config.BannedIPs {
		remSec, remText := formatRemainingTime(b.ExpiresAt)
		result = append(result, BannedIPResponse{
			IP:               b.IP,
			Reason:           b.Reason,
			BannedAt:         b.BannedAt,
			ExpiresAt:        b.ExpiresAt,
			DurationHours:    b.DurationHours,
			IsPermanent:      b.ExpiresAt.IsZero(),
			RemainingSeconds: remSec,
			RemainingText:    remText,
		})
	}
	return result
}

func (s *AppState) startBanTTLExpirer() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			now := time.Now()
			var expiredIPs []string

			s.mu.RLock()
			for _, b := range s.config.BannedIPs {
				if !b.ExpiresAt.IsZero() && now.After(b.ExpiresAt) {
					expiredIPs = append(expiredIPs, b.IP)
				}
			}
			s.mu.RUnlock()

			for _, ip := range expiredIPs {
				log.Printf("[Blacklist TTL] IP %s ban duration expired. Automatically unbanning...", ip)
				s.unbanIP(ip, "[TTL Expired] Tự động mở khóa sau thời gian cách ly")
			}
		}
	}()
}

func (s *AppState) addWhitelistIP(ip, note string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("Địa chỉ IP không được để trống")
	}

	// Validate IP or CIDR
	if strings.Contains(ip, "/") {
		if _, _, err := net.ParseCIDR(ip); err != nil {
			return fmt.Errorf("Định dạng dải mạng CIDR không hợp lệ (ví dụ: 192.168.1.0/24)")
		}
	} else {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("Địa chỉ IP không hợp lệ (ví dụ: 1.2.3.4)")
		}
	}

	s.mu.Lock()

	// If this IP was currently banned, unban it immediately
	delete(s.bannedMap, ip)
	newBanned := make([]BannedIPEntry, 0, len(s.config.BannedIPs))
	for _, b := range s.config.BannedIPs {
		if b.IP != ip {
			newBanned = append(newBanned, b)
		}
	}
	s.config.BannedIPs = newBanned
	if runtime.GOOS == "linux" {
		exec.Command("ipset", "del", "vsafegate-blacklist", ip).Run()
	}

	// Add or update Whitelist
	found := false
	for i, w := range s.config.WhitelistIPs {
		if w.IP == ip {
			s.config.WhitelistIPs[i].Note = note
			found = true
			break
		}
	}
	if !found {
		s.config.WhitelistIPs = append(s.config.WhitelistIPs, WhitelistIPEntry{
			IP:        ip,
			Note:      note,
			CreatedAt: time.Now(),
		})
	}

	// Add to kernel ipset vsafegate-allowed
	if runtime.GOOS == "linux" {
		exec.Command("ipset", "add", "vsafegate-allowed", ip, "-exist").Run()
	}
	s.mu.Unlock()

	s.saveConfig()
	return nil
}

func (s *AppState) removeWhitelistIP(ip string) error {
	ip = strings.TrimSpace(ip)
	s.mu.Lock()

	newWL := make([]WhitelistIPEntry, 0, len(s.config.WhitelistIPs))
	for _, w := range s.config.WhitelistIPs {
		if w.IP != ip {
			newWL = append(newWL, w)
		}
	}
	s.config.WhitelistIPs = newWL

	// Remove from kernel ipset vsafegate-allowed
	if runtime.GOOS == "linux" {
		exec.Command("ipset", "del", "vsafegate-allowed", ip).Run()
	}
	s.mu.Unlock()

	s.saveConfig()
	return nil
}
