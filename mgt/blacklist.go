package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var cgnatBanGuardPrefix = netip.MustParsePrefix("100.64.0.0/10")

type OffenseRecord struct {
	Count      int       `json:"count"`
	LastSeenAt time.Time `json:"last_seen_at"`
	LastReason string    `json:"last_reason,omitempty"`
}

type persistedBansState struct {
	Version   int                      `json:"version"`
	UpdatedAt time.Time                `json:"updated_at"`
	Offenses  map[string]OffenseRecord `json:"offenses"`
}

func (s *AppState) effectiveBansStatePath() string {
	if s != nil && strings.TrimSpace(s.bansStatePath) != "" {
		return strings.TrimSpace(s.bansStatePath)
	}
	if s != nil && s.configPath != "" && s.configPath != "/etc/vsafegate/config.json" && s.configPath != "./config.json" {
		return filepath.Join(filepath.Dir(s.configPath), "bans_state.json")
	}
	if os.Getenv("ENV") == "dev" {
		return "./bans_state.json"
	}
	return "/var/lib/vsafegate/bans_state.json"
}

// normalizeBanTarget strictly validates an IP or non-zero CIDR target for blacklisting/escalation.
func normalizeBanTarget(raw string) (string, error) {
	str := strings.TrimSpace(raw)
	if str == "" {
		return "", fmt.Errorf("địa chỉ IP không được để trống")
	}
	if strings.Contains(str, "/") {
		pfx, err := netip.ParsePrefix(str)
		if err != nil {
			return "", fmt.Errorf("CIDR không hợp lệ: %q", str)
		}
		if pfx.Bits() == 0 {
			return "", fmt.Errorf("không cho phép dải mạng 0.0.0.0/0 hoặc ::/0")
		}
		if pfx.Addr().Is4In6() {
			addr4 := pfx.Addr().Unmap()
			bits := pfx.Bits() - 96
			if bits <= 0 {
				return "", fmt.Errorf("CIDR không hợp lệ: %q", str)
			}
			pfx = netip.PrefixFrom(addr4, bits)
		}
		return pfx.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(str)
	if err != nil {
		return "", fmt.Errorf("địa chỉ IP không hợp lệ: %q", str)
	}
	return addr.Unmap().String(), nil
}

func isPrivateOrReservedIP(ipStr string) bool {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" || ipStr == "127.0.0.1" || ipStr == "::1" || ipStr == "localhost" {
		return true
	}
	if strings.Contains(ipStr, "/") {
		pfx, err := netip.ParsePrefix(ipStr)
		if err != nil || pfx.Bits() == 0 {
			return true
		}
		addr := pfx.Addr().Unmap()
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() || cgnatBanGuardPrefix.Contains(addr) {
			return true
		}
		// Reject overly broad prefixes that overlap private/loopback space
		if addr.Is4() && pfx.Bits() < 8 {
			return true
		}
		return false
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() || cgnatBanGuardPrefix.Contains(addr) {
		return true
	}
	return false
}

func (s *AppState) loadBansState() {
	if s == nil {
		return
	}
	path := s.effectiveBansStatePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var st persistedBansState
	if err := json.Unmarshal(data, &st); err != nil {
		return
	}

	s.mu.Lock()
	if s.offenseCount == nil {
		s.offenseCount = make(map[string]int)
	}
	if s.offenseRecords == nil {
		s.offenseRecords = make(map[string]OffenseRecord)
	}
	for rawIP, rec := range st.Offenses {
		norm, err := normalizeBanTarget(rawIP)
		if err != nil || rec.Count <= 0 || isPrivateOrReservedIP(norm) || isTrustedProxyOrCloudflareIP(norm, s.config) {
			continue
		}
		s.offenseCount[norm] = rec.Count
		s.offenseRecords[norm] = rec
	}
	s.mu.Unlock()
}

func (s *AppState) saveBansState() {
	if s == nil {
		return
	}
	path := s.effectiveBansStatePath()
	if path == "" {
		return
	}

	s.bansStateMu.Lock()
	defer s.bansStateMu.Unlock()

	s.mu.RLock()
	st := persistedBansState{
		Version:   1,
		UpdatedAt: time.Now().UTC(),
		Offenses:  make(map[string]OffenseRecord, len(s.offenseCount)),
	}
	for ip, cnt := range s.offenseCount {
		if cnt <= 0 {
			continue
		}
		rec := s.offenseRecords[ip]
		rec.Count = cnt
		if rec.LastSeenAt.IsZero() {
			rec.LastSeenAt = st.UpdatedAt
		}
		st.Offenses[ip] = rec
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0750)
	tmp := path + ".tmp"
	if os.WriteFile(tmp, data, 0600) == nil {
		if os.Rename(tmp, path) == nil {
			_ = os.Chmod(path, 0600)
		}
	}
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

func (s *AppState) publishAttackLog(entry AttackLog) {
	if s == nil {
		return
	}
	if s.logManager != nil {
		_ = s.logManager.Append(entry)
	}
	if s.telemetry != nil {
		s.telemetry.RecordThreatEvent(entry)
	}
	if s.sseBroker != nil {
		s.sseBroker.Publish("attack", entry)
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
	if strings.Contains(ipStr, "/") {
		pfx, err := netip.ParsePrefix(ipStr)
		if err != nil {
			return true
		}
		for _, w := range s.config.WhitelistIPs {
			target := strings.TrimSpace(w.IP)
			if target == "" {
				continue
			}
			if wpfx, perr := netip.ParsePrefix(target); perr == nil {
				if wpfx.Overlaps(pfx) {
					return true
				}
			} else if waddr, aerr := netip.ParseAddr(target); aerr == nil {
				if pfx.Contains(waddr.Unmap()) {
					return true
				}
			}
		}
		return false
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
	norm, err := normalizeBanTarget(ip)
	if err != nil || isPrivateOrReservedIP(norm) {
		return
	}
	ip = norm

	s.mu.Lock()
	if s.isWhitelistedLocked(ip) {
		s.mu.Unlock()
		log.Printf("[Whitelist] IP %s thuộc danh sách Cho Phép (Whitelist), bỏ qua chặn!", ip)
		return
	}
	if isTrustedProxyOrCloudflareIP(ip, s.config) {
		s.mu.Unlock()
		log.Printf("[Anti-Self-DoS] IP %s thuộc Cloudflare Edge / Trusted Proxy, từ chối đưa vào Blacklist Kernel!", ip)
		return
	}

	offenseChanged := false
	if durationHours < 0 {
		if s.offenseCount == nil {
			s.offenseCount = make(map[string]int)
		}
		if s.offenseRecords == nil {
			s.offenseRecords = make(map[string]OffenseRecord)
		}
		s.offenseCount[ip]++
		offenses := s.offenseCount[ip]
		s.offenseRecords[ip] = OffenseRecord{
			Count:      offenses,
			LastSeenAt: time.Now().UTC(),
			LastReason: reason,
		}
		offenseChanged = true

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

	// Immediate Linux Kernel ipset drop (O(1)) for IPv4 addresses/CIDRs
	if runtime.GOOS == "linux" {
		if isIPv4Target(ip) {
			_ = exec.Command("ipset", "add", "vsafegate-blacklist", ip, "-exist").Run()
		}
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

	if offenseChanged {
		s.saveBansState()
	}
	s.publishAttackLog(logEntry)
	if s.alertEngine != nil {
		s.alertEngine.NotifyIPBan(ip, reason, "Kernel ipset", durationHours)
	}

	s.saveConfig()
	if s.reloadManager != nil {
		s.reloadManager.Trigger()
	}
}

func isIPv4Target(target string) bool {
	if strings.Contains(target, "/") {
		pfx, err := netip.ParsePrefix(target)
		return err == nil && pfx.Addr().Unmap().Is4()
	}
	addr, err := netip.ParseAddr(target)
	return err == nil && addr.Unmap().Is4()
}

func (s *AppState) clearAllBannedIPs(reason string) {
	if runtime.GOOS == "linux" {
		_ = exec.Command("ipset", "flush", "vsafegate-blacklist").Run()
	}

	s.mu.Lock()
	count := len(s.config.BannedIPs)
	s.bannedMap = make(map[string]*BannedIPEntry)
	s.config.BannedIPs = []BannedIPEntry{}
	s.config.BlacklistIP = []string{}
	s.offenseCount = make(map[string]int)
	s.offenseRecords = make(map[string]OffenseRecord)

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

	s.saveBansState()
	s.publishAttackLog(logEntry)
	s.saveConfig()
	if s.reloadManager != nil {
		s.reloadManager.Trigger()
	}
}

func (s *AppState) unbanIP(ip, reason string) {
	resetOffenses := !strings.HasPrefix(reason, "[TTL Expired]")
	s.unbanIPInternal(ip, reason, resetOffenses)
}

func (s *AppState) unbanIPInternal(ip, reason string, resetOffenses bool) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	if norm, err := normalizeBanTarget(ip); err == nil {
		ip = norm
	}

	if runtime.GOOS == "linux" {
		_ = exec.Command("ipset", "del", "vsafegate-blacklist", ip).Run()
	}

	s.mu.Lock()
	delete(s.bannedMap, ip)
	offenseChanged := false
	if resetOffenses {
		if _, ok := s.offenseCount[ip]; ok {
			delete(s.offenseCount, ip)
			offenseChanged = true
		}
		delete(s.offenseRecords, ip)
	}

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

	if offenseChanged {
		s.saveBansState()
	}
	s.publishAttackLog(logEntry)
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
				s.unbanIPInternal(ip, "[TTL Expired] Tự động mở khóa sau thời gian cách ly", false)
			}
			s.expireShieldBans(now)
		}
	}()
}

func normalizeWhitelistInput(raw string) (string, error) {
	ip := strings.TrimSpace(raw)
	if ip == "" {
		return "", fmt.Errorf("Địa chỉ IP không được để trống")
	}
	if strings.Contains(ip, "/") {
		pfx, err := netip.ParsePrefix(ip)
		if err != nil {
			return "", fmt.Errorf("Định dạng dải mạng CIDR không hợp lệ (ví dụ: 192.168.1.0/24)")
		}
		if pfx.Bits() == 0 {
			return "", fmt.Errorf("Không cho phép thêm dải mạng 0.0.0.0/0 hoặc ::/0 vào Whitelist")
		}
		if pfx.Addr().Is4In6() {
			addr4 := pfx.Addr().Unmap()
			bits := pfx.Bits() - 96
			if bits < 0 {
				bits = 0
			}
			pfx = netip.PrefixFrom(addr4, bits)
		}
		return pfx.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", fmt.Errorf("Địa chỉ IP không hợp lệ (ví dụ: 1.2.3.4)")
	}
	return addr.Unmap().String(), nil
}

func (s *AppState) addWhitelistIP(ip, note string) error {
	norm, err := normalizeWhitelistInput(ip)
	if err != nil {
		return err
	}
	ip = norm

	s.mu.Lock()

	// If this IP was currently banned at kernel or L7 Shield, unban it immediately
	delete(s.bannedMap, ip)
	offenseChanged := false
	if _, ok := s.offenseCount[ip]; ok {
		delete(s.offenseCount, ip)
		offenseChanged = true
	}
	delete(s.offenseRecords, ip)

	newBanned := make([]BannedIPEntry, 0, len(s.config.BannedIPs))
	for _, b := range s.config.BannedIPs {
		if b.IP != ip {
			newBanned = append(newBanned, b)
		}
	}
	s.config.BannedIPs = newBanned
	newLegacy := make([]string, 0, len(s.config.BlacklistIP))
	for _, b := range s.config.BlacklistIP {
		if b != ip {
			newLegacy = append(newLegacy, b)
		}
	}
	s.config.BlacklistIP = newLegacy

	shieldChanged := false
	newShield := make([]ShieldBanEntry, 0, len(s.config.ShieldBannedIPs))
	for _, sb := range s.config.ShieldBannedIPs {
		if sb.IP == ip {
			shieldChanged = true
			continue
		}
		newShield = append(newShield, sb)
	}
	s.config.ShieldBannedIPs = newShield

	if runtime.GOOS == "linux" {
		_ = exec.Command("ipset", "del", "vsafegate-blacklist", ip).Run()
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

	// Immediately add to kernel ipset vsafegate-whitelist & vsafegate-allowed on Linux
	if runtime.GOOS == "linux" {
		_ = exec.Command("ipset", "add", "vsafegate-whitelist", ip, "-exist").Run()
		_ = exec.Command("ipset", "add", "vsafegate-allowed", ip, "-exist").Run()
	}
	s.mu.Unlock()

	if offenseChanged {
		s.saveBansState()
	}
	s.saveConfig()
	if shieldChanged && s.reloadManager != nil {
		s.reloadManager.Trigger()
	}
	s.triggerFirewallSync()
	return nil
}

func (s *AppState) removeWhitelistIP(ip string) error {
	trimmed := strings.TrimSpace(ip)
	norm, err := normalizeWhitelistInput(trimmed)
	if err != nil {
		norm = trimmed
	}

	s.mu.Lock()
	newWL := make([]WhitelistIPEntry, 0, len(s.config.WhitelistIPs))
	for _, w := range s.config.WhitelistIPs {
		if w.IP != trimmed && w.IP != norm {
			newWL = append(newWL, w)
		}
	}
	s.config.WhitelistIPs = newWL
	s.mu.Unlock()

	s.saveConfig()
	s.triggerFirewallSync()
	return nil
}
