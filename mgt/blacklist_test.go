package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBlacklistTTLManagement(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vsafegate-bl-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfgPath := filepath.Join(tmpDir, "config.json")
	caddyPath := filepath.Join(tmpDir, "Caddyfile")
	rulesPath := filepath.Join(tmpDir, "rules.conf")
	logsPath := filepath.Join(tmpDir, "attacks.jsonl")

	s := initDefaults(cfgPath, caddyPath, rulesPath, logsPath)

	// 1. Ban IP with 24 hours TTL
	testIP := "198.51.100.5"
	s.banIP(testIP, "Test scanner", 24)

	s.mu.RLock()
	entry, exists := s.bannedMap[testIP]
	s.mu.RUnlock()

	if !exists || entry == nil {
		t.Fatalf("Expected IP %s to be banned in map", testIP)
	}
	if entry.DurationHours != 24 {
		t.Errorf("Expected DurationHours 24, got %d", entry.DurationHours)
	}
	if entry.ExpiresAt.IsZero() {
		t.Errorf("Expected ExpiresAt to be set for TTL ban")
	}

	// 2. Ban IP with Permanent (0 hours)
	permIP := "198.51.100.99"
	s.banIP(permIP, "Permanent ban test", 0)

	s.mu.RLock()
	permEntry, permExists := s.bannedMap[permIP]
	s.mu.RUnlock()

	if !permExists || permEntry == nil {
		t.Fatalf("Expected IP %s to be banned", permIP)
	}
	if permEntry.DurationHours != 0 || !permEntry.ExpiresAt.IsZero() {
		t.Errorf("Expected permanent ban to have zero ExpiresAt")
	}

	// 3. Test Response list format
	list := s.getBannedIPList()
	if len(list) < 2 {
		t.Errorf("Expected at least 2 banned IPs, got %d", len(list))
	}

	// 4. Test Unban
	s.unbanIP(testIP, "Test unban")
	s.mu.RLock()
	_, stillBanned := s.bannedMap[testIP]
	s.mu.RUnlock()

	if stillBanned {
		t.Errorf("Expected IP %s to be unbanned", testIP)
	}

	// 5. Test Private IP is rejected
	s.banIP("192.168.1.50", "LAN IP", 24)
	s.mu.RLock()
	_, lanBanned := s.bannedMap["192.168.1.50"]
	s.mu.RUnlock()
	if lanBanned {
		t.Errorf("Private IP should never be banned")
	}

	// 6. Test Clear All
	s.clearAllBannedIPs("Test clear all")
	clearedList := s.getBannedIPList()
	if len(clearedList) != 0 {
		t.Errorf("Expected 0 banned IPs after clearAllBannedIPs, got %d", len(clearedList))
	}
}

func TestWhitelistAndDefensePolicy(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vsafegate-wl-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfgPath := filepath.Join(tmpDir, "config.json")
	caddyPath := filepath.Join(tmpDir, "Caddyfile")
	rulesPath := filepath.Join(tmpDir, "rules.conf")
	logsPath := filepath.Join(tmpDir, "attacks.jsonl")

	s := initDefaults(cfgPath, caddyPath, rulesPath, logsPath)

	// Add Whitelist IP
	wlIP := "203.0.113.10"
	if err := s.addWhitelistIP(wlIP, "Admin Office"); err != nil {
		t.Fatalf("Failed to add whitelist IP: %v", err)
	}

	// Verify Whitelist prevents ban
	s.banIP(wlIP, "Should be ignored", 24)
	s.mu.RLock()
	_, banned := s.bannedMap[wlIP]
	s.mu.RUnlock()
	if banned {
		t.Errorf("Whitelisted IP %s must never be banned", wlIP)
	}

	// Add Whitelist CIDR
	wlCIDR := "198.51.100.0/24"
	if err := s.addWhitelistIP(wlCIDR, "Branch Office CIDR"); err != nil {
		t.Fatalf("Failed to add whitelist CIDR: %v", err)
	}
	// Try banning an IP in that CIDR
	s.banIP("198.51.100.45", "Should be ignored due to CIDR whitelist", 24)
	s.mu.RLock()
	_, bannedCIDR := s.bannedMap["198.51.100.45"]
	s.mu.RUnlock()
	if bannedCIDR {
		t.Errorf("IP inside whitelisted CIDR must never be banned")
	}

	// Remove Whitelist IP
	if err := s.removeWhitelistIP(wlIP); err != nil {
		t.Fatalf("Failed to remove whitelist IP: %v", err)
	}
	s.mu.RLock()
	foundWL := false
	for _, w := range s.config.WhitelistIPs {
		if w.IP == wlIP {
			foundWL = true
			break
		}
	}
	s.mu.RUnlock()
	if foundWL {
		t.Errorf("Expected IP %s to be removed from whitelist", wlIP)
	}
}
