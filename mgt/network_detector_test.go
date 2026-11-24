package main

import (
	"os"
	"testing"
	"time"
)

func TestDetectNetworkInterfaces(t *testing.T) {
	s := &AppState{
		config: Config{
			WhitelistIPs: []WhitelistIPEntry{
				{IP: "127.0.0.1", Note: "Loopback", CreatedAt: time.Now()},
			},
		},
	}

	detected := s.detectNetworkInterfaces()
	// Should at least run without panics or errors
	t.Logf("Detected %d network interfaces on this host", len(detected))
	for _, ifi := range detected {
		t.Logf(" - [%s] Name: %s, IP: %s, Subnet: %s, Recommended: %s, WL: %v",
			ifi.Type, ifi.Name, ifi.IP, ifi.CIDR, ifi.RecommendedCIDR, ifi.IsWhitelisted)
	}
}

func TestNetworkDetectorApplyRoutes(t *testing.T) {
	testFile := "test_config_detector.json"
	defer os.Remove(testFile)
	defer os.Remove(testFile + ".tmp")

	s := &AppState{
		configPath: testFile,
		config: Config{
			WhitelistIPs: []WhitelistIPEntry{
				{IP: "127.0.0.1", Note: "Loopback", CreatedAt: time.Now()},
			},
		},
	}

	// Test adding a detected interface
	err := s.addWhitelistIP("100.64.0.0/10", "Tailscale VPN Test")
	if err != nil {
		t.Fatalf("Failed to add detected interface: %v", err)
	}

	found := false
	for _, w := range s.config.WhitelistIPs {
		if w.IP == "100.64.0.0/10" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Expected 100.64.0.0/10 in WhitelistIPs")
	}
}
