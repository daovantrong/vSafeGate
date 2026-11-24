package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentLogManager(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vsafegate-log-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "attacks.jsonl")
	lm := NewPersistentLogManager(logPath, 50000)

	// Append 10 entries
	for i := 1; i <= 10; i++ {
		entry := AttackLog{
			ID:        "log-" + string(rune('0'+i)),
			Timestamp: time.Now(),
			ClientIP:  "203.0.113." + string(rune('0'+i)),
			Host:      "app.example.com",
			URI:       "/test?id=1",
			Method:    "GET",
			RuleID:    1003,
			RuleName:  "SQL Injection Detected",
			Action:    "BLOCKED (403)",
			UserAgent: "sqlmap",
		}
		if err := lm.Append(entry); err != nil {
			t.Fatalf("Failed to append entry: %v", err)
		}
	}

	// Read recent
	recent, err := lm.ReadRecent(5)
	if err != nil {
		t.Fatalf("Failed to read recent: %v", err)
	}
	if len(recent) != 5 {
		t.Fatalf("Expected 5 recent entries, got %d", len(recent))
	}

	// TotalCount test
	totalEntries := lm.TotalCount()
	if totalEntries != 10 {
		t.Fatalf("Expected TotalCount 10, got %d", totalEntries)
	}

	// Query with search
	matched, total, err := lm.Query("sqlmap", 10, 0)
	if err != nil {
		t.Fatalf("Failed to query: %v", err)
	}
	if total == 0 || len(matched) == 0 {
		t.Fatalf("Expected matched entries, got %d", total)
	}

	// Pagination test: 10 items, limit 3 -> pages: 3, 3, 3, 1
	p1, t1, err := lm.Query("", 3, 0)
	if err != nil || len(p1) != 3 || t1 != 10 {
		t.Fatalf("Page 1 error: got %d items, total %d, err %v", len(p1), t1, err)
	}
	p2, t2, err := lm.Query("", 3, 3)
	if err != nil || len(p2) != 3 || t2 != 10 {
		t.Fatalf("Page 2 error: got %d items, total %d, err %v", len(p2), t2, err)
	}
	p4, t4, err := lm.Query("", 3, 9)
	if err != nil || len(p4) != 1 || t4 != 10 {
		t.Fatalf("Page 4 error: got %d items, total %d, err %v", len(p4), t4, err)
	}
	// Verify p1 and p2 have distinct items
	if p1[0].ID == p2[0].ID {
		t.Fatalf("Page 1 and Page 2 shouldn't overlap: %s == %s", p1[0].ID, p2[0].ID)
	}

	// Clear
	if err := lm.Clear(); err != nil {
		t.Fatalf("Failed to clear: %v", err)
	}

	recentAfterClear, _ := lm.ReadRecent(10)
	if len(recentAfterClear) != 0 {
		t.Fatalf("Expected 0 entries after clear, got %d", len(recentAfterClear))
	}
}

func TestFormatRemainingTime(t *testing.T) {
	// Zero time (permanent)
	sec, text := formatRemainingTime(time.Time{})
	if sec != 0 || text != "Vĩnh viễn" {
		t.Errorf("Expected permanent, got sec=%d text=%s", sec, text)
	}

	// Future time (e.g. 2 hours)
	future := time.Now().Add(2 * time.Hour)
	sec, text = formatRemainingTime(future)
	if sec <= 0 || text == "" {
		t.Errorf("Expected positive remaining, got sec=%d text=%s", sec, text)
	}

	// Past time (expired)
	past := time.Now().Add(-1 * time.Minute)
	sec, text = formatRemainingTime(past)
	if sec != 0 || text != "Đã hết hạn" {
		t.Errorf("Expected expired, got sec=%d text=%s", sec, text)
	}
}

func TestIsPrivateOrReservedIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"localhost", true},
		{"192.168.1.100", true},
		{"10.0.0.5", true},
		{"172.16.0.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"203.0.113.50", false},
		{"1.1.1.1", false},
	}

	for _, tc := range tests {
		got := isPrivateOrReservedIP(tc.ip)
		if got != tc.expected {
			t.Errorf("isPrivateOrReservedIP(%s) = %v; want %v", tc.ip, got, tc.expected)
		}
	}
}
