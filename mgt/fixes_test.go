package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestPasswordHashing(t *testing.T) {
	plain := "SecretP@ssw0rd123!"
	hashed := hashPassword(plain)

	if !strings.HasPrefix(hashed, "$pbkdf_sha256$") {
		t.Fatalf("Expected $pbkdf_sha256$ prefix, got %s", hashed)
	}

	if !checkPassword(hashed, plain) {
		t.Fatalf("Password verification failed for valid password")
	}

	if checkPassword(hashed, "WrongPassword") {
		t.Fatalf("Password verification succeeded for wrong password")
	}

	// Test backward compatibility with plaintext
	if !checkPassword("legacyPlain", "legacyPlain") {
		t.Fatalf("Plaintext backward compatibility check failed")
	}
	if checkPassword("legacyPlain", "wrong") {
		t.Fatalf("Plaintext backward compatibility check accepted wrong password")
	}
}

func TestRuleSanitization(t *testing.T) {
	maliciousPattern := `(?i)admin"\nSecRule ARGS "@rx evil" "id:666,deny"`
	sanitizedPattern := sanitizeRulePattern(maliciousPattern)
	if strings.Contains(sanitizedPattern, "\n") || strings.Contains(sanitizedPattern, "\r") {
		t.Errorf("Sanitized pattern contains newline: %q", sanitizedPattern)
	}
	if !strings.Contains(sanitizedPattern, `\"`) {
		t.Errorf("Quotes were not properly escaped in pattern: %q", sanitizedPattern)
	}

	maliciousMsg := "Test\n'SecRule evil\n"
	sanitizedMsg := sanitizeRuleMessage(maliciousMsg)
	if strings.Contains(sanitizedMsg, "\n") || strings.Contains(sanitizedMsg, "\r") {
		t.Errorf("Sanitized msg contains newline: %q", sanitizedMsg)
	}
	if !strings.Contains(sanitizedMsg, `\'`) {
		t.Errorf("Single quotes were not properly escaped in message: %q", sanitizedMsg)
	}

	badHeader := "User-Agent\r\nInjected-Header: evil"
	cleanHeader := sanitizeHeaderName(badHeader)
	if cleanHeader != "X-Custom" {
		t.Errorf("Expected invalid header to fallback to X-Custom, got %q", cleanHeader)
	}

	goodHeader := "X-Forwarded-For"
	if sanitizeHeaderName(goodHeader) != goodHeader {
		t.Errorf("Expected valid header to remain unchanged")
	}
}

func TestAddRecentLogRingBuffer(t *testing.T) {
	s := &AppState{
		recentLogs: make([]AttackLog, 0),
	}

	for i := 0; i < 250; i++ {
		s.addRecentLog(AttackLog{
			ID:        "log-" + string(rune(i)),
			Timestamp: time.Now(),
		})
	}

	if len(s.recentLogs) != 200 {
		t.Fatalf("Expected recentLogs capped at 200, got %d", len(s.recentLogs))
	}
}

func TestSaveConfigDeadlockSafety(t *testing.T) {
	testFile := "test_config_deadlock.json"
	defer os.Remove(testFile)
	defer os.Remove(testFile + ".tmp")

	s := &AppState{configPath: testFile}

	// 1. Test saveConfigLocked while holding write lock (must NOT deadlock)
	done1 := make(chan bool)
	go func() {
		s.mu.Lock()
		s.saveConfigLocked()
		s.mu.Unlock()
		done1 <- true
	}()
	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("DEADLOCK in saveConfigLocked while holding s.mu.Lock()!")
	}

	// 2. Test saveConfig without holding lock (must NOT deadlock)
	done2 := make(chan bool)
	go func() {
		s.saveConfig()
		done2 <- true
	}()
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("DEADLOCK in saveConfig outside lock!")
	}
}

func TestL4ServicesSaveDeadlockPrevention(t *testing.T) {
	testFile := "test_config_l4.json"
	defer os.Remove(testFile)
	defer os.Remove(testFile + ".tmp")

	s := &AppState{
		configPath: testFile,
		config: Config{
			L4Services: []L4Service{
				{ID: "l4-test-1", Name: "Test 1", ListenPort: 19001, BackendAddr: "127.0.0.1:19001", Enabled: false},
			},
		},
	}

	// Simulate POST /api/l4/services
	newSvc := L4Service{
		ID:          "l4-test-2",
		Name:        "Test 2",
		ListenPort:  19002,
		BackendAddr: "127.0.0.1:19002",
		Enabled:     false,
	}

	done := make(chan bool)
	go func() {
		s.mu.Lock()
		s.config.L4Services = append(s.config.L4Services, newSvc)
		servicesCopy := make([]L4Service, len(s.config.L4Services))
		copy(servicesCopy, s.config.L4Services)
		s.mu.Unlock()

		s.saveConfig()
		l4Manager.Sync(servicesCopy)
		done <- true
	}()

	select {
	case <-done:
		if len(s.config.L4Services) != 2 {
			t.Fatalf("Expected 2 services, got %d", len(s.config.L4Services))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DEADLOCK in L4 services save flow!")
	}
}

