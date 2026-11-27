package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestAppState(t *testing.T) *AppState {
	t.Helper()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	caddyPath := filepath.Join(tmpDir, "caddy.json")
	rulesDir := filepath.Join(tmpDir, "rules.d")
	logsPath := filepath.Join(tmpDir, "attacks.jsonl")

	s := initDefaults(cfgPath, caddyPath, rulesDir, logsPath)
	s.mu.Lock()
	s.certsDir = filepath.Join(tmpDir, "certs")
	s.config.AdminUser = "admin"
	s.config.AdminPassword = hashPassword("InitialStrongPass!123")
	s.mu.Unlock()
	s.saveConfig()
	return s
}

func TestAuthPhase0_PBKDFCompatAndIterations(t *testing.T) {
	pw := "Str0ng!Pass#2026"
	modern := hashPassword(pw)
	if !strings.HasPrefix(modern, fmt.Sprintf("$pbkdf_sha256$%d$", pbkdfDefaultIterations)) {
		t.Fatalf("expected 120000-iteration prefix, got %q", modern)
	}
	if !checkPassword(modern, pw) {
		t.Fatal("checkPassword rejected valid 120k PBKDF hash")
	}
	if checkPassword(modern, "wrong") {
		t.Fatal("checkPassword accepted wrong password for 120k hash")
	}

	// Legacy 4-part format (10,000 iterations) must remain supported
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	legacySum := derivePBKDFSHA256(salt, pw, 10000)
	legacyHash := fmt.Sprintf("$pbkdf_sha256$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(legacySum))
	if !checkPassword(legacyHash, pw) {
		t.Fatal("checkPassword failed on legacy 4-part 10k PBKDF hash")
	}
	if checkPassword(legacyHash, "wrong") {
		t.Fatal("checkPassword accepted wrong password on legacy hash")
	}

	// Out-of-bounds iteration counts must be rejected cleanly
	excessive := fmt.Sprintf("$pbkdf_sha256$99999999$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(legacySum))
	if checkPassword(excessive, pw) {
		t.Fatal("checkPassword must reject iterations > 2000000")
	}
	zeroIter := fmt.Sprintf("$pbkdf_sha256$0$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(legacySum))
	if checkPassword(zeroIter, pw) {
		t.Fatal("checkPassword must reject 0 iterations")
	}
}

func TestAuthPhase0_ChangeLocalAdminPassword(t *testing.T) {
	s := newTestAppState(t)
	state = s

	if err := changeLocalAdminPassword(s, "admin", "WrongOldPass", "NewValidPass123!"); err == nil {
		t.Fatal("expected error for incorrect current password")
	}
	if err := changeLocalAdminPassword(s, "admin", "InitialStrongPass!123", "short"); err == nil {
		t.Fatal("expected error for new password < 8 characters")
	}
	if err := changeLocalAdminPassword(s, "otheruser", "InitialStrongPass!123", "NewValidPass123!"); err == nil {
		t.Fatal("expected error for wrong username")
	}

	if err := changeLocalAdminPassword(s, "admin", "InitialStrongPass!123", "UpdatedSecure!2026"); err != nil {
		t.Fatalf("unexpected error changing valid password: %v", err)
	}
	s.mu.RLock()
	stored := s.config.AdminPassword
	s.mu.RUnlock()
	if !strings.HasPrefix(stored, "$pbkdf_sha256$120000$") {
		t.Fatalf("expected updated hash with 120000 iterations, got %q", stored)
	}
	if !checkPassword(stored, "UpdatedSecure!2026") {
		t.Fatal("updated password failed verification")
	}
}

func TestAuthPhase0_LoginRateLimiter(t *testing.T) {
	lim := newLoginRateLimiter()
	cur := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	lim.nowFn = func() time.Time { return cur }

	ip := "198.51.100.77"
	for i := 1; i <= 4; i++ {
		locked, _ := lim.RecordFailure(ip)
		if locked {
			t.Fatalf("did not expect lock after %d failure(s)", i)
		}
		if blk, _ := lim.IsBlocked(ip); blk {
			t.Fatalf("IsBlocked returned true prematurely at attempt %d", i)
		}
	}

	locked, dur := lim.RecordFailure(ip)
	if !locked || dur != 10*time.Minute {
		t.Fatalf("expected 10m lockout on 5th failure, got locked=%v dur=%v", locked, dur)
	}
	if blk, rem := lim.IsBlocked(ip); !blk || rem <= 0 {
		t.Fatalf("expected blocked=true after 5th failure, got blocked=%v rem=%v", blk, rem)
	}

	// Advance past lockout -> unblocked cleanly
	cur = cur.Add(10*time.Minute + time.Second)
	if blk, _ := lim.IsBlocked(ip); blk {
		t.Fatal("expected IP to unblock after lockout duration elapsed")
	}

	// Failures spaced beyond window reset counter
	lim.RecordFailure(ip)
	cur = cur.Add(6 * time.Minute)
	locked, _ = lim.RecordFailure(ip)
	if locked {
		t.Fatal("window expiry should reset failure count back to 1")
	}
	lim.Reset(ip)
	if blk, _ := lim.IsBlocked(ip); blk {
		t.Fatal("Reset should clear entry")
	}
}

func TestAuthPhase0_ExtractClientIP(t *testing.T) {
	// Untrusted direct remote host spoofing X-Forwarded-For must be ignored
	reqUntrusted := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	reqUntrusted.RemoteAddr = "203.0.113.9:54321"
	reqUntrusted.Header.Set("X-Forwarded-For", "127.0.0.1")
	reqUntrusted.Header.Set("X-Real-IP", "1.2.3.4")
	if got := extractClientIP(reqUntrusted); got != "203.0.113.9" {
		t.Fatalf("spoofed XFF from untrusted remote must be ignored, got %q", got)
	}

	// Trusted loopback proxy hop honors X-Forwarded-For
	reqLoopbackXFF := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	reqLoopbackXFF.RemoteAddr = "127.0.0.1:41234"
	reqLoopbackXFF.Header.Set("X-Forwarded-For", "198.51.100.12, 10.0.0.1")
	if got := extractClientIP(reqLoopbackXFF); got != "198.51.100.12" {
		t.Fatalf("expected XFF client IP from loopback proxy, got %q", got)
	}

	// Trusted loopback hop falls back to X-Real-IP
	reqLoopbackXRI := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	reqLoopbackXRI.RemoteAddr = "[::1]:41234"
	reqLoopbackXRI.Header.Set("X-Real-IP", "198.51.100.88")
	if got := extractClientIP(reqLoopbackXRI); got != "198.51.100.88" {
		t.Fatalf("expected X-Real-IP from ::1 proxy, got %q", got)
	}
}

func TestAuthPhase0_CSRFLockoutCookieSecureAndPasswordEndpoint(t *testing.T) {
	s := newTestAppState(t)
	handler := csrfMiddleware(setupRouter(s))

	// 1. CSRF rejections
	csrfCases := []struct {
		name   string
		header map[string]string
	}{
		{"cross-site sec-fetch-site", map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{"null origin", map[string]string{"Origin": "null"}},
		{"mismatched origin", map[string]string{"Origin": "https://attacker.evil"}},
		{"mismatched referer", map[string]string{"Referer": "http://attacker.evil/phish"}},
	}
	for _, tc := range csrfCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/login", strings.NewReader(`{}`))
			req.Host = "127.0.0.1:8080"
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s: expected 403 Forbidden, got %d", tc.name, rec.Code)
			}
		})
	}

	// 2. Successful HTTPS login returns HttpOnly, Secure, SameSite=Strict cookie
	loginBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "InitialStrongPass!123",
	})
	loginReq := httptest.NewRequest(http.MethodPost, "https://waf.example.com/api/login", bytes.NewReader(loginBody))
	loginReq.Host = "waf.example.com"
	loginReq.RemoteAddr = "127.0.0.1:44444"
	loginReq.Header.Set("Origin", "https://waf.example.com")
	loginReq.Header.Set("X-Forwarded-Proto", "https")
	loginReq.Header.Set("X-Forwarded-For", "198.51.100.15")
	loginRec := httptest.NewRecorder()
	handler.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on valid login, got %d (%s)", loginRec.Code, loginRec.Body.String())
	}
	cookies := loginRec.Result().Cookies()
	var sessCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "vsafegate_session" {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatal("missing vsafegate_session cookie")
	}
	if !sessCookie.HttpOnly || !sessCookie.Secure || sessCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("weak cookie attributes: HttpOnly=%v Secure=%v SameSite=%v", sessCookie.HttpOnly, sessCookie.Secure, sessCookie.SameSite)
	}

	// 3. Password change endpoint with valid session + matching Origin
	pwdPayload, _ := json.Marshal(map[string]string{
		"current_password": "InitialStrongPass!123",
		"new_password":     "ChangedPass!2026",
	})
	pwdReq := httptest.NewRequest(http.MethodPost, "https://waf.example.com/api/auth/password", bytes.NewReader(pwdPayload))
	pwdReq.Host = "waf.example.com"
	pwdReq.Header.Set("Origin", "https://waf.example.com")
	pwdReq.AddCookie(sessCookie)
	pwdRec := httptest.NewRecorder()
	handler.ServeHTTP(pwdRec, pwdReq)
	if pwdRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/auth/password, got %d (%s)", pwdRec.Code, pwdRec.Body.String())
	}

	// 4. 5 failed login attempts from same IP trigger 429 lockout
	badBody, _ := json.Marshal(map[string]string{"username": "admin", "password": "bad"})
	for i := 1; i <= 5; i++ {
		badReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/login", bytes.NewReader(badBody))
		badReq.Host = "127.0.0.1:8080"
		badReq.RemoteAddr = "203.0.113.55:1111"
		badRec := httptest.NewRecorder()
		handler.ServeHTTP(badRec, badReq)
		if i < 5 && badRec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d expected 401, got %d", i, badRec.Code)
		}
		if i == 5 && badRec.Code != http.StatusTooManyRequests {
			t.Fatalf("5th failed attempt expected 429 Too Many Requests, got %d", badRec.Code)
		}
	}
}

func TestPhase0_LinuxAuthHelperScriptSafety(t *testing.T) {
	script := buildAuthHelperScript()
	if !strings.Contains(script, "libc.musl-x86_64.so.1") || !strings.Contains(script, "libc.musl-aarch64.so.1") {
		t.Fatal("expected vsafegate-auth helper script to include Alpine musl ctypes candidates")
	}
	if !strings.Contains(script, "is_usable_shadow_hash") || !strings.Contains(script, "hmac.compare_digest") {
		t.Fatal("expected vsafegate-auth helper script to validate usable shadow hashes and use constant-time compare")
	}
	if !strings.Contains(script, "os.geteuid() != 0") {
		t.Fatal("expected vsafegate-auth helper script to forbid passwordless su fallback when executed as UID 0")
	}
}
