package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const pbkdfDefaultIterations = 120000

func derivePBKDFSHA256(salt []byte, password string, iterations int) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	sum := h.Sum(nil)
	for i := 1; i < iterations; i++ {
		h.Reset()
		h.Write(sum)
		h.Write(salt)
		sum = h.Sum(nil)
	}
	return sum
}

func hashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return password
	}
	sum := derivePBKDFSHA256(salt, password, pbkdfDefaultIterations)
	return fmt.Sprintf("$pbkdf_sha256$%d$%s$%s", pbkdfDefaultIterations, hex.EncodeToString(salt), hex.EncodeToString(sum))
}

func checkPassword(storedHashOrPlain, password string) bool {
	if strings.HasPrefix(storedHashOrPlain, "$pbkdf_sha256$") {
		parts := strings.Split(storedHashOrPlain, "$")
		switch len(parts) {
		case 4:
			// Legacy format: $pbkdf_sha256$<salt>$<hash> (10,000 iterations)
			salt, err1 := hex.DecodeString(parts[2])
			expectedHash, err2 := hex.DecodeString(parts[3])
			if err1 == nil && err2 == nil {
				sum := derivePBKDFSHA256(salt, password, 10000)
				return subtle.ConstantTimeCompare(sum, expectedHash) == 1
			}
		case 5:
			// Modern format: $pbkdf_sha256$<iterations>$<salt>$<hash>
			iters, err0 := strconv.Atoi(parts[2])
			salt, err1 := hex.DecodeString(parts[3])
			expectedHash, err2 := hex.DecodeString(parts[4])
			if err0 == nil && err1 == nil && err2 == nil && iters >= 1 && iters <= 2000000 {
				sum := derivePBKDFSHA256(salt, password, iters)
				return subtle.ConstantTimeCompare(sum, expectedHash) == 1
			}
		}
		return false
	}
	// Fallback for legacy plain-text password using constant time comparison
	return subtle.ConstantTimeCompare([]byte(storedHashOrPlain), []byte(password)) == 1
}

func initAuthHelper() {
	if runtime.GOOS != "linux" {
		return
	}
	authScript := `/usr/local/bin/vsafegate-auth`
	content := buildAuthHelperScript()
	if existing, err := os.ReadFile(authScript); err != nil || string(existing) != content {
		_ = os.WriteFile(authScript, []byte(content), 0755)
		_ = os.Chmod(authScript, 0755)
	}
}

func buildAuthHelperScript() string {
	return `#!/usr/bin/env python3
import sys, os, hmac

if len(sys.argv) < 2:
    sys.exit(1)

user = sys.argv[1]
pwd = sys.stdin.read().rstrip('\r\n')
if not user or not pwd:
    print("AUTH_FAIL")
    sys.exit(1)

def is_usable_shadow_hash(h):
    return bool(h) and not h.startswith('!') and not h.startswith('*') and h != 'x'

# 1. PAM check
try:
    import pamela
    if pamela.authenticate(user, pwd):
        print("AUTH_OK")
        sys.exit(0)
except Exception:
    pass

try:
    import pam
    p = pam.pam()
    if p.authenticate(user, pwd):
        print("AUTH_OK")
        sys.exit(0)
except Exception:
    pass

# 2. Legacy crypt + spwd (Python <= 3.12)
try:
    import spwd, crypt
    entry = spwd.getspnam(user)
    if not is_usable_shadow_hash(entry.sp_pwdp):
        print("AUTH_FAIL")
        sys.exit(1)
    res = crypt.crypt(pwd, entry.sp_pwdp)
    if res and hmac.compare_digest(res, entry.sp_pwdp):
        print("AUTH_OK")
        sys.exit(0)
    print("AUTH_FAIL")
    sys.exit(1)
except KeyError:
    print("AUTH_FAIL")
    sys.exit(1)
except Exception:
    pass

# 3. Direct /etc/shadow check using ctypes calling C library crypt()
# Supports glibc (Debian/Ubuntu) and musl (Alpine Linux) on Python 3.8 - 3.14+
try:
    import ctypes, ctypes.util
    libcrypt_name = ctypes.util.find_library('crypt')
    candidates = [
        libcrypt_name,
        'libcrypt.so.2',
        'libcrypt.so.1',
        'libcrypt.so',
        'libc.musl-x86_64.so.1',
        'libc.musl-aarch64.so.1',
        'libc.so',
        'libc.so.6',
        None,
    ]
    lib = None
    seen = set()
    for name in candidates:
        key = '<self>' if name is None else name
        if not key or key in seen:
            continue
        seen.add(key)
        try:
            cand = ctypes.CDLL(name)
            if hasattr(cand, 'crypt'):
                lib = cand
                break
        except Exception:
            continue

    if lib and hasattr(lib, 'crypt'):
        lib.crypt.restype = ctypes.c_char_p
        lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

        if os.path.exists('/etc/shadow'):
            with open('/etc/shadow', 'r') as f:
                for line in f:
                    parts = line.rstrip('\r\n').split(':')
                    if parts[0] == user and len(parts) > 1:
                        stored_hash = parts[1]
                        if not is_usable_shadow_hash(stored_hash):
                            print("AUTH_FAIL")
                            sys.exit(1)
                        res = lib.crypt(pwd.encode('utf-8'), stored_hash.encode('utf-8'))
                        res_str = res.decode('utf-8', errors='strict') if res else ''
                        if res_str and hmac.compare_digest(res_str, stored_hash):
                            print("AUTH_OK")
                            sys.exit(0)
                        print("AUTH_FAIL")
                        sys.exit(1)
except Exception:
    pass

# 4. Fallback: su verification ONLY when not running as root (UID 0 bypasses pam_rootok)
if hasattr(os, 'geteuid') and os.geteuid() != 0:
    try:
        import subprocess
        proc = subprocess.Popen(['su', '-c', 'exit 0', user], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.communicate(input=(pwd + '\n').encode('utf-8'))
        if proc.returncode == 0:
            print("AUTH_OK")
            sys.exit(0)
    except Exception:
        pass

print("AUTH_FAIL")
sys.exit(1)
`
}

func verifyLinuxAuth(username, password string) bool {
	if username == "" || password == "" {
		return false
	}

	// 1. Check internal Admin account from config if set
	if state != nil {
		state.mu.RLock()
		adminUser := state.config.AdminUser
		adminPass := state.config.AdminPassword
		state.mu.RUnlock()

		if adminUser != "" && adminPass != "" {
			if subtle.ConstantTimeCompare([]byte(username), []byte(adminUser)) == 1 {
				if checkPassword(adminPass, password) {
					return true
				}
			}
		}
	}

	// 2. Dev mode fallback credentials (only in explicit dev environment)
	if os.Getenv("ENV") == "dev" {
		if subtle.ConstantTimeCompare([]byte(username), []byte("admin")) == 1 &&
			subtle.ConstantTimeCompare([]byte(password), []byte("vsafegate123")) == 1 {
			return true
		}
	}

	// 3. System Linux auth helper (only supported on Linux hosts)
	if runtime.GOOS == "linux" {
		cmd := exec.Command("/usr/local/bin/vsafegate-auth", username)
		cmd.Stdin = strings.NewReader(password)
		out, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(out), "AUTH_OK") {
			return true
		}
	}
	return false
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *AppState) createSession(username string) string {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	token := generateToken()
	s.sessions[token] = Session{
		Username:  username,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	return token
}

func (s *AppState) validateSession(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	sess, ok := s.sessions[token]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return "", false
	}
	return sess.Username, true
}

func (s *AppState) revokeSession(token string) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	delete(s.sessions, token)
}

func (s *AppState) startSessionCleaner() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			now := time.Now()
			s.sessionsMu.Lock()
			for token, sess := range s.sessions {
				if now.After(sess.ExpiresAt) {
					delete(s.sessions, token)
				}
			}
			s.sessionsMu.Unlock()
		}
	}()
}

type loginAttemptEntry struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

type loginRateLimiter struct {
	mu          sync.Mutex
	entries     map[string]*loginAttemptEntry
	maxFailures int
	window      time.Duration
	lockout     time.Duration
	nowFn       func() time.Time
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{
		entries:     make(map[string]*loginAttemptEntry),
		maxFailures: 5,
		window:      5 * time.Minute,
		lockout:     10 * time.Minute,
		nowFn:       time.Now,
	}
}

func (l *loginRateLimiter) now() time.Time {
	if l.nowFn != nil {
		return l.nowFn()
	}
	return time.Now()
}

func (l *loginRateLimiter) IsBlocked(key string) (bool, time.Duration) {
	if key == "" {
		return false, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	entry, ok := l.entries[key]
	if !ok {
		return false, 0
	}
	if !entry.lockedUntil.IsZero() && now.Before(entry.lockedUntil) {
		return true, entry.lockedUntil.Sub(now)
	}
	if !entry.lockedUntil.IsZero() && !now.Before(entry.lockedUntil) {
		delete(l.entries, key)
	}
	return false, 0
}

func (l *loginRateLimiter) RecordFailure(key string) (bool, time.Duration) {
	if key == "" {
		return false, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if len(l.entries) > 2048 {
		for k, v := range l.entries {
			if (v.lockedUntil.IsZero() || now.After(v.lockedUntil)) && now.Sub(v.windowStart) > l.window {
				delete(l.entries, k)
			}
		}
	}

	entry, ok := l.entries[key]
	if !ok || (!entry.lockedUntil.IsZero() && !now.Before(entry.lockedUntil)) || now.Sub(entry.windowStart) > l.window {
		entry = &loginAttemptEntry{failures: 1, windowStart: now}
		l.entries[key] = entry
		return false, 0
	}
	entry.failures++
	if entry.failures >= l.maxFailures {
		entry.lockedUntil = now.Add(l.lockout)
		return true, l.lockout
	}
	return false, 0
}

func (l *loginRateLimiter) Reset(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

func extractClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	parsedRemote := net.ParseIP(host)
	isTrustedHop := parsedRemote != nil && parsedRemote.IsLoopback()

	if isTrustedHop {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				candidate := strings.TrimSpace(parts[0])
				if ip := net.ParseIP(candidate); ip != nil {
					return ip.String()
				}
			}
		}
		if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
			if ip := net.ParseIP(xri); ip != nil {
				return ip.String()
			}
		}
	}
	if parsedRemote != nil {
		return parsedRemote.String()
	}
	return host
}

func changeLocalAdminPassword(s *AppState, username, currentPassword, newPassword string) error {
	if s == nil {
		return errors.New("state unavailable")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username required")
	}
	if len(newPassword) < 8 {
		return errors.New("mật khẩu mới phải có ít nhất 8 ký tự")
	}
	if !verifyLinuxAuth(username, currentPassword) {
		return errors.New("mật khẩu hiện tại không chính xác")
	}

	hashed := hashPassword(newPassword)
	s.mu.Lock()
	if s.config.AdminUser == "" {
		s.config.AdminUser = username
	}
	if s.config.AdminUser != username {
		s.mu.Unlock()
		return errors.New("chỉ hỗ trợ đổi mật khẩu tài khoản quản trị nội bộ đang cấu hình")
	}
	s.config.AdminPassword = hashed
	s.mu.Unlock()
	s.saveConfig()
	return nil
}
