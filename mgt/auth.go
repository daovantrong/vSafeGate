package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func hashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return password
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	sum := h.Sum(nil)
	for i := 0; i < 9999; i++ {
		h.Reset()
		h.Write(sum)
		h.Write(salt)
		sum = h.Sum(nil)
	}
	return fmt.Sprintf("$pbkdf_sha256$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(sum))
}

func checkPassword(storedHashOrPlain, password string) bool {
	if strings.HasPrefix(storedHashOrPlain, "$pbkdf_sha256$") {
		parts := strings.Split(storedHashOrPlain, "$")
		if len(parts) == 4 {
			salt, err1 := hex.DecodeString(parts[2])
			expectedHash, err2 := hex.DecodeString(parts[3])
			if err1 == nil && err2 == nil {
				h := sha256.New()
				h.Write(salt)
				h.Write([]byte(password))
				sum := h.Sum(nil)
				for i := 0; i < 9999; i++ {
					h.Reset()
					h.Write(sum)
					h.Write(salt)
					sum = h.Sum(nil)
				}
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
	content := `#!/usr/bin/env python3
import sys, os

if len(sys.argv) < 2:
    sys.exit(1)

user = sys.argv[1]
pwd = sys.stdin.read().rstrip('\r\n')

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
    if crypt.crypt(pwd, entry.sp_pwdp) == entry.sp_pwdp:
        print("AUTH_OK")
        sys.exit(0)
except Exception:
    pass

# 3. Direct /etc/shadow check using ctypes calling C library crypt()
# Supported natively on Python 3.8 - 3.14+ without external dependencies
try:
    import ctypes, ctypes.util
    libcrypt_name = ctypes.util.find_library('crypt') or 'libcrypt.so.1'
    lib = None
    for name in [libcrypt_name, 'libcrypt.so.2', 'libcrypt.so.1', 'libc.so.6']:
        try:
            lib = ctypes.CDLL(name)
            if hasattr(lib, 'crypt'):
                break
        except Exception:
            continue

    if lib and hasattr(lib, 'crypt'):
        lib.crypt.restype = ctypes.c_char_p
        lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

        if os.path.exists('/etc/shadow'):
            with open('/etc/shadow', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if parts[0] == user and len(parts) > 1:
                        stored_hash = parts[1]
                        res = lib.crypt(pwd.encode('utf-8'), stored_hash.encode('utf-8'))
                        if res and res.decode('utf-8') == stored_hash:
                            print("AUTH_OK")
                            sys.exit(0)
                        else:
                            print("AUTH_FAIL")
                            sys.exit(1)
except Exception:
    pass

# 4. Fallback: su verification
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
	if _, err := os.Stat(authScript); os.IsNotExist(err) {
		os.WriteFile(authScript, []byte(content), 0755)
	}
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
