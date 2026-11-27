package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	idsAlertTotal   int64
	idsSeverity1    int64
	idsSeverity2    int64
	idsSeverity3    int64
	idsRecentAlerts []AttackLog
	idsRecentMu     sync.RWMutex
)

func (s *AppState) startSuricataWatcher() {
	go func() {
		evePath := "/var/log/suricata/eve.json"
		firstOpen := true

		for {
			f, err := os.Open(evePath)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}

			// On very first startup, seek to end. On reopen after log rotation, start from 0
			if firstOpen {
				f.Seek(0, io.SeekEnd)
				firstOpen = false
			}

			r := bufio.NewReader(f)

			for {
				line, err := r.ReadString('\n')
				if err != nil {
					// Check if file was rotated or truncated
					if fi, statErr := os.Stat(evePath); statErr == nil {
						curPos, _ := f.Seek(0, io.SeekCurrent)
						if fi.Size() < curPos {
							f.Close()
							break // Reopen file from offset 0
						}
					}
					time.Sleep(500 * time.Millisecond)
					continue
				}

				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}

				var eve EveAlert
				if err := json.Unmarshal([]byte(line), &eve); err != nil {
					continue
				}

				if eve.EventType == "alert" && eve.Alert.Signature != "" {
					// 1. Validate Source IP: Must have a valid IPv4/IPv6 address
					srcIP := strings.TrimSpace(eve.SrcIP)
					if srcIP == "" || net.ParseIP(srcIP) == nil {
						// Filter out non-IP Layer-2 decode anomalies (e.g. SURICATA Ethertype unknown)
						continue
					}

					// 2. Filter out known decoder noise / engine warnings
					if strings.HasPrefix(eve.Alert.Signature, "SURICATA ") && eve.Alert.Severity >= 3 {
						continue
					}

					// 3. Filter out ET INFO signatures (pure informational, non-malicious noise)
					if strings.HasPrefix(eve.Alert.Signature, "ET INFO ") {
						continue
					}

					// 4. Filter out self/internal loopback and vSafeGate host IP alerts
					if isHostOrLoopbackIP(srcIP) {
						continue
					}

					atomic.AddInt64(&idsAlertTotal, 1)
					switch eve.Alert.Severity {
					case 1:
						atomic.AddInt64(&idsSeverity1, 1)
					case 2:
						atomic.AddInt64(&idsSeverity2, 1)
					default:
						atomic.AddInt64(&idsSeverity3, 1)
					}

					actionStr := "IDS ALERT"
					if eve.Alert.Severity == 1 {
						actionStr = "IDS AUTO-BAN"
					}

					hostStr := "N/A"
					if eve.DestIP != "" {
						if eve.DestPort > 0 {
							hostStr = fmt.Sprintf("%s:%d", eve.DestIP, eve.DestPort)
						} else {
							hostStr = eve.DestIP
						}
					}

					uriStr := eve.Alert.Signature
					if eve.Proto != "" {
						uriStr = fmt.Sprintf("%s (%s)", eve.Alert.Signature, eve.Proto)
					}

					methodStr := eve.Proto
					if methodStr == "" {
						methodStr = "IDS"
					}

					logEntry := AttackLog{
						ID:        fmt.Sprintf("ids-%d", time.Now().UnixNano()),
						Timestamp: time.Now(),
						ClientIP:  srcIP,
						Host:      hostStr,
						URI:       uriStr,
						Method:    methodStr,
						RuleID:    eve.Alert.SignatureID,
						RuleName:  fmt.Sprintf("[Suricata IDS] %s", eve.Alert.Signature),
						Action:    actionStr,
						UserAgent: fmt.Sprintf("Phân loại: %s | Mức độ: %d", eve.Alert.Category, eve.Alert.Severity),
					}

					s.mu.Lock()
					s.addRecentLog(logEntry)
					s.mu.Unlock()

					s.publishAttackLog(logEntry)

					idsRecentMu.Lock()
					idsRecentAlerts = append([]AttackLog{logEntry}, idsRecentAlerts...)
					if len(idsRecentAlerts) > 20 {
						idsRecentAlerts = idsRecentAlerts[:20]
					}
					idsRecentMu.Unlock()

					// Auto-ban severity 1 threats with default TTL if policy allows
					if eve.Alert.Severity == 1 && srcIP != "" {
						s.mu.RLock()
						suricataAutoBan := s.config.DefensePolicy.SuricataAutoBan
						s.mu.RUnlock()
						if suricataAutoBan {
							s.banIP(srcIP, fmt.Sprintf("[Suricata IPS] %s", eve.Alert.Signature), -1)
						}
					}
				}
			}
			f.Close()
			time.Sleep(1 * time.Second)
		}
	}()
}

type sshLogSource struct {
	Mode string   // "file" or "journalctl"
	Path string   // file path or "journalctl"
	Args []string // command args when Mode == "journalctl"
}

var (
	reSSHFailed  = regexp.MustCompile(`(?:^|\s)(?:sshd(?:-session)?\[\d+\]:\s+)?Failed\s+(?:password|none|keyboard-interactive(?:/pam)?)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+([0-9a-fA-F.:]+)`)
	reSSHInvalid = regexp.MustCompile(`(?:^|\s)(?:sshd(?:-session)?\[\d+\]:\s+)?Invalid\s+user\s+(\S+)\s+from\s+([0-9a-fA-F.:]+)`)
)

func detectSSHLogSource(statFn func(string) (os.FileInfo, error), lookPathFn func(string) (string, error)) sshLogSource {
	if statFn == nil {
		statFn = os.Stat
	}
	if lookPathFn == nil {
		lookPathFn = exec.LookPath
	}
	for _, candidate := range []string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages"} {
		if fi, err := statFn(candidate); err == nil && (fi == nil || !fi.IsDir()) {
			return sshLogSource{Mode: "file", Path: candidate}
		}
	}
	if jp, err := lookPathFn("journalctl"); err == nil && jp != "" {
		return sshLogSource{
			Mode: "journalctl",
			Path: jp,
			Args: []string{"-u", "ssh", "-u", "sshd", "-f", "-n", "0", "-o", "cat"},
		}
	}
	return sshLogSource{}
}

func parseSSHFailedLine(line string) (user string, ip string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}
	var rawIP string
	if m := reSSHFailed.FindStringSubmatch(line); len(m) > 2 {
		user = m[1]
		rawIP = m[2]
	} else if m := reSSHInvalid.FindStringSubmatch(line); len(m) > 2 {
		user = m[1]
		rawIP = m[2]
	} else {
		return "", "", false
	}

	rawIP = strings.TrimPrefix(rawIP, "::ffff:")
	rawIP, _, _ = strings.Cut(rawIP, "%")
	addr, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return "", "", false
	}
	return user, addr.Unmap().String(), true
}

type sshAttemptEntry struct {
	count    int
	lastSeen time.Time
}

type sshAttemptTracker struct {
	mu       sync.Mutex
	attempts map[string]*sshAttemptEntry
	nowFn    func() time.Time
}

func newSSHAttemptTracker() *sshAttemptTracker {
	return &sshAttemptTracker{
		attempts: make(map[string]*sshAttemptEntry),
		nowFn:    time.Now,
	}
}

func (tr *sshAttemptTracker) Record(line string, maxAttempts int) (user, ip string, shouldBan bool) {
	u, parsedIP, ok := parseSSHFailedLine(line)
	if !ok {
		return "", "", false
	}
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	now := time.Now()
	if tr.nowFn != nil {
		now = tr.nowFn()
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.attempts) > 20 {
		for k, a := range tr.attempts {
			if now.Sub(a.lastSeen) > 15*time.Minute {
				delete(tr.attempts, k)
			}
		}
	}
	att, exists := tr.attempts[parsedIP]
	if !exists || now.Sub(att.lastSeen) > 10*time.Minute {
		tr.attempts[parsedIP] = &sshAttemptEntry{count: 1, lastSeen: now}
		return u, parsedIP, maxAttempts == 1
	}
	att.count++
	att.lastSeen = now
	if att.count >= maxAttempts {
		delete(tr.attempts, parsedIP)
		return u, parsedIP, true
	}
	return u, parsedIP, false
}

func (s *AppState) handleSSHLine(line string, tracker *sshAttemptTracker) {
	s.mu.RLock()
	sshGuardEnabled := s.config.DefensePolicy.SSHGuardEnabled
	maxAttempts := s.config.DefensePolicy.SSHMaxAttempts
	s.mu.RUnlock()

	if !sshGuardEnabled {
		return
	}
	user, ip, shouldBan := tracker.Record(line, maxAttempts)
	if shouldBan && ip != "" {
		atomic.AddInt64(&s.sshBannedCount, 1)
		s.banIP(ip, fmt.Sprintf("[SSH Guard] Dò quét mật khẩu SSH trái phép (User: %s)", user), -1)
	}
}

func (s *AppState) startSSHWatcher() {
	go func() {
		tracker := newSSHAttemptTracker()
		firstOpen := true
		loggedSource := ""

		for {
			src := detectSSHLogSource(os.Stat, exec.LookPath)
			if src.Mode == "" {
				time.Sleep(3 * time.Second)
				continue
			}
			if src.Path != loggedSource {
				log.Printf("[SSH Guard] Monitoring source (%s): %s", src.Mode, src.Path)
				loggedSource = src.Path
			}

			if src.Mode == "journalctl" {
				cmd := exec.Command(src.Path, src.Args...)
				stdout, err := cmd.StdoutPipe()
				if err != nil {
					time.Sleep(3 * time.Second)
					continue
				}
				if err := cmd.Start(); err != nil {
					time.Sleep(3 * time.Second)
					continue
				}
				sc := bufio.NewScanner(stdout)
				sc.Buffer(make([]byte, 32*1024), 512*1024)
				for sc.Scan() {
					s.handleSSHLine(sc.Text(), tracker)
				}
				_ = cmd.Wait()
				time.Sleep(2 * time.Second)
				continue
			}

			f, err := os.Open(src.Path)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}

			curFi, _ := f.Stat()
			if firstOpen {
				_, _ = f.Seek(0, io.SeekEnd)
				firstOpen = false
			}

			r := bufio.NewReader(f)
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					if fi, statErr := os.Stat(src.Path); statErr == nil {
						curPos, _ := f.Seek(0, io.SeekCurrent)
						if fi.Size() < curPos || (curFi != nil && !os.SameFile(fi, curFi)) {
							f.Close()
							break
						}
					} else {
						// File disappeared (e.g. rotated) -> break to re-detect source
						f.Close()
						break
					}
					time.Sleep(500 * time.Millisecond)
					continue
				}
				s.handleSSHLine(line, tracker)
			}
			f.Close()
			time.Sleep(1 * time.Second)
		}
	}()
}

func (s *AppState) startCanaryHoneypot() {
	canaryPorts := []int{21, 23, 1433, 2222, 3306, 3389, 5060, 5432, 6379, 8088}
	for _, port := range canaryPorts {
		go func(p int) {
			s.mu.RLock()
			for _, l4 := range s.config.L4Services {
				if l4.Enabled && l4.ListenPort == p {
					s.mu.RUnlock()
					return
				}
			}
			s.mu.RUnlock()

			addr := fmt.Sprintf("0.0.0.0:%d", p)
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				log.Printf("[Canary] Port %d listener skipped: %v", p, err)
				return
			}
			defer listener.Close()
			log.Printf("[Canary] Honeypot listening on port %d", p)

			for {
				conn, err := listener.Accept()
				if err != nil {
					time.Sleep(500 * time.Millisecond)
					continue
				}

				s.mu.RLock()
				canaryEnabled := s.config.DefensePolicy.CanaryEnabled
				s.mu.RUnlock()
				if !canaryEnabled {
					conn.Close()
					continue
				}

				conn.SetDeadline(time.Now().Add(3 * time.Second))
				remote := conn.RemoteAddr().String()
				conn.Close()

				host, _, err := net.SplitHostPort(remote)
				if err == nil && host != "" {
					host = strings.TrimPrefix(host, "::ffff:")
					if !isPrivateOrReservedIP(host) {
						atomic.AddInt64(&s.portScanCount, 1)
						// Ban with Default TTL
						s.banIP(host, fmt.Sprintf("[Port Scan Canary] Dò quét cổng trái phép (Cổng %d)", p), -1)
					}
				}
			}
		}(port)
	}
}

type corazaAuditPayload struct {
	Transaction struct {
		Timestamp       string `json:"timestamp"`
		UnixTimestamp   int64  `json:"unix_timestamp"`
		ID              string `json:"id"`
		ClientIP        string `json:"client_ip"`
		IsInterrupted   bool   `json:"is_interrupted"`
		HighestSeverity string `json:"highest_severity"`
		Request         *struct {
			Method  string              `json:"method"`
			URI     string              `json:"uri"`
			Headers map[string][]string `json:"headers"`
		} `json:"request"`
		Response *struct {
			Status int `json:"status"`
		} `json:"response"`
	} `json:"transaction"`
	Messages []struct {
		Actionset    string `json:"actionset"`
		Message      string `json:"message"`
		ErrorMessage string `json:"error_message"`
		Data         *struct {
			ID       int             `json:"id"`
			Msg      string          `json:"msg"`
			Data     string          `json:"data"`
			Severity json.RawMessage `json:"severity"`
			Raw      string          `json:"raw"`
		} `json:"data"`
	} `json:"messages"`
}

var (
	reAuditPhase    = regexp.MustCompile(`\(phase\s+([1-5])\)`)
	reAuditErrID    = regexp.MustCompile(`\[id "(\d+)"\]`)
	reAuditErrMsg   = regexp.MustCompile(`\[msg "([^"]*)"\]`)
	reAuditErrData  = regexp.MustCompile(`\[data "([^"]*)"\]`)
	reAuditRawStat  = regexp.MustCompile(`\bstatus:(\d{3})\b`)
)

func firstHeaderValue(headers map[string][]string, name string) string {
	for k, vals := range headers {
		if strings.EqualFold(k, name) && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

func normalizeAuditSeverity(raw json.RawMessage, fallback string) string {
	s := strings.TrimSpace(string(raw))
	s = strings.Trim(s, `"`)
	switch s {
	case "0":
		return "emergency"
	case "1":
		return "alert"
	case "2":
		return "critical"
	case "3":
		return "error"
	case "4":
		return "warning"
	case "5":
		return "notice"
	case "6":
		return "info"
	case "7":
		return "debug"
	case "-1", "":
		return strings.ToLower(strings.TrimSpace(fallback))
	}
	return strings.ToLower(s)
}

func parseCorazaAuditLine(line string) (*AttackLog, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, false
	}

	var p corazaAuditPayload
	if err := json.Unmarshal([]byte(line), &p); err != nil {
		return nil, false
	}
	if p.Transaction.ID == "" && p.Transaction.ClientIP == "" && len(p.Messages) == 0 {
		return nil, false
	}
	if !p.Transaction.IsInterrupted && len(p.Messages) == 0 {
		return nil, false
	}

	var host, uri, method, ua string
	if p.Transaction.Request != nil {
		uri = p.Transaction.Request.URI
		method = p.Transaction.Request.Method
		host = firstHeaderValue(p.Transaction.Request.Headers, "Host")
		ua = firstHeaderValue(p.Transaction.Request.Headers, "User-Agent")
	}

	ruleID := 0
	ruleName := "WAF Policy Match"
	matchedVar := ""
	severity := strings.ToLower(strings.TrimSpace(p.Transaction.HighestSeverity))
	phase := 0

	// Prefer the blocking/last rule or non-anomaly primary rule with an ID
	sawDenied := false
	sawDropped := false
	rawBlockStatus := 0
	for _, msg := range p.Messages {
		if strings.Contains(msg.ErrorMessage, "Access denied") {
			sawDenied = true
		} else if strings.Contains(msg.ErrorMessage, "Access dropped") {
			sawDropped = true
		}
		if msg.Data != nil {
			if m := reAuditRawStat.FindStringSubmatch(msg.Data.Raw); len(m) == 2 {
				if st, err := strconv.Atoi(m[1]); err == nil && st >= 400 {
					rawBlockStatus = st
				}
			}
			if !sawDenied && !sawDropped {
				if strings.Contains(msg.Data.Raw, "deny") {
					sawDenied = true
				} else if strings.Contains(msg.Data.Raw, "drop") {
					sawDropped = true
				}
			}
		}

		if msg.Data != nil && msg.Data.ID > 0 {
			// Anomaly enforcement rules (949110/959100) tell us it blocked, while earlier
			// messages carry the concrete rule ID & matched data. Keep first concrete rule if available.
			if ruleID == 0 || ruleID == 949110 || ruleID == 959100 {
				ruleID = msg.Data.ID
				if msg.Data.Msg != "" {
					ruleName = msg.Data.Msg
				} else if msg.Message != "" {
					ruleName = msg.Message
				}
				if msg.Data.Data != "" {
					matchedVar = msg.Data.Data
				}
				if sev := normalizeAuditSeverity(msg.Data.Severity, severity); sev != "" {
					severity = sev
				}
			}
			if phase == 0 {
				if m := reAuditPhase.FindStringSubmatch(msg.Message + " " + msg.ErrorMessage + " " + msg.Data.Raw); len(m) == 2 {
					phase, _ = strconv.Atoi(m[1])
				}
			}
		} else {
			if ruleID == 0 && msg.ErrorMessage != "" {
				if m := reAuditErrID.FindStringSubmatch(msg.ErrorMessage); len(m) == 2 {
					ruleID, _ = strconv.Atoi(m[1])
				}
			}
			if ruleName == "WAF Policy Match" {
				if msg.Message != "" {
					ruleName = msg.Message
				} else if m := reAuditErrMsg.FindStringSubmatch(msg.ErrorMessage); len(m) == 2 && m[1] != "" {
					ruleName = m[1]
				} else if msg.ErrorMessage != "" {
					ruleName = msg.ErrorMessage
				}
			}
			if matchedVar == "" && msg.ErrorMessage != "" {
				if m := reAuditErrData.FindStringSubmatch(msg.ErrorMessage); len(m) == 2 {
					matchedVar = m[1]
				}
			}
			if phase == 0 && msg.ErrorMessage != "" {
				if m := reAuditPhase.FindStringSubmatch(msg.ErrorMessage); len(m) == 2 {
					phase, _ = strconv.Atoi(m[1])
				}
			}
		}
	}

	action := "DETECTED"
	if p.Transaction.IsInterrupted {
		status := 0
		if p.Transaction.Response != nil {
			status = p.Transaction.Response.Status
		}
		if status == 0 {
			if sawDenied && !sawDropped {
				if rawBlockStatus > 0 {
					action = fmt.Sprintf("BLOCKED (%d)", rawBlockStatus)
				} else {
					action = "BLOCKED (403)"
				}
			} else {
				action = "DROPPED"
			}
		} else {
			action = fmt.Sprintf("BLOCKED (%d)", status)
		}
	}

	ts := time.Now()
	if p.Transaction.UnixTimestamp > 0 {
		if p.Transaction.UnixTimestamp > 1e15 {
			ts = time.Unix(0, p.Transaction.UnixTimestamp)
		} else if p.Transaction.UnixTimestamp > 1e12 {
			ts = time.UnixMilli(p.Transaction.UnixTimestamp)
		} else {
			ts = time.Unix(p.Transaction.UnixTimestamp, 0)
		}
	} else if p.Transaction.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, p.Transaction.Timestamp); err == nil {
			ts = parsed
		}
	}

	id := p.Transaction.ID
	if id == "" {
		id = fmt.Sprintf("waf-%d", time.Now().UnixNano())
	} else {
		id = "waf-" + id
	}

	clientIP := strings.TrimSpace(p.Transaction.ClientIP)
	if addr, err := netip.ParseAddr(clientIP); err == nil {
		clientIP = addr.Unmap().String()
	}

	return &AttackLog{
		ID:         id,
		Timestamp:  ts,
		ClientIP:   clientIP,
		Host:       host,
		URI:        uri,
		Method:     method,
		RuleID:     ruleID,
		RuleName:   ruleName,
		Action:     action,
		UserAgent:  ua,
		MatchedVar: matchedVar,
		Phase:      phase,
		Severity:   severity,
		UniqueID:   p.Transaction.ID,
	}, true
}

func isTrustedProxyOrCloudflareIP(ipStr string, cfg Config) bool {
	targetStr := strings.TrimSpace(ipStr)
	if targetStr == "" {
		return false
	}
	var targetAddr netip.Addr
	var targetPfx netip.Prefix
	isCIDR := false
	if strings.Contains(targetStr, "/") {
		pfx, err := netip.ParsePrefix(targetStr)
		if err != nil || pfx.Bits() == 0 {
			return false
		}
		if pfx.Addr().Is4In6() {
			bits := pfx.Bits() - 96
			if bits <= 0 {
				return false
			}
			pfx = netip.PrefixFrom(pfx.Addr().Unmap(), bits)
		}
		targetPfx = pfx.Masked()
		isCIDR = true
	} else {
		addr, err := netip.ParseAddr(targetStr)
		if err != nil {
			return false
		}
		targetAddr = addr.Unmap()
	}

	matchEntry := func(entry string) bool {
		entry = strings.TrimSpace(entry)
		if entry == "" || entry == "0.0.0.0/0" || entry == "::/0" {
			return false
		}
		if pfx, err := netip.ParsePrefix(entry); err == nil {
			if pfx.Bits() == 0 {
				return false
			}
			if pfx.Addr().Is4In6() {
				if bits := pfx.Bits() - 96; bits > 0 {
					pfx = netip.PrefixFrom(pfx.Addr().Unmap(), bits)
				}
			}
			if isCIDR {
				return pfx.Overlaps(targetPfx)
			}
			return pfx.Contains(targetAddr)
		}
		if single, err := netip.ParseAddr(entry); err == nil {
			single = single.Unmap()
			if isCIDR {
				return targetPfx.Contains(single)
			}
			return single == targetAddr
		}
		return false
	}
	for _, cidr := range buildTrustedProxyCIDRs(cfg) {
		if matchEntry(cidr) {
			return true
		}
	}
	for _, site := range cfg.Sites {
		for _, entry := range site.TrustedProxies {
			if matchEntry(entry) {
				return true
			}
		}
	}
	return false
}

func (s *AppState) startLogWatcher() {
	go func() {
		logFile := s.effectiveWAFAuditLogPath()
		_ = os.MkdirAll(filepath.Dir(logFile), 0750)

		type WAFTrack struct {
			count    int
			lastSeen time.Time
		}
		wafViolations := make(map[string]*WAFTrack)
		var wafMu sync.Mutex
		firstOpen := true

		for {
			file, err := os.Open(logFile)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}

			curFi, _ := file.Stat()
			if firstOpen {
				file.Seek(0, io.SeekEnd)
				firstOpen = false
			}

			reader := bufio.NewReader(file)

			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					if fi, statErr := os.Stat(logFile); statErr == nil {
						curPos, _ := file.Seek(0, io.SeekCurrent)
						if fi.Size() < curPos || (curFi != nil && !os.SameFile(fi, curFi)) {
							file.Close()
							break
						}
					}
					time.Sleep(500 * time.Millisecond)
					continue
				}

				entry, ok := parseCorazaAuditLine(line)
				if !ok {
					continue
				}

				s.mu.Lock()
				s.addRecentLog(*entry)
				cfgSnap := s.config
				autoProxy := s.autoProxyCtrl
				s.mu.Unlock()

				s.publishAttackLog(*entry)
				if autoProxy != nil {
					autoProxy.recordWAFEvent()
				}

				// WAF Auto-Ban only on interrupted (blocked/dropped) requests from untrusted public client IPs
				clientIP := entry.ClientIP
				isBlocked := strings.HasPrefix(entry.Action, "BLOCKED") || entry.Action == "DROPPED"
				if isBlocked && clientIP != "" && !isPrivateOrReservedIP(clientIP) && !isTrustedProxyOrCloudflareIP(clientIP, cfgSnap) {
					wafAutoBan := cfgSnap.DefensePolicy.WAFAutoBanEnabled
					wafThreshold := cfgSnap.DefensePolicy.WAFAutoBanThreshold
					if wafThreshold <= 0 {
						wafThreshold = 10
					}

					if wafAutoBan {
						shouldBan := false
						banReason := ""

						wafMu.Lock()
						if len(wafViolations) > 100 {
							now := time.Now()
							for k, v := range wafViolations {
								if now.Sub(v.lastSeen) > 10*time.Minute {
									delete(wafViolations, k)
								}
							}
						}
						track, exists := wafViolations[clientIP]
						if !exists || time.Since(track.lastSeen) > 2*time.Minute {
							wafViolations[clientIP] = &WAFTrack{count: 1, lastSeen: time.Now()}
						} else {
							track.count++
							track.lastSeen = time.Now()
							if track.count >= wafThreshold {
								delete(wafViolations, clientIP)
								shouldBan = true
								banReason = fmt.Sprintf("[WAF Auto-Ban] Vi phạm Rule #%d liên tục %d lần trong 2 phút", entry.RuleID, track.count)
							}
						}
						wafMu.Unlock()

						if shouldBan {
							s.banIP(clientIP, banReason, -1)
						}
					}
				}
			}
			file.Close()
			time.Sleep(1 * time.Second)
		}
	}()
}
