package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
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

					// Persistent Log
					if s.logManager != nil {
						s.logManager.Append(logEntry)
					}

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

func (s *AppState) startSSHWatcher() {
	go func() {
		reFailed := regexp.MustCompile(`sshd(?:-session)?\[\d+\]:\s+Failed\s+(?:password|none)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+([0-9a-fA-F.:]+)`)
		reInvalid := regexp.MustCompile(`sshd(?:-session)?\[\d+\]:\s+Invalid\s+user\s+(\S+)\s+from\s+([0-9a-fA-F.:]+)`)

		type Attempt struct {
			count    int
			lastSeen time.Time
		}
		attempts := make(map[string]*Attempt)
		var attMu sync.Mutex

		logPath := "/var/log/messages"
		firstOpen := true

		for {
			f, err := os.Open(logPath)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}

			if firstOpen {
				f.Seek(0, io.SeekEnd)
				firstOpen = false
			}

			r := bufio.NewReader(f)

			for {
				line, err := r.ReadString('\n')
				if err != nil {
					if fi, statErr := os.Stat(logPath); statErr == nil {
						curPos, _ := f.Seek(0, io.SeekCurrent)
						if fi.Size() < curPos {
							f.Close()
							break
						}
					}
					time.Sleep(500 * time.Millisecond)
					continue
				}

				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}

				var user, ip string
				if m := reFailed.FindStringSubmatch(line); len(m) > 2 {
					user = m[1]
					ip = m[2]
				} else if m := reInvalid.FindStringSubmatch(line); len(m) > 2 {
					user = m[1]
					ip = m[2]
				}

				if ip != "" {
					s.mu.RLock()
					sshGuardEnabled := s.config.DefensePolicy.SSHGuardEnabled
					maxAttempts := s.config.DefensePolicy.SSHMaxAttempts
					s.mu.RUnlock()

					if !sshGuardEnabled {
						continue
					}
					if maxAttempts <= 0 {
						maxAttempts = 3
					}

					ip = strings.TrimPrefix(ip, "::ffff:")
					attMu.Lock()
					if len(attempts) > 20 {
						now := time.Now()
						for k, a := range attempts {
							if now.Sub(a.lastSeen) > 15*time.Minute {
								delete(attempts, k)
							}
						}
					}
					att, ok := attempts[ip]
					if !ok || time.Since(att.lastSeen) > 10*time.Minute {
						attempts[ip] = &Attempt{count: 1, lastSeen: time.Now()}
					} else {
						att.count++
						att.lastSeen = time.Now()
						if att.count >= maxAttempts {
							delete(attempts, ip)
							atomic.AddInt64(&s.sshBannedCount, 1)
							attMu.Unlock()
							// Ban with Default TTL
							s.banIP(ip, fmt.Sprintf("[SSH Guard] Dò quét mật khẩu SSH trái phép (User: %s)", user), -1)
							continue
						}
					}
					attMu.Unlock()
				}
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

func (s *AppState) startLogWatcher() {
	go func() {
		os.MkdirAll("/var/log/caddy", 0755)
		logFile := "/var/log/caddy/access.log"

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
					// Check if log file was rotated or truncated
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

				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}

				var raw map[string]interface{}
				if err := json.Unmarshal([]byte(line), &raw); err == nil {
					status, _ := raw["status"].(float64)
					if status == 403 {
						req, _ := raw["request"].(map[string]interface{})
						headers, _ := req["headers"].(map[string]interface{})
						ua := ""
						if uas, ok := headers["User-Agent"].([]interface{}); ok && len(uas) > 0 {
							ua = fmt.Sprintf("%v", uas[0])
						}

						clientIP, _ := req["remote_ip"].(string)
						if clientIP == "" {
							clientIP, _ = req["client_ip"].(string)
						}
						host, _ := req["host"].(string)
						uri, _ := req["uri"].(string)
						method, _ := req["method"].(string)

						logEntry := AttackLog{
							ID:        fmt.Sprintf("log-%d", time.Now().UnixNano()),
							Timestamp: time.Now(),
							ClientIP:  clientIP,
							Host:      host,
							URI:       uri,
							Method:    method,
							RuleID:    403,
							RuleName:  "WAF Security Policy Violation (Blocked)",
							Action:    "BLOCKED (403)",
							UserAgent: ua,
						}

						s.mu.Lock()
						s.addRecentLog(logEntry)
						s.mu.Unlock()

						// Persistent Log
						if s.logManager != nil {
							s.logManager.Append(logEntry)
						}

						// WAF Auto-Ban if repeated 403 violations
						if clientIP != "" && !isPrivateOrReservedIP(clientIP) {
							s.mu.RLock()
							wafAutoBan := s.config.DefensePolicy.WAFAutoBanEnabled
							wafThreshold := s.config.DefensePolicy.WAFAutoBanThreshold
							s.mu.RUnlock()

							if wafThreshold <= 0 {
								wafThreshold = 10
							}

							if wafAutoBan {
								shouldBan := false
								banReason := ""

								wafMu.Lock()
								if len(wafViolations) > 50 {
									now := time.Now()
									for k, v := range wafViolations {
										if now.Sub(v.lastSeen) > 10*time.Minute {
											delete(wafViolations, k)
										}
									}
								}
								track, ok := wafViolations[clientIP]
								if !ok || time.Since(track.lastSeen) > 2*time.Minute {
									wafViolations[clientIP] = &WAFTrack{count: 1, lastSeen: time.Now()}
								} else {
									track.count++
									track.lastSeen = time.Now()
									if track.count >= wafThreshold {
										delete(wafViolations, clientIP)
										shouldBan = true
										banReason = fmt.Sprintf("[WAF Auto-Ban] Vi phạm chính sách WAF liên tục %d lần trong 2 phút", track.count)
									}
								}
								wafMu.Unlock()

								if shouldBan {
									s.banIP(clientIP, banReason, -1)
								}
							}
						}
					}
				}
			}
			file.Close()
			time.Sleep(1 * time.Second)
		}
	}()
}
