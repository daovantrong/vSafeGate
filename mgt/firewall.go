package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

func getIpsetCount(name string) int {
	if runtime.GOOS != "linux" {
		return 0
	}
	out, err := exec.Command("ipset", "list", name).CombinedOutput()
	if err != nil {
		return 0
	}
	lines := strings.Split(string(out), "\n")
	inMembers := false
	count := 0
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "Members:" {
			inMembers = true
			continue
		}
		if inMembers && l != "" {
			count++
		}
	}
	return count
}

func (s *AppState) applyIptablesRules() {
	if runtime.GOOS != "linux" {
		return
	}
	s.mu.RLock()
	mode := s.config.GeoIPMode
	if mode == "" {
		mode = "whitelist"
	}
	s.mu.RUnlock()

	// 1. Always allow Loopback interface
	exec.Command("sh", "-c", "iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -j ACCEPT").Run()

	// 2. Always allow Established and Related connections
	exec.Command("sh", "-c", "iptables -C INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I INPUT 2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT").Run()

	// 3. CRITICAL: Always allow Tailscale & ZeroTier interface traffic unconditionally
	exec.Command("sh", "-c", "iptables -C INPUT -i tailscale+ -j ACCEPT 2>/dev/null || iptables -I INPUT 3 -i tailscale+ -j ACCEPT").Run()
	exec.Command("sh", "-c", "iptables -C INPUT -i zt+ -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -i zt+ -j ACCEPT").Run()

	// 4. CRITICAL: Always allow Tailscale & ZeroTier Tunnel Daemons (UDP 41641, UDP 9993) to communicate globally
	exec.Command("sh", "-c", "iptables -C INPUT -p udp --dport 41641 -j ACCEPT 2>/dev/null || iptables -I INPUT 5 -p udp --dport 41641 -j ACCEPT").Run()
	exec.Command("sh", "-c", "iptables -C INPUT -p udp --dport 9993 -j ACCEPT 2>/dev/null || iptables -I INPUT 6 -p udp --dport 9993 -j ACCEPT").Run()

	// 5. CRITICAL: Always drop explicitly blacklisted IPs & Subnets before ANY service or SSH
	exec.Command("sh", "-c", "iptables -C INPUT -m set --match-set vsafegate-blacklist src -j DROP 2>/dev/null || iptables -I INPUT 7 -m set --match-set vsafegate-blacklist src -j DROP").Run()

	// 6. CRITICAL: Drop global Threat Intelligence feed (Spamhaus DROP, DShield, Feodo, Scanners)
	exec.Command("sh", "-c", "ipset list vsafegate-threatintel -t 2>/dev/null && (iptables -C INPUT -m set --match-set vsafegate-threatintel src -j DROP 2>/dev/null || iptables -I INPUT 8 -m set --match-set vsafegate-threatintel src -j DROP) || true").Run()

	// 7. Always allow Port 80 for Let's Encrypt ACME challenges (from non-blacklisted sources)
	exec.Command("sh", "-c", "iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT 9 -p tcp --dport 80 -j ACCEPT").Run()

	// 8. GeoIP Filtering: Never drop internal, loopback, or VPN interfaces
	if mode == "whitelist" {
		exec.Command("sh", "-c", "iptables -D INPUT ! -i tailscale+ ! -i zt+ ! -i lo -m set --match-set vsafegate-countries src -j DROP 2>/dev/null").Run()
		exec.Command("sh", "-c", "iptables -D INPUT -m set --match-set vsafegate-countries src -j DROP 2>/dev/null").Run()
		exec.Command("sh", "-c", "iptables -C INPUT ! -i tailscale+ ! -i zt+ ! -i lo -m conntrack --ctstate NEW -m set ! --match-set vsafegate-allowed src -j DROP 2>/dev/null || iptables -A INPUT ! -i tailscale+ ! -i zt+ ! -i lo -m conntrack --ctstate NEW -m set ! --match-set vsafegate-allowed src -j DROP").Run()
	} else if mode == "blacklist" {
		exec.Command("sh", "-c", "iptables -D INPUT ! -i tailscale+ ! -i zt+ ! -i lo -m conntrack --ctstate NEW -m set ! --match-set vsafegate-allowed src -j DROP 2>/dev/null").Run()
		exec.Command("sh", "-c", "iptables -C INPUT ! -i tailscale+ ! -i zt+ ! -i lo -m set --match-set vsafegate-countries src -j DROP 2>/dev/null || iptables -A INPUT ! -i tailscale+ ! -i zt+ ! -i lo -m set --match-set vsafegate-countries src -j DROP").Run()
	} else {
		// "disabled": remove both GeoIP drop rules, keep kernel open for global access
		exec.Command("sh", "-c", "iptables -D INPUT ! -i tailscale+ ! -i zt+ ! -i lo -m conntrack --ctstate NEW -m set ! --match-set vsafegate-allowed src -j DROP 2>/dev/null").Run()
		exec.Command("sh", "-c", "iptables -D INPUT ! -i tailscale+ ! -i zt+ ! -i lo -m set --match-set vsafegate-countries src -j DROP 2>/dev/null").Run()
		exec.Command("sh", "-c", "iptables -D INPUT -m set --match-set vsafegate-countries src -j DROP 2>/dev/null").Run()
	}

	// 9. Management SSH (Ports 2251, 22222, and 22) - Protected by Blacklist & GeoIP
	exec.Command("sh", "-c", "iptables -D INPUT -p tcp -m multiport --dports 22,22222 -j ACCEPT 2>/dev/null").Run()
	exec.Command("sh", "-c", "iptables -C INPUT -p tcp -m multiport --dports 2251,22222,22 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp -m multiport --dports 2251,22222,22 -j ACCEPT").Run()
}

func (s *AppState) initFirewall() {
	if runtime.GOOS != "linux" {
		return
	}
	exec.Command("sh", "-c", "ipset create vsafegate-blacklist hash:net maxelem 65536 -exist 2>/dev/null || (ipset create vsafegate-blacklist-tmp hash:net maxelem 65536 -exist && ipset swap vsafegate-blacklist vsafegate-blacklist-tmp 2>/dev/null && ipset destroy vsafegate-blacklist-tmp 2>/dev/null)").Run()
	exec.Command("ipset", "create", "vsafegate-threatintel", "hash:net", "maxelem", "131072", "-exist").Run()
	exec.Command("ipset", "create", "vsafegate-countries", "hash:net", "maxelem", "262144", "-exist").Run()
	exec.Command("ipset", "create", "vsafegate-allowed", "hash:net", "maxelem", "262144", "-exist").Run()

	// Sync banned IPs into kernel ipset
	s.mu.RLock()
	for _, b := range s.config.BannedIPs {
		if b.IP != "" {
			exec.Command("ipset", "add", "vsafegate-blacklist", b.IP, "-exist").Run()
		}
	}
	// Fallback legacy BlacklistIP
	for _, ip := range s.config.BlacklistIP {
		if ip != "" {
			exec.Command("ipset", "add", "vsafegate-blacklist", ip, "-exist").Run()
		}
	}
	s.mu.RUnlock()

	s.applyIptablesRules()
}

func (s *AppState) syncGeoIP() {
	s.mu.RLock()
	mode := s.config.GeoIPMode
	if mode == "" {
		mode = "whitelist"
	}
	var countries []string
	if mode == "whitelist" {
		countries = make([]string, len(s.config.AllowedCountries))
		copy(countries, s.config.AllowedCountries)
	} else {
		countries = make([]string, len(s.config.BlockedCountries))
		copy(countries, s.config.BlockedCountries)
	}
	s.mu.RUnlock()

	dir := "/etc/vsafegate/geoip"
	if err := os.MkdirAll(dir, 0755); err != nil {
		dir = filepath.Join(os.TempDir(), "vsafegate-geoip")
		os.MkdirAll(dir, 0755)
	}

	client := http.Client{Timeout: 10 * time.Second}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, c := range countries {
		code := strings.ToLower(strings.TrimSpace(c))
		if len(code) != 2 {
			continue
		}
		zonePath := filepath.Join(dir, code+".zone")
		fi, err := os.Stat(zonePath)
		needsDownload := err != nil || fi.Size() == 0 || time.Since(fi.ModTime()) > 7*24*time.Hour
		if needsDownload {
			wg.Add(1)
			go func(cc, zp string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", cc)
				resp, err := client.Get(url)
				if err != nil || resp.StatusCode != 200 {
					url = fmt.Sprintf("http://www.ipdeny.com/ipblocks/data/countries/%s.zone", cc)
					resp, err = client.Get(url)
				}
				if err == nil && resp.StatusCode == 200 {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					if len(body) > 0 {
						os.WriteFile(zp, body, 0644)
					}
				}
			}(code, zonePath)
		}
	}
	wg.Wait()

	var allCIDRs []string
	for _, c := range countries {
		code := strings.ToLower(strings.TrimSpace(c))
		if len(code) != 2 {
			continue
		}
		zonePath := filepath.Join(dir, code+".zone")
		if data, err := os.ReadFile(zonePath); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l != "" && !strings.HasPrefix(l, "#") {
					allCIDRs = append(allCIDRs, l)
				}
			}
		}
	}

	if mode == "whitelist" {
		lanCIDRs := []string{
			"127.0.0.0/8",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
			"100.64.0.0/10",
		}
		allCIDRs = append(lanCIDRs, allCIDRs...)
		s.mu.RLock()
		for _, w := range s.config.WhitelistIPs {
			if w.IP != "" {
				allCIDRs = append(allCIDRs, w.IP)
			}
		}
		s.mu.RUnlock()

		combPath := filepath.Join(dir, "allowed-all.txt")
		os.WriteFile(combPath, []byte(strings.Join(allCIDRs, "\n")), 0644)

		if runtime.GOOS == "linux" {
			var ipsetScript strings.Builder
			ipsetScript.WriteString("create vsafegate-allowed hash:net maxelem 262144 -exist\n")
			ipsetScript.WriteString("flush vsafegate-allowed\n")
			for _, cidr := range allCIDRs {
				ipsetScript.WriteString(fmt.Sprintf("add vsafegate-allowed %s\n", cidr))
			}
			cmd := exec.Command("ipset", "restore")
			cmd.Stdin = strings.NewReader(ipsetScript.String())
			cmd.Run()
		}
	} else {
		combPath := filepath.Join(dir, "blocked-all.txt")
		os.WriteFile(combPath, []byte(strings.Join(allCIDRs, "\n")), 0644)

		if runtime.GOOS == "linux" {
			var ipsetScript strings.Builder
			ipsetScript.WriteString("create vsafegate-countries hash:net maxelem 262144 -exist\n")
			ipsetScript.WriteString("flush vsafegate-countries\n")
			for _, cidr := range allCIDRs {
				ipsetScript.WriteString(fmt.Sprintf("add vsafegate-countries %s\n", cidr))
			}
			cmd := exec.Command("ipset", "restore")
			cmd.Stdin = strings.NewReader(ipsetScript.String())
			cmd.Run()
		}
	}

	s.applyIptablesRules()
	if s.reloadManager != nil {
		s.reloadManager.Trigger()
	}
}
