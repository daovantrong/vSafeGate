package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type firewallRuleSpec struct {
	args     []string
	optional bool
}

type firewallCapabilities struct {
	IsContainer     bool
	IsLXC           bool
	HasIPTables     bool
	HasIP6Tables    bool
	HasIPSet        bool
	CanWriteSysctl  bool
	SysctlReadOnly  bool
	IP6TablesBroken bool
}

type firewallRunner interface {
	Run(name string, args ...string) error
	Output(name string, args ...string) ([]byte, error)
	RunStdin(stdinData string, name string, args ...string) error
	WriteFile(path string, data []byte, perm os.FileMode) error
	ReadFile(path string) ([]byte, error)
	LookPath(file string) (string, error)
}

type osFirewallRunner struct{}

func (osFirewallRunner) Run(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func (osFirewallRunner) Output(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func (osFirewallRunner) RunStdin(stdinData string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdinData)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (osFirewallRunner) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func (osFirewallRunner) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (osFirewallRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

var (
	fwWarnOnceMu sync.Mutex
	fwWarnedKeys = make(map[string]bool)
)

func logFirewallWarnOnce(key, format string, args ...any) {
	fwWarnOnceMu.Lock()
	if fwWarnedKeys[key] {
		fwWarnOnceMu.Unlock()
		return
	}
	fwWarnedKeys[key] = true
	fwWarnOnceMu.Unlock()
	log.Printf(format, args...)
}

func detectFirewallCapabilitiesWith(r firewallRunner) firewallCapabilities {
	caps := firewallCapabilities{}
	if r == nil {
		return caps
	}
	if _, err := r.LookPath("iptables"); err == nil {
		if r.Run("iptables", "-L", "INPUT", "-n") == nil {
			caps.HasIPTables = true
		}
	}
	if _, err := r.LookPath("ip6tables"); err == nil {
		if r.Run("ip6tables", "-L", "INPUT", "-n") == nil {
			caps.HasIP6Tables = true
		} else {
			caps.IP6TablesBroken = true
		}
	}
	if _, err := r.LookPath("ipset"); err == nil {
		caps.HasIPSet = true
	}
	if envData, err := r.ReadFile("/proc/1/environ"); err == nil {
		envStr := string(envData)
		if strings.Contains(envStr, "container=lxc") {
			caps.IsLXC = true
			caps.IsContainer = true
		} else if strings.Contains(envStr, "container=") {
			caps.IsContainer = true
		}
	}
	if data, err := r.ReadFile("/proc/sys/net/ipv4/tcp_syncookies"); err == nil {
		val := strings.TrimSpace(string(data))
		if err := r.WriteFile("/proc/sys/net/ipv4/tcp_syncookies", []byte(val), 0644); err == nil {
			caps.CanWriteSysctl = true
		} else {
			caps.SysctlReadOnly = true
		}
	}
	return caps
}

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

func ipsetExists(r firewallRunner, name string) bool {
	return r.Run("ipset", "list", name, "-t") == nil
}

func buildAtomicIpsetSwapScript(setName string, maxElem int, entries []string) string {
	tmpName := setName + "-tmp"
	var b strings.Builder
	b.WriteString(fmt.Sprintf("create %s hash:net maxelem %d -exist\n", setName, maxElem))
	b.WriteString(fmt.Sprintf("create %s hash:net maxelem %d -exist\n", tmpName, maxElem))
	b.WriteString(fmt.Sprintf("flush %s\n", tmpName))
	seen := make(map[string]struct{}, len(entries))
	for _, raw := range entries {
		entry := normalizeIPv4IpsetEntry(raw)
		if entry == "" {
			continue
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		b.WriteString(fmt.Sprintf("add %s %s -exist\n", tmpName, entry))
	}
	b.WriteString(fmt.Sprintf("swap %s %s\n", tmpName, setName))
	b.WriteString(fmt.Sprintf("destroy %s\n", tmpName))
	return b.String()
}

func normalizeIPv4IpsetEntry(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "/") {
		pfx, err := netip.ParsePrefix(s)
		if err != nil || pfx.Bits() == 0 || !pfx.Addr().Unmap().Is4() {
			return ""
		}
		return pfx.Masked().String()
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Unmap().Is4() {
		return ""
	}
	return addr.Unmap().String()
}

func collectTrustedIPv4Entries(cfg Config) []string {
	cfV4, _ := effectiveCloudflareCIDRs(cfg.Cloudflare)
	var extra []string
	for _, s := range cfg.Sites {
		extra = append(extra, s.TrustedProxies...)
	}
	all := buildTrustedProxyCIDRs(cfg, extra)
	_ = cfV4
	var out []string
	for _, c := range all {
		if norm := normalizeIPv4IpsetEntry(c); norm != "" {
			out = append(out, norm)
		}
	}
	return out
}

func collectWhitelistIPv4Entries(cfg Config) []string {
	entries := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
	}
	for _, w := range cfg.WhitelistIPs {
		if norm := normalizeIPv4IpsetEntry(w.IP); norm != "" {
			entries = append(entries, norm)
		}
	}
	return entries
}

func collectManagementIPv4CIDRs(cfg Config) []string {
	var rawList []string
	if len(cfg.MgmtAllowedCIDRs) > 0 {
		rawList = cfg.MgmtAllowedCIDRs
	} else {
		rawList = []string{
			"127.0.0.0/8",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"100.64.0.0/10",
		}
	}
	seen := make(map[string]struct{})
	var out []string
	for _, item := range rawList {
		norm := normalizeIPv4IpsetEntry(item)
		if norm == "" {
			continue
		}
		if _, ok := seen[norm]; !ok {
			seen[norm] = struct{}{}
			out = append(out, norm)
		}
	}
	return out
}

func collectActiveL4Ports(cfg Config) (tcpPorts, udpPorts []string) {
	seenTCP := make(map[int]struct{})
	seenUDP := make(map[int]struct{})
	for _, svc := range cfg.L4Services {
		if !svc.Enabled || svc.ListenPort <= 0 || svc.ListenPort > 65535 {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(svc.Protocol))
		if proto == "udp" {
			seenUDP[svc.ListenPort] = struct{}{}
		} else {
			seenTCP[svc.ListenPort] = struct{}{}
		}
	}
	var tcpInts, udpInts []int
	for p := range seenTCP {
		tcpInts = append(tcpInts, p)
	}
	for p := range seenUDP {
		udpInts = append(udpInts, p)
	}
	sort.Ints(tcpInts)
	sort.Ints(udpInts)
	for _, p := range tcpInts {
		tcpPorts = append(tcpPorts, strconv.Itoa(p))
	}
	for _, p := range udpInts {
		udpPorts = append(udpPorts, strconv.Itoa(p))
	}
	return tcpPorts, udpPorts
}

func buildIPv4InputRules(cfg Config, hasThreatIntel, hasTrustedSet, hasWhitelistSet bool) []firewallRuleSpec {
	return buildIPv4InputRulesWithShared(cfg, hasThreatIntel, hasTrustedSet, hasWhitelistSet, false)
}

func buildIPv4InputRulesWithShared(cfg Config, hasThreatIntel, hasTrustedSet, hasWhitelistSet, hasSharedThreat bool) []firewallRuleSpec {
	mode := strings.ToLower(strings.TrimSpace(cfg.GeoIPMode))
	if mode == "" {
		mode = "disabled"
	}

	rules := []firewallRuleSpec{
		// 1. Loopback & invalid conntrack state
		{args: []string{"-i", "lo", "-j", "ACCEPT"}},
		{args: []string{"-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"}},

		// 2. Established / Related sessions
		{args: []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
	}

	// 3. Trusted VPN/LAN interfaces, tunnel ports & explicit Admin Whitelist (always immune)
	trustedIfaces := effectiveTrustedInterfaces(cfg)
	for _, iface := range trustedIfaces {
		rules = append(rules, firewallRuleSpec{args: []string{"-i", iface, "-j", "ACCEPT"}})
		if iface == "tailscale+" || strings.HasPrefix(iface, "tailscale") {
			rules = append(rules, firewallRuleSpec{args: []string{"-p", "udp", "--dport", "41641", "-j", "ACCEPT"}})
		} else if iface == "zt+" || strings.HasPrefix(iface, "zt") {
			rules = append(rules, firewallRuleSpec{args: []string{"-p", "udp", "--dport", "9993", "-j", "ACCEPT"}})
		}
	}

	if hasWhitelistSet {
		rules = append(rules, firewallRuleSpec{
			args: []string{"-m", "set", "--match-set", "vsafegate-whitelist", "src", "-j", "ACCEPT"},
		})
	}

	// 4. Blacklist & ThreatIntel DROP ALL protocols (TCP/UDP/ICMP)
	rules = append(rules, firewallRuleSpec{
		args: []string{"-m", "set", "--match-set", "vsafegate-blacklist", "src", "-j", "DROP"},
	})
	if hasThreatIntel {
		rules = append(rules, firewallRuleSpec{
			args: []string{"-m", "set", "--match-set", "vsafegate-threatintel", "src", "-j", "DROP"},
		})
	}
	if hasSharedThreat && cfg.SharedThreat.Enabled && cfg.SharedThreat.SyncEnabled {
		rules = append(rules, firewallRuleSpec{
			args: []string{"-m", "set", "--match-set", "vsafegate-shared", "src", "-j", "DROP"},
		})
	}

	// 5. GeoIP filtering (NOTE: NO :80 ACCEPT rule before GeoIP! Trusted proxies/Cloudflare exempt from GeoIP to prevent self-DoS)
	switch mode {
	case "whitelist":
		geoArgs := make([]string, 0, 12)
		for _, iface := range trustedIfaces {
			geoArgs = append(geoArgs, "!", "-i", iface)
		}
		geoArgs = append(geoArgs, "!", "-i", "lo", "-m", "conntrack", "--ctstate", "NEW")
		if hasTrustedSet {
			geoArgs = append(geoArgs, "-m", "set", "!", "--match-set", "vsafegate-trusted", "src")
		}
		geoArgs = append(geoArgs, "-m", "set", "!", "--match-set", "vsafegate-allowed", "src", "-j", "DROP")
		rules = append(rules, firewallRuleSpec{args: geoArgs})
	case "blacklist":
		geoArgs := make([]string, 0, 10)
		for _, iface := range trustedIfaces {
			geoArgs = append(geoArgs, "!", "-i", iface)
		}
		geoArgs = append(geoArgs, "!", "-i", "lo")
		if hasTrustedSet {
			geoArgs = append(geoArgs, "-m", "set", "!", "--match-set", "vsafegate-trusted", "src")
		}
		geoArgs = append(geoArgs, "-m", "set", "--match-set", "vsafegate-countries", "src", "-j", "DROP")
		rules = append(rules, firewallRuleSpec{args: geoArgs})
	}

	// 6. Kernel L3/L4 SYN/UDP/ICMP hashlimit & per-IP connlimit (skip Cloudflare/TrustedProxies to avoid self-DoS)
	if hasTrustedSet {
		rules = append(rules,
			firewallRuleSpec{
				optional: true,
				args:     []string{"-p", "tcp", "--syn", "-m", "set", "!", "--match-set", "vsafegate-trusted", "src", "-m", "hashlimit", "--hashlimit-above", "120/sec", "--hashlimit-burst", "240", "--hashlimit-mode", "srcip", "--hashlimit-name", "vsg_syn", "-j", "DROP"},
			},
			firewallRuleSpec{
				optional: true,
				args:     []string{"-p", "tcp", "-m", "multiport", "--dports", "80,443", "--syn", "-m", "set", "!", "--match-set", "vsafegate-trusted", "src", "-m", "connlimit", "--connlimit-above", "150", "--connlimit-mask", "32", "-j", "DROP"},
			},
			firewallRuleSpec{
				optional: true,
				args:     []string{"-p", "udp", "-m", "set", "!", "--match-set", "vsafegate-trusted", "src", "-m", "hashlimit", "--hashlimit-above", "300/sec", "--hashlimit-burst", "600", "--hashlimit-mode", "srcip", "--hashlimit-name", "vsg_udp", "-j", "DROP"},
			},
		)
	} else {
		rules = append(rules,
			firewallRuleSpec{
				optional: true,
				args:     []string{"-p", "tcp", "--syn", "-m", "hashlimit", "--hashlimit-above", "120/sec", "--hashlimit-burst", "240", "--hashlimit-mode", "srcip", "--hashlimit-name", "vsg_syn", "-j", "DROP"},
			},
			firewallRuleSpec{
				optional: true,
				args:     []string{"-p", "tcp", "-m", "multiport", "--dports", "80,443", "--syn", "-m", "connlimit", "--connlimit-above", "150", "--connlimit-mask", "32", "-j", "DROP"},
			},
			firewallRuleSpec{
				optional: true,
				args:     []string{"-p", "udp", "-m", "hashlimit", "--hashlimit-above", "300/sec", "--hashlimit-burst", "600", "--hashlimit-mode", "srcip", "--hashlimit-name", "vsg_udp", "-j", "DROP"},
			},
		)
	}
	rules = append(rules, firewallRuleSpec{
		optional: true,
		args:     []string{"-p", "icmp", "-m", "hashlimit", "--hashlimit-above", "20/sec", "--hashlimit-burst", "40", "--hashlimit-mode", "srcip", "--hashlimit-name", "vsg_icmp", "-j", "DROP"},
	})

	// 7. Public HTTP/HTTPS & Active L4 Services (protected by Blacklist, ThreatIntel, GeoIP & hashlimit above)
	rules = append(rules, firewallRuleSpec{
		args: []string{"-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "ACCEPT"},
	})
	allowH3 := false
	for _, site := range cfg.Sites {
		if site.SSL && !site.HideAltSvc {
			allowH3 = true
			break
		}
	}
	if allowH3 {
		rules = append(rules, firewallRuleSpec{
			args: []string{"-p", "udp", "--dport", "443", "-j", "ACCEPT"},
		})
	}

	l4TCP, l4UDP := collectActiveL4Ports(cfg)
	for i := 0; i < len(l4TCP); i += 15 {
		end := min(i+15, len(l4TCP))
		rules = append(rules, firewallRuleSpec{
			args: []string{"-p", "tcp", "-m", "multiport", "--dports", strings.Join(l4TCP[i:end], ","), "-j", "ACCEPT"},
		})
	}
	for i := 0; i < len(l4UDP); i += 15 {
		end := min(i+15, len(l4UDP))
		rules = append(rules, firewallRuleSpec{
			args: []string{"-p", "udp", "-m", "multiport", "--dports", strings.Join(l4UDP[i:end], ","), "-j", "ACCEPT"},
		})
	}

	// 8. Management Panel Ports (default: allow public Internet protected by Blacklist/ThreatIntel/GeoIP;
	// or restrict to MgmtAllowedCIDRs / LAN+VPN when MgmtAllowPublicInternet=false)
	httpsPort := cfg.MgmtHTTPSPort
	if httpsPort <= 0 {
		httpsPort = 4438
	}
	httpPort := cfg.MgmtHTTPPort
	if httpPort <= 0 {
		httpPort = 808
	}
	mgmtPorts := fmt.Sprintf("%d,%d", httpsPort, httpPort)
	if len(cfg.MgmtAllowedCIDRs) == 0 && isMgmtPublicInternetAllowed(cfg) {
		rules = append(rules, firewallRuleSpec{
			args: []string{"-p", "tcp", "-m", "multiport", "--dports", mgmtPorts, "-j", "ACCEPT"},
		})
	} else {
		for _, cidr := range collectManagementIPv4CIDRs(cfg) {
			rules = append(rules, firewallRuleSpec{
				args: []string{"-p", "tcp", "-s", cidr, "-m", "multiport", "--dports", mgmtPorts, "-j", "ACCEPT"},
			})
		}
		rules = append(rules, firewallRuleSpec{
			args: []string{"-p", "tcp", "-m", "multiport", "--dports", mgmtPorts, "-j", "DROP"},
		})
	}

	// 9. Management SSH Ports (protected by Blacklist, ThreatIntel & GeoIP)
	sshPorts := effectiveSSHPorts(cfg)
	sshPortStrs := make([]string, 0, len(sshPorts))
	for _, p := range sshPorts {
		sshPortStrs = append(sshPortStrs, strconv.Itoa(p))
	}
	rules = append(rules, firewallRuleSpec{
		args: []string{"-p", "tcp", "-m", "multiport", "--dports", strings.Join(sshPortStrs, ","), "-j", "ACCEPT"},
	})

	// 10. Return cleanly to INPUT chain
	rules = append(rules, firewallRuleSpec{
		args: []string{"-j", "RETURN"},
	})

	return rules
}

func buildIPv6InputRules() []firewallRuleSpec {
	return []firewallRuleSpec{
		// Allow loopback (::1) & drop invalid conntrack
		{args: []string{"-i", "lo", "-j", "ACCEPT"}},
		{args: []string{"-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"}},
		{args: []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},

		// Allow Link-Local (fe80::/10) only
		{args: []string{"-s", "fe80::/10", "-j", "ACCEPT"}},
		{args: []string{"-d", "fe80::/10", "-j", "ACCEPT"}},

		// Minimal ICMPv6 Neighbor/Router Discovery on LAN with hop-limit 255
		{optional: true, args: []string{"-p", "ipv6-icmp", "--icmpv6-type", "133", "-m", "hl", "--hl-eq", "255", "-j", "ACCEPT"}},
		{optional: true, args: []string{"-p", "ipv6-icmp", "--icmpv6-type", "134", "-m", "hl", "--hl-eq", "255", "-j", "ACCEPT"}},
		{optional: true, args: []string{"-p", "ipv6-icmp", "--icmpv6-type", "135", "-m", "hl", "--hl-eq", "255", "-j", "ACCEPT"}},
		{optional: true, args: []string{"-p", "ipv6-icmp", "--icmpv6-type", "136", "-m", "hl", "--hl-eq", "255", "-j", "ACCEPT"}},

		// Allow link-local multicast NDP/mDNS sourced from fe80::/10
		{args: []string{"-s", "fe80::/10", "-d", "ff02::/16", "-j", "ACCEPT"}},

		// DROP ALL non-link-local / public IPv6 traffic silently
		{args: []string{"-j", "DROP"}},
	}
}

func buildIPv4OutputRules(hasThreatIntel, hasWhitelistSet bool) []firewallRuleSpec {
	rules := []firewallRuleSpec{
		{args: []string{"-o", "lo", "-j", "ACCEPT"}},
		{args: []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
	}
	if hasWhitelistSet {
		rules = append(rules, firewallRuleSpec{
			args: []string{"-m", "set", "--match-set", "vsafegate-whitelist", "dst", "-j", "ACCEPT"},
		})
	}
	rules = append(rules, firewallRuleSpec{
		args: []string{"-m", "set", "--match-set", "vsafegate-blacklist", "dst", "-j", "DROP"},
	})
	if hasThreatIntel {
		rules = append(rules, firewallRuleSpec{
			args: []string{"-m", "set", "--match-set", "vsafegate-threatintel", "dst", "-j", "DROP"},
		})
	}
	rules = append(rules, firewallRuleSpec{
		args: []string{"-j", "RETURN"},
	})
	return rules
}

func buildSysctlHardeningParams() map[string]string {
	return map[string]string{
		"/proc/sys/net/ipv4/tcp_syncookies":              "1",
		"/proc/sys/net/ipv4/conf/all/rp_filter":          "1",
		"/proc/sys/net/ipv4/conf/default/rp_filter":      "1",
		"/proc/sys/net/ipv4/conf/all/accept_redirects":   "0",
		"/proc/sys/net/ipv4/conf/default/accept_redirects": "0",
		"/proc/sys/net/ipv4/conf/all/send_redirects":     "0",
		"/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts": "1",
		"/proc/sys/net/ipv4/tcp_rfc1337":                 "1",
		"/proc/sys/net/ipv4/tcp_max_syn_backlog":         "4096",
	}
}

func applyBestEffortSysctlWith(r firewallRunner, caps firewallCapabilities) {
	if r == nil {
		return
	}
	for path, val := range buildSysctlHardeningParams() {
		if err := r.WriteFile(path, []byte(val+"\n"), 0644); err != nil {
			if caps.IsContainer || caps.IsLXC || caps.SysctlReadOnly {
				logFirewallWarnOnce("sysctl-ro", "[Firewall] Sysctl hardening limited in container/LXC (%s: %v); continuing safely", path, err)
				return
			}
			logFirewallWarnOnce("sysctl-"+path, "[Firewall] Best-effort sysctl %s skipped: %v", path, err)
		}
	}
}

func cleanupLegacyInputRulesWith(r firewallRunner) {
	legacy := [][]string{
		{"-D", "INPUT", "-i", "lo", "-j", "ACCEPT"},
		{"-D", "INPUT", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		{"-D", "INPUT", "-i", "tailscale+", "-j", "ACCEPT"},
		{"-D", "INPUT", "-i", "zt+", "-j", "ACCEPT"},
		{"-D", "INPUT", "-p", "udp", "--dport", "41641", "-j", "ACCEPT"},
		{"-D", "INPUT", "-p", "udp", "--dport", "9993", "-j", "ACCEPT"},
		{"-D", "INPUT", "-m", "set", "--match-set", "vsafegate-blacklist", "src", "-j", "DROP"},
		{"-D", "INPUT", "-m", "set", "--match-set", "vsafegate-threatintel", "src", "-j", "DROP"},
		{"-D", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"},
		{"-D", "INPUT", "!", "-i", "tailscale+", "!", "-i", "zt+", "!", "-i", "lo", "-m", "conntrack", "--ctstate", "NEW", "-m", "set", "!", "--match-set", "vsafegate-allowed", "src", "-j", "DROP"},
		{"-D", "INPUT", "!", "-i", "tailscale+", "!", "-i", "zt+", "!", "-i", "lo", "-m", "set", "--match-set", "vsafegate-countries", "src", "-j", "DROP"},
		{"-D", "INPUT", "-m", "set", "--match-set", "vsafegate-countries", "src", "-j", "DROP"},
		{"-D", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", "2251,22222,22", "-j", "ACCEPT"},
		{"-D", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", "22,22222", "-j", "ACCEPT"},
	}
	for _, args := range legacy {
		for i := 0; i < 4; i++ {
			if err := r.Run("iptables", args...); err != nil {
				break
			}
		}
	}
}

func applyChainWith(r firewallRunner, bin, parentChain, chainName string, rules []firewallRuleSpec) {
	_ = r.Run(bin, "-N", chainName)
	_ = r.Run(bin, "-F", chainName)

	for _, rule := range rules {
		args := append([]string{"-A", chainName}, rule.args...)
		if err := r.Run(bin, args...); err != nil {
			if rule.optional {
				logFirewallWarnOnce("opt-"+bin+"-"+strings.Join(rule.args, "_"), "[Firewall] Optional %s rule skipped (kernel/LXC module unavailable): %v", bin, err)
			} else {
				logFirewallWarnOnce("req-"+bin+"-"+chainName, "[Firewall] Failed applying %s rule in %s (%v): %v", bin, chainName, rule.args, err)
			}
		}
	}

	if err := r.Run(bin, "-C", parentChain, "-j", chainName); err != nil {
		_ = r.Run(bin, "-I", parentChain, "1", "-j", chainName)
	}
}

func removeChainWith(r firewallRunner, bin, parentChain, chainName string) {
	for i := 0; i < 4; i++ {
		if err := r.Run(bin, "-D", parentChain, "-j", chainName); err != nil {
			break
		}
	}
	_ = r.Run(bin, "-F", chainName)
	_ = r.Run(bin, "-X", chainName)
}

func (s *AppState) syncWhitelistAndTrustedIpsetsWith(r firewallRunner, cfg Config) {
	if r == nil {
		return
	}
	wlScript := buildAtomicIpsetSwapScript("vsafegate-whitelist", 65536, collectWhitelistIPv4Entries(cfg))
	if err := r.RunStdin(wlScript, "ipset", "restore"); err != nil {
		logFirewallWarnOnce("ipset-wl", "[Firewall] Failed syncing vsafegate-whitelist ipset: %v", err)
	}
	trustedScript := buildAtomicIpsetSwapScript("vsafegate-trusted", 4096, collectTrustedIPv4Entries(cfg))
	if err := r.RunStdin(trustedScript, "ipset", "restore"); err != nil {
		logFirewallWarnOnce("ipset-trusted", "[Firewall] Failed syncing vsafegate-trusted ipset: %v", err)
	}
}

func (s *AppState) applyIptablesRules() {
	if runtime.GOOS != "linux" {
		return
	}
	s.applyIptablesRulesWith(osFirewallRunner{})
}

func (s *AppState) applyIptablesRulesWith(r firewallRunner) {
	s.firewallMu.Lock()
	defer s.firewallMu.Unlock()
	s.applyIptablesRulesWithLocked(r)
}

func (s *AppState) applyIptablesRulesWithLocked(r firewallRunner) {
	s.mu.RLock()
	cfgSnap := s.config
	cfgSnap.Sites = append([]Site(nil), s.config.Sites...)
	cfgSnap.L4Services = append([]L4Service(nil), s.config.L4Services...)
	cfgSnap.WhitelistIPs = append([]WhitelistIPEntry(nil), s.config.WhitelistIPs...)
	cfgSnap.TrustedProxies = append([]string(nil), s.config.TrustedProxies...)
	cfgSnap.MgmtAllowedCIDRs = append([]string(nil), s.config.MgmtAllowedCIDRs...)
	s.mu.RUnlock()

	if cfgSnap.GeoIPMode == "" {
		cfgSnap.GeoIPMode = "disabled"
	}

	caps := detectFirewallCapabilitiesWith(r)
	applyBestEffortSysctlWith(r, caps)

	if caps.HasIPSet {
		s.syncWhitelistAndTrustedIpsetsWith(r, cfgSnap)
	}

	if caps.HasIPTables {
		cleanupLegacyInputRulesWith(r)
		hasTI := caps.HasIPSet && ipsetExists(r, "vsafegate-threatintel")
		hasTrusted := caps.HasIPSet && ipsetExists(r, "vsafegate-trusted")
		hasWL := caps.HasIPSet && ipsetExists(r, "vsafegate-whitelist")
		hasShared := caps.HasIPSet && ipsetExists(r, "vsafegate-shared")

		inRules := buildIPv4InputRulesWithShared(cfgSnap, hasTI, hasTrusted, hasWL, hasShared)
		applyChainWith(r, "iptables", "INPUT", "VSAFEGATE_INPUT", inRules)

		if cfgSnap.DefensePolicy.EgressFilterEnabled {
			outRules := buildIPv4OutputRules(hasTI, hasWL)
			applyChainWith(r, "iptables", "OUTPUT", "VSAFEGATE_OUTPUT", outRules)
		} else {
			removeChainWith(r, "iptables", "OUTPUT", "VSAFEGATE_OUTPUT")
		}
	} else {
		logFirewallWarnOnce("no-iptables", "[Firewall] iptables not available or lacks CAP_NET_ADMIN; L3/L4 IPv4 rules skipped")
	}

	if caps.HasIP6Tables {
		v6Rules := buildIPv6InputRules()
		applyChainWith(r, "ip6tables", "INPUT", "VSAFEGATE6_INPUT", v6Rules)
	} else {
		logFirewallWarnOnce("no-ip6tables", "[Firewall] ip6tables unavailable (e.g. LXC host lacks ip6table_filter); IPv6 chain skipped")
	}
}

func (s *AppState) initFirewall() {
	if runtime.GOOS != "linux" {
		return
	}
	s.firewallMu.Lock()
	defer s.firewallMu.Unlock()

	r := osFirewallRunner{}
	caps := detectFirewallCapabilitiesWith(r)
	if !caps.HasIPSet {
		logFirewallWarnOnce("no-ipset", "[Firewall] ipset unavailable; kernel IP sets skipped")
		s.applyIptablesRulesWithLocked(r)
		return
	}

	_ = r.Run("ipset", "create", "vsafegate-blacklist", "hash:net", "maxelem", "65536", "-exist")
	_ = r.Run("ipset", "create", "vsafegate-threatintel", "hash:net", "maxelem", "131072", "-exist")
	_ = r.Run("ipset", "create", "vsafegate-countries", "hash:net", "maxelem", "262144", "-exist")
	_ = r.Run("ipset", "create", "vsafegate-allowed", "hash:net", "maxelem", "262144", "-exist")
	_ = r.Run("ipset", "create", "vsafegate-whitelist", "hash:net", "maxelem", "65536", "-exist")
	_ = r.Run("ipset", "create", "vsafegate-trusted", "hash:net", "maxelem", "4096", "-exist")

	// Sync banned IPs into kernel ipset using atomic swap (or add)
	s.mu.RLock()
	var bannedEntries []string
	for _, b := range s.config.BannedIPs {
		if b.IP != "" {
			bannedEntries = append(bannedEntries, b.IP)
		}
	}
	if len(bannedEntries) == 0 {
		for _, ip := range s.config.BlacklistIP {
			if ip != "" {
				bannedEntries = append(bannedEntries, ip)
			}
		}
	}
	s.mu.RUnlock()

	script := buildAtomicIpsetSwapScript("vsafegate-blacklist", 65536, bannedEntries)
	if err := r.RunStdin(script, "ipset", "restore"); err != nil {
		log.Printf("[Firewall] Warning: failed to initialize vsafegate-blacklist ipset: %v", err)
	}

	s.applyIptablesRulesWithLocked(r)
}

func (s *AppState) syncGeoIP() {
	s.mu.RLock()
	mode := s.config.GeoIPMode
	if mode == "" {
		mode = "disabled"
	}
	var countries []string
	if mode == "whitelist" {
		countries = make([]string, len(s.config.AllowedCountries))
		copy(countries, s.config.AllowedCountries)
	} else if mode == "blacklist" {
		countries = make([]string, len(s.config.BlockedCountries))
		copy(countries, s.config.BlockedCountries)
	}
	cfgSnap := s.config
	cfgSnap.WhitelistIPs = append([]WhitelistIPEntry(nil), s.config.WhitelistIPs...)
	s.mu.RUnlock()

	if mode == "disabled" {
		s.applyIptablesRules()
		return
	}

	dir := "/etc/vsafegate/geoip"
	if err := os.MkdirAll(dir, 0755); err != nil {
		dir = filepath.Join(os.TempDir(), "vsafegate-geoip")
		_ = os.MkdirAll(dir, 0755)
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

				zoneURL := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", cc)
				resp, err := client.Get(zoneURL)
				if err != nil || resp.StatusCode != 200 {
					if resp != nil {
						resp.Body.Close()
					}
					zoneURL = fmt.Sprintf("http://www.ipdeny.com/ipblocks/data/countries/%s.zone", cc)
					resp, err = client.Get(zoneURL)
				}
				if err == nil && resp != nil {
					if resp.StatusCode == 200 {
						body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
						if err == nil && len(body) > 0 {
							_ = os.WriteFile(zp, body, 0644)
						}
					}
					resp.Body.Close()
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

	r := osFirewallRunner{}
	if mode == "whitelist" {
		allCIDRs = append(collectWhitelistIPv4Entries(cfgSnap), allCIDRs...)
		combPath := filepath.Join(dir, "allowed-all.txt")
		_ = os.WriteFile(combPath, []byte(strings.Join(allCIDRs, "\n")), 0644)
	} else {
		combPath := filepath.Join(dir, "blocked-all.txt")
		_ = os.WriteFile(combPath, []byte(strings.Join(allCIDRs, "\n")), 0644)
	}

	if runtime.GOOS == "linux" {
		s.firewallMu.Lock()
		if mode == "whitelist" {
			script := buildAtomicIpsetSwapScript("vsafegate-allowed", 262144, allCIDRs)
			if err := r.RunStdin(script, "ipset", "restore"); err != nil {
				log.Printf("[GeoIP] Warning: ipset restore failed for vsafegate-allowed: %v", err)
			}
		} else {
			script := buildAtomicIpsetSwapScript("vsafegate-countries", 262144, allCIDRs)
			if err := r.RunStdin(script, "ipset", "restore"); err != nil {
				log.Printf("[GeoIP] Warning: ipset restore failed for vsafegate-countries: %v", err)
			}
		}
		s.applyIptablesRulesWithLocked(r)
		s.firewallMu.Unlock()
	}
	if s.telemetry != nil {
		s.telemetry.InvalidateGeoIPCache()
	}
	if s.reloadManager != nil {
		s.reloadManager.Trigger()
	}
}
