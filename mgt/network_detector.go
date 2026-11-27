package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// DetectedInterface represents a network interface discovered in real-time from the kernel
type DetectedInterface struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	IP              string `json:"ip"`
	CIDR            string `json:"cidr"`
	RecommendedCIDR string `json:"recommended_cidr"`
	Note            string `json:"note"`
	IsWhitelisted   bool   `json:"is_whitelisted"`
}

// detectNetworkInterfaces inspects all active network interfaces in real-time
func (s *AppState) detectNetworkInterfaces() []DetectedInterface {
	s.mu.RLock()
	whitelisted := make(map[string]bool)
	for _, w := range s.config.WhitelistIPs {
		whitelisted[strings.TrimSpace(w.IP)] = true
	}
	s.mu.RUnlock()

	interfaces, err := net.Interfaces()
	if err != nil {
		return []DetectedInterface{}
	}

	results := make([]DetectedInterface, 0)
	seenCIDRs := make(map[string]bool)

	for _, ifi := range interfaces {
		// Skip down interfaces
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		// Skip loopback interface
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			ip := ipnet.IP.To4()
			if ip.IsLoopback() {
				continue
			}

			nameLower := strings.ToLower(ifi.Name)
			var ifType, recCIDR, note string

			ones, _ := ipnet.Mask.Size()
			calcSubnet := fmt.Sprintf("%s/%d", ip.Mask(ipnet.Mask).String(), ones)

			// Identification logic for Tailscale, ZeroTier, Docker, Bridges, LAN
			if strings.HasPrefix(nameLower, "tailscale") || (ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127) {
				ifType = "Tailscale VPN"
				recCIDR = "100.64.0.0/10"
				note = fmt.Sprintf("Tailscale VPN Network (%s - %s)", ifi.Name, ip.String())
			} else if strings.HasPrefix(nameLower, "zt") || (ip[0] == 172 && (ip[1] == 28 || ip[1] == 29)) {
				ifType = "ZeroTier VPN"
				recCIDR = "172.29.0.0/16"
				note = fmt.Sprintf("ZeroTier VPN Network (%s - %s)", ifi.Name, ip.String())
			} else if strings.HasPrefix(nameLower, "vmbr") {
				ifType = "Proxmox LAN Bridge"
				recCIDR = calcSubnet
				note = fmt.Sprintf("Proxmox Bridge LAN (%s - %s)", ifi.Name, ip.String())
			} else if strings.HasPrefix(nameLower, "docker") || strings.HasPrefix(nameLower, "br-") {
				ifType = "Docker Bridge"
				recCIDR = calcSubnet
				note = fmt.Sprintf("Docker Network (%s)", ifi.Name)
			} else if strings.HasPrefix(nameLower, "eth") || strings.HasPrefix(nameLower, "en") || strings.HasPrefix(nameLower, "wl") {
				ifType = "LAN Vật Lý (Ethernet/WiFi)"
				recCIDR = calcSubnet
				note = fmt.Sprintf("LAN Nội Bộ (%s - %s)", ifi.Name, ip.String())
			} else {
				ifType = "Card Mạng Nội Bộ"
				recCIDR = calcSubnet
				note = fmt.Sprintf("Card Mạng (%s - %s)", ifi.Name, ip.String())
			}

			if seenCIDRs[recCIDR] {
				continue
			}
			seenCIDRs[recCIDR] = true

			// Check if already in whitelist
			isWL := whitelisted[recCIDR] || whitelisted[ip.String()]
			if !isWL {
				for wlIP := range whitelisted {
					if wlIP == recCIDR {
						isWL = true
						break
					}
				}
			}

			results = append(results, DetectedInterface{
				Name:            ifi.Name,
				Type:            ifType,
				IP:              ip.String(),
				CIDR:            ipnet.String(),
				RecommendedCIDR: recCIDR,
				Note:            note,
				IsWhitelisted:   isWL,
			})
		}
	}

	return results
}

// registerNetworkDetectorRoutes mounts the real-time interface detection APIs
func registerNetworkDetectorRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/network/interfaces", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		interfaces := state.detectNetworkInterfaces()
		json.NewEncoder(w).Encode(interfaces)
	}))

	mux.HandleFunc("/api/network/interfaces/apply", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			CIDRs []struct {
				CIDR string `json:"cidr"`
				Note string `json:"note"`
			} `json:"cidrs"`
			All bool `json:"all"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		addedCount := 0
		if payload.All {
			detected := state.detectNetworkInterfaces()
			for _, item := range detected {
				if !item.IsWhitelisted {
					if err := state.addWhitelistIP(item.RecommendedCIDR, item.Note); err == nil {
						addedCount++
					}
				}
			}
		} else {
			for _, item := range payload.CIDRs {
				if item.CIDR != "" {
					note := item.Note
					if note == "" {
						note = "Card Mạng Hệ Thống (" + item.CIDR + ")"
					}
					if err := state.addWhitelistIP(item.CIDR, note); err == nil {
						addedCount++
					}
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "ok",
			"added_count": addedCount,
		})
	}))
}
