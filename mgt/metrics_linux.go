//go:build linux

package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	cpuMu         sync.RWMutex
	curCPUPercent float64
)

func startCPUMonitor() {
	go func() {
		var prevIdle, prevTotal uint64
		for {
			data, err := os.ReadFile("/proc/stat")
			if err == nil {
				lines := strings.Split(string(data), "\n")
				if len(lines) > 0 && strings.HasPrefix(lines[0], "cpu ") {
					fields := strings.Fields(lines[0])
					if len(fields) >= 5 {
						var total, idle uint64
						for i := 1; i < len(fields); i++ {
							val, _ := strconv.ParseUint(fields[i], 10, 64)
							total += val
							if i == 4 { // idle field
								idle = val
							}
						}
						if prevTotal > 0 && total > prevTotal {
							deltaTotal := float64(total - prevTotal)
							deltaIdle := float64(idle - prevIdle)
							percent := (1.0 - (deltaIdle / deltaTotal)) * 100.0
							if percent < 0 {
								percent = 0
							} else if percent > 100 {
								percent = 100
							}
							cpuMu.Lock()
							curCPUPercent = math.Round(percent*10) / 10
							cpuMu.Unlock()
						}
						prevTotal = total
						prevIdle = idle
					}
				}
			}
			time.Sleep(2 * time.Second)
		}
	}()
}

func (s *AppState) getSystemMetrics() SystemMetrics {
	cpuMu.RLock()
	cpu := curCPUPercent
	cpuMu.RUnlock()

	var metrics SystemMetrics
	metrics.CPUPercent = cpu

	// RAM from /proc/meminfo
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		var memTotalKB, memAvailKB int64
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if parts[0] == "MemTotal:" {
					memTotalKB, _ = strconv.ParseInt(parts[1], 10, 64)
				} else if parts[0] == "MemAvailable:" {
					memAvailKB, _ = strconv.ParseInt(parts[1], 10, 64)
				}
			}
		}
		if memTotalKB > 0 {
			metrics.MemTotalMB = memTotalKB / 1024
			metrics.MemUsedMB = (memTotalKB - memAvailKB) / 1024
			metrics.MemPercent = math.Round(float64(metrics.MemUsedMB)/float64(metrics.MemTotalMB)*1000) / 10
		}
	}

	// Disk from syscall.Statfs
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		totalBytes := stat.Blocks * uint64(stat.Bsize)
		freeBytes := stat.Bfree * uint64(stat.Bsize)
		usedBytes := totalBytes - freeBytes
		metrics.DiskTotalGB = math.Round(float64(totalBytes)/(1024*1024*1024)*10) / 10
		metrics.DiskUsedGB = math.Round(float64(usedBytes)/(1024*1024*1024)*10) / 10
		if metrics.DiskTotalGB > 0 {
			metrics.DiskPercent = math.Round(metrics.DiskUsedGB/metrics.DiskTotalGB*1000) / 10
		}
	}

	// Load Average from /proc/loadavg
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			metrics.Load1, _ = strconv.ParseFloat(fields[0], 64)
			metrics.Load5, _ = strconv.ParseFloat(fields[1], 64)
			metrics.Load15, _ = strconv.ParseFloat(fields[2], 64)
		}
	}

	// Uptime from /proc/uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			upSec, _ := strconv.ParseFloat(fields[0], 64)
			metrics.UptimeSeconds = int64(upSec)
			days := int(upSec) / 86400
			hours := (int(upSec) % 86400) / 3600
			mins := (int(upSec) % 3600) / 60
			if days > 0 {
				metrics.UptimeStr = fmt.Sprintf("%d ngày, %d giờ", days, hours)
			} else if hours > 0 {
				metrics.UptimeStr = fmt.Sprintf("%d giờ, %d phút", hours, mins)
			} else {
				metrics.UptimeStr = fmt.Sprintf("%d phút", mins)
			}
		}
	}

	// TCP Connections from /proc/net/sockstat
	if data, err := os.ReadFile("/proc/net/sockstat"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "TCP:") {
				fields := strings.Fields(line)
				for i := 0; i < len(fields)-1; i++ {
					if fields[i] == "inuse" {
						metrics.TCPConns, _ = strconv.Atoi(fields[i+1])
						break
					}
				}
			}
		}
	}

	s.mu.RLock()
	metrics.SSHBans = atomic.LoadInt64(&s.sshBannedCount)
	metrics.PortScanBans = atomic.LoadInt64(&s.portScanCount)
	metrics.BlockedIPs = len(s.config.BannedIPs)
	if metrics.BlockedIPs == 0 {
		metrics.BlockedIPs = len(s.config.BlacklistIP)
	}
	metrics.GeoIPMode = s.config.GeoIPMode
	if metrics.GeoIPMode == "" {
		metrics.GeoIPMode = "disabled"
	}
	s.mu.RUnlock()

	if metrics.GeoIPMode == "whitelist" {
		metrics.GeoIPCount = getIpsetCount("vsafegate-allowed")
	} else if metrics.GeoIPMode == "blacklist" {
		metrics.GeoIPCount = getIpsetCount("vsafegate-countries")
	} else {
		metrics.GeoIPCount = 0
	}

	metrics.IDSAlerts = atomic.LoadInt64(&idsAlertTotal)
	var l4Active int64
	l4Manager.mu.Lock()
	for _, svc := range l4Manager.services {
		l4Active += atomic.LoadInt64(&svc.ActiveConns)
	}
	l4Manager.mu.Unlock()
	metrics.L4ActiveConns = l4Active
	s.mu.RLock()
	metrics.L4ServiceCount = len(s.config.L4Services)
	s.mu.RUnlock()

	return metrics
}
