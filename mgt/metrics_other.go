//go:build !linux

package main

import (
	"sync/atomic"
)

func startCPUMonitor() {
	// No-op on non-Linux
}

func (s *AppState) getSystemMetrics() SystemMetrics {
	var metrics SystemMetrics
	metrics.CPUPercent = 5.2
	metrics.MemUsedMB = 512
	metrics.MemTotalMB = 4096
	metrics.MemPercent = 12.5
	metrics.DiskUsedGB = 20.5
	metrics.DiskTotalGB = 100.0
	metrics.DiskPercent = 20.5
	metrics.Load1 = 0.15
	metrics.Load5 = 0.25
	metrics.Load15 = 0.10
	metrics.UptimeSeconds = 3600
	metrics.UptimeStr = "1 giờ, 0 phút"
	metrics.TCPConns = 12

	s.mu.RLock()
	metrics.SSHBans = atomic.LoadInt64(&s.sshBannedCount)
	metrics.PortScanBans = atomic.LoadInt64(&s.portScanCount)
	metrics.BlockedIPs = len(s.config.BannedIPs)
	if metrics.BlockedIPs == 0 {
		metrics.BlockedIPs = len(s.config.BlacklistIP)
	}
	metrics.GeoIPMode = s.config.GeoIPMode
	if metrics.GeoIPMode == "" {
		metrics.GeoIPMode = "whitelist"
	}
	metrics.L4ServiceCount = len(s.config.L4Services)
	s.mu.RUnlock()

	metrics.GeoIPCount = 1
	metrics.IDSAlerts = atomic.LoadInt64(&idsAlertTotal)

	var l4Active int64
	l4Manager.mu.Lock()
	for _, svc := range l4Manager.services {
		l4Active += atomic.LoadInt64(&svc.ActiveConns)
	}
	l4Manager.mu.Unlock()
	metrics.L4ActiveConns = l4Active

	return metrics
}
