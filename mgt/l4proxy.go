package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type L4ProxyManager struct {
	mu        sync.Mutex
	listeners map[string]net.Listener
	services  map[string]*L4Service
}

var l4Manager = &L4ProxyManager{
	listeners: make(map[string]net.Listener),
	services:  make(map[string]*L4Service),
}

func (m *L4ProxyManager) Sync(services []L4Service) {
	m.mu.Lock()
	defer m.mu.Unlock()

	activeIDs := make(map[string]bool)

	for i := range services {
		svc := &services[i]
		managed, exists := m.services[svc.ID]
		if !exists {
			managed = &L4Service{
				ID:          svc.ID,
				Name:        svc.Name,
				Protocol:    svc.Protocol,
				ListenPort:  svc.ListenPort,
				BackendAddr: svc.BackendAddr,
				Mode:        svc.Mode,
				Enabled:     svc.Enabled,
				MaxConns:    svc.MaxConns,
				RateLimit:   svc.RateLimit,
				Description: svc.Description,
			}
			m.services[svc.ID] = managed
		} else {
			managed.Name = svc.Name
			managed.Protocol = svc.Protocol
			managed.ListenPort = svc.ListenPort
			managed.BackendAddr = svc.BackendAddr
			managed.Mode = svc.Mode
			managed.Enabled = svc.Enabled
			managed.MaxConns = svc.MaxConns
			managed.RateLimit = svc.RateLimit
			managed.Description = svc.Description
		}

		if svc.Enabled {
			activeIDs[svc.ID] = true
			ln, exists := m.listeners[svc.ID]
			if exists {
				tcpAddr, ok := ln.Addr().(*net.TCPAddr)
				if !ok || tcpAddr.Port != svc.ListenPort {
					log.Printf("[L4 Proxy] Port changed for %s (now %d), restarting listener", svc.Name, svc.ListenPort)
					ln.Close()
					delete(m.listeners, svc.ID)
					exists = false
				}
			}
			if !exists {
				addr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)
				newLn, err := net.Listen("tcp", addr)
				if err != nil {
					log.Printf("[L4 Proxy] Failed to bind %s (Port %d): %v", svc.Name, svc.ListenPort, err)
					continue
				}
				m.listeners[svc.ID] = newLn
				log.Printf("[L4 Proxy] Started listening for %s on %s -> %s", svc.Name, addr, svc.BackendAddr)

				go m.handleListener(svc.ID, newLn)
			}
		}
	}

	for id, ln := range m.listeners {
		if !activeIDs[id] {
			log.Printf("[L4 Proxy] Stopping listener for service ID %s", id)
			ln.Close()
			delete(m.listeners, id)
		}
	}
}

func (m *L4ProxyManager) handleListener(svcID string, ln net.Listener) {
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			// Listener was closed (Sync stopped or restart) -> exit cleanly
			return
		}

		m.mu.Lock()
		svc, ok := m.services[svcID]
		m.mu.Unlock()

		// If service is disabled, drop connection and CONTINUE waiting until ln is closed
		if !ok || !svc.Enabled {
			clientConn.Close()
			continue
		}

		if svc.MaxConns > 0 && atomic.LoadInt64(&svc.ActiveConns) >= int64(svc.MaxConns) {
			log.Printf("[L4 Proxy] Max connections reached for %s (%d), dropping", svc.Name, svc.MaxConns)
			clientConn.Close()
			continue
		}

		atomic.AddInt64(&svc.ActiveConns, 1)
		atomic.AddInt64(&svc.TotalConns, 1)

		go func(c net.Conn, targetAddr string, s *L4Service) {
			defer func() {
				c.Close()
				atomic.AddInt64(&s.ActiveConns, -1)
			}()

			backendConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
			if err != nil {
				log.Printf("[L4 Proxy] Failed to connect to backend %s for %s: %v", targetAddr, s.Name, err)
				return
			}
			defer backendConn.Close()

			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetKeepAlive(true)
				tc.SetKeepAlivePeriod(30 * time.Second)
			}
			if tb, ok := backendConn.(*net.TCPConn); ok {
				tb.SetKeepAlive(true)
				tb.SetKeepAlivePeriod(30 * time.Second)
			}

			var wg sync.WaitGroup
			wg.Add(2)

			// Client -> Backend (zero-copy splice on Linux)
			go func() {
				defer wg.Done()
				n, _ := io.Copy(backendConn, c)
				atomic.AddInt64(&s.BytesIn, n)
				if tcpConn, ok := backendConn.(*net.TCPConn); ok {
					tcpConn.CloseWrite()
				}
			}()

			// Backend -> Client
			go func() {
				defer wg.Done()
				n, _ := io.Copy(c, backendConn)
				atomic.AddInt64(&s.BytesOut, n)
				if tcpConn, ok := c.(*net.TCPConn); ok {
					tcpConn.CloseWrite()
				}
			}()

			wg.Wait()
		}(clientConn, svc.BackendAddr, svc)
	}
}
