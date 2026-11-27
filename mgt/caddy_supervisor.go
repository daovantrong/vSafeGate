package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CaddySupervisor manages the lifecycle of the Caddy + Coraza WAF L7 child process
// directly inside the vsafegate daemon so administrators only operate a single service.
type CaddySupervisor struct {
	caddyPath        string
	adminAddr        string
	mu               sync.Mutex
	cmd              *exec.Cmd
	stopCh           chan struct{}
	doneCh           chan struct{}
	stopOnce         sync.Once
	started          atomic.Bool
	stopped          atomic.Bool
	running          atomic.Bool
	managed          atomic.Bool
	restartCount     atomic.Int64
	onUnexpectedExit func(uptime time.Duration, err error)
}

func (cs *CaddySupervisor) SetOnUnexpectedExit(fn func(uptime time.Duration, err error)) {
	cs.mu.Lock()
	cs.onUnexpectedExit = fn
	cs.mu.Unlock()
}

func NewCaddySupervisor(caddyPath string) *CaddySupervisor {
	return &CaddySupervisor{
		caddyPath: caddyPath,
		adminAddr: "127.0.0.1:2019",
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

func findCaddyBinary() string {
	if p, err := exec.LookPath("caddy"); err == nil {
		return p
	}
	for _, candidate := range []string{"/usr/bin/caddy", "/usr/local/bin/caddy"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func isAddrListening(addr string) bool {
	if addr == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (cs *CaddySupervisor) Start() {
	if !cs.started.CompareAndSwap(false, true) {
		return
	}
	go cs.runLoop()
}

func (cs *CaddySupervisor) waitOrStop(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-cs.stopCh:
		return false
	case <-timer.C:
		return true
	}
}

func (cs *CaddySupervisor) runLoop() {
	defer close(cs.doneCh)

	backoff := 2 * time.Second
	externalLogged := false

	for !cs.stopped.Load() {
		bin := findCaddyBinary()
		if bin == "" {
			cs.running.Store(false)
			cs.managed.Store(false)
			if !cs.waitOrStop(10 * time.Second) {
				return
			}
			continue
		}

		// Yield safely if an external Caddy instance (e.g., Docker) already owns Admin API
		if isAddrListening(cs.adminAddr) {
			if !externalLogged {
				log.Printf("[Caddy Supervisor] External Caddy detected on %s; using reload-only mode", cs.adminAddr)
				externalLogged = true
			}
			cs.running.Store(true)
			cs.managed.Store(false)
			if !cs.waitOrStop(5 * time.Second) {
				return
			}
			continue
		}
		externalLogged = false

		cmd := exec.Command(bin, "run", "--environ", "--config", cs.caddyPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		dataDir := "/etc/vsafegate/caddy-data"
		cfgDir := filepath.Dir(cs.caddyPath)
		if os.Getenv("ENV") == "dev" {
			dataDir = "./caddy-data"
		}
		_ = os.MkdirAll(dataDir, 0700)
		_ = os.MkdirAll(cfgDir, 0755)
		env := os.Environ()
		hasHome := false
		for _, e := range env {
			if strings.HasPrefix(e, "HOME=") {
				hasHome = true
				break
			}
		}
		if !hasHome {
			env = append(env, "HOME=/root")
		}
		env = append(env, "XDG_DATA_HOME="+dataDir, "XDG_CONFIG_HOME="+cfgDir)
		cmd.Env = env
		setCaddySysProcAttr(cmd)

		if err := cmd.Start(); err != nil {
			log.Printf("[Caddy Supervisor] Failed to start %s: %v (retrying in %s)", bin, err, backoff)
			cs.running.Store(false)
			cs.managed.Store(false)
			if !cs.waitOrStop(backoff) {
				return
			}
			if backoff < 15*time.Second {
				backoff += 3 * time.Second
			}
			continue
		}

		cs.mu.Lock()
		cs.cmd = cmd
		cs.mu.Unlock()

		startTime := time.Now()
		cs.running.Store(true)
		cs.managed.Store(true)
		log.Printf("[Caddy Supervisor] Started managed Caddy L7 WAF (PID: %d)", cmd.Process.Pid)

		waitErr := cmd.Wait()

		cs.mu.Lock()
		cs.cmd = nil
		cs.mu.Unlock()
		cs.running.Store(false)
		cs.managed.Store(false)

		if cs.stopped.Load() {
			return
		}

		uptime := time.Since(startTime)
		cs.restartCount.Add(1)
		log.Printf("[Caddy Supervisor] Caddy exited unexpectedly after %s (%v); restarting...", uptime.Round(time.Millisecond), waitErr)
		cs.mu.Lock()
		cb := cs.onUnexpectedExit
		cs.mu.Unlock()
		if cb != nil {
			go cb(uptime, waitErr)
		}

		if uptime >= 5*time.Second {
			backoff = 1 * time.Second
		} else if backoff < 15*time.Second {
			backoff += 3 * time.Second
		}

		if !cs.waitOrStop(backoff) {
			return
		}
	}
}

func (cs *CaddySupervisor) Reload() error {
	if cs.caddyPath != "" {
		if data, err := os.ReadFile(cs.caddyPath); err == nil {
			if err := reloadCaddyViaAdminAPI(cs.adminAddr, data); err == nil {
				return nil
			}
		}
	}
	bin := findCaddyBinary()
	if bin == "" {
		return fmt.Errorf("caddy binary not found")
	}
	out, err := exec.Command(bin, "reload", "--config", cs.caddyPath, "--force").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}

func (cs *CaddySupervisor) Stop() {
	cs.stopped.Store(true)
	cs.stopOnce.Do(func() {
		close(cs.stopCh)
	})

	cs.mu.Lock()
	var proc *os.Process
	if cs.cmd != nil && cs.cmd.Process != nil {
		proc = cs.cmd.Process
	}
	cs.mu.Unlock()

	if proc != nil {
		log.Printf("[Caddy Supervisor] Stopping managed Caddy (PID: %d)...", proc.Pid)
		_ = signalTerminateProcess(proc)
	}

	if !cs.started.Load() {
		return
	}

	select {
	case <-cs.doneCh:
	case <-time.After(5 * time.Second):
		if proc != nil {
			log.Printf("[Caddy Supervisor] Force-killing Caddy (PID: %d) after timeout", proc.Pid)
			_ = proc.Kill()
		}
		select {
		case <-cs.doneCh:
		case <-time.After(1 * time.Second):
		}
	}
}

func (cs *CaddySupervisor) IsRunning() bool {
	return cs.running.Load() || isAddrListening(cs.adminAddr) || isProcessRunning("caddy")
}

func (cs *CaddySupervisor) IsManaged() bool {
	return cs.managed.Load()
}

func (cs *CaddySupervisor) RestartCount() int64 {
	return cs.restartCount.Load()
}
