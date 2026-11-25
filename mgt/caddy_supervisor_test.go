package main

import (
	"net"
	"testing"
)

func TestCaddySupervisorLifecycleHelpers(t *testing.T) {
	cs := NewCaddySupervisor("./Caddyfile")
	if cs.IsManaged() {
		t.Fatal("expected IsManaged() to be false before Start()")
	}

	// Stop() before Start() must be safe and non-blocking
	cs.Stop()
	cs.Stop()

	// Verify isAddrListening accurately detects open/closed local TCP ports
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind ephemeral port: %v", err)
	}
	addr := ln.Addr().String()
	if !isAddrListening(addr) {
		ln.Close()
		t.Fatalf("expected isAddrListening(%s) to return true while listener is open", addr)
	}
	ln.Close()
	if isAddrListening(addr) {
		t.Fatalf("expected isAddrListening(%s) to return false after Close()", addr)
	}
	if isAddrListening("") {
		t.Fatal("expected isAddrListening(\"\") to return false")
	}
}
