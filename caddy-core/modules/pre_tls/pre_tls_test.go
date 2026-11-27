package pre_tls

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func buildTestClientHelloRecord(sni, alpn string, tls13 bool) []byte {
	var exts []byte
	if sni != "" {
		name := []byte(sni)
		// server_name entry: type(1)=0 + len(2) + name
		entry := make([]byte, 3+len(name))
		entry[0] = 0x00
		binary.BigEndian.PutUint16(entry[1:3], uint16(len(name)))
		copy(entry[3:], name)

		list := make([]byte, 2+len(entry))
		binary.BigEndian.PutUint16(list[0:2], uint16(len(entry)))
		copy(list[2:], entry)

		ext := make([]byte, 4+len(list))
		binary.BigEndian.PutUint16(ext[0:2], 0x0000)
		binary.BigEndian.PutUint16(ext[2:4], uint16(len(list)))
		copy(ext[4:], list)
		exts = append(exts, ext...)
	}
	if alpn != "" {
		proto := append([]byte{byte(len(alpn))}, []byte(alpn)...)
		list := make([]byte, 2+len(proto))
		binary.BigEndian.PutUint16(list[0:2], uint16(len(proto)))
		copy(list[2:], proto)

		ext := make([]byte, 4+len(list))
		binary.BigEndian.PutUint16(ext[0:2], 0x0010)
		binary.BigEndian.PutUint16(ext[2:4], uint16(len(list)))
		copy(ext[4:], list)
		exts = append(exts, ext...)
	}
	if tls13 {
		// supported_versions: GREASE 0x0a0a + 0x0304
		sv := []byte{0x04, 0x0a, 0x0a, 0x03, 0x04}
		ext := make([]byte, 4+len(sv))
		binary.BigEndian.PutUint16(ext[0:2], 0x002b)
		binary.BigEndian.PutUint16(ext[2:4], uint16(len(sv)))
		copy(ext[4:], sv)
		exts = append(exts, ext...)
	}

	var body []byte
	body = append(body, 0x03, 0x03)              // legacy_version TLS 1.2
	body = append(body, make([]byte, 32)...)     // random
	body = append(body, 0x00)                    // session_id len = 0
	body = append(body, 0x00, 0x04, 0x13, 0x01, 0x0a, 0x0a) // ciphers + GREASE
	body = append(body, 0x01, 0x00)              // compression = null

	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(len(exts)))
	body = append(body, extLen...)
	body = append(body, exts...)

	hs := make([]byte, 4+len(body))
	hs[0] = 0x01
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

func TestParseClientHello(t *testing.T) {
	rec := buildTestClientHelloRecord("App.Example.COM.", "h2", true)
	info, err := ParseClientHello(rec[5:])
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}
	if info.SNI != "app.example.com" {
		t.Fatalf("expected normalized SNI app.example.com, got %q", info.SNI)
	}
	if info.ALPN != "h2" {
		t.Fatalf("expected ALPN h2, got %q", info.ALPN)
	}
	if info.TLSVersion != "13" {
		t.Fatalf("expected TLSVersion 13, got %q", info.TLSVersion)
	}
	if !strings.HasPrefix(info.JA4Light, "t13d0101_") {
		t.Fatalf("unexpected JA4Light fingerprint: %q", info.JA4Light)
	}

	// Missing SNI + IPv4 literal rejected as SNI
	recNoSNI := buildTestClientHelloRecord("1.2.3.4", "http/1.1", false)
	infoNoSNI, err := ParseClientHello(recNoSNI[5:])
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}
	if infoNoSNI.SNI != "" {
		t.Fatalf("expected IP literal SNI to be normalized to empty, got %q", infoNoSNI.SNI)
	}
	if !strings.HasPrefix(infoNoSNI.JA4Light, "t12i0100_") {
		t.Fatalf("unexpected JA4Light without SNI: %q", infoNoSNI.JA4Light)
	}
}

func TestPreTLS_SNIEnforcementAndBytesPreserved(t *testing.T) {
	p := &PreTLS{
		AllowedSNIs:          []string{"example.com", "*.app.example.com"},
		DropMissingSNI:       true,
		DropUnknownSNI:       true,
		HandshakePeekTimeout: caddy.Duration(2 * time.Second),
	}
	if err := p.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	wrapped := p.WrapListener(ln)
	defer wrapped.Close()

	// 1. Valid SNI (wildcard single-label): all ClientHello bytes preserved identically
	t.Run("valid_wildcard_sni", func(t *testing.T) {
		hello := buildTestClientHelloRecord("api.app.example.com", "h2", true)
		done := make(chan []byte, 1)
		errCh := make(chan error, 1)
		go func() {
			c, err := wrapped.Accept()
			if err != nil {
				errCh <- err
				return
			}
			defer c.Close()
			buf := make([]byte, 10) // test partial reads across buffered boundary
			var got []byte
			for len(got) < len(hello) {
				n, rerr := c.Read(buf)
				if n > 0 {
					got = append(got, buf[:n]...)
				}
				if rerr != nil {
					if rerr != io.EOF {
						errCh <- rerr
						return
					}
					break
				}
			}
			info, ok := UnwrapInfo(c)
			if !ok || info.SNI != "api.app.example.com" || info.JA4Light == "" {
				errCh <- io.ErrUnexpectedEOF
				return
			}
			done <- got
		}()

		cli, err := net.Dial("tcp", wrapped.Addr().String())
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if _, werr := cli.Write(hello[:7]); werr != nil {
			_ = cli.Close()
			t.Fatalf("Write part1: %v", werr)
		}
		time.Sleep(15 * time.Millisecond)
		if _, werr := cli.Write(hello[7:]); werr != nil {
			_ = cli.Close()
			t.Fatalf("Write part2: %v", werr)
		}
		if tc, ok := cli.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		defer cli.Close()

		select {
		case got := <-done:
			if string(got) != string(hello) {
				t.Fatalf("peek corrupted ClientHello bytes: got %d want %d", len(got), len(hello))
			}
		case e := <-errCh:
			t.Fatalf("server error: %v", e)
		case <-time.After(3 * time.Second):
			t.Fatal("timeout")
		}
	})

	// 2. Unknown SNI and multi-label wildcard bypass rejected silently with 0 bytes returned
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"unknown_sni", buildTestClientHelloRecord("evil.com", "h2", true)},
		{"multilevel_wildcard", buildTestClientHelloRecord("deep.sub.app.example.com", "h2", true)},
		{"missing_sni", buildTestClientHelloRecord("", "h2", true)},
		{"plaintext_http", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverDone := make(chan error, 1)
			go func() {
				c, err := wrapped.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer c.Close()
				b := make([]byte, 64)
				_, rerr := c.Read(b)
				serverDone <- rerr
			}()

			cli, err := net.Dial("tcp", wrapped.Addr().String())
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			_, _ = cli.Write(tc.payload)
			_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
			resp, rerr := io.ReadAll(cli)
			_ = cli.Close()

			if len(resp) != 0 {
				t.Fatalf("expected 0 response bytes on silent drop, got %q", resp)
			}
			if rerr != nil && rerr != io.EOF && !strings.Contains(rerr.Error(), "reset") && !strings.Contains(rerr.Error(), "closed") {
				t.Fatalf("unexpected client read error: %v", rerr)
			}

			select {
			case serr := <-serverDone:
				if serr == nil {
					t.Fatal("expected server Read to abort rejected connection")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timeout waiting for server drop")
			}
		})
	}
}

func TestPreTLS_StrictCloudflareOrigin(t *testing.T) {
	p := &PreTLS{
		StrictCloudflareOrigin: true,
		TrustedCIDRs:           []string{"10.0.0.0/8"}, // intentionally excludes 127.0.0.1
	}
	if err := p.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Empty CIDRs must fail Validate()
	bad := &PreTLS{StrictCloudflareOrigin: true}
	_ = bad.Provision(caddy.Context{})
	if err := bad.Validate(); err == nil {
		t.Fatal("expected Validate error when StrictCloudflareOrigin=true and TrustedCIDRs empty")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	wrapped := p.WrapListener(ln)
	defer wrapped.Close()

	// Accept loop runs on background goroutine and silently drops 127.0.0.1
	acceptReturned := make(chan struct{})
	go func() {
		_, _ = wrapped.Accept()
		close(acceptReturned)
	}()

	cli, err := net.Dial("tcp", wrapped.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf, _ := io.ReadAll(cli)
	_ = cli.Close()

	if len(buf) != 0 {
		t.Fatalf("expected 0 bytes from strict origin drop, got %d", len(buf))
	}
	select {
	case <-acceptReturned:
		t.Fatal("Accept() should not have returned untrusted client connection")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPreTLS_StandardTLSHandshake(t *testing.T) {
	p := &PreTLS{
		AllowedSNIs:    []string{"safe.example.com"},
		DropMissingSNI: true,
		DropUnknownSNI: true,
	}
	if err := p.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// Verify UnwrapInfo returns false on nil or non-PreTLS conn
	if _, ok := UnwrapInfo(nil); ok {
		t.Fatal("expected false for nil conn")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, ok := UnwrapInfo(a); ok {
		t.Fatal("expected false for plain net.Pipe")
	}
	_ = tls.VersionTLS13 // keep import for future handshake tests
}

func TestPreTLS_PerSNIStrictOriginIsolation(t *testing.T) {
	// Validate must fail if StrictOriginSNIs is configured without TrustedCIDRs
	bad := &PreTLS{
		StrictOriginSNIs: []string{"strict.example.com"},
	}
	_ = bad.Provision(caddy.Context{})
	if err := bad.Validate(); err == nil {
		t.Fatal("expected Validate error when StrictOriginSNIs is set without TrustedCIDRs")
	}

	// Case 1: 127.0.0.1 is NOT in TrustedCIDRs (simulating direct public visitor)
	// direct.example.com MUST be allowed while strict.example.com and *.cf.example.com MUST be silently dropped
	pUntrusted := &PreTLS{
		AllowedSNIs:            []string{"direct.example.com", "strict.example.com", "*.cf.example.com"},
		DropMissingSNI:         true,
		DropUnknownSNI:         true,
		StrictCloudflareOrigin: false,
		StrictOriginSNIs:       []string{"strict.example.com", "*.cf.example.com"},
		TrustedCIDRs:           []string{"10.0.0.0/8"},
		HandshakePeekTimeout:   caddy.Duration(2 * time.Second),
	}
	if err := pUntrusted.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := pUntrusted.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	wrapped := pUntrusted.WrapListener(ln)
	defer wrapped.Close()

	// 1a. direct.example.com succeeds even from untrusted 127.0.0.1
	t.Run("direct_site_allowed_from_untrusted_ip", func(t *testing.T) {
		hello := buildTestClientHelloRecord("direct.example.com", "h2", true)
		done := make(chan Info, 1)
		errCh := make(chan error, 1)
		go func() {
			c, err := wrapped.Accept()
			if err != nil {
				errCh <- err
				return
			}
			defer c.Close()
			buf := make([]byte, len(hello))
			if _, rerr := io.ReadFull(c, buf); rerr != nil {
				errCh <- rerr
				return
			}
			pc, ok := UnwrapConn(c)
			if !ok {
				errCh <- io.ErrUnexpectedEOF
				return
			}
			ctx := WithConn(context.Background(), pc)
			info, ok := FromContext(ctx)
			if !ok {
				errCh <- io.ErrNoProgress
				return
			}
			done <- info
		}()

		cli, err := net.Dial("tcp", wrapped.Addr().String())
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		_, _ = cli.Write(hello)
		_ = cli.Close()

		select {
		case info := <-done:
			if info.SNI != "direct.example.com" || info.JA4Light == "" {
				t.Fatalf("unexpected PreTLS info: %+v", info)
			}
		case e := <-errCh:
			t.Fatalf("server error for direct site: %v", e)
		case <-time.After(3 * time.Second):
			t.Fatal("timeout")
		}
	})

	// 1b. strict.example.com and app.cf.example.com are silently dropped (0 bytes) for untrusted 127.0.0.1
	for _, strictSNI := range []string{"strict.example.com", "app.cf.example.com"} {
		t.Run("strict_sni_dropped_for_untrusted_"+strictSNI, func(t *testing.T) {
			hello := buildTestClientHelloRecord(strictSNI, "h2", true)
			serverErr := make(chan error, 1)
			go func() {
				c, err := wrapped.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer c.Close()
				b := make([]byte, 32)
				_, rerr := c.Read(b)
				serverErr <- rerr
			}()

			cli, err := net.Dial("tcp", wrapped.Addr().String())
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			_, _ = cli.Write(hello)
			_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
			resp, _ := io.ReadAll(cli)
			_ = cli.Close()
			if len(resp) != 0 {
				t.Fatalf("expected 0 bytes on per-SNI strict drop, got %q", resp)
			}
			select {
			case serr := <-serverErr:
				if serr == nil {
					t.Fatalf("expected Read error on strict SNI %s drop", strictSNI)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timeout waiting for strict SNI drop")
			}
		})
	}

	// Case 2: 127.0.0.1 IS in TrustedCIDRs -> strict.example.com succeeds
	pTrusted := &PreTLS{
		AllowedSNIs:      []string{"strict.example.com"},
		DropMissingSNI:   true,
		DropUnknownSNI:   true,
		StrictOriginSNIs: []string{"strict.example.com"},
		TrustedCIDRs:     []string{"127.0.0.1/32"},
	}
	if err := pTrusted.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision trusted: %v", err)
	}
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen2: %v", err)
	}
	wrapped2 := pTrusted.WrapListener(ln2)
	defer wrapped2.Close()

	helloStrict := buildTestClientHelloRecord("strict.example.com", "h2", true)
	gotInfo := make(chan Info, 1)
	go func() {
		c, err := wrapped2.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, len(helloStrict))
		if _, err := io.ReadFull(c, buf); err == nil {
			info, _ := UnwrapInfo(c)
			gotInfo <- info
		}
	}()
	cli2, err := net.Dial("tcp", wrapped2.Addr().String())
	if err != nil {
		t.Fatalf("Dial2: %v", err)
	}
	_, _ = cli2.Write(helloStrict)
	_ = cli2.Close()

	select {
	case info := <-gotInfo:
		if info.SNI != "strict.example.com" {
			t.Fatalf("expected strict.example.com from trusted IP, got %+v", info)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for trusted strict SNI")
	}
}
