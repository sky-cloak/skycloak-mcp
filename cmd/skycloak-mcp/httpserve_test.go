package main

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// A public listener with no timeouts leaks connections that never finish their
// headers, so an idle peer can hold a slot indefinitely.
func TestHTTPServerSetsTimeouts(t *testing.T) {
	srv := newHTTPServer(":0", http.NotFoundHandler())
	if srv.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout is unset")
	}
	if srv.ReadTimeout == 0 {
		t.Error("ReadTimeout is unset")
	}
	if srv.IdleTimeout == 0 {
		t.Error("IdleTimeout is unset")
	}
}

// Kubernetes sends SIGTERM and then waits. The server must stop accepting and
// drain rather than dying mid-request, so rolling updates don't drop calls.
func TestServeDrainsOnContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newHTTPServer("", http.NotFoundHandler())
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- serveWithShutdown(ctx, srv, ln) }()

	// Server is up.
	resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatalf("get before shutdown: %v", err)
	}
	_ = resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveWithShutdown returned %v, want nil on graceful stop", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down within 5s of context cancel")
	}

	if resp, err := http.Get("http://" + ln.Addr().String() + "/healthz"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("server still accepting connections after shutdown")
	}
}
