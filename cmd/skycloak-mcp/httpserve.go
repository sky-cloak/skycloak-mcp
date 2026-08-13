package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"time"
)

// shutdownGrace bounds how long in-flight tool calls get to finish after a
// SIGTERM. Kubernetes' default grace period is 30s, so stay under it or the
// kubelet's SIGKILL lands mid-drain.
const shutdownGrace = 20 * time.Second

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:    addr,
		Handler: h,
		// A peer that opens a connection and stalls must not hold a slot forever.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: a tool call can legitimately take a while (the Skycloak
		// client retries with Retry-After backoff), and capping it here would cut
		// the response off mid-flight. ReadHeaderTimeout covers the slow-peer case.
	}
}

// serveWithShutdown serves until ctx is done, then drains in-flight requests.
// It returns nil on a graceful stop.
func serveWithShutdown(ctx context.Context, srv *http.Server, ln net.Listener) error {
	errc := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
			return
		}
		errc <- nil
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			// Running out of drain time is a slow request, not a failure: report it
			// and still exit cleanly, so a rollout doesn't look like a crash loop.
			if errors.Is(err, context.DeadlineExceeded) {
				log.Printf("shutdown: drain exceeded %s; closing remaining connections", shutdownGrace)
				_ = srv.Close()
			} else {
				return err
			}
		}
		return <-errc
	}
}
