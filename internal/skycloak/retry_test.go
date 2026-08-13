package skycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryOn429(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writeJSON(w, 200, `[{"id":"`+cuid+`","name":"prod","status":"available"}]`)
	}))
	defer srv.Close()

	clusters, err := newTestClient(srv.URL).ListClusters(context.Background(), ListClustersParams{})
	if err != nil {
		t.Fatalf("ListClusters after retry: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 calls, got %d", calls.Load())
	}
	if len(clusters) != 1 {
		t.Fatalf("unexpected clusters: %+v", clusters)
	}
}

func TestBackoffDelayHonorsRetryAfter(t *testing.T) {
	if d := backoffDelay(0, "5"); d.Seconds() != 5 {
		t.Fatalf("Retry-After: got %v, want 5s", d)
	}
	if d := backoffDelay(2, ""); d.Seconds() != 4 {
		t.Fatalf("exponential: got %v, want 4s", d)
	}
}

// The retry budget must not be consumed by a single overall client deadline:
// a server asking us to wait longer than one attempt's timeout should still be
// honored, otherwise a busy Skycloak gateway turns every 429 into a hard fail.
func TestRetryAfterOutlivesPerAttemptTimeout(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1") // longer than one attempt's budget
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writeJSON(w, 200, `[{"id":"`+cuid+`","name":"prod","status":"available"}]`)
	}))
	defer srv.Close()

	c := New(srv.URL, "k", "v", WithPerAttemptTimeout(300*time.Millisecond))
	clusters, err := c.ListClusters(context.Background(), ListClustersParams{})
	if err != nil {
		t.Fatalf("ListClusters: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 calls, got %d", calls.Load())
	}
	if len(clusters) != 1 {
		t.Fatalf("unexpected clusters: %+v", clusters)
	}
}

// A single hung attempt must still be cut off.
func TestPerAttemptTimeoutBoundsOneAttempt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
			writeJSON(w, 200, `[]`)
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "k", "v", WithPerAttemptTimeout(150*time.Millisecond))
	start := time.Now()
	if _, err := c.ListClusters(context.Background(), ListClustersParams{}); err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("attempt was not bounded: took %v", elapsed)
	}
}

// The caller's context still bounds the whole operation, retries included.
func TestCallerContextCancelsRetryLoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := New(srv.URL, "k", "v").ListClusters(ctx, ListClustersParams{}); err == nil {
		t.Fatal("expected error when caller context expires mid-backoff")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("retry loop ignored caller context: took %v", elapsed)
	}
}
