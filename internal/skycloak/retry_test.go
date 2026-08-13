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

// A gateway asking us to wait an hour must not park the call for an hour.
func TestBackoffDelayCapsRetryAfter(t *testing.T) {
	if d := backoffDelay(0, "3600"); d != maxRetryAfter {
		t.Fatalf("Retry-After 3600 gave %v, want it capped at %v", d, maxRetryAfter)
	}
	if d := backoffDelay(0, "5"); d != 5*time.Second {
		t.Fatalf("Retry-After 5 gave %v, want 5s (under the cap it is honored as-is)", d)
	}
}

// In stateless HTTP mode nothing cancels a handler when the client goes away,
// so a gateway incident returning repeated 429s must not leave goroutines
// sleeping for minutes. The retry loop gives up once its wait budget is spent.
func TestRetryLoopGivesUpOnceWaitBudgetIsSpent(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	tr := &retryTransport{maxRetries: 4, perAttempt: time.Second, totalWaitBudget: 150 * time.Millisecond}
	req, _ := http.NewRequest("GET", srv.URL, nil)
	start := time.Now()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want the 429 surfaced to the caller", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("retry loop slept past its budget: %v", elapsed)
	}
}

// A gateway 5xx on a POST may mean the origin accepted the request. Replaying
// it would start a second realm import, so only 429 is retried there.
func TestNonIdempotentRequestsAreNotRetriedOn5xx(t *testing.T) {
	for _, tt := range []struct {
		name      string
		method    string
		status    int
		wantCalls int32
	}{
		{"POST 504 is not replayed", "POST", http.StatusGatewayTimeout, 1},
		{"POST 429 is retried: the request was refused, not performed", "POST", http.StatusTooManyRequests, 2},
		{"GET 504 is retried", "GET", http.StatusGatewayTimeout, 2},
		{"DELETE 503 is retried", "DELETE", http.StatusServiceUnavailable, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) == 1 {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(tt.status)
					return
				}
				writeJSON(w, 200, `{}`)
			}))
			defer srv.Close()

			tr := &retryTransport{maxRetries: 4, perAttempt: 2 * time.Second, totalWaitBudget: time.Minute}
			req, _ := http.NewRequest(tt.method, srv.URL, nil)
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			_ = resp.Body.Close()
			if got := calls.Load(); got != tt.wantCalls {
				t.Fatalf("upstream saw %d calls, want %d", got, tt.wantCalls)
			}
		})
	}
}
