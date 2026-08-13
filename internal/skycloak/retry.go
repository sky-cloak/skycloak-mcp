package skycloak

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	// maxRetryAfter caps how long a single server-supplied Retry-After can park
	// a call.
	maxRetryAfter = 60 * time.Second
	// defaultTotalWaitBudget caps the backoff a whole call may accumulate. In
	// stateless HTTP mode nothing cancels a handler when the client disconnects,
	// so an unbounded loop would leave goroutines sleeping through an incident.
	// Once the budget is spent the last response is returned as-is, and the
	// caller sees the 429 rather than a hang.
	defaultTotalWaitBudget = 2 * time.Minute
)

// retryTransport retries 429 and 5xx responses, honoring a numeric Retry-After
// header, with bounded exponential backoff.
//
// perAttempt bounds each individual attempt. The total call is bounded by the
// caller's context instead, so a Retry-After longer than one attempt's budget
// is still honored rather than being cut short by an overall deadline.
type retryTransport struct {
	base            http.RoundTripper
	maxRetries      int
	perAttempt      time.Duration
	totalWaitBudget time.Duration
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	var waited time.Duration
	for attempt := 0; ; attempt++ {
		attemptReq := req.Clone(req.Context())
		// Replay the body on retries (oapi-codegen sets GetBody for JSON bodies).
		if attempt > 0 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			attemptReq.Body = body
		}

		var cancel context.CancelFunc
		if t.perAttempt > 0 {
			var ctx context.Context
			ctx, cancel = context.WithTimeout(req.Context(), t.perAttempt)
			attemptReq = attemptReq.WithContext(ctx)
		}

		resp, err := base.RoundTrip(attemptReq)
		if err != nil {
			if cancel != nil {
				cancel()
			}
			return nil, err
		}
		wait := backoffDelay(attempt, resp.Header.Get("Retry-After"))
		budgetSpent := t.totalWaitBudget > 0 && waited+wait > t.totalWaitBudget

		// Give up either because this response is final, or because sleeping again
		// would overrun the wait budget; in both cases the caller gets the
		// response rather than a hang.
		if !retryable(req.Method, resp.StatusCode) || attempt >= t.maxRetries || budgetSpent {
			if cancel != nil {
				// The body is still streaming, so the attempt's context must outlive
				// this return and be released when the caller closes the body.
				resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
			}
			return resp, nil
		}
		waited += wait
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if cancel != nil {
			cancel()
		}
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(wait):
		}
	}
}

// cancelOnClose releases an attempt's context once the response body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

// retryable reports whether a response may be retried.
//
// 429 is always safe: the request was refused, not performed. A 5xx is only
// safe on an idempotent method. A gateway 504 on a POST often means the origin
// did accept the request, and replaying it would start a second realm import
// or a second export.
func retryable(method string, code int) bool {
	if code == http.StatusTooManyRequests {
		return true
	}
	switch code {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return idempotent(method)
	}
	return false
}

func idempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions, http.MethodTrace, "":
		return true
	}
	return false
}

// backoffDelay returns the wait before the next attempt: the server's numeric
// Retry-After if present, else capped exponential backoff (1s, 2s, 4s, ... ≤30s).
func backoffDelay(attempt int, retryAfter string) time.Duration {
	if retryAfter != "" {
		if secs, err := strconv.Atoi(retryAfter); err == nil && secs >= 0 {
			d := time.Duration(secs) * time.Second
			// Honor the gateway's pacing, but don't park a tool call for an hour
			// because a header said so; past the cap the caller is better served
			// by the 429 than by a wait it never agreed to.
			if d > maxRetryAfter {
				return maxRetryAfter
			}
			return d
		}
	}
	d := time.Duration(1<<uint(attempt)) * time.Second
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}
