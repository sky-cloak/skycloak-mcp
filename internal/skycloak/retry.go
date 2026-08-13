package skycloak

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"
)

// retryTransport retries 429 and 5xx responses, honoring a numeric Retry-After
// header, with bounded exponential backoff.
//
// perAttempt bounds each individual attempt. The total call is bounded by the
// caller's context instead, so a Retry-After longer than one attempt's budget
// is still honored rather than being cut short by an overall deadline.
type retryTransport struct {
	base       http.RoundTripper
	maxRetries int
	perAttempt time.Duration
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
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
		if !retryableStatus(resp.StatusCode) || attempt >= t.maxRetries {
			if cancel != nil {
				// The body is still streaming, so the attempt's context must outlive
				// this return and be released when the caller closes the body.
				resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
			}
			return resp, nil
		}

		wait := backoffDelay(attempt, resp.Header.Get("Retry-After"))
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

func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests ||
		code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

// backoffDelay returns the wait before the next attempt: the server's numeric
// Retry-After if present, else capped exponential backoff (1s, 2s, 4s, ... ≤30s).
func backoffDelay(attempt int, retryAfter string) time.Duration {
	if retryAfter != "" {
		if secs, err := strconv.Atoi(retryAfter); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
	}
	d := time.Duration(1<<uint(attempt)) * time.Second
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}
