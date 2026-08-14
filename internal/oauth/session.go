package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Sentinel errors so the transport can map a refusal to the right status
// without matching on message text.
var (
	// ErrNotPermitted means the dashboard refused this caller: the token was
	// rejected, or they are not a member of the workspace they asked for.
	ErrNotPermitted = errors.New("not permitted")
	// ErrExchangeFailed means the exchange itself did not complete.
	ErrExchangeFailed = errors.New("session key exchange failed")
)

const (
	// refreshSkew mints a replacement before the current key lapses, so a tool
	// call started just under the wire does not 401 halfway through.
	refreshSkew = 5 * time.Minute
	// exchangeTimeout bounds the dashboard call, which sits in the request path.
	exchangeTimeout = 15 * time.Second
	// maxSessions bounds the cache. Entries are small, but the map is keyed by
	// something a caller influences, so it needs a ceiling.
	maxSessions = 512
)

// WorkspaceChoice is one of the workspaces a caller could have meant.
type WorkspaceChoice struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AmbiguousWorkspaceError is returned when the caller belongs to several
// workspaces and named none. It carries the choices so the transport can tell
// the user which ones exist and how to pick.
type AmbiguousWorkspaceError struct {
	Choices []WorkspaceChoice
}

func (e *AmbiguousWorkspaceError) Error() string {
	names := make([]string, 0, len(e.Choices))
	for _, c := range e.Choices {
		names = append(names, fmt.Sprintf("%s (%s)", c.Name, c.ID))
	}
	return "you belong to more than one Skycloak workspace, so this session has no default: " +
		"reconnect with `?workspace=<id>` on the server URL. Available: " + strings.Join(names, ", ")
}

// Session is a minted, workspace-scoped Skycloak API key and what it may do.
type Session struct {
	APIKey      string
	WorkspaceID string
	ExpiresAt   time.Time
	Scopes      []string
}

// Exchanger swaps a verified Keycloak access token for a short-lived Skycloak
// API key, and remembers the result until it is nearly spent.
//
// The cache is keyed by a digest of the token's subject and the requested
// workspace, never by the token or the key: two tokens for the same user are
// the same session, and nothing secret is used as a map key.
type Exchanger struct {
	dashboardURL string
	hc           *http.Client

	mu       sync.Mutex
	sessions map[string]*Session
	clock    func() time.Time
	// mint coalesces concurrent misses for the same session. The dashboard keeps
	// one live key per user and rotates it in place, so two mints racing would
	// leave whichever request finished first holding a key already replaced.
	mint singleflight.Group
}

// NewExchanger returns an Exchanger against the given dashboard base URL.
// hc may be nil.
func NewExchanger(dashboardURL string, hc *http.Client) *Exchanger {
	if hc == nil {
		hc = &http.Client{Timeout: exchangeTimeout}
	}
	return &Exchanger{
		dashboardURL: strings.TrimRight(dashboardURL, "/"),
		hc:           hc,
		sessions:     map[string]*Session{},
		clock:        time.Now,
	}
}

// Session returns the API key this caller's MCP session runs on, minting one if
// there is no live key for the (subject, workspace) pair.
func (e *Exchanger) Session(ctx context.Context, token, subject, workspaceID string) (*Session, error) {
	key := sessionKey(subject, workspaceID)

	e.mu.Lock()
	cached, ok := e.sessions[key]
	now := e.clock()
	e.mu.Unlock()
	if ok && now.Before(cached.ExpiresAt.Add(-refreshSkew)) {
		return cached, nil
	}

	result, err, _ := e.mint.Do(key, func() (any, error) {
		// Re-check under the flight: a request that queued behind an in-flight
		// mint should take its result rather than start another.
		e.mu.Lock()
		fresh, ok := e.sessions[key]
		e.mu.Unlock()
		if ok && e.clock().Before(fresh.ExpiresAt.Add(-refreshSkew)) {
			return fresh, nil
		}

		// Detached from the initiating request: its result serves every caller
		// waiting on this flight, so one client hanging up must not fail them
		// all. exchangeTimeout still bounds it.
		minted, err := e.request(context.WithoutCancel(ctx), token, workspaceID)
		if err != nil {
			// Deliberately not cached: a dashboard blip must not lock the caller
			// out for the rest of the key's lifetime.
			return nil, err
		}
		e.mu.Lock()
		e.evictLocked(e.clock())
		e.sessions[key] = minted
		e.mu.Unlock()
		return minted, nil
	})
	if err != nil {
		return nil, err
	}
	return result.(*Session), nil
}

// evictLocked drops lapsed entries, and if the cache is still full, the entry
// closest to expiry.
func (e *Exchanger) evictLocked(now time.Time) {
	for k, s := range e.sessions {
		if now.After(s.ExpiresAt) {
			delete(e.sessions, k)
		}
	}
	for len(e.sessions) >= maxSessions {
		var soonestKey string
		var soonest time.Time
		for k, s := range e.sessions {
			if soonestKey == "" || s.ExpiresAt.Before(soonest) {
				soonestKey, soonest = k, s.ExpiresAt
			}
		}
		delete(e.sessions, soonestKey)
	}
}

type sessionKeyResponse struct {
	APIKey      string    `json:"api_key"`
	WorkspaceID string    `json:"workspace_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	Scopes      []string  `json:"scopes"`
}

func (e *Exchanger) request(ctx context.Context, token, workspaceID string) (*Session, error) {
	ctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()

	body := struct {
		WorkspaceID string `json:"workspace_id,omitempty"`
	}{WorkspaceID: workspaceID}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrExchangeFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.dashboardURL+"/api/mcp/session-key", bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrExchangeFailed, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := e.hc.Do(req)
	if err != nil {
		// http.Client errors quote the request URL but never headers, so the
		// token cannot ride along here.
		return nil, fmt.Errorf("%w: %s", ErrExchangeFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, exchangeError(resp)
	}

	var out sessionKeyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: decoding the response: %s", ErrExchangeFailed, err)
	}
	if out.APIKey == "" {
		return nil, fmt.Errorf("%w: the dashboard returned no key", ErrExchangeFailed)
	}
	if out.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: the dashboard returned no expiry", ErrExchangeFailed)
	}
	return &Session{
		APIKey:      out.APIKey,
		WorkspaceID: out.WorkspaceID,
		ExpiresAt:   out.ExpiresAt,
		Scopes:      out.Scopes,
	}, nil
}

// exchangeError turns a non-200 into something the caller can act on.
func exchangeError(resp *http.Response) error {
	var payload struct {
		Error      string            `json:"error"`
		Workspaces []WorkspaceChoice `json:"workspaces"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	_ = json.Unmarshal(raw, &payload)

	switch resp.StatusCode {
	case http.StatusBadRequest:
		if len(payload.Workspaces) > 0 {
			return &AmbiguousWorkspaceError{Choices: payload.Workspaces}
		}
		return fmt.Errorf("%w: %s", ErrNotPermitted, message(payload.Error, "the dashboard rejected the request"))
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: %s", ErrNotPermitted, message(payload.Error, "the dashboard refused this sign-in"))
	default:
		return fmt.Errorf("%w: status %d: %s", ErrExchangeFailed, resp.StatusCode, message(payload.Error, "no detail"))
	}
}

func message(from, fallback string) string {
	if s := strings.TrimSpace(from); s != "" {
		return s
	}
	return fallback
}

// sessionKey digests the identity of a session. The subject is not secret, but
// hashing keeps identifiers out of any map dump or profile.
func sessionKey(subject, workspaceID string) string {
	sum := sha256.Sum256([]byte(subject + "\x00" + workspaceID))
	return hex.EncodeToString(sum[:])
}
