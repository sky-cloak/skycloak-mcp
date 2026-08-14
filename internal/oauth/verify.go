// Package oauth verifies the Keycloak access tokens the hosted HTTP transport
// accepts, and exchanges them for the short-lived Skycloak API key a session
// runs on.
//
// It exists so an MCP client can connect with no credential configured: the
// client discovers the realm from the server's RFC 9728 metadata, runs the
// browser authorization-code flow against it, and presents the resulting access
// token. The server verifies that token here and swaps it, at the dashboard,
// for a workspace-scoped API key.
package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken wraps every rejection, so callers can answer 401 without
// matching on message text.
var ErrInvalidToken = errors.New("invalid token")

// minRefetchInterval bounds how often an unknown key id may trigger a JWKS
// fetch. A kid sits in the unsigned header, so anyone can put anything there;
// without a floor, junk tokens would turn into a request to Keycloak apiece.
const minRefetchInterval = 30 * time.Second

// discoveryTimeout bounds the calls to the realm. They sit in the request path,
// so a hanging Keycloak must not hold the caller open.
const discoveryTimeout = 10 * time.Second

// Claims is what the server needs from a verified token.
type Claims struct {
	// Subject is the Keycloak user id (`sub`). It keys the session-key cache.
	Subject string
	// Expiry is the token's own expiry, an upper bound on any session built
	// from it.
	Expiry time.Time
}

// Verifier validates realm-issued access tokens against the realm's published
// signing keys.
//
// The audience is deliberately not checked. The realm allows anonymous Dynamic
// Client Registration, which is what lets an MCP client authenticate with no
// pre-provisioned client id, and every client registered that way ends up with
// the same audience. Requiring it would filter nothing while reading like a
// control. Issuer, expiry and signature are what actually bind a token to this
// realm, and those are enforced.
type Verifier struct {
	issuer string
	hc     *http.Client

	mu          sync.Mutex
	jwksURI     string
	keys        map[string]*rsa.PublicKey
	lastRefetch time.Time
	// clock is overridable so tests can drive the refetch floor.
	clock func() time.Time
}

// NewVerifier returns a Verifier for the given OIDC issuer. hc may be nil.
func NewVerifier(issuer string, hc *http.Client) *Verifier {
	if hc == nil {
		hc = &http.Client{Timeout: discoveryTimeout}
	}
	return &Verifier{
		issuer: strings.TrimRight(issuer, "/"),
		hc:     hc,
		keys:   map[string]*rsa.PublicKey{},
		clock:  time.Now,
	}
}

// Verify checks a raw access token and returns its claims.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%w: empty bearer token", ErrInvalidToken)
	}

	var claims jwt.RegisteredClaims
	_, err := jwt.ParseWithClaims(raw, &claims,
		func(t *jwt.Token) (any, error) { return v.keyFor(ctx, t) },
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		// The token itself never appears in the message: it is a live credential,
		// and this error is returned to the caller and may be logged.
		return nil, fmt.Errorf("%w: %s", ErrInvalidToken, err)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: token carries no subject", ErrInvalidToken)
	}
	if claims.ExpiresAt == nil {
		return nil, fmt.Errorf("%w: token carries no expiry", ErrInvalidToken)
	}
	return &Claims{Subject: claims.Subject, Expiry: claims.ExpiresAt.Time}, nil
}

// keyFor resolves the signing key for a token, refetching the key set once if
// the key id is one we have not seen.
func (v *Verifier) keyFor(ctx context.Context, t *jwt.Token) (*rsa.PublicKey, error) {
	kid, _ := t.Header["kid"].(string)
	if kid == "" {
		return nil, errors.New("token header carries no key id")
	}

	v.mu.Lock()
	key, ok := v.keys[kid]
	stale := v.clock().Sub(v.lastRefetch) >= minRefetchInterval
	v.mu.Unlock()
	if ok {
		return key, nil
	}
	if !stale {
		return nil, fmt.Errorf("unknown signing key id %q", kid)
	}

	if err := v.refetch(ctx); err != nil {
		return nil, err
	}
	v.mu.Lock()
	key, ok = v.keys[kid]
	v.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown signing key id %q", kid)
	}
	return key, nil
}

// refetch reloads the realm's key set, discovering the JWKS URI first if it is
// not known yet.
func (v *Verifier) refetch(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()

	v.mu.Lock()
	uri := v.jwksURI
	v.mu.Unlock()

	if uri == "" {
		discovered, err := v.discoverJWKSURI(ctx)
		if err != nil {
			return err
		}
		uri = discovered
	}

	keys, err := fetchJWKS(ctx, v.hc, uri)
	if err != nil {
		return err
	}

	v.mu.Lock()
	v.jwksURI = uri
	v.keys = keys
	v.lastRefetch = v.clock()
	v.mu.Unlock()
	return nil
}

func (v *Verifier) discoverJWKSURI(ctx context.Context) (string, error) {
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := getJSON(ctx, v.hc, v.issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return "", fmt.Errorf("discover issuer metadata: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", errors.New("issuer metadata declares no jwks_uri")
	}
	return doc.JWKSURI, nil
}

// jwk is the subset of a JSON Web Key we need. Only RSA keys are supported:
// Keycloak realms sign with RS256 by default, and an unsupported key type is
// skipped rather than failing the whole set, so one exotic key cannot lock out
// tokens signed by the usable ones.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func fetchJWKS(ctx context.Context, hc *http.Client, uri string) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := getJSON(ctx, hc, uri, &set); err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		pub, err := k.rsaPublicKey()
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks contains no usable RSA signing key")
	}
	return keys, nil
}

func (k jwk) rsaPublicKey() (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	exp := new(big.Int).SetBytes(e)
	if !exp.IsInt64() || exp.Int64() > 1<<31-1 || exp.Int64() < 3 {
		return nil, errors.New("implausible RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}, nil
}

func getJSON(ctx context.Context, hc *http.Client, url string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	// Cap the body: this is a network peer, and a key set is small.
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into)
}
