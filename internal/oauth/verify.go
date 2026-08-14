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
	"golang.org/x/sync/singleflight"
)

// ErrInvalidToken wraps every rejection, so callers can answer 401 without
// matching on message text.
var ErrInvalidToken = errors.New("invalid token")

// VerifyReason names the check a token failed. Every rejection is answered with
// the same 401, so this is what tells an expired token from one signed by
// another realm, or from a key the realm has rotated out.
type VerifyReason string

// Every way a token can be refused, from the shape of the bearer through to the
// claims the realm signed.
const (
	ReasonEmptyToken     VerifyReason = "empty_token"
	ReasonMalformed      VerifyReason = "malformed"
	ReasonBadSignature   VerifyReason = "bad_signature"
	ReasonWrongIssuer    VerifyReason = "wrong_issuer"
	ReasonExpired        VerifyReason = "expired"
	ReasonNotYetValid    VerifyReason = "not_yet_valid"
	ReasonNoKeyID        VerifyReason = "no_key_id"
	ReasonUnknownKeyID   VerifyReason = "unknown_key_id"
	ReasonKeysUnusable   VerifyReason = "signing_keys_unusable"
	ReasonWrongTokenType VerifyReason = "wrong_token_type"
	ReasonNoSubject      VerifyReason = "no_subject"
	ReasonNoExpiry       VerifyReason = "no_expiry"
	ReasonRejected       VerifyReason = "rejected"
)

// VerifyError is a rejection that carries which check produced it. Detail is
// the underlying message, which never contains the token.
type VerifyError struct {
	Reason VerifyReason
	Detail string
}

func (e *VerifyError) Error() string {
	return fmt.Sprintf("%s (%s): %s", ErrInvalidToken, e.Reason, e.Detail)
}

// Unwrap keeps errors.Is(err, ErrInvalidToken) working for callers that only
// care about the status to answer with.
func (e *VerifyError) Unwrap() error { return ErrInvalidToken }

// Sentinels for the two ways key resolution fails, so a rejection can name them
// rather than being flattened into "unverifiable" by the JWT library.
var (
	errNoKeyID      = errors.New("token header carries no key id")
	errUnknownKeyID = errors.New("unknown signing key id")
)

func rejected(reason VerifyReason, detail string) error {
	return &VerifyError{Reason: reason, Detail: detail}
}

// classify maps a parse failure onto the check that caused it. Key resolution
// is tested first: the library reports both as "unverifiable", which would hide
// a rotated-out key behind an unreachable issuer.
func classify(err error) VerifyReason {
	switch {
	case errors.Is(err, errUnknownKeyID):
		return ReasonUnknownKeyID
	case errors.Is(err, errNoKeyID):
		return ReasonNoKeyID
	case errors.Is(err, jwt.ErrTokenExpired):
		return ReasonExpired
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return ReasonNotYetValid
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return ReasonWrongIssuer
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return ReasonBadSignature
	case errors.Is(err, jwt.ErrTokenMalformed):
		return ReasonMalformed
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		// The key set itself could not be resolved or the algorithm is one we do
		// not accept: the realm, not the token.
		return ReasonKeysUnusable
	default:
		return ReasonRejected
	}
}

// minRefetchInterval bounds how often the key set may be refetched. A kid sits
// in the unsigned header, so anyone can put anything there; without a floor,
// junk tokens from an unauthenticated caller would turn into a request to
// Keycloak apiece. The floor counts failed attempts too, so an issuer that is
// down does not become an amplifier.
const minRefetchInterval = 30 * time.Second

// maxKeySetAge is how long a fetched key set is trusted before it is refreshed,
// even for a key id already in it. Without it, a key withdrawn from the realm
// (rotated out, or revoked after a compromise) would keep verifying tokens
// until this process restarted, because a known kid never triggers a refetch.
const maxKeySetAge = 10 * time.Minute

// minRSAModulusBits is the smallest signing key accepted from the realm's JWKS.
const minRSAModulusBits = 2048

// discoveryTimeout bounds the calls to the realm. They sit in the request path,
// so a hanging Keycloak must not hold the caller open.
const discoveryTimeout = 10 * time.Second

// Claims is what the server needs from a verified token: who the caller is.
// Expiry is enforced during verification rather than returned, because every
// request is verified afresh, so there is nothing downstream to age.
type Claims struct {
	// Subject is the Keycloak user id (`sub`). It keys the session-key cache.
	Subject string
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

	mu      sync.Mutex
	jwksURI string
	keys    map[string]*rsa.PublicKey
	// lastAttempt covers failures too, so an unreachable issuer cannot be used
	// to drive one outbound request per inbound request.
	lastAttempt time.Time
	lastSuccess time.Time
	// group collapses concurrent refetches. Without it, a burst of requests
	// carrying the same unknown kid would each open its own fetch.
	group singleflight.Group
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
		return nil, rejected(ReasonEmptyToken, "empty bearer token")
	}

	var claims realmClaims
	_, err := jwt.ParseWithClaims(raw, &claims,
		func(t *jwt.Token) (any, error) { return v.keyFor(ctx, t) },
		parserOptions(v.issuer)...,
	)
	if err != nil {
		// The token itself never appears in the message: it is a live credential,
		// and this error is returned to the caller and may be logged.
		return nil, rejected(classify(err), err.Error())
	}
	if claims.Subject == "" {
		return nil, rejected(ReasonNoSubject, "token carries no subject")
	}
	if claims.ExpiresAt == nil {
		return nil, rejected(ReasonNoExpiry, "token carries no expiry")
	}
	// The realm signs more than access tokens, and they share an issuer and a
	// signing key. An ID token in particular is handed to browser front-ends and
	// handled far more loosely, so accepting one would let anything that can read
	// a user's ID token act as them here. Keycloak labels the kind in `typ`; a
	// token that declares a kind other than Bearer is not an access token.
	//
	// A token with no `typ` at all is allowed through rather than refused: the
	// claim is not part of the OAuth core, and refusing on its absence would put
	// the whole sign-in at the mercy of a realm setting. Issuer, expiry and
	// signature still bind it.
	if claims.Type != "" && !strings.EqualFold(claims.Type, "Bearer") {
		return nil, rejected(ReasonWrongTokenType, fmt.Sprintf("%q is not an access token", claims.Type))
	}
	return &Claims{Subject: claims.Subject}, nil
}

// parserOptions is every check the token itself must pass, independent of which
// key verifies it. It is a function rather than inline so a test can exercise
// the algorithm pin on its own: through Verify the pin is masked, because
// keyFor hands back an *rsa.PublicKey and the library rejects an HS256 or
// unsigned token on the key type before the pin is ever consulted.
func parserOptions(issuer string) []jwt.ParserOption {
	return []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30 * time.Second),
	}
}

// realmClaims is the registered set plus Keycloak's `typ`, which says what kind
// of token this is (Bearer, ID, Refresh, Offline).
type realmClaims struct {
	jwt.RegisteredClaims
	Type string `json:"typ"`
}

// keyFor resolves the signing key for a token.
//
// It refetches the key set when the key id is unknown, and also when the set
// has aged past maxKeySetAge, so a key the realm has withdrawn stops verifying
// tokens rather than living on in this cache. Both are rate limited.
func (v *Verifier) keyFor(ctx context.Context, t *jwt.Token) (*rsa.PublicKey, error) {
	kid, _ := t.Header["kid"].(string)
	if kid == "" {
		return nil, errNoKeyID
	}

	v.mu.Lock()
	key, known := v.keys[kid]
	fresh := v.clock().Sub(v.lastSuccess) < maxKeySetAge
	v.mu.Unlock()
	if known && fresh {
		return key, nil
	}

	// Either the key id is new to us or the set has aged out. refetch is both
	// rate limited and coalesced, so calling it here is cheap even under a flood
	// of junk key ids, and a caller that arrives mid-fetch waits for that fetch
	// rather than deciding on the empty map it read a moment earlier.
	err := v.refetch(ctx)

	v.mu.Lock()
	key, known = v.keys[kid]
	v.mu.Unlock()
	if known {
		// Either the refresh confirmed the key, or it did not happen and we still
		// hold it. Serving a slightly stale key beats rejecting every caller
		// because the realm is briefly unreachable.
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w %q", errUnknownKeyID, kid)
}

// refetch reloads the realm's key set, discovering the JWKS URI first if it is
// not known yet. Concurrent callers share one fetch, and a fetch that happened
// very recently is not repeated.
func (v *Verifier) refetch(ctx context.Context) error {
	_, err, _ := v.group.Do("jwks", func() (any, error) {
		v.mu.Lock()
		// The floor lives inside the flight so it is evaluated once per fetch,
		// and is recorded before the attempt: a fetch that fails or hangs still
		// holds off the next caller, which is what stops an unreachable issuer
		// turning every inbound request into an outbound one.
		if v.clock().Sub(v.lastAttempt) < minRefetchInterval {
			v.mu.Unlock()
			return nil, nil
		}
		uri := v.jwksURI
		v.lastAttempt = v.clock()
		v.mu.Unlock()

		// Detached from the initiating request: the result serves every caller
		// waiting on this flight. discoveryTimeout still bounds it.
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), discoveryTimeout)
		defer cancel()

		if uri == "" {
			discovered, err := v.discoverJWKSURI(fetchCtx)
			if err != nil {
				return nil, err
			}
			uri = discovered
		}

		keys, err := fetchJWKS(fetchCtx, v.hc, uri)
		if err != nil {
			return nil, err
		}

		v.mu.Lock()
		v.jwksURI = uri
		v.keys = keys
		v.lastSuccess = v.clock()
		v.mu.Unlock()
		return nil, nil
	})
	return err
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
	modulus := new(big.Int).SetBytes(n)
	// A short modulus is forgeable. The issuer is trusted configuration, but a
	// single weak key in an otherwise good set would quietly become a way to
	// mint tokens this server accepts.
	if modulus.BitLen() < minRSAModulusBits {
		return nil, errors.New("RSA modulus below the minimum size")
	}
	return &rsa.PublicKey{N: modulus, E: int(exp.Int64())}, nil
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
