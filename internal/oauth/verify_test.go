package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeIssuer stands in for the Skycloak Keycloak realm: it serves the OIDC
// discovery document and a JWKS, and can mint and rotate signing keys.
type fakeIssuer struct {
	srv       *httptest.Server
	keys      map[string]*rsa.PrivateKey
	jwksCalls atomic.Int64
	discCalls atomic.Int64
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{keys: map[string]*rsa.PrivateKey{}}
	f.addKey(t, "kid-1")

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		f.discCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   f.srv.URL,
			"jwks_uri": f.srv.URL + "/protocol/openid-connect/certs",
		})
	})
	mux.HandleFunc("/protocol/openid-connect/certs", func(w http.ResponseWriter, _ *http.Request) {
		f.jwksCalls.Add(1)
		var jwks struct {
			Keys []map[string]string `json:"keys"`
		}
		for kid, k := range f.keys {
			jwks.Keys = append(jwks.Keys, map[string]string{
				"kty": "RSA",
				"kid": kid,
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) addKey(t *testing.T, kid string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f.keys[kid] = k
}

// token mints a signed access token. issuer and expiry are explicit so tests
// can produce the invalid shapes too.
func (f *fakeIssuer) token(t *testing.T, kid, issuer, subject string, expiry time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer,
		"sub": subject,
		"exp": expiry.Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
		"aud": "account",
	})
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(f.keys[kid])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func TestVerifyAcceptsAGenuineToken(t *testing.T) {
	iss := newFakeIssuer(t)
	v := NewVerifier(iss.srv.URL, iss.srv.Client())

	claims, err := v.Verify(t.Context(), iss.token(t, "kid-1", iss.srv.URL, "user-123", time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Fatalf("subject = %q, want user-123", claims.Subject)
	}
	if claims.Expiry.IsZero() {
		t.Fatal("expiry is zero; the session cache has nothing to age against")
	}
}

func TestVerifyRejectsTamperedAndInvalidTokens(t *testing.T) {
	iss := newFakeIssuer(t)
	other := newFakeIssuer(t)
	v := NewVerifier(iss.srv.URL, iss.srv.Client())

	valid := iss.token(t, "kid-1", iss.srv.URL, "user-123", time.Now().Add(time.Hour))
	tampered := valid[:len(valid)-6] + "AAAAAA"

	for _, tt := range []struct{ name, token string }{
		{"tampered signature", tampered},
		{"expired", iss.token(t, "kid-1", iss.srv.URL, "u", time.Now().Add(-time.Minute))},
		{"wrong issuer", iss.token(t, "kid-1", "https://evil.example/realms/x", "u", time.Now().Add(time.Hour))},
		{"signed by another realm's key", other.token(t, "kid-1", iss.srv.URL, "u", time.Now().Add(time.Hour))},
		{"not a jwt at all", "sk_sc_not_a_token"},
		{"empty", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := v.Verify(t.Context(), tt.token); err == nil {
				t.Fatal("Verify accepted a token it must reject")
			} else if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("error = %v, want it to unwrap to ErrInvalidToken", err)
			}
		})
	}
}

// A realm rotates its signing keys. A token signed by a key we have not seen
// must trigger a refetch once the rate-limit floor has passed, not a permanent
// rejection.
func TestVerifyRefetchesJWKSOnAnUnknownKeyID(t *testing.T) {
	iss := newFakeIssuer(t)
	v := NewVerifier(iss.srv.URL, iss.srv.Client())

	if _, err := v.Verify(t.Context(), iss.token(t, "kid-1", iss.srv.URL, "u", time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	before := iss.jwksCalls.Load()

	// Rotation is rare; the floor only delays it. Step past the floor rather
	// than sleeping through it.
	later := time.Now().Add(2 * minRefetchInterval)
	v.clock = func() time.Time { return later }

	iss.addKey(t, "kid-2")
	if _, err := v.Verify(t.Context(), iss.token(t, "kid-2", iss.srv.URL, "u", time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("verify after rotation: %v", err)
	}
	if iss.jwksCalls.Load() <= before {
		t.Fatal("the unknown key id did not trigger a JWKS refetch")
	}
}

// The keys are cached: a steady stream of requests must not mean a JWKS fetch
// per request.
func TestVerifyCachesTheKeySet(t *testing.T) {
	iss := newFakeIssuer(t)
	v := NewVerifier(iss.srv.URL, iss.srv.Client())

	for range 5 {
		if _, err := v.Verify(t.Context(), iss.token(t, "kid-1", iss.srv.URL, "u", time.Now().Add(time.Hour))); err != nil {
			t.Fatalf("verify: %v", err)
		}
	}
	if got := iss.jwksCalls.Load(); got != 1 {
		t.Fatalf("JWKS fetched %d times for 5 verifications, want 1", got)
	}
	if got := iss.discCalls.Load(); got != 1 {
		t.Fatalf("discovery fetched %d times, want 1", got)
	}
}

// An attacker can put any kid they like in an unsigned header. Refetching on
// each one turns a stream of junk tokens into a stream of requests to Keycloak.
func TestVerifyRateLimitsRefetchOnUnknownKeyIDs(t *testing.T) {
	iss := newFakeIssuer(t)
	v := NewVerifier(iss.srv.URL, iss.srv.Client())

	if _, err := v.Verify(t.Context(), iss.token(t, "kid-1", iss.srv.URL, "u", time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	before := iss.jwksCalls.Load()

	junk := newFakeIssuer(t)
	for i := range 10 {
		kid := "junk-" + string(rune('a'+i))
		junk.addKey(t, kid)
		_, _ = v.Verify(t.Context(), junk.token(t, kid, iss.srv.URL, "u", time.Now().Add(time.Hour)))
	}
	if got := iss.jwksCalls.Load() - before; got > 1 {
		t.Fatalf("10 unknown key ids caused %d JWKS refetches, want at most 1", got)
	}
}

// A token is a credential: it must never reach a log line or an error string a
// caller could see.
func TestVerifyErrorsNeverEchoTheToken(t *testing.T) {
	iss := newFakeIssuer(t)
	v := NewVerifier(iss.srv.URL, iss.srv.Client())

	token := iss.token(t, "kid-1", "https://evil.example", "u", time.Now().Add(time.Hour))
	_, err := v.Verify(t.Context(), token)
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("error message leaked the token: %v", err)
	}
}
