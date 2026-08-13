package main

import (
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// counting build function: returns a distinct server per call so tests can tell
// a cache hit from a rebuild by identity.
func countingBuilder(calls *int) func(string, bool) *mcp.Server {
	return func(string, bool) *mcp.Server {
		*calls++
		return mcp.NewServer(&mcp.Implementation{Name: "t", Version: "t"}, nil)
	}
}

func TestServerCacheReusesServerForSameCredential(t *testing.T) {
	calls := 0
	c := newServerCache(8, time.Minute, countingBuilder(&calls))

	first := c.get("sk_sc_a", false)
	second := c.get("sk_sc_a", false)

	if first != second {
		t.Fatal("same credential produced different servers; the cache is not hitting")
	}
	if calls != 1 {
		t.Fatalf("build called %d times, want 1", calls)
	}
}

func TestServerCacheSeparatesCredentialsAndWriteMode(t *testing.T) {
	calls := 0
	c := newServerCache(8, time.Minute, countingBuilder(&calls))

	// Different credentials must never share a server — that is the tenant
	// boundary. Same credential at different write modes must not share either,
	// or a read-only session would be handed the write-enabled tool set.
	a := c.get("sk_sc_a", false)
	b := c.get("sk_sc_b", false)
	aWrite := c.get("sk_sc_a", true)

	if a == b {
		t.Fatal("different credentials shared a server")
	}
	if a == aWrite {
		t.Fatal("read-only and write-enabled sessions shared a server")
	}
	if calls != 3 {
		t.Fatalf("build called %d times, want 3", calls)
	}
}

func TestServerCacheEvictsLeastRecentlyUsedBeyondMax(t *testing.T) {
	calls := 0
	clock := time.Unix(0, 0)
	c := newServerCache(2, time.Minute, countingBuilder(&calls))
	c.now = func() time.Time { return clock }

	c.get("a", false)
	clock = clock.Add(time.Second)
	c.get("b", false)
	clock = clock.Add(time.Second)
	c.get("a", false) // refresh a, making b the least recently used
	clock = clock.Add(time.Second)
	c.get("c", false) // exceeds max -> evicts b

	if got := c.len(); got != 2 {
		t.Fatalf("cache holds %d entries, want 2", got)
	}
	callsBefore := calls
	c.get("a", false)
	if calls != callsBefore {
		t.Fatal("`a` was evicted; least-recently-used should have been `b`")
	}
	c.get("b", false)
	if calls != callsBefore+1 {
		t.Fatal("`b` was not evicted")
	}
}

func TestServerCacheRebuildsAfterIdleTTL(t *testing.T) {
	calls := 0
	clock := time.Unix(0, 0)
	c := newServerCache(8, 30*time.Minute, countingBuilder(&calls))
	c.now = func() time.Time { return clock }

	first := c.get("a", false)
	clock = clock.Add(31 * time.Minute)
	second := c.get("a", false)

	if first == second {
		t.Fatal("expired entry was reused")
	}
	if calls != 2 {
		t.Fatalf("build called %d times, want 2", calls)
	}
}

// The cache is keyed by a digest so a heap dump or a map walk never reveals a
// customer's API key.
func TestServerCacheDoesNotStoreRawCredential(t *testing.T) {
	c := newServerCache(8, time.Minute, countingBuilder(new(int)))
	const secret = "sk_sc_super_secret_value"
	c.get(secret, false)

	for k := range c.entries {
		if strings.Contains(k, secret) {
			t.Fatalf("cache key %q contains the raw credential", k)
		}
	}
}
