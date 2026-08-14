package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/tools"
)

// counting build function: returns a distinct server per call so tests can tell
// a cache hit from a rebuild by identity.
func countingBuilder(calls *int) func(string, bool, tools.Scopes) *mcp.Server {
	return func(string, bool, tools.Scopes) *mcp.Server {
		*calls++
		return mcp.NewServer(&mcp.Implementation{Name: "t", Version: "t"}, nil)
	}
}

func TestServerCacheReusesServerForSameCredential(t *testing.T) {
	calls := 0
	c := newServerCache(8, time.Minute, countingBuilder(&calls))

	first := c.get("sk_sc_a", false, nil)
	second := c.get("sk_sc_a", false, nil)

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
	a := c.get("sk_sc_a", false, nil)
	b := c.get("sk_sc_b", false, nil)
	aWrite := c.get("sk_sc_a", true, nil)

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

// Two callers can hold the same key at different grants only in theory, but the
// cached server carries a tool set, so the scopes it was built for are part of
// its identity. Sharing across them would hand one caller the other's surface.
func TestServerCacheSeparatesScopeSets(t *testing.T) {
	calls := 0
	c := newServerCache(8, time.Minute, countingBuilder(&calls))

	unknown := c.get("sk_sc_a", true, nil)
	readOnly := c.get("sk_sc_a", true, tools.NewScopes([]string{"clusters:read"}))
	sameReadOnly := c.get("sk_sc_a", true, tools.NewScopes([]string{"clusters:read"}))
	readWrite := c.get("sk_sc_a", true, tools.NewScopes([]string{"clusters:read", "clusters:write"}))

	if unknown == readOnly || readOnly == readWrite {
		t.Fatal("servers built for different scope sets were shared")
	}
	if readOnly != sameReadOnly {
		t.Fatal("the same scope set rebuilt the server; the cache key is unstable")
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

	c.get("a", false, nil)
	clock = clock.Add(time.Second)
	c.get("b", false, nil)
	clock = clock.Add(time.Second)
	c.get("a", false, nil) // refresh a, making b the least recently used
	clock = clock.Add(time.Second)
	c.get("c", false, nil) // exceeds max -> evicts b

	if got := c.len(); got != 2 {
		t.Fatalf("cache holds %d entries, want 2", got)
	}
	callsBefore := calls
	c.get("a", false, nil)
	if calls != callsBefore {
		t.Fatal("`a` was evicted; least-recently-used should have been `b`")
	}
	c.get("b", false, nil)
	if calls != callsBefore+1 {
		t.Fatal("`b` was not evicted")
	}
}

func TestServerCacheRebuildsAfterIdleTTL(t *testing.T) {
	calls := 0
	clock := time.Unix(0, 0)
	c := newServerCache(8, 30*time.Minute, countingBuilder(&calls))
	c.now = func() time.Time { return clock }

	first := c.get("a", false, nil)
	clock = clock.Add(31 * time.Minute)
	second := c.get("a", false, nil)

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
	c.get(secret, false, nil)

	for k := range c.entries {
		if strings.Contains(k, secret) {
			t.Fatalf("cache key %q contains the raw credential", k)
		}
	}
}

// Building a server is slow. If it happens under the cache's lock, one build
// stalls every other caller, so a flood of unknown credentials serializes the
// whole server. Concurrent misses for distinct keys must proceed in parallel.
func TestServerCacheBuildsConcurrentlyAcrossKeys(t *testing.T) {
	const keys = 8
	var building sync.WaitGroup
	building.Add(keys)
	release := make(chan struct{})

	c := newServerCache(64, time.Minute, func(string, bool, tools.Scopes) *mcp.Server {
		building.Done() // announce arrival
		<-release       // hold until every builder has arrived
		return mcp.NewServer(&mcp.Implementation{Name: "t", Version: "t"}, nil)
	})

	var wg sync.WaitGroup
	for i := 0; i < keys; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.get(fmt.Sprintf("key-%d", i), false, nil)
		}(i)
	}

	done := make(chan struct{})
	go func() { building.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("builds are serialized: not all builders started concurrently")
	}
	close(release)
	wg.Wait()
}

// Concurrent misses for the SAME credential must build once, not once per
// caller, or a burst of new sessions multiplies the cost.
func TestServerCacheBuildsOncePerKeyUnderConcurrency(t *testing.T) {
	var calls atomic.Int32
	c := newServerCache(64, time.Minute, func(string, bool, tools.Scopes) *mcp.Server {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return mcp.NewServer(&mcp.Implementation{Name: "t", Version: "t"}, nil)
	})

	var wg sync.WaitGroup
	servers := make([]*mcp.Server, 16)
	for i := range servers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			servers[i] = c.get("same-key", false, nil)
		}(i)
	}
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("build called %d times for one credential, want 1", got)
	}
	for i, s := range servers {
		if s != servers[0] || s == nil {
			t.Fatalf("caller %d got a different (or nil) server", i)
		}
	}
}
