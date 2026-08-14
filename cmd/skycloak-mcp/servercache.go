package main

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/tools"
)

// Building a server registers every tool and infers a JSON schema per tool,
// which costs roughly 17ms and a few MB. The stateless HTTP transport asks for
// a server on every request, so without a cache each call would pay that.
const (
	defaultServerCacheSize = 64
	defaultServerCacheTTL  = 30 * time.Minute
)

type cachedServer struct {
	once     sync.Once // builds this entry exactly once, however many callers race for it
	server   *mcp.Server
	lastUsed time.Time // guarded by serverCache.mu
}

// serverCache hands out one MCP server per (credential, write mode) pair.
//
// Entries are keyed by digest, never by the credential itself. Servers are
// never shared across credentials: each closes over its own Skycloak client, so
// the tenant boundary is structural rather than something handlers must respect.
type serverCache struct {
	mu      sync.Mutex
	entries map[string]*cachedServer
	max     int
	ttl     time.Duration
	build   func(apiKey string, allowWrites bool, scopes tools.Scopes) *mcp.Server
	now     func() time.Time
}

func newServerCache(maxEntries int, ttl time.Duration, build func(string, bool, tools.Scopes) *mcp.Server) *serverCache {
	return &serverCache{
		entries: make(map[string]*cachedServer, maxEntries),
		max:     maxEntries,
		ttl:     ttl,
		build:   build,
		now:     time.Now,
	}
}

func (c *serverCache) get(apiKey string, allowWrites bool, scopes tools.Scopes) *mcp.Server {
	key := cacheKey(apiKey, allowWrites, scopes)

	c.mu.Lock()
	now := c.now()
	entry, ok := c.entries[key]
	if ok && now.Sub(entry.lastUsed) < c.ttl {
		entry.lastUsed = now
	} else {
		c.evictExpiredLocked(now)
		if len(c.entries) >= c.max {
			c.evictOldestLocked()
		}
		entry = &cachedServer{lastUsed: now}
		c.entries[key] = entry
	}
	c.mu.Unlock()

	// Build outside the lock. A build takes ~17ms, so holding the lock across it
	// would make one unknown credential stall every other caller, and a flood of
	// them would serialize the whole process. The Once collapses concurrent
	// misses for the same credential into a single build.
	entry.once.Do(func() { entry.server = c.build(apiKey, allowWrites, scopes) })
	return entry.server
}

func (c *serverCache) evictExpiredLocked(now time.Time) {
	for k, e := range c.entries {
		if now.Sub(e.lastUsed) >= c.ttl {
			delete(c.entries, k)
		}
	}
}

func (c *serverCache) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, e := range c.entries {
		if oldestKey == "" || e.lastUsed.Before(oldest) {
			oldestKey, oldest = k, e.lastUsed
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

func (c *serverCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// cacheKey identifies a built server. The scope set is part of it because it
// decides which tools the server carries, so two grants must never collide on
// one entry. "unknown" (nil scopes) is its own key, distinct from any grant.
func cacheKey(apiKey string, allowWrites bool, scopes tools.Scopes) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:]) + "|" + strconv.FormatBool(allowWrites) + "|" + scopeKey(scopes)
}

func scopeKey(scopes tools.Scopes) string {
	if scopes == nil {
		return "*"
	}
	names := make([]string, 0, len(scopes))
	for s := range scopes {
		names = append(names, s)
	}
	slices.Sort(names)
	return strings.Join(names, " ")
}
