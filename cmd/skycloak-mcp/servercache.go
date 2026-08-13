package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Building a server registers every tool and infers a JSON schema per tool,
// which costs roughly 17ms and a few MB. The stateless HTTP transport asks for
// a server on every request, so without a cache each call would pay that.
const (
	defaultServerCacheSize = 64
	defaultServerCacheTTL  = 30 * time.Minute
)

type cachedServer struct {
	server   *mcp.Server
	lastUsed time.Time
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
	build   func(apiKey string, allowWrites bool) *mcp.Server
	now     func() time.Time
}

func newServerCache(maxEntries int, ttl time.Duration, build func(string, bool) *mcp.Server) *serverCache {
	return &serverCache{
		entries: make(map[string]*cachedServer, maxEntries),
		max:     maxEntries,
		ttl:     ttl,
		build:   build,
		now:     time.Now,
	}
}

func (c *serverCache) get(apiKey string, allowWrites bool) *mcp.Server {
	key := cacheKey(apiKey, allowWrites)

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()

	if e, ok := c.entries[key]; ok && now.Sub(e.lastUsed) < c.ttl {
		e.lastUsed = now
		return e.server
	}

	c.evictExpiredLocked(now)
	if len(c.entries) >= c.max {
		c.evictOldestLocked()
	}

	server := c.build(apiKey, allowWrites)
	c.entries[key] = &cachedServer{server: server, lastUsed: now}
	return server
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

func cacheKey(apiKey string, allowWrites bool) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:]) + "|" + strconv.FormatBool(allowWrites)
}
