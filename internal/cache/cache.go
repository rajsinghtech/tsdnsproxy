package cache

import (
	"sync"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"tailscale.com/client/tailscale/apitype"
)

// Cache is a generic time-based cache with automatic cleanup
type Cache[K comparable, V any] struct {
	mu      sync.RWMutex
	entries map[K]*entry[V]
	ttl     time.Duration
	done    chan struct{}
}

type entry[V any] struct {
	value  V
	expiry time.Time
}

// New creates a new cache with the specified TTL
func New[K comparable, V any](ttl time.Duration) *Cache[K, V] {
	c := &Cache[K, V]{
		entries: make(map[K]*entry[V]),
		ttl:     ttl,
		done:    make(chan struct{}),
	}
	go c.cleanup()
	return c
}

// Get retrieves a value from cache
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var zero V
	e, exists := c.entries[key]
	if !exists || time.Now().After(e.expiry) {
		return zero, false
	}
	return e.value, true
}

// Set stores a value in cache
func (c *Cache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &entry[V]{
		value:  value,
		expiry: time.Now().Add(c.ttl),
	}
}

// GetOrSet atomically gets from cache or sets if not present
func (c *Cache[K, V]) GetOrSet(key K, loader func() (V, error)) (V, error) {
	// Fast path with read lock
	c.mu.RLock()
	if e, exists := c.entries[key]; exists && time.Now().Before(e.expiry) {
		value := e.value
		c.mu.RUnlock()
		return value, nil
	}
	c.mu.RUnlock()

	// Need to load - acquire write lock
	c.mu.Lock()
	// Double-check in case another goroutine loaded it
	if e, exists := c.entries[key]; exists && time.Now().Before(e.expiry) {
		value := e.value
		c.mu.Unlock()
		return value, nil
	}

	// Release lock while loading to avoid blocking other operations
	c.mu.Unlock()

	// Load the value without holding the lock
	value, err := loader()
	if err != nil {
		var zero V
		return zero, err
	}

	// Re-acquire lock to cache the result
	c.mu.Lock()
	c.entries[key] = &entry[V]{
		value:  value,
		expiry: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()

	return value, nil
}

func (c *Cache[K, V]) cleanup() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for key, e := range c.entries {
				if now.After(e.expiry) {
					delete(c.entries, key)
				}
			}
			c.mu.Unlock()
		case <-c.done:
			return
		}
	}
}

// Close stops the cleanup goroutine
func (c *Cache[K, V]) Close() {
	close(c.done)
}

// WhoisCache caches whois lookups to reduce LocalAPI calls
type WhoisCache = Cache[string, *apitype.WhoIsResponse]

// NewWhoisCache creates a new whois cache with the specified TTL
func NewWhoisCache(ttl time.Duration) *WhoisCache {
	return New[string, *apitype.WhoIsResponse](ttl)
}

// GrantCache caches parsed grants by source identity
type GrantCache = Cache[string, []grants.GrantConfig]

// NewGrantCache creates a new grant cache with the specified TTL
func NewGrantCache(ttl time.Duration) *GrantCache {
	return New[string, []grants.GrantConfig](ttl)
}
