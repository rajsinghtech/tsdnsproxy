package cache

import (
	"fmt"
	"sync"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"tailscale.com/client/tailscale/apitype"
)

// Cache is a generic time-based cache with automatic cleanup
type Cache[K comparable, V any] struct {
	mu        sync.RWMutex
	entries   map[K]*entry[V]
	inflight  map[K]*flight[V]
	ttl       time.Duration
	done      chan struct{}
	closeOnce sync.Once
}

type flight[V any] struct {
	done chan struct{}
	val  V
	err  error
}

type entry[V any] struct {
	value  V
	expiry time.Time
}

// New creates a new cache with the specified TTL
func New[K comparable, V any](ttl time.Duration) *Cache[K, V] {
	c := &Cache[K, V]{
		entries:  make(map[K]*entry[V]),
		inflight: make(map[K]*flight[V]),
		ttl:      ttl,
		done:     make(chan struct{}),
	}
	if ttl > 0 {
		go c.cleanup()
	}
	return c
}

// Len reports how many unexpired entries are stored.
func (c *Cache[K, V]) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	n := 0
	now := time.Now()
	for _, e := range c.entries {
		if e != nil && now.Before(e.expiry) {
			n++
		}
	}
	return n
}

// Timing reports how long a live entry has been stored and when it expires.
func (c *Cache[K, V]) Timing(key K) (age time.Duration, expire time.Time, ok bool) {
	if c == nil {
		return 0, time.Time{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, exists := c.entries[key]
	if !exists || e == nil || !time.Now().Before(e.expiry) {
		return 0, time.Time{}, false
	}
	age = c.ttl - time.Until(e.expiry)
	if age < 0 {
		age = 0
	}
	return age, e.expiry, true
}

// TTL returns the lifetime of a cached value.
func (c *Cache[K, V]) TTL() time.Duration {
	if c == nil {
		return 0
	}
	return c.ttl
}

// Get retrieves a value from cache
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var zero V
	e, exists := c.entries[key]
	if !exists || !time.Now().Before(e.expiry) {
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

// GetOrSet atomically gets from cache or sets if not present.
// Concurrent callers for the same key share one loader call.
func (c *Cache[K, V]) GetOrSet(key K, loader func() (V, error)) (V, error) {
	c.mu.Lock()
	if e, exists := c.entries[key]; exists && time.Now().Before(e.expiry) {
		value := e.value
		c.mu.Unlock()
		return value, nil
	}
	if f, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		<-f.done
		return f.val, f.err
	}
	f := &flight[V]{done: make(chan struct{})}
	c.inflight[key] = f
	c.mu.Unlock()

	// A panicking loader must still release waiters, then panic again so the
	// caller can answer the query.
	panicked := true
	defer func() {
		if !panicked {
			return
		}
		rec := recover()
		var zero V
		c.completeFlight(key, f, zero, fmt.Errorf("loader panic: %v", rec))
		panic(rec)
	}()
	value, err := loader()
	panicked = false
	c.completeFlight(key, f, value, err)
	return value, err
}

func (c *Cache[K, V]) completeFlight(key K, f *flight[V], value V, err error) {
	c.mu.Lock()
	if err == nil {
		c.entries[key] = &entry[V]{
			value:  value,
			expiry: time.Now().Add(c.ttl),
		}
	}
	delete(c.inflight, key)
	c.mu.Unlock()
	f.val = value
	f.err = err
	close(f.done)
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

// Close stops the cleanup goroutine. It is safe to call more than once.
func (c *Cache[K, V]) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() { close(c.done) })
}

// WhoisCache caches whois lookups to reduce LocalAPI calls
type WhoisCache = Cache[string, *apitype.WhoIsResponse]

// NewWhoisCache creates a new whois cache with the specified TTL
func NewWhoisCache(ttl time.Duration) *WhoisCache {
	return New[string, *apitype.WhoIsResponse](ttl)
}

// GrantCacheKey identifies cached grants for one source and capability.
// CapName keeps grants parsed from one capability separate from another.
type GrantCacheKey struct {
	Identity string
	CapName  string
}

// GrantCache caches parsed grants by source identity and capability name.
type GrantCache = Cache[GrantCacheKey, []grants.GrantConfig]

// NewGrantCache creates a new grant cache with the specified TTL.
func NewGrantCache(ttl time.Duration) *GrantCache {
	return New[GrantCacheKey, []grants.GrantConfig](ttl)
}
