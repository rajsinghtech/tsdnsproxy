package cache

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"tailscale.com/client/tailscale/apitype"
)

func TestBasicOperations(t *testing.T) {
	c := New[string, string](time.Minute)
	defer c.Close()

	// Test Get on empty cache
	_, found := c.Get("key1")
	if found {
		t.Error("expected not found for empty cache")
	}

	// Test Set and Get
	c.Set("key1", "value1")
	val, found := c.Get("key1")
	if !found {
		t.Error("expected to find key1")
	}
	if val != "value1" {
		t.Errorf("expected value1, got %s", val)
	}

	// Test overwrite
	c.Set("key1", "value2")
	val, found = c.Get("key1")
	if !found {
		t.Error("expected to find key1")
	}
	if val != "value2" {
		t.Errorf("expected value2, got %s", val)
	}

	// Test multiple keys
	c.Set("key2", "value3")
	c.Set("key3", "value4")

	val2, found2 := c.Get("key2")
	val3, found3 := c.Get("key3")

	if !found2 || val2 != "value3" {
		t.Errorf("expected key2=value3, got found=%v, val=%s", found2, val2)
	}
	if !found3 || val3 != "value4" {
		t.Errorf("expected key3=value4, got found=%v, val=%s", found3, val3)
	}
}

func TestTTLExpiration(t *testing.T) {
	c := New[string, int](50 * time.Millisecond)
	defer c.Close()

	c.Set("key1", 100)

	// Should find immediately
	val, found := c.Get("key1")
	if !found || val != 100 {
		t.Errorf("expected to find key1=100, got found=%v, val=%d", found, val)
	}

	// Wait for expiration
	time.Sleep(60 * time.Millisecond)

	// Should not find after TTL
	_, found = c.Get("key1")
	if found {
		t.Error("expected key1 to be expired")
	}

	// Set new value after expiration
	c.Set("key1", 200)
	val, found = c.Get("key1")
	if !found || val != 200 {
		t.Errorf("expected to find key1=200, got found=%v, val=%d", found, val)
	}
}

func TestGetOrSet(t *testing.T) {
	c := New[string, string](time.Minute)
	defer c.Close()

	loadCount := 0
	loader := func() (string, error) {
		loadCount++
		return "loaded", nil
	}

	// First call should load
	val, err := c.GetOrSet("key1", loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "loaded" {
		t.Errorf("expected loaded, got %s", val)
	}
	if loadCount != 1 {
		t.Errorf("expected load count 1, got %d", loadCount)
	}

	// Second call should use cache
	val, err = c.GetOrSet("key1", loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "loaded" {
		t.Errorf("expected loaded, got %s", val)
	}
	if loadCount != 1 {
		t.Errorf("expected load count still 1, got %d", loadCount)
	}

	// Test error handling
	errorLoader := func() (string, error) {
		return "", errors.New("load failed")
	}

	val, err = c.GetOrSet("key2", errorLoader)
	if err == nil {
		t.Error("expected error")
	}
	if val != "" {
		t.Errorf("expected empty value on error, got %s", val)
	}

	// Verify error didn't cache anything
	_, found := c.Get("key2")
	if found {
		t.Error("expected key2 not to be cached after error")
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New[int, int](time.Minute)
	defer c.Close()

	const numGoroutines = 100
	const numOperations = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := j % 10
				c.Set(key, id*1000+j)
				_, _ = c.Get(key)
			}
		}(i)
	}

	wg.Wait()

	// Verify cache still works
	c.Set(999, 999)
	val, found := c.Get(999)
	if !found || val != 999 {
		t.Errorf("expected 999, got found=%v, val=%d", found, val)
	}
}

func TestGetOrSetConcurrency(t *testing.T) {
	c := New[string, int](time.Minute)
	defer c.Close()

	const numGoroutines = 50
	var loadCount atomic.Int32
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	loader := func() (int, error) {
		loadCount.Add(1)
		time.Sleep(10 * time.Millisecond) // Simulate slow load
		return 42, nil
	}

	// All goroutines try to load the same key
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			val, err := c.GetOrSet("shared-key", loader)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if val != 42 {
				t.Errorf("expected 42, got %d", val)
			}
		}()
	}

	wg.Wait()

	// Note: GetOrSet doesn't prevent multiple loaders from running concurrently
	// if they all arrive before the first one completes. This is expected behavior
	// for this simple cache implementation.
	finalCount := loadCount.Load()
	if finalCount == 0 {
		t.Error("loader was never called")
	}
	// Multiple loads are acceptable for this implementation
	t.Logf("loader called %d times for %d goroutines", finalCount, numGoroutines)
}

func TestCleanup(t *testing.T) {
	c := New[string, string](50 * time.Millisecond)
	defer c.Close()

	// Add entries
	for i := 0; i < 10; i++ {
		c.Set(string(rune('a'+i)), "value")
	}

	// Verify all are present
	for i := 0; i < 10; i++ {
		_, found := c.Get(string(rune('a' + i)))
		if !found {
			t.Errorf("expected to find key %c", 'a'+i)
		}
	}

	// Wait for cleanup cycle (TTL + buffer)
	time.Sleep(100 * time.Millisecond)

	// Add a new entry to verify cache still works
	c.Set("new", "value")

	// Old entries should be gone
	for i := 0; i < 10; i++ {
		_, found := c.Get(string(rune('a' + i)))
		if found {
			t.Errorf("expected key %c to be cleaned up", 'a'+i)
		}
	}

	// New entry should be present
	val, found := c.Get("new")
	if !found || val != "value" {
		t.Error("expected to find new entry")
	}
}

func TestCloseStopsCleanup(t *testing.T) {
	c := New[string, string](50 * time.Millisecond)

	// Add entry first
	c.Set("key", "value")

	// Close to stop cleanup goroutine
	c.Close()

	// Cache should still function for basic operations
	val, found := c.Get("key")
	if !found || val != "value" {
		t.Error("cache should still work after close")
	}

	// Wait longer than TTL
	time.Sleep(60 * time.Millisecond)

	// Entry has expired but cleanup goroutine is stopped,
	// so Get will check expiry and return false
	_, found = c.Get("key")
	if found {
		t.Error("Get should return false for expired entry")
	}

	// But the entry is still in the map (not cleaned up)
	c.mu.RLock()
	_, exists := c.entries["key"]
	c.mu.RUnlock()
	if !exists {
		t.Error("expired entry should still exist in map after close (cleanup stopped)")
	}
}

func TestWhoisCache(t *testing.T) {
	wc := NewWhoisCache(time.Minute)
	defer wc.Close()

	// Note: WhoIsResponse is defined in tailscale.com/client/tailscale/apitype
	// We'll use a simple test that just verifies caching works with this type
	whois1 := &apitype.WhoIsResponse{}

	wc.Set("192.168.1.1", whois1)

	cached, found := wc.Get("192.168.1.1")
	if !found {
		t.Error("expected to find cached whois")
	}
	if cached != whois1 {
		t.Error("expected same whois response object")
	}
}

func TestGrantCache(t *testing.T) {
	gc := NewGrantCache(time.Minute)
	defer gc.Close()

	// GrantConfig is a map[string]DNSGrant
	grants1 := []grants.GrantConfig{
		{
			"example.com": grants.DNSGrant{
				DNS:     []string{"8.8.8.8:53"},
				Rewrite: "internal.example.com",
			},
		},
		{
			"cluster.local": grants.DNSGrant{
				DNS:         []string{"10.0.0.1:53"},
				TranslateID: 1,
			},
		},
	}

	gc.Set("user@example.com", grants1)

	cached, found := gc.Get("user@example.com")
	if !found {
		t.Error("expected to find cached grants")
	}
	if len(cached) != 2 {
		t.Errorf("expected 2 grants, got %d", len(cached))
	}

	// Check first grant config
	if grant, ok := cached[0]["example.com"]; !ok {
		t.Error("expected example.com in first grant config")
	} else {
		if grant.Rewrite != "internal.example.com" {
			t.Errorf("expected rewrite internal.example.com, got %s", grant.Rewrite)
		}
		if len(grant.DNS) != 1 || grant.DNS[0] != "8.8.8.8:53" {
			t.Errorf("expected DNS [8.8.8.8:53], got %v", grant.DNS)
		}
	}

	// Check second grant config
	if grant, ok := cached[1]["cluster.local"]; !ok {
		t.Error("expected cluster.local in second grant config")
	} else {
		if grant.TranslateID != 1 {
			t.Errorf("expected TranslateID 1, got %d", grant.TranslateID)
		}
	}
}

func TestZeroValueHandling(t *testing.T) {
	// Test with pointer types
	c1 := New[string, *string](time.Minute)
	defer c1.Close()

	var nilStr *string
	c1.Set("key", nilStr)

	val, found := c1.Get("key")
	if !found {
		t.Error("expected to find nil value")
	}
	if val != nil {
		t.Error("expected nil value")
	}

	// Test with slice types
	c2 := New[string, []int](time.Minute)
	defer c2.Close()

	c2.Set("key", nil)

	val2, found := c2.Get("key")
	if !found {
		t.Error("expected to find nil slice")
	}
	if val2 != nil {
		t.Error("expected nil slice")
	}

	// Test with empty slice
	c2.Set("key2", []int{})
	val3, found := c2.Get("key2")
	if !found {
		t.Error("expected to find empty slice")
	}
	if len(val3) != 0 {
		t.Error("expected empty slice")
	}
}

func BenchmarkCacheGet(b *testing.B) {
	c := New[int, string](time.Minute)
	defer c.Close()

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		c.Set(i, "value")
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _ = c.Get(i % 1000)
			i++
		}
	})
}

func BenchmarkCacheSet(b *testing.B) {
	c := New[int, string](time.Minute)
	defer c.Close()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			c.Set(i, "value")
			i++
		}
	})
}

func BenchmarkCacheGetOrSet(b *testing.B) {
	c := New[int, string](time.Minute)
	defer c.Close()

	loader := func() (string, error) {
		return "loaded", nil
	}

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _ = c.GetOrSet(i%100, loader)
			i++
		}
	})
}
