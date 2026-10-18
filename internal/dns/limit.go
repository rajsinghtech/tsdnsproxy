package dns

import (
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// sourceLimiter limits queries per client address.
// A zero limit disables the limiter.
type sourceLimiter struct {
	limit rate.Limit
	burst int
	mu    sync.Mutex
	m     map[string]*clientBucket
}

type clientBucket struct {
	lim  *rate.Limiter
	seen time.Time
}

func newSourceLimiter(perSecond float64, burst int) *sourceLimiter {
	if perSecond <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &sourceLimiter{
		limit: rate.Limit(perSecond),
		burst: burst,
		m:     map[string]*clientBucket{},
	}
}

func (l *sourceLimiter) allow(addr string) bool {
	if l == nil {
		return true
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) > 1024 {
		for key, b := range l.m {
			if now.Sub(b.seen) > 10*time.Minute {
				delete(l.m, key)
			}
		}
	}
	b := l.m[host]
	if b == nil {
		b = &clientBucket{lim: rate.NewLimiter(l.limit, l.burst)}
		l.m[host] = b
	}
	b.seen = now
	return b.lim.Allow()
}
