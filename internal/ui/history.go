package ui

import (
	"strings"
	"sync"
	"time"
)

// Ring is a bounded log of recent queries. A non-positive size stores nothing.
type Ring struct {
	mu     sync.Mutex
	buf    []Query
	size   int
	next   int
	filled bool
}

// NewRing returns a ring that keeps size entries. Zero disables the log.
func NewRing(size int) *Ring {
	if size < 0 {
		size = 0
	}
	r := &Ring{size: size}
	if size > 0 {
		r.buf = make([]Query, size)
	}
	return r
}

// Size is the configured capacity.
func (r *Ring) Size() int {
	if r == nil {
		return 0
	}
	return r.size
}

// Add stores one query. Secrets in the text fields are redacted first.
func (r *Ring) Add(q Query) {
	if r == nil || r.size == 0 {
		return
	}
	q = redactQuery(q)
	if q.Time.IsZero() {
		q.Time = time.Now()
	}
	r.mu.Lock()
	r.buf[r.next] = q
	r.next = (r.next + 1) % r.size
	if r.next == 0 {
		r.filled = true
	}
	r.mu.Unlock()
}

// List returns newest matches first.
func (r *Ring) List(peer, user, domain, rcode string) []Query {
	all := r.snapshot()
	peer = strings.ToLower(strings.TrimSpace(peer))
	user = strings.ToLower(strings.TrimSpace(user))
	domain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	rcode = strings.ToUpper(strings.TrimSpace(rcode))
	out := make([]Query, 0, len(all))
	for _, q := range all {
		if peer != "" && !peerMatch(q, peer) {
			continue
		}
		if user != "" && !strings.Contains(strings.ToLower(q.User), user) {
			continue
		}
		if domain != "" && !domainMatch(q.Name, domain) {
			continue
		}
		if rcode != "" && !strings.EqualFold(q.RCode, rcode) {
			continue
		}
		out = append(out, q)
	}
	return out
}

// Access aggregates the whole ring.
func (r *Ring) Access() Access {
	all := r.snapshot()
	report := Access{History: r != nil && r.size > 0, Total: len(all)}
	peers := map[string]*Tally{}
	domains := map[string]*Tally{}
	for _, q := range all {
		refused := strings.EqualFold(q.RCode, "REFUSED")
		if refused {
			report.Refused++
		}
		pkey := q.Node
		if pkey == "" {
			pkey = q.PeerIP
		}
		if pkey == "" {
			pkey = "unknown"
		}
		addTally(peers, pkey, refused)
		name := strings.Trim(strings.ToLower(q.Name), ".")
		if name == "" {
			name = "unknown"
		}
		addTally(domains, name, refused)
	}
	report.Peers = topTallies(peers, 50)
	report.Domains = topTallies(domains, 50)
	return report
}

func (r *Ring) snapshot() []Query {
	if r == nil || r.size == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.next
	if r.filled {
		n = r.size
	}
	out := make([]Query, 0, n)
	if !r.filled {
		for i := r.next - 1; i >= 0; i-- {
			out = append(out, r.buf[i])
		}
		return out
	}
	for i := 0; i < r.size; i++ {
		idx := r.next - 1 - i
		if idx < 0 {
			idx += r.size
		}
		out = append(out, r.buf[idx])
	}
	return out
}

func peerMatch(q Query, peer string) bool {
	return strings.Contains(strings.ToLower(q.PeerIP), peer) ||
		strings.Contains(strings.ToLower(q.Node), peer) ||
		strings.Contains(strings.ToLower(q.User), peer)
}

func domainMatch(name, domain string) bool {
	name = strings.Trim(strings.ToLower(name), ".")
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func addTally(m map[string]*Tally, name string, refused bool) {
	t := m[name]
	if t == nil {
		t = &Tally{Name: name}
		m[name] = t
	}
	t.Queries++
	if refused {
		t.Refused++
	}
}

func topTallies(m map[string]*Tally, limit int) []Tally {
	out := make([]Tally, 0, len(m))
	for _, t := range m {
		out = append(out, *t)
	}
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 {
			prev, cur := out[j-1], out[j]
			if prev.Queries > cur.Queries || (prev.Queries == cur.Queries && prev.Name < cur.Name) {
				break
			}
			out[j-1], out[j] = cur, prev
			j--
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func redactQuery(q Query) Query {
	q.PeerIP = Redact(q.PeerIP)
	q.Node = Redact(q.Node)
	q.User = Redact(q.User)
	q.Name = Redact(q.Name)
	q.Zone = Redact(q.Zone)
	q.Rewrite = Redact(q.Rewrite)
	q.Backend = Redact(q.Backend)
	q.Action = Redact(q.Action)
	q.Source = Redact(q.Source)
	for i := range q.Tags {
		q.Tags[i] = Redact(q.Tags[i])
	}
	return q
}
