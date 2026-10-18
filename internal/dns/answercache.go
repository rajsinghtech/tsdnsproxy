package dns

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/constants"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"github.com/rajsinghtech/tsdnsproxy/internal/metrics"
	"golang.org/x/net/dns/dnsmessage"
)

// answerKey identifies one cached response.
// policy is a hash of the effective rules. src is set only when those rules
// read the client address, so peers with the same rules share an entry.
type answerKey struct {
	name   string
	qtype  uint16
	qclass uint16
	do     bool
	cd     bool
	policy [32]byte
	src    string
}

type answerEntry struct {
	key     answerKey
	raw     []byte
	stored  time.Time
	expires time.Time
	elem    *list.Element
}

type answerFlight struct {
	once   sync.Once
	done   chan struct{}
	raw    []byte
	stored time.Time
	err    error
}

// answerCache stores final DNS responses with an LRU bound and singleflight loads.
type answerCache struct {
	size    int
	minTTL  time.Duration
	maxTTL  time.Duration
	failTTL time.Duration
	now     func() time.Time
	metrics *metrics.Metrics

	mu      sync.Mutex
	items   map[answerKey]*answerEntry
	order   *list.List
	flights map[answerKey]*answerFlight

	// joined, when set, runs after a caller attaches to an in-flight load.
	joined func()
}

func newAnswerCache(size int, minTTL, maxTTL time.Duration, m *metrics.Metrics) *answerCache {
	if size < 1 {
		return nil
	}
	if minTTL < 0 {
		minTTL = 0
	}
	if maxTTL <= 0 {
		maxTTL = constants.DefaultAnswerMaxTTL
	}
	if minTTL > maxTTL {
		minTTL = maxTTL
	}
	return &answerCache{
		size:    size,
		minTTL:  minTTL,
		maxTTL:  maxTTL,
		failTTL: constants.ServfailAnswerTTL,
		items:   make(map[answerKey]*answerEntry),
		order:   list.New(),
		flights: make(map[answerKey]*answerFlight),
		metrics: m,
	}
}

func (c *answerCache) clock() time.Time {
	if c != nil && c.now != nil {
		return c.now()
	}
	return time.Now()
}

// lookup returns the response for q. Concurrent callers for one key share one load.
// A panicking load releases the waiters and panics again.
func (c *answerCache) lookup(q *dnsmessage.Message, key answerKey, load func() ([]byte, error)) ([]byte, bool, error) {
	if c == nil || c.size < 1 {
		raw, err := load()
		return raw, false, err
	}
	c.mu.Lock()
	if raw, stored, ok := c.freshLocked(key); ok {
		c.mu.Unlock()
		c.metrics.CacheHit()
		out, err := present(raw, q, c.clock().Sub(stored))
		return out, true, err
	}
	if f, ok := c.flights[key]; ok {
		c.mu.Unlock()
		if c.joined != nil {
			c.joined()
		}
		<-f.done
		c.metrics.CacheMiss()
		if f.err != nil {
			return nil, false, f.err
		}
		age := time.Duration(0)
		if !f.stored.IsZero() {
			age = c.clock().Sub(f.stored)
			if age < 0 {
				age = 0
			}
		}
		out, err := present(f.raw, q, age)
		return out, false, err
	}
	f := &answerFlight{done: make(chan struct{})}
	c.flights[key] = f
	c.mu.Unlock()
	c.metrics.CacheMiss()

	panicked := true
	defer func() {
		if !panicked {
			return
		}
		rec := recover()
		c.finish(key, f, nil, time.Time{}, fmt.Errorf("answer cache panic: %v", rec))
		panic(rec)
	}()
	raw, err := load()
	panicked = false
	if err != nil {
		c.rememberFailure(key, f, err)
		return nil, false, err
	}
	ttl, store := retention(raw, c.minTTL, c.maxTTL, c.failTTL)
	var stored time.Time
	if store {
		stored = c.insert(key, raw, ttl)
	}
	c.finish(key, f, raw, stored, nil)
	out, perr := present(raw, q, 0)
	return out, false, perr
}

func (c *answerCache) rememberFailure(key answerKey, f *answerFlight, err error) {
	ttl := c.failTTL
	if c.maxTTL > 0 && ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	wire := servfailTemplate()
	if ttl > 0 && len(wire) > 0 {
		stored := c.insert(key, wire, ttl)
		c.finish(key, f, wire, stored, nil)
		return
	}
	c.finish(key, f, nil, time.Time{}, err)
}

func (c *answerCache) finish(key answerKey, f *answerFlight, raw []byte, stored time.Time, err error) {
	f.once.Do(func() {
		f.raw = append([]byte(nil), raw...)
		f.stored = stored
		f.err = err
		c.mu.Lock()
		if c.flights[key] == f {
			delete(c.flights, key)
		}
		c.mu.Unlock()
		close(f.done)
	})
}

func (c *answerCache) freshLocked(key answerKey) ([]byte, time.Time, bool) {
	e, ok := c.items[key]
	if !ok {
		return nil, time.Time{}, false
	}
	if !c.clock().Before(e.expires) {
		c.order.Remove(e.elem)
		delete(c.items, key)
		return nil, time.Time{}, false
	}
	c.order.MoveToFront(e.elem)
	return e.raw, e.stored, true
}

func (c *answerCache) insert(key answerKey, raw []byte, ttl time.Duration) time.Time {
	now := c.clock()
	c.mu.Lock()
	if old, ok := c.items[key]; ok {
		c.order.Remove(old.elem)
		delete(c.items, key)
	}
	e := &answerEntry{
		key:     key,
		raw:     append([]byte(nil), raw...),
		stored:  now,
		expires: now.Add(ttl),
	}
	e.elem = c.order.PushFront(e)
	c.items[key] = e
	evicted := 0
	for c.order.Len() > c.size {
		back := c.order.Back()
		if back == nil {
			break
		}
		victim := back.Value.(*answerEntry)
		c.order.Remove(back)
		delete(c.items, victim.key)
		evicted++
	}
	c.mu.Unlock()
	c.metrics.CacheEviction(evicted)
	return now
}

func newAnswerKey(q *dnsmessage.Message, cfgs []grants.GrantConfig, src netip.Addr) answerKey {
	key := answerKey{policy: policyHash(cfgs)}
	if q == nil || len(q.Questions) == 0 {
		return key
	}
	question := q.Questions[0]
	key.name = grants.NormalizeDomain(question.Name.String())
	key.qtype = uint16(question.Type)
	key.qclass = uint16(question.Class)
	key.do = queryDO(q)
	key.cd = q.CheckingDisabled
	if policyBindsSource(cfgs) && src.IsValid() {
		key.src = src.String()
	}
	return key
}

func queryDO(q *dnsmessage.Message) bool {
	if q == nil {
		return false
	}
	for _, extra := range q.Additionals {
		if extra.Header.Type == dnsmessage.TypeOPT && extra.Header.DNSSECAllowed() {
			return true
		}
	}
	return false
}

// policyBindsSource reports whether the rules can answer differently for two clients.
func policyBindsSource(cfgs []grants.GrantConfig) bool {
	for _, cfg := range cfgs {
		for _, grant := range cfg {
			if grant.IPNames == nil {
				continue
			}
			if len(grant.IPNames.AllowSrc) > 0 || strings.EqualFold(grant.IPNames.A, "direct") {
				return true
			}
		}
	}
	return false
}

type policyItem struct {
	Name  string          `json:"name"`
	Grant grants.DNSGrant `json:"grant"`
}

func policyHash(cfgs []grants.GrantConfig) [32]byte {
	items := make([]policyItem, 0)
	for _, cfg := range cfgs {
		for name, grant := range cfg {
			items = append(items, policyItem{
				Name:  grants.NormalizeDomain(name),
				Grant: canonGrant(grant),
			})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		ai, aerr := json.Marshal(items[i].Grant)
		aj, berr := json.Marshal(items[j].Grant)
		if aerr != nil || berr != nil {
			return aerr == nil && berr != nil
		}
		return bytes.Compare(ai, aj) < 0
	})
	raw, err := json.Marshal(items)
	if err != nil {
		raw = []byte{}
	}
	return sha256.Sum256(raw)
}

func canonGrant(g grants.DNSGrant) grants.DNSGrant {
	g.AllowIPs = sortedCopy(g.AllowIPs)
	g.DenyIPs = sortedCopy(g.DenyIPs)
	g.DNS = append([]string(nil), g.DNS...)
	if g.IPNames != nil {
		cp := *g.IPNames
		if cp.A == "" {
			cp.A = "never"
		}
		cp.AllowSrc = sortedCopy(cp.AllowSrc)
		cp.DirectSrc = sortedCopy(cp.DirectSrc)
		cp.AllowIPs = sortedCopy(cp.AllowIPs)
		g.IPNames = &cp
	}
	return g
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// retention reports how long raw may be stored.
// The boolean is false when the response must not be cached.
func retention(raw []byte, minTTL, maxTTL, failTTL time.Duration) (time.Duration, bool) {
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return 0, false
	}
	if msg.Truncated {
		return 0, false
	}
	if msg.RCode == dnsmessage.RCodeServerFailure {
		if failTTL <= 0 {
			return 0, false
		}
		if maxTTL > 0 && failTTL > maxTTL {
			failTTL = maxTTL
		}
		return failTTL, true
	}
	sec, ok := ttlSeconds(&msg)
	if !ok {
		return 0, false
	}
	d := time.Duration(sec) * time.Second
	if d < minTTL {
		d = minTTL
	}
	if maxTTL > 0 && d > maxTTL {
		d = maxTTL
	}
	if d <= 0 {
		return 0, false
	}
	return d, true
}

func ttlSeconds(msg *dnsmessage.Message) (uint32, bool) {
	if msg == nil {
		return 0, false
	}
	negative := msg.RCode == dnsmessage.RCodeNameError || (msg.RCode == dnsmessage.RCodeSuccess && len(msg.Answers) == 0)
	if negative {
		soa, ok := findSOA(msg)
		if !ok {
			return 0, false
		}
		ttl := soa.Header.TTL
		if body, ok := soa.Body.(*dnsmessage.SOAResource); ok && body.MinTTL < ttl {
			ttl = body.MinTTL
		}
		return ttl, true
	}
	var min uint32
	found := false
	consider := func(rs []dnsmessage.Resource) {
		for _, rr := range rs {
			if rr.Header.Type == dnsmessage.TypeOPT {
				continue
			}
			if !found || rr.Header.TTL < min {
				min = rr.Header.TTL
				found = true
			}
		}
	}
	consider(msg.Answers)
	consider(msg.Authorities)
	return min, found
}

func findSOA(msg *dnsmessage.Message) (dnsmessage.Resource, bool) {
	for _, rr := range msg.Authorities {
		if rr.Header.Type == dnsmessage.TypeSOA {
			return rr, true
		}
	}
	for _, rr := range msg.Answers {
		if rr.Header.Type == dnsmessage.TypeSOA {
			return rr, true
		}
	}
	return dnsmessage.Resource{}, false
}

func present(raw []byte, q *dnsmessage.Message, age time.Duration) ([]byte, error) {
	if q == nil {
		return append([]byte(nil), raw...), nil
	}
	if age < 0 {
		age = 0
	}
	if age == 0 && len(raw) >= 2 && binary.BigEndian.Uint16(raw[:2]) == q.ID {
		return append([]byte(nil), raw...), nil
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return nil, fmt.Errorf("cached answer: %w", err)
	}
	msg.ID = q.ID
	msg.Response = true
	if len(q.Questions) > 0 {
		if len(msg.Questions) == 0 {
			msg.Questions = append([]dnsmessage.Question(nil), q.Questions[0])
		} else {
			msg.Questions[0] = q.Questions[0]
		}
		echoQuestionName(msg.Answers, q.Questions[0].Name)
		echoQuestionName(msg.Authorities, q.Questions[0].Name)
		echoQuestionName(msg.Additionals, q.Questions[0].Name)
	}
	if age > 0 {
		dec := uint32(age / time.Second)
		if dec > 0 {
			countDown(msg.Answers, dec)
			countDown(msg.Authorities, dec)
			countDown(msg.Additionals, dec)
		}
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack cached answer: %w", err)
	}
	return packed, nil
}

func echoQuestionName(rs []dnsmessage.Resource, want dnsmessage.Name) {
	folded := grants.NormalizeDomain(want.String())
	for i := range rs {
		if rs[i].Header.Type == dnsmessage.TypeOPT {
			continue
		}
		if grants.NormalizeDomain(rs[i].Header.Name.String()) == folded {
			rs[i].Header.Name = want
		}
	}
}

func countDown(rs []dnsmessage.Resource, dec uint32) {
	for i := range rs {
		if rs[i].Header.Type == dnsmessage.TypeOPT {
			continue
		}
		if rs[i].Header.TTL > dec {
			rs[i].Header.TTL -= dec
		} else {
			rs[i].Header.TTL = 0
		}
	}
}

func servfailTemplate() []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response: true,
			RCode:    dnsmessage.RCodeServerFailure,
		},
	}
	raw, err := msg.Pack()
	if err != nil {
		return nil
	}
	return raw
}
