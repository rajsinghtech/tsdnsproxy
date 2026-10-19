package dns

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"github.com/rajsinghtech/tsdnsproxy/internal/logging"
	"github.com/rajsinghtech/tsdnsproxy/internal/ui"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg/peercap"
)

const learnedPeerLimit = 512

// seenPeer is one identity observed on a DNS query.
type seenPeer struct {
	id        string
	ip        string
	node      string
	user      string
	tags      []string
	addrs     []string
	seen      time.Time
	expire    time.Time
	caps      []string
	acl       []grants.GrantConfig
	origin    string
	rulesOnly bool
}

type peerBook struct {
	mu    sync.Mutex
	peers map[string]*seenPeer
	order []string
}

func newPeerBook() *peerBook {
	return &peerBook{peers: map[string]*seenPeer{}}
}

func (b *peerBook) put(p *seenPeer) {
	if b == nil || p == nil || p.id == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if prev, ok := b.peers[p.id]; ok {
		for _, addr := range p.addrs {
			if addr != "" && !contains(prev.addrs, addr) {
				prev.addrs = append(prev.addrs, addr)
			}
		}
		prev.seen = p.seen
		if !p.expire.IsZero() {
			prev.expire = p.expire
		}
		if p.node != "" {
			prev.node = p.node
		}
		if p.user != "" {
			prev.user = p.user
		}
		if len(p.tags) > 0 {
			prev.tags = p.tags
		}
		if len(p.caps) > 0 {
			prev.caps = p.caps
		}
		if p.acl != nil {
			prev.acl = p.acl
		}
		prev.origin = p.origin
		prev.rulesOnly = p.rulesOnly
		return
	}
	if p.ip != "" && !contains(p.addrs, p.ip) {
		p.addrs = append([]string{p.ip}, p.addrs...)
	}
	b.peers[p.id] = p
	b.order = append(b.order, p.id)
	for len(b.order) > learnedPeerLimit {
		drop := b.order[0]
		b.order = b.order[1:]
		delete(b.peers, drop)
	}
}

func (b *peerBook) list() []*seenPeer {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*seenPeer, 0, len(b.order))
	for i := len(b.order) - 1; i >= 0; i-- {
		if p := b.peers[b.order[i]]; p != nil {
			cp := *p
			cp.tags = append([]string(nil), p.tags...)
			cp.addrs = append([]string(nil), p.addrs...)
			cp.caps = append([]string(nil), p.caps...)
			out = append(out, &cp)
		}
	}
	return out
}

func (s *Server) notePeer(host string, whois *apitype.WhoIsResponse, acl []grants.GrantConfig, origin string, rulesOnly bool) {
	if s == nil {
		return
	}
	if s.learn == nil {
		s.learn = newPeerBook()
	}
	p := &seenPeer{
		id:        host,
		ip:        host,
		seen:      time.Now(),
		origin:    origin,
		rulesOnly: rulesOnly,
		acl:       acl,
	}
	identity := host
	if whois != nil {
		if whois.Node != nil {
			p.node = logging.Redact(strings.TrimSuffix(whois.Node.Name, "."))
			p.tags = append([]string(nil), whois.Node.Tags...)
			for _, addr := range whois.Node.Addresses {
				p.addrs = append(p.addrs, addr.String())
			}
		}
		if whois.UserProfile != nil {
			p.user = logging.Redact(whois.UserProfile.LoginName)
		}
		if id := s.getIdentity(whois); id != "" && id != "unknown" {
			identity = id
			p.id = logging.Redact(id)
		}
		p.caps = rawCaps(whois, s.capName())
	}
	if p.id == "" {
		p.id = host
	}
	if p.node == "" {
		p.node = p.id
	}
	if exp, ok := s.grantExpiry(identity); ok {
		p.expire = exp
	} else if s.GrantCache != nil && s.GrantCache.TTL() > 0 {
		p.expire = time.Now().Add(s.GrantCache.TTL())
	}
	s.learn.put(p)
}

func (s *Server) capName() string {
	if s != nil && s.GrantParser != nil {
		return s.GrantParser.CapName()
	}
	return grants.DefaultCapName
}

func rawCaps(whois *apitype.WhoIsResponse, capName string) []string {
	if whois == nil || whois.CapMap == nil {
		return nil
	}
	vals := whois.CapMap[peercap.Cap(capName)]
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, logging.Redact(string(v)))
	}
	return out
}

func (s *Server) grantExpiry(identity string) (time.Time, bool) {
	if s == nil || s.GrantCache == nil {
		return time.Time{}, false
	}
	_, exp, ok := s.GrantCache.Timing(s.grantCacheKey(identity))
	return exp, ok
}

func (s *Server) learnedPeers() []ui.Peer {
	if s == nil || s.learn == nil {
		return nil
	}
	file, _ := s.fileRules()
	now := time.Now()
	var out []ui.Peer
	for _, p := range s.learn.list() {
		age := now.Sub(p.seen)
		if !p.expire.IsZero() {
			if remain := time.Until(p.expire); remain > 0 && s.GrantCache != nil {
				age = s.GrantCache.TTL() - remain
				if age < 0 {
					age = 0
				}
			}
		}
		out = append(out, ui.Peer{
			ID:          p.id,
			Node:        p.node,
			User:        p.user,
			Tags:        p.tags,
			IPs:         p.addrs,
			Seen:        p.seen,
			CacheAgeSec: int64(age / time.Second),
			CacheExpire: p.expire,
			Caps:        p.caps,
			Rules:       displayRules(file, p.acl, p.origin, p.rulesOnly),
		})
	}
	return out
}

func displayRules(file grants.GrantConfig, acl []grants.GrantConfig, origin string, rulesOnly bool) []ui.Rule {
	if origin == "default" {
		return rulesFromList(acl, "default")
	}
	if rulesOnly || origin == "rules" {
		return rulesFromMap(file, "rules")
	}
	over := map[string]struct{}{}
	for _, cfg := range acl {
		for domain := range cfg {
			key := grants.NormalizeDomain(domain)
			if _, ok := file[key]; ok {
				over[key] = struct{}{}
			}
		}
	}
	var out []ui.Rule
	for domain, grant := range file {
		key := grants.NormalizeDomain(domain)
		if _, skip := over[key]; skip {
			continue
		}
		out = append(out, ruleFrom(key, grant, "rules"))
	}
	out = append(out, rulesFromList(acl, "grant")...)
	sortRules(out)
	return out
}

func rulesFromMap(cfg grants.GrantConfig, source string) []ui.Rule {
	var out []ui.Rule
	for domain, grant := range cfg {
		out = append(out, ruleFrom(grants.NormalizeDomain(domain), grant, source))
	}
	sortRules(out)
	return out
}

func rulesFromList(cfgs []grants.GrantConfig, source string) []ui.Rule {
	var out []ui.Rule
	for _, cfg := range cfgs {
		out = append(out, rulesFromMap(cfg, source)...)
	}
	sortRules(out)
	return out
}

func ruleFrom(domain string, grant grants.DNSGrant, source string) ui.Rule {
	rule := ui.Rule{
		Domain:   domain,
		Source:   source,
		Rewrite:  grant.Rewrite,
		Backends: append([]string(nil), grant.DNS...),
		AllowIPs: append([]string(nil), grant.AllowIPs...),
		DenyIPs:  append([]string(nil), grant.DenyIPs...),
	}
	if id, ok := grant.ExplicitTranslateID(); ok {
		idCopy := id
		rule.TranslateID = &idCopy
		if id > 0 {
			rule.SitePrefix = sitePrefix(id)
		}
	}
	if grant.IPNames != nil {
		view := &ui.IPNames{
			A:         grant.IPNames.A,
			AllowSrc:  append([]string(nil), grant.IPNames.AllowSrc...),
			AllowIPs:  append([]string(nil), grant.IPNames.AllowIPs...),
			DirectSrc: append([]string(nil), grant.IPNames.DirectSrc...),
		}
		if grant.IPNames.SiteID != nil {
			view.SiteID = *grant.IPNames.SiteID
			view.SitePrefix = sitePrefix(view.SiteID)
			rule.SitePrefix = view.SitePrefix
		}
		if view.A == "" {
			view.A = "never"
		}
		rule.IPNames = view
		rule.AllowSrc = view.AllowSrc
	}
	return rule
}

func sortRules(rules []ui.Rule) {
	for i := 1; i < len(rules); i++ {
		j := i
		for j > 0 && rules[j].Domain < rules[j-1].Domain {
			rules[j], rules[j-1] = rules[j-1], rules[j]
			j--
		}
	}
}

func sitePrefix(id int) string {
	if id <= 0 {
		return ""
	}
	p, err := viaPrefix(uint32(id)) //nolint:gosec // site id is limited to 0..65535
	if err != nil {
		return ""
	}
	return p
}

func viaPrefix(siteID uint32) (string, error) {
	pfx, err := tsaddr.MapVia(siteID, netip.PrefixFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		return "", err
	}
	return pfx.Masked().String(), nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
