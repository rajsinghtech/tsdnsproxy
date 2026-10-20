package dns

import (
	"net/netip"
	"strings"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/backend"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"github.com/rajsinghtech/tsdnsproxy/internal/ui"
	"golang.org/x/net/dns/dnsmessage"
)

// UISnapshot is the read-only view served by the tailnet status site.
func (s *Server) UISnapshot() ui.Snapshot {
	if s == nil {
		return ui.Snapshot{}
	}
	snap := ui.Snapshot{
		Version:      s.Version,
		Image:        s.Image,
		CapName:      s.capName(),
		RulesOnly:    s.RulesOnly,
		HistoryLimit: s.HistoryLimit,
		Listeners:    s.listenerViews(),
		Rules:        rulesFromMap(nil, "rules"),
		Backends:     backendViews(s.BackendMgr),
	}
	if !s.Started.IsZero() {
		snap.Started = s.Started
		snap.UptimeSec = int64(time.Since(s.Started) / time.Second)
	}
	if s.Rules != nil {
		if cfg, ok := s.fileRules(); ok {
			snap.Rules = rulesFromMap(cfg, "rules")
		}
		snap.RulesUpdated = s.Rules.Updated()
	}
	hosted, err := ParseHostedService(s.Service)
	if err == nil && hosted.Name != "" {
		state := "configured"
		if s.listening("service", hosted.Name) {
			state = "listening"
		}
		snap.Service = ui.Service{Name: hosted.Name, Port: int(hosted.Port), State: state}
	} else {
		snap.Service = ui.Service{State: "not configured"}
	}
	stats := s.answers.stats()
	snap.Caches.Answer = ui.CacheStat{
		Enabled:   s.answers != nil,
		Entries:   stats.Entries,
		Limit:     s.AnswerCacheSize,
		Hits:      stats.Hits,
		Misses:    stats.Misses,
		Evictions: stats.Evictions,
	}
	if s.answers != nil && snap.Caches.Answer.Limit == 0 {
		snap.Caches.Answer.Limit = stats.Limit
	}
	if s.WhoisCache != nil {
		snap.Caches.Whois = ui.CacheStat{Enabled: true, Entries: s.WhoisCache.Len(), TTLSec: int64(s.WhoisCache.TTL() / time.Second)}
	}
	if s.GrantCache != nil {
		snap.Caches.Grants = ui.CacheStat{Enabled: true, Entries: s.GrantCache.Len(), TTLSec: int64(s.GrantCache.TTL() / time.Second)}
	}
	return snap
}

// UIPeers is the learned per-identity view.
func (s *Server) UIPeers() []ui.Peer {
	peers := s.learnedPeers()
	if peers == nil {
		return []ui.Peer{}
	}
	return peers
}

func backendViews(mgr BackendManager) []ui.Backend {
	type backendStatus interface {
		Status() []backend.BackendStatus
	}
	st, ok := mgr.(backendStatus)
	if !ok || st == nil {
		return nil
	}
	raw := st.Status()
	out := make([]ui.Backend, 0, len(raw))
	for _, b := range raw {
		out = append(out, ui.Backend{
			Address:  b.Address,
			Mode:     b.Mode,
			Healthy:  b.Healthy,
			Failures: b.Failures,
			RetryAt:  b.RetryAt,
		})
	}
	return out
}

func (s *Server) listenerViews() []ui.Listener {
	if s == nil {
		return nil
	}
	s.boundMu.Lock()
	defer s.boundMu.Unlock()
	out := make([]ui.Listener, 0, len(s.bound))
	for _, b := range s.bound {
		out = append(out, ui.Listener{Proto: b.proto, Addr: b.addr, Service: b.service, State: "listening"})
	}
	return out
}

func (s *Server) listening(proto, service string) bool {
	s.boundMu.Lock()
	defer s.boundMu.Unlock()
	for _, b := range s.bound {
		if b.proto == proto && (service == "" || b.service == service) {
			return true
		}
	}
	return false
}

func (s *Server) addBound(proto, addr, service string) {
	s.trackListener()
	s.boundMu.Lock()
	s.bound = append(s.bound, boundListener{proto: proto, addr: addr, service: service})
	s.boundMu.Unlock()
}

func (s *Server) removeBound(proto, addr, service string) {
	s.untrackListener()
	s.boundMu.Lock()
	for i := range s.bound {
		b := s.bound[i]
		if b.proto == proto && b.addr == addr && b.service == service {
			s.bound = append(s.bound[:i], s.bound[i+1:]...)
			break
		}
	}
	s.boundMu.Unlock()
}

type boundListener struct {
	proto   string
	addr    string
	service string
}

func (s *Server) emitQuery(start time.Time, via, qname, qtype, rcode string, addr string, grants []grants.GrantConfig, cacheState string) {
	if s == nil || s.OnQuery == nil || qname == "" {
		return
	}
	zone, action, rewrite, backend, source, translate := describeMatch(s.GrantParser, grants, qname)
	peer := s.peerBrief(addr)
	if file, _ := s.fileRules(); peer != nil && zone != "" {
		for _, rule := range displayRules(file, peer.acl, peer.origin, peer.rulesOnly) {
			if rule.Domain == zone {
				source = rule.Source
				break
			}
		}
	}
	s.OnQuery(ui.Query{
		Time:        start,
		PeerIP:      addr,
		Node:        peer.node,
		User:        peer.user,
		Tags:        peer.tags,
		Name:        strings.TrimSuffix(qname, "."),
		Type:        qtype,
		Zone:        zone,
		Source:      source,
		Rewrite:     rewrite,
		TranslateID: translate,
		Action:      action,
		Backend:     backend,
		RCode:       rcode,
		LatencyMS:   time.Since(start).Milliseconds(),
		Cache:       cacheState,
		Path:        via,
	})
}

func (s *Server) peerBrief(ip string) *seenPeer {
	if s == nil || s.learn == nil {
		return &seenPeer{}
	}
	for _, p := range s.learn.list() {
		if p.ip == ip || contains(p.addrs, ip) || p.id == ip {
			return p
		}
	}
	return &seenPeer{}
}

func describeMatch(parser *grants.Parser, cfgs []grants.GrantConfig, qname string) (zone, action, rewrite, backend, source string, translate *int) {
	if parser == nil {
		return "", "", "", "", "", nil
	}
	domain, grant, ok := parser.FindBestMatch(grants.NormalizeDomain(qname), cfgs)
	if !ok {
		return "", "default", "", "default", "default", nil
	}
	zone = domain
	rewrite = grant.Rewrite
	if id, explicit := grant.ExplicitTranslateID(); explicit {
		idCopy := id
		translate = &idCopy
		if id > 0 {
			action = "4via6"
		}
	}
	if grant.Static != nil {
		action = "static"
	} else if grant.IPNames != nil {
		action = "ipnames"
	} else if rewrite != "" && action == "" {
		action = "rewrite"
	} else if action == "" {
		action = "forward"
	}
	if len(grant.DNS) > 0 {
		backend = strings.Join(grant.DNS, ", ")
	} else if action != "ipnames" && action != "static" {
		backend = "default"
	}
	source = "grant"
	return zone, action, rewrite, backend, source, translate
}

func answerLines(raw []byte) (string, []string) {
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return "", nil
	}
	var lines []string
	for _, ans := range msg.Answers {
		switch body := ans.Body.(type) {
		case *dnsmessage.AResource:
			lines = append(lines, netip.AddrFrom4(body.A).String())
		case *dnsmessage.AAAAResource:
			lines = append(lines, netip.AddrFrom16(body.AAAA).String())
		case *dnsmessage.CNAMEResource:
			lines = append(lines, strings.TrimSuffix(body.CNAME.String(), "."))
		case *dnsmessage.TXTResource:
			lines = append(lines, strings.Join(body.TXT, ""))
		default:
			lines = append(lines, ans.Header.Type.String())
		}
	}
	return msg.RCode.String(), lines
}
