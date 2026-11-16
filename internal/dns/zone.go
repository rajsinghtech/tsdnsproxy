package dns

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/rajsinghtech/tsdnsproxy/internal/backend"
	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"golang.org/x/net/dns/dnsmessage"
)

// handleZone answers a name under a zone rule.
// A private A answer from the upstreams becomes a 4via6 AAAA, and the A query
// for that name is NODATA, as with an authoritative translateid. Public
// answers are returned unchanged. An empty, failed, or slow upstream answer
// is retried on the fallback resolvers and that answer is returned as is.
func (s *Server) handleZone(ctx context.Context, query *dnsmessage.Message, domain string, grant *grants.DNSGrant, configs []grants.GrantConfig) ([]byte, error) {
	question := query.Questions[0]
	eff := grant.ZoneGrant()
	timeout := grant.Zone.TimeoutValue()
	upstreams, err := s.BackendMgr.CreateBackends(grant.DNS)
	if err != nil {
		return nil, err
	}

	// Both upstream asks share one deadline so a miss costs at most two timeouts.
	upCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	upstreamDown := false
	if question.Type == dnsmessage.TypeAAAA {
		aq := *query
		aq.Questions = []dnsmessage.Question{{Name: question.Name, Type: dnsmessage.TypeA, Class: question.Class}}
		resp, err := s.zoneAsk(upCtx, upstreams, &aq)
		if err != nil {
			upstreamDown = true
		} else if out, ok := s.zoneVia6(resp, query, &eff, configs); ok {
			s.Logf("[v] zone %s: translated AAAA for %s", domain, question.Name)
			return out.Pack()
		}
	}

	var upstream *dnsmessage.Message
	if !upstreamDown {
		upstream, err = s.zoneAsk(upCtx, upstreams, query)
		if err != nil {
			s.Logf("[v] zone %s: upstream failed for %s: %v", domain, question.Name, err)
		}
	}
	if upstream != nil && zoneUsable(upstream) {
		if question.Type == dnsmessage.TypeA {
			s.zoneStripPrivate(upstream, &eff, configs)
		}
		return upstream.Pack()
	}

	fallback, err := s.BackendMgr.CreateBackends(grant.Zone.Fallback)
	if err != nil {
		return nil, err
	}
	fbCtx, fbCancel := context.WithTimeout(ctx, timeout)
	defer fbCancel()
	resp, ferr := s.zoneAsk(fbCtx, fallback, query)
	if ferr != nil {
		if upstream != nil && upstream.RCode != dnsmessage.RCodeServerFailure && upstream.RCode != dnsmessage.RCodeRefused {
			return upstream.Pack()
		}
		return nil, fmt.Errorf("zone %s: fallback: %w", domain, ferr)
	}
	s.Logf("[v] zone %s: fallback answered %s", domain, question.Name)
	return resp.Pack()
}

// zoneAsk sends query to backends. Empty backends use the defaults.
func (s *Server) zoneAsk(ctx context.Context, backends []backend.Backend, query *dnsmessage.Message) (*dnsmessage.Message, error) {
	raw, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack query: %w", err)
	}
	respRaw, err := s.BackendMgr.Query(ctx, backends, raw)
	if err != nil {
		return nil, err
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(respRaw); err != nil {
		return nil, fmt.Errorf("unpack response: %w", err)
	}
	return &resp, nil
}

// zoneUsable reports whether an upstream answer is kept instead of falling back.
func zoneUsable(resp *dnsmessage.Message) bool {
	return resp.RCode == dnsmessage.RCodeSuccess && len(resp.Answers) > 0
}

// zoneVia6 builds an AAAA answer from the private A records in resp.
// It returns false when resp holds no private A record.
func (s *Server) zoneVia6(resp, query *dnsmessage.Message, grant *grants.DNSGrant, configs []grants.GrantConfig) (*dnsmessage.Message, bool) {
	if !zoneUsable(resp) {
		return nil, false
	}
	var chain, via []dnsmessage.Resource
	for _, ans := range resp.Answers {
		a, ok := ans.Body.(*dnsmessage.AResource)
		if !ok {
			if ans.Header.Type == dnsmessage.TypeCNAME {
				chain = append(chain, ans)
			}
			continue
		}
		siteID, ok := s.translationTarget(netip.AddrFrom4(a.A), grant, configs)
		if !ok {
			continue
		}
		addr, err := s.mapVia6(netip.AddrFrom4(a.A), siteID)
		if err != nil {
			continue
		}
		via = append(via, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  ans.Header.Name,
				Type:  dnsmessage.TypeAAAA,
				Class: ans.Header.Class,
				TTL:   ans.Header.TTL,
			},
			Body: &dnsmessage.AAAAResource{AAAA: addr.As16()},
		})
	}
	if len(via) == 0 {
		return nil, false
	}
	out := &dnsmessage.Message{
		Header:    resp.Header,
		Questions: query.Questions,
		Answers:   append(chain, via...),
	}
	out.ID = query.ID
	out.Response = true
	return out, true
}

// zoneStripPrivate removes A records that zoneVia6 would translate.
func (s *Server) zoneStripPrivate(resp *dnsmessage.Message, grant *grants.DNSGrant, configs []grants.GrantConfig) {
	kept := resp.Answers[:0]
	for _, ans := range resp.Answers {
		if a, ok := ans.Body.(*dnsmessage.AResource); ok {
			if _, private := s.translationTarget(netip.AddrFrom4(a.A), grant, configs); private {
				continue
			}
		}
		kept = append(kept, ans)
	}
	resp.Answers = kept
}
