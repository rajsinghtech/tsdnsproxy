package dns

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"github.com/rajsinghtech/tsdnsproxy/internal/ui"
	"golang.org/x/net/dns/dnsmessage"
)

// Where a service rule's answer comes from.
const (
	serviceFromNetmap   = "netmap"
	serviceFromAddrs    = "addrs"
	serviceFromUpstream = "upstream"
)

// serviceTarget is the current answer source for a service rule.
type serviceTarget struct {
	from  string
	addrs []netip.Addr
}

// resolveService picks the VIPs from the netmap, then the rule's addrs.
// With neither, the query goes to the default upstreams.
func (s *Server) resolveService(grant *grants.DNSGrant) serviceTarget {
	if s != nil && s.ServiceVIPs != nil {
		if addrs, ok := s.ServiceVIPs.Lookup(grant.Service); ok {
			return serviceTarget{from: serviceFromNetmap, addrs: addrs}
		}
	}
	if addrs := grant.ServiceAddrs(); len(addrs) > 0 {
		return serviceTarget{from: serviceFromAddrs, addrs: addrs}
	}
	return serviceTarget{from: serviceFromUpstream}
}

func (s *Server) handleService(ctx context.Context, query *dnsmessage.Message, domain string, grant *grants.DNSGrant) ([]byte, error) {
	if grant.Service == "" {
		return nil, fmt.Errorf("missing service")
	}
	if query.OpCode != 0 {
		return ipNamesStatus(query, dnsmessage.RCodeNotImplemented, nil, nil)
	}
	if len(query.Questions) != 1 {
		return ipNamesStatus(query, dnsmessage.RCodeFormatError, nil, nil)
	}
	question := query.Questions[0]
	if question.Class != dnsmessage.ClassINET {
		return ipNamesStatus(query, dnsmessage.RCodeRefused, nil, nil)
	}
	target := s.resolveService(grant)
	if target.from == serviceFromUpstream {
		s.Logf("[v] service %s: %s has no address, forwarding %s", domain, grant.Service, question.Name)
		return s.forwardQuery(ctx, query, nil, nil, dnsmessage.Name{}, nil)
	}
	ttl := grant.ServiceTTL()
	var answers []dnsmessage.Resource
	for _, ip := range target.addrs {
		hdr := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: question.Class, TTL: ttl}
		switch {
		case question.Type == dnsmessage.TypeA && ip.Is4():
			answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: ip.As4()}})
		case question.Type == dnsmessage.TypeAAAA && ip.Is6():
			answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AAAAResource{AAAA: ip.As16()}})
		}
	}
	if len(answers) > 0 {
		s.Logf("[v] service %s %s from %s (%d)", question.Name, question.Type, target.from, len(answers))
		return ipNamesStatus(query, dnsmessage.RCodeSuccess, answers, nil)
	}
	return staticNODATA(query, domain, ttl)
}

// serviceCacheLimit is the longest a cached answer for query may be kept.
// It is the rule's TTL when query hits a service rule, and zero otherwise.
func (s *Server) serviceCacheLimit(query *dnsmessage.Message, cfgs []grants.GrantConfig) time.Duration {
	if s == nil || s.GrantParser == nil || len(query.Questions) == 0 {
		return 0
	}
	_, grant, ok := s.GrantParser.FindBestMatch(query.Questions[0].Name.String(), cfgs)
	if !ok || grant.Service == "" {
		return 0
	}
	return time.Duration(grant.ServiceTTL()) * time.Second
}

// describeService fills in the answer a service rule gives now.
func (s *Server) describeService(view *ui.ServiceVIP) {
	if view == nil {
		return
	}
	t := s.resolveService(&grants.DNSGrant{Service: view.Name, Addrs: view.Addrs})
	view.From = t.from
	view.Resolved = nil
	for _, ip := range t.addrs {
		view.Resolved = append(view.Resolved, ip.String())
	}
}

func (s *Server) describeServices(rules []ui.Rule) {
	for i := range rules {
		s.describeService(rules[i].ServiceVIP)
	}
}

// serviceVIPViews lists the service rules from the rules file and the
// server's own grants, with their current answers. Rules granted to other
// peers are left to the audit-only peer view.
func (s *Server) serviceVIPViews(file []ui.Rule) []ui.ServiceVIP {
	s.grantsMu.RLock()
	own := rulesFromList(s.serverGrants, "default")
	s.grantsMu.RUnlock()
	seen := map[string]bool{}
	out := []ui.ServiceVIP{}
	for _, rules := range [][]ui.Rule{file, own} {
		for _, r := range rules {
			if r.ServiceVIP == nil {
				continue
			}
			id := r.Domain + "\x00" + r.ServiceVIP.Name + "\x00" + r.Source + "\x00" + strings.Join(r.ServiceVIP.Addrs, ",")
			if seen[id] {
				continue
			}
			seen[id] = true
			view := *r.ServiceVIP
			view.Domain = r.Domain
			view.Source = r.Source
			view.Addrs = append([]string(nil), r.ServiceVIP.Addrs...)
			s.describeService(&view)
			out = append(out, view)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func policyHasService(cfgs []grants.GrantConfig) bool {
	for _, cfg := range cfgs {
		for _, grant := range cfg {
			if grant.Service != "" {
				return true
			}
		}
	}
	return false
}
