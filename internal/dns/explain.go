package dns

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"github.com/rajsinghtech/tsdnsproxy/internal/ui"
	"golang.org/x/net/dns/dnsmessage"
)

// Explain describes the rule a peer would hit for name and qtype.
// Upstream servers are contacted only when forward is true.
func (s *Server) Explain(ctx context.Context, req ui.LookupRequest) (ui.Lookup, error) {
	out := ui.Lookup{
		Name: strings.Trim(strings.TrimSpace(req.Name), "."),
		Type: strings.ToUpper(strings.TrimSpace(req.Type)),
		Peer: strings.TrimSpace(req.Peer),
	}
	if out.Type == "" {
		out.Type = "A"
	}
	if s == nil || s.GrantParser == nil {
		return out, fmt.Errorf("dns server is not ready")
	}
	qtype, err := parseQType(out.Type)
	if err != nil {
		return out, err
	}
	name := out.Name
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return out, fmt.Errorf("name: %w", err)
	}
	var cfgs []grants.GrantConfig
	if out.Peer != "" {
		cfgs, err = s.getGrantsForSource(ctx, netJoin(out.Peer))
		if err != nil {
			out.Error = err.Error()
			return out, err
		}
		if brief := s.peerBrief(out.Peer); brief != nil {
			out.Identity = brief.id
		}
	}
	domain, grant, ok := s.GrantParser.FindBestMatch(grants.NormalizeDomain(qname.String()), cfgs)
	if ok {
		out.Matched = true
		source := "grant"
		if brief := s.peerBrief(out.Peer); brief != nil && brief.id != "" {
			file, _ := s.fileRules()
			for _, rule := range displayRules(file, brief.acl, brief.origin, brief.rulesOnly) {
				if rule.Domain == domain {
					source = rule.Source
					break
				}
			}
		}
		rule := ruleFrom(domain, grant, source)
		out.Rule = &rule
	}
	if !req.Forward {
		return out, nil
	}
	msg := &dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  qname,
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	raw, err := s.processQuery(ctx, msg, cfgs, parsePeerIP(out.Peer))
	out.Forwarded = true
	if err != nil {
		out.RCode = "SERVFAIL"
		out.Error = err.Error()
		return out, err
	}
	_, out.Answers = answerLines(raw)
	out.RCode = rcodeOf(raw)
	return out, nil
}

func parseQType(s string) (dnsmessage.Type, error) {
	switch strings.ToUpper(s) {
	case "A":
		return dnsmessage.TypeA, nil
	case "AAAA":
		return dnsmessage.TypeAAAA, nil
	case "TXT":
		return dnsmessage.TypeTXT, nil
	case "CNAME":
		return dnsmessage.TypeCNAME, nil
	case "NS":
		return dnsmessage.TypeNS, nil
	case "SOA":
		return dnsmessage.TypeSOA, nil
	case "MX":
		return dnsmessage.TypeMX, nil
	case "PTR":
		return dnsmessage.TypePTR, nil
	default:
		return 0, fmt.Errorf("unsupported type %s", s)
	}
}

func netJoin(ip string) string {
	if strings.Count(ip, ":") >= 2 {
		return "[" + ip + "]:0"
	}
	return ip + ":0"
}

func parsePeerIP(ip string) netip.Addr {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}
