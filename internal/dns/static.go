package dns

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"golang.org/x/net/dns/dnsmessage"
)

func (s *Server) handleStatic(query *dnsmessage.Message, pattern string, grant *grants.DNSGrant, src netip.Addr) ([]byte, error) {
	cfg := grant.Static
	if cfg == nil {
		return nil, fmt.Errorf("missing static config")
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
	if !cfg.SourceAllowed(src) {
		return ipNamesStatus(query, dnsmessage.RCodeRefused, nil, nil)
	}

	policy, err := grant.IPPolicy()
	if err != nil {
		return nil, err
	}
	var answers []dnsmessage.Resource
	switch question.Type {
	case dnsmessage.TypeA:
		for _, ip := range cfg.ARecords(policy) {
			answers = append(answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name: question.Name, Type: dnsmessage.TypeA, Class: question.Class, TTL: cfg.AnswerTTL(),
				},
				Body: &dnsmessage.AResource{A: ip.As4()},
			})
		}
	case dnsmessage.TypeAAAA:
		for _, ip := range cfg.AAAARecords(policy.Deny) {
			answers = append(answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name: question.Name, Type: dnsmessage.TypeAAAA, Class: question.Class, TTL: cfg.AnswerTTL(),
				},
				Body: &dnsmessage.AAAAResource{AAAA: ip.As16()},
			})
		}
	}
	if len(answers) > 0 {
		if s != nil && s.Logf != nil {
			s.Logf("[v] static %s %s (%d)", question.Name, question.Type, len(answers))
		}
		return ipNamesStatus(query, dnsmessage.RCodeSuccess, answers, nil)
	}
	return staticNODATA(query, staticZone(pattern), cfg.AnswerTTL())
}

func staticZone(pattern string) string {
	pattern = grants.NormalizeDomain(pattern)
	if parent, ok := strings.CutPrefix(pattern, "*."); ok && parent != "" {
		return parent
	}
	return pattern
}

func staticNODATA(query *dnsmessage.Message, zone string, ttl uint32) ([]byte, error) {
	var auth []dnsmessage.Resource
	if soa, name, err := staticSOA(zone, ttl); err == nil {
		auth = []dnsmessage.Resource{soaRecord(name, ttl, soa)}
	}
	return ipNamesStatus(query, dnsmessage.RCodeSuccess, nil, auth)
}

func staticSOA(zone string, ttl uint32) (dnsmessage.SOAResource, dnsmessage.Name, error) {
	owner, err := dnsmessage.NewName(grants.NormalizeDomain(zone) + ".")
	if err != nil {
		return dnsmessage.SOAResource{}, dnsmessage.Name{}, err
	}
	z := owner.String()
	ns, err := dnsmessage.NewName("ns." + z)
	if err != nil {
		return dnsmessage.SOAResource{}, dnsmessage.Name{}, err
	}
	mbox, err := dnsmessage.NewName("hostmaster." + z)
	if err != nil {
		return dnsmessage.SOAResource{}, dnsmessage.Name{}, err
	}
	return dnsmessage.SOAResource{
		NS:      ns,
		MBox:    mbox,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		MinTTL:  ttl,
	}, owner, nil
}
