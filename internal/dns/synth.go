package dns

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rajsinghtech/tsdnsproxy/internal/grants"
	"github.com/rajsinghtech/tsdnsproxy/internal/ipnames"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/net/tsaddr"
)

const (
	ipRelApex = iota
	ipRelOne
	ipRelOther
)

// via6For builds the translated IPv6 address for an IPv4 site address.
func via6For(siteID uint32, ip4 netip.Addr) (netip.Addr, error) {
	if !ip4.Is4() {
		return netip.Addr{}, fmt.Errorf("want ipv4 address")
	}
	via, err := tsaddr.MapVia(siteID, netip.PrefixFrom(ip4, 32))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("map site %d address %s: %w", siteID, ip4, err)
	}
	return via.Addr(), nil
}

func (s *Server) handleIPNames(query *dnsmessage.Message, zone string, grant *grants.DNSGrant, src netip.Addr) ([]byte, error) {
	cfg := grant.IPNames
	if cfg == nil {
		return nil, fmt.Errorf("missing encoded-name config")
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

	qname := grants.NormalizeDomain(question.Name.String())
	zone = grants.NormalizeDomain(zone)
	label, rel := ipNamesRelation(qname, zone)
	soa, err := soaResource(zone, cfg)
	if err != nil {
		return nil, err
	}
	switch rel {
	case ipRelApex:
		if question.Type == dnsmessage.TypeSOA {
			return ipNamesStatus(query, dnsmessage.RCodeSuccess, []dnsmessage.Resource{
				soaRecord(question.Name, cfg.AnswerTTL(), soa),
			}, nil)
		}
		return ipNamesStatus(query, dnsmessage.RCodeSuccess, nil, []dnsmessage.Resource{
			soaRecord(mustZoneName(zone), cfg.NegativeTTL(), soa),
		})
	case ipRelOne:
		ip, perr := ipnames.ParseDashedIPv4(label)
		if perr != nil || !cfg.EncodedAllowed(ip) {
			return ipNamesStatus(query, dnsmessage.RCodeNameError, nil, []dnsmessage.Resource{
				soaRecord(mustZoneName(zone), cfg.NegativeTTL(), soa),
			})
		}
		switch question.Type {
		case dnsmessage.TypeAAAA:
			site, serr := cfg.SiteIDValue()
			if serr != nil {
				return nil, serr
			}
			via, verr := via6For(uint32(site), ip)
			if verr != nil {
				return nil, verr
			}
			return ipNamesStatus(query, dnsmessage.RCodeSuccess, []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name: question.Name, Type: dnsmessage.TypeAAAA, Class: question.Class, TTL: cfg.AnswerTTL(),
				},
				Body: &dnsmessage.AAAAResource{AAAA: via.As16()},
			}}, nil)
		case dnsmessage.TypeA:
			if !cfg.AAllowed(src) {
				return ipNamesStatus(query, dnsmessage.RCodeSuccess, nil, []dnsmessage.Resource{
					soaRecord(mustZoneName(zone), cfg.NegativeTTL(), soa),
				})
			}
			return ipNamesStatus(query, dnsmessage.RCodeSuccess, []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name: question.Name, Type: dnsmessage.TypeA, Class: question.Class, TTL: cfg.AnswerTTL(),
				},
				Body: &dnsmessage.AResource{A: ip.As4()},
			}}, nil)
		default:
			return ipNamesStatus(query, dnsmessage.RCodeSuccess, nil, []dnsmessage.Resource{
				soaRecord(mustZoneName(zone), cfg.NegativeTTL(), soa),
			})
		}
	default:
		return ipNamesStatus(query, dnsmessage.RCodeNameError, nil, []dnsmessage.Resource{
			soaRecord(mustZoneName(zone), cfg.NegativeTTL(), soa),
		})
	}
}

func ipNamesRelation(qname, zone string) (string, int) {
	if qname == zone {
		return "", ipRelApex
	}
	suffix := "." + zone
	if !strings.HasSuffix(qname, suffix) {
		return "", ipRelOther
	}
	rest := strings.TrimSuffix(qname, suffix)
	if rest == "" || strings.Contains(rest, ".") {
		return rest, ipRelOther
	}
	return rest, ipRelOne
}

func soaResource(zone string, cfg *grants.IPNamesConfig) (dnsmessage.SOAResource, error) {
	z := grants.NormalizeDomain(zone) + "."
	ns, err := dnsmessage.NewName("ns." + z)
	if err != nil {
		return dnsmessage.SOAResource{}, err
	}
	mbox, err := dnsmessage.NewName("hostmaster." + z)
	if err != nil {
		return dnsmessage.SOAResource{}, err
	}
	return dnsmessage.SOAResource{
		NS:      ns,
		MBox:    mbox,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		MinTTL:  cfg.NegativeTTL(),
	}, nil
}

func mustZoneName(zone string) dnsmessage.Name {
	name, err := dnsmessage.NewName(grants.NormalizeDomain(zone) + ".")
	if err != nil {
		return dnsmessage.Name{}
	}
	return name
}

func soaRecord(name dnsmessage.Name, ttl uint32, soa dnsmessage.SOAResource) dnsmessage.Resource {
	body := soa
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: name, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: ttl,
		},
		Body: &body,
	}
}

func ipNamesStatus(query *dnsmessage.Message, rcode dnsmessage.RCode, answers, authorities []dnsmessage.Resource) ([]byte, error) {
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.ID,
			Response:           true,
			OpCode:             query.OpCode,
			Authoritative:      true,
			RecursionDesired:   query.RecursionDesired,
			RecursionAvailable: false,
			RCode:              rcode,
		},
		Questions:   query.Questions,
		Answers:     answers,
		Authorities: authorities,
	}
	return resp.Pack()
}
