package dns

import (
	"fmt"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// dnsHeaderSize is the fixed DNS header.
	dnsHeaderSize = 12
	// minUDPPayload is the size a client accepts when it sends no EDNS OPT.
	minUDPPayload = 512
	// defaultMaxUDP is the largest UDP response we will send unless configured.
	// 1232 stays under typical internet MTU once IP and UDP headers are counted.
	defaultMaxUDP = 1232
)

// clientUDPLimit is how many bytes the client can accept.
// capSize is the server ceiling. Zero means defaultMaxUDP.
func clientUDPLimit(query *dnsmessage.Message, capSize int) int {
	limit := minUDPPayload
	if query != nil {
		for _, extra := range query.Additionals {
			if extra.Header.Type != dnsmessage.TypeOPT {
				continue
			}
			if sz := int(extra.Header.Class); sz > limit {
				limit = sz
			}
		}
	}
	ceiling := capSize
	if ceiling <= 0 {
		ceiling = defaultMaxUDP
	}
	if limit > ceiling {
		limit = ceiling
	}
	if limit < minUDPPayload {
		limit = minUDPPayload
	}
	return limit
}

// fitUDP returns a response that fits the client UDP buffer.
// Oversized messages are replaced with a truncated reply so the client retries over TCP.
func fitUDP(query *dnsmessage.Message, raw []byte, capSize int) ([]byte, error) {
	limit := clientUDPLimit(query, capSize)
	if len(raw) <= limit {
		return raw, nil
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(raw); err != nil {
		return truncated(query, limit)
	}
	resp.Response = true
	resp.Truncated = true
	resp.Answers = nil
	resp.Authorities = nil
	resp.Additionals = optFor(query, limit)
	packed, err := resp.Pack()
	if err != nil || len(packed) > limit {
		return truncated(query, limit)
	}
	return packed, nil
}

func truncated(query *dnsmessage.Message, limit int) ([]byte, error) {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:  true,
			Truncated: true,
			RCode:     dnsmessage.RCodeSuccess,
		},
	}
	if query != nil {
		msg.ID = query.ID
		msg.OpCode = query.OpCode
		msg.RecursionDesired = query.RecursionDesired
		msg.Questions = query.Questions
	}
	msg.Additionals = optFor(query, limit)
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack truncated response: %w", err)
	}
	if len(packed) <= limit {
		return packed, nil
	}
	msg.Questions = nil
	msg.Additionals = nil
	packed, err = msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack truncated header: %w", err)
	}
	return packed, nil
}

func optFor(query *dnsmessage.Message, limit int) []dnsmessage.Resource {
	if query == nil || !hasOPT(query) {
		return nil
	}
	return []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("."),
			Type:  dnsmessage.TypeOPT,
			Class: dnsmessage.Class(limit),
		},
		Body: &dnsmessage.OPTResource{},
	}}
}

func hasOPT(query *dnsmessage.Message) bool {
	for _, extra := range query.Additionals {
		if extra.Header.Type == dnsmessage.TypeOPT {
			return true
		}
	}
	return false
}

// messageTruncated reports the TC bit. A short buffer is treated as truncated.
func messageTruncated(raw []byte) bool {
	if len(raw) < dnsHeaderSize {
		return true
	}
	return raw[2]&0x02 != 0
}
