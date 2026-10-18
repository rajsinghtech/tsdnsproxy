package dns

import (
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"tailscale.com/ipn/ipnlocal"

	_ "unsafe" // for go:linkname
)

// peerDNSPrefix is the PeerAPI path MagicDNS uses for a split-DNS nameserver
// that is this node's tailnet address. tailscale.com v1.104.1 handles that
// path inside peerAPIHandler.ServeHTTP, before any handler registered with
// RegisterPeerAPIHandler. The prefix map is the only check that runs first.
//
// A trailing-slash registration does not match /dns-query. HookReplyToDNSQueries
// only decides whether the built-in exit-node resolver may answer, and that
// resolver does not apply tsdnsproxy rules or the peer source address.
// Forwarding the query to the local port 53 listener would also hide the peer
// address. Leaving the peerapi-dns-proxy advertisement unset is not a tsnet API.
//
// The map is written once, from init, before any peer can connect.
//
//go:linkname peerAPIHandlerPrefixes tailscale.com/ipn/ipnlocal.peerAPIHandlerPrefixes
var peerAPIHandlerPrefixes map[string]func(ipnlocal.PeerAPIHandler, http.ResponseWriter, *http.Request)

const peerDNSPrefix = "/dns-query"

// activePeerServer is the proxy that answers PeerAPI DNS. It stays nil until
// UsePeerAPI, so an early query is refused instead of reaching the built-in resolver.
var activePeerServer atomic.Pointer[Server]

func init() {
	// Assign a key only. Replacing the map would drop handlers tailscale
	// registered, including the drive prefix.
	peerAPIHandlerPrefixes[peerDNSPrefix] = dispatchPeerDNS
}

func dispatchPeerDNS(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	s := activePeerServer.Load()
	if s == nil {
		http.Error(w, "dns proxy not ready", http.StatusServiceUnavailable)
		return
	}
	s.ServePeerDNS(h, w, r)
}

// UsePeerAPI publishes s as the handler for PeerAPI /dns-query.
// Call it before the node is available to peers.
func (s *Server) UsePeerAPI() {
	if s == nil {
		return
	}
	s.ensureRuntime()
	activePeerServer.Store(s)
}

// ServePeerDNS answers one DNS-over-HTTPS request from a tailnet peer.
// The peer's source address is the client address for whois and rules,
// the same value a query to port 53 would use.
func (s *Server) ServePeerDNS(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	if s == nil || s.currentClient() == nil || s.BackendMgr == nil || s.GrantParser == nil || s.WhoisCache == nil || s.GrantCache == nil {
		http.Error(w, "dns proxy not ready", http.StatusServiceUnavailable)
		return
	}
	s.ensureRuntime()
	query, publicErr := readDOH(r, s.maxMessage())
	if publicErr != "" {
		http.Error(w, publicErr, http.StatusBadRequest)
		return
	}
	addr, err := peerQueryAddr(h)
	if err != nil {
		http.Error(w, "missing peer address", http.StatusBadRequest)
		return
	}
	if !s.acquire() {
		if s.Logf != nil {
			s.Logf("dropping peerapi query from %s: worker pool full", addr)
		}
		http.Error(w, "dns proxy busy", http.StatusServiceUnavailable)
		return
	}
	defer s.release()

	pc := &replyConn{}
	s.handleQuery(r.Context(), pc, addr, query, "peerapi")
	if len(pc.reply) == 0 {
		http.Error(w, "invalid dns query", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", strconv.Itoa(len(pc.reply)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(pc.reply); err != nil && s.Logf != nil {
		s.Logf("peerapi write to %s: %v", addr, err)
	}
}

func peerQueryAddr(h ipnlocal.PeerAPIHandler) (net.Addr, error) {
	if h == nil {
		return nil, errMissingPeer
	}
	ap := h.RemoteAddr()
	if !ap.IsValid() || !ap.Addr().IsValid() {
		return nil, errMissingPeer
	}
	return net.TCPAddrFromAddrPort(ap), nil
}

var errMissingPeer = errors.New("missing peer address")

// readDOH reads an RFC 8484 DNS-over-HTTPS query.
// A non-empty string is a client error message.
func readDOH(r *http.Request, max int) ([]byte, string) {
	if r == nil {
		return nil, "bad request"
	}
	if max < 12 {
		max = 12
	}
	const hardMax = 256 << 10
	if max > hardMax {
		max = hardMax
	}
	switch r.Method {
	case http.MethodGet:
		q64 := r.URL.Query().Get("dns")
		if q64 == "" {
			return nil, "missing dns parameter"
		}
		if base64.RawURLEncoding.DecodedLen(len(q64)) > max {
			return nil, "query too large"
		}
		q, err := base64.RawURLEncoding.DecodeString(q64)
		if err != nil {
			return nil, "invalid dns base64"
		}
		if len(q) == 0 {
			return nil, "empty query"
		}
		if len(q) > max {
			return nil, "query too large"
		}
		return q, ""
	case http.MethodPost:
		if !dnsMessageType(r.Header.Get("Content-Type")) {
			return nil, "unexpected content type"
		}
		q, err := io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
		if err != nil {
			return nil, "error reading query"
		}
		if len(q) == 0 {
			return nil, "empty query"
		}
		if len(q) > max {
			return nil, "query too large"
		}
		return q, ""
	default:
		return nil, "bad method"
	}
}

func dnsMessageType(v string) bool {
	if v == "application/dns-message" {
		return true
	}
	mt, _, err := mime.ParseMediaType(v)
	return err == nil && mt == "application/dns-message"
}

// replyConn captures the DNS response handleQuery writes for a single query.
type replyConn struct {
	reply []byte
}

func (c *replyConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *replyConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.reply = append([]byte(nil), p...)
	return len(p), nil
}
func (c *replyConn) Close() error                     { return nil }
func (c *replyConn) LocalAddr() net.Addr              { return nil }
func (c *replyConn) SetDeadline(time.Time) error      { return nil }
func (c *replyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *replyConn) SetWriteDeadline(time.Time) error { return nil }
