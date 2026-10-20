package ui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

//go:embed web/*
var web embed.FS

const (
	defaultUserHeader   = "Tailscale-User-Login"
	defaultNameHeader   = "Tailscale-User-Name"
	defaultGroupsHeader = "X-Tailscale-Groups"
	maxIdentityLen      = 256
	maxGroupsHeader     = 2048
	maxGroups           = 32
)

// Caller is the tailnet node at the TCP remote address.
// A nil Caller and a nil error means the address is not an identified peer.
type Caller struct {
	Caps  []string
	Tags  []string
	Node  string
	Login string
	Name  string
}

// WhoIs reports the tailnet node at an address.
type WhoIs func(ctx context.Context, ip string) (*Caller, error)

// LookupFunc answers a dry-run question. It must not contact an upstream
// unless req.Forward is true.
type LookupFunc func(ctx context.Context, req LookupRequest) (Lookup, error)

// Server is the tailnet status site.
type Server struct {
	Snapshot          func() Snapshot
	Peers             func() []Peer
	Lookup            LookupFunc
	History           *Ring
	WhoIs             WhoIs
	ViewCap           string
	AuditCap          string
	ViewGroups        []string
	AuditGroups       []string
	TrustedProxyTags  []string
	TrustedProxyCIDRs []netip.Prefix
	UserHeader        string
	NameHeader        string
	GroupsHeader      string
	// Logf records a proxied viewer. It may be nil.
	Logf func(format string, args ...any)
}

// Handler is the read-only site. It rejects every method except GET and HEAD.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /{$}", s.page)
	mux.HandleFunc("GET /assets/app.css", s.asset)
	mux.HandleFunc("GET /assets/app.js", s.asset)
	mux.HandleFunc("GET /api/config", s.config)
	mux.HandleFunc("GET /api/peers", s.peers)
	mux.HandleFunc("GET /api/queries", s.queries)
	mux.HandleFunc("GET /api/access", s.access)
	mux.HandleFunc("GET /api/lookup", s.lookup)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secureHeaders(w)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// Serve listens with listen and serves until ctx is canceled.
// listen is tsnet.Listen for the real process and net.Listen in tests.
func (s *Server) Serve(ctx context.Context, listen func() (net.Listener, error)) error {
	return s.serve(ctx, listen, false)
}

// ServeLocal serves the same site on a host listener.
// Connections that are not in TrustedProxyCIDRs are denied and are not
// identified with WhoIs.
func (s *Server) ServeLocal(ctx context.Context, listen func() (net.Listener, error)) error {
	return s.serve(ctx, listen, true)
}

func (s *Server) serve(ctx context.Context, listen func() (net.Listener, error), local bool) error {
	ln, err := listen()
	if err != nil {
		return err
	}
	handler := s.Handler()
	if local {
		base := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			base.ServeHTTP(w, r.WithContext(markLocal(r.Context())))
		})
	}
	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()
	err = httpSrv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.allow(w, r, false); !ok {
		return
	}
	serveFile(w, r, "web/index.html")
}

func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.allow(w, r, false); !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/assets/")
	if name != "app.css" && name != "app.js" {
		http.NotFound(w, r)
		return
	}
	serveFile(w, r, "web/"+name)
}

func (s *Server) config(w http.ResponseWriter, r *http.Request) {
	viewer, ok := s.allow(w, r, false)
	if !ok {
		return
	}
	snap := Snapshot{}
	if s.Snapshot != nil {
		snap = s.Snapshot()
	}
	snap.ViewCap = s.ViewCap
	snap.AuditCap = s.AuditCap
	snap.Viewer = viewer
	if s.History != nil {
		snap.HistoryLimit = s.History.Size()
		snap.HistoryEnabled = s.History.Size() > 0
	}
	writeJSON(w, snap)
}

func (s *Server) peers(w http.ResponseWriter, r *http.Request) {
	viewer, ok := s.allow(w, r, true)
	if !ok {
		return
	}
	list := []Peer{}
	if s.Peers != nil {
		list = s.Peers()
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, map[string]any{"peers": list, "viewer": viewer})
		return
	}
	var found *Peer
	for i := range list {
		if list[i].ID == id || list[i].Node == id || list[i].User == id {
			found = &list[i]
			break
		}
	}
	queries := []Query{}
	if s.History != nil && found != nil {
		key := found.Node
		if key == "" && len(found.IPs) > 0 {
			key = found.IPs[0]
		}
		queries = s.History.List(key, "", "", "")
	}
	writeJSON(w, map[string]any{"peer": found, "queries": queries, "viewer": viewer})
}

func (s *Server) queries(w http.ResponseWriter, r *http.Request) {
	viewer, ok := s.allow(w, r, true)
	if !ok {
		return
	}
	q := r.URL.Query()
	var list []Query
	if s.History != nil {
		list = s.History.List(q.Get("peer"), q.Get("user"), q.Get("domain"), q.Get("rcode"))
	}
	if list == nil {
		list = []Query{}
	}
	writeJSON(w, map[string]any{
		"enabled": s.History != nil && s.History.Size() > 0,
		"queries": list,
		"viewer":  viewer,
	})
}

func (s *Server) access(w http.ResponseWriter, r *http.Request) {
	viewer, ok := s.allow(w, r, true)
	if !ok {
		return
	}
	report := Access{}
	if s.History != nil {
		report = s.History.Access()
	}
	report.Viewer = viewer
	writeJSON(w, report)
}

func (s *Server) lookup(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.allow(w, r, false); !ok {
		return
	}
	if s.Lookup == nil {
		http.Error(w, "lookup is not available", http.StatusNotImplemented)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" || len(name) > 253 {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	qtype := strings.TrimSpace(r.URL.Query().Get("type"))
	if qtype == "" {
		qtype = "A"
	}
	if len(qtype) > 16 {
		http.Error(w, "type is too long", http.StatusBadRequest)
		return
	}
	peer := strings.TrimSpace(r.URL.Query().Get("peer"))
	if len(peer) > 128 {
		http.Error(w, "peer is too long", http.StatusBadRequest)
		return
	}
	forward := r.URL.Query().Get("forward") == "1" || strings.EqualFold(r.URL.Query().Get("forward"), "true")
	result, err := s.Lookup(r.Context(), LookupRequest{
		Name:    name,
		Type:    qtype,
		Peer:    peer,
		Forward: forward,
	})
	if err != nil && result.Error == "" {
		result.Error = Redact(err.Error())
	}
	writeJSON(w, result)
}

func (s *Server) allow(w http.ResponseWriter, r *http.Request, audit bool) (Viewer, bool) {
	viewer, err := s.authorize(r, audit)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return Viewer{}, false
	}
	return viewer, true
}

func (s *Server) authorize(r *http.Request, audit bool) (Viewer, error) {
	if s == nil {
		return Viewer{}, errors.New("no identity")
	}
	ip := remoteIP(r)
	if ip == "" {
		return Viewer{}, errors.New("no peer address")
	}
	if addr, ok := parseIP(ip); ok && prefixContains(s.TrustedProxyCIDRs, addr) {
		parsed, perr := s.forwardedViewer(r)
		parsed.ViaProxy = true
		if perr != nil {
			s.logProxy(parsed, false)
			return Viewer{}, perr
		}
		// A CIDR proxy is not a tailnet node, so capability checks do not apply.
		// Group lists still do. An empty group list allows the forwarded user.
		return s.finishAuth(parsed, nil, audit, true)
	}
	if isLocal(r.Context()) {
		return Viewer{}, errors.New("local listener outside trusted cidrs")
	}
	if s.WhoIs == nil {
		return Viewer{}, errors.New("no identity")
	}
	caller, err := s.WhoIs(r.Context(), ip)
	if err != nil || caller == nil {
		return Viewer{}, errors.New("not a tailnet peer")
	}
	trusted := hasAny(caller.Tags, s.TrustedProxyTags)
	var viewer Viewer
	if trusted {
		parsed, perr := s.forwardedViewer(r)
		parsed.Node = caller.Node
		parsed.ViaProxy = true
		if perr != nil {
			s.logProxy(parsed, false)
			return Viewer{}, perr
		}
		viewer = parsed
	} else {
		viewer = Viewer{Login: caller.Login, Name: caller.Name, Node: caller.Node}
	}
	return s.finishAuth(viewer, caller, audit, trusted)
}

func (s *Server) finishAuth(viewer Viewer, caller *Caller, audit, proxied bool) (Viewer, error) {
	capName := s.ViewCap
	if audit && s.AuditCap != "" {
		capName = s.AuditCap
	}
	if caller != nil && capName != "" && !hasCap(caller.Caps, capName) {
		if proxied {
			s.logProxy(viewer, false)
		}
		return Viewer{}, errors.New("missing capability")
	}
	groups := s.ViewGroups
	if audit && len(s.AuditGroups) > 0 {
		groups = s.AuditGroups
	}
	if len(groups) > 0 {
		if proxied {
			if !hasAny(viewer.Groups, groups) {
				s.logProxy(viewer, false)
				return Viewer{}, errors.New("missing group")
			}
		} else if capName == "" {
			// WhoIs has no groups. A direct viewer can pass only when a
			// capability is configured for this page and they hold it.
			return Viewer{}, errors.New("direct viewer has no groups")
		}
	}
	if !proxied && caller != nil && capName != "" && hasCap(caller.Caps, capName) {
		viewer.GrantedCap = capName
	}
	if proxied {
		s.logProxy(viewer, true)
	}
	return viewer, nil
}

func (s *Server) forwardedViewer(r *http.Request) (Viewer, error) {
	login, ok := headerValue(r, s.headerOr(s.UserHeader, defaultUserHeader), maxIdentityLen)
	if !ok {
		return Viewer{}, errors.New("bad user header")
	}
	if login == "" {
		return Viewer{}, errors.New("missing user header")
	}
	name, ok := headerValue(r, s.headerOr(s.NameHeader, defaultNameHeader), maxIdentityLen)
	if !ok {
		return Viewer{}, errors.New("bad name header")
	}
	groups, ok := groupsHeader(r, s.headerOr(s.GroupsHeader, defaultGroupsHeader))
	if !ok {
		return Viewer{}, errors.New("bad groups header")
	}
	return Viewer{Login: login, Name: name, Groups: groups, ViaProxy: true}, nil
}

func (s *Server) headerOr(name, fallback string) string {
	if strings.TrimSpace(name) != "" {
		return name
	}
	return fallback
}

func (s *Server) logProxy(v Viewer, allow bool) {
	if s == nil || s.Logf == nil {
		return
	}
	state := "denied"
	if allow {
		state = "allowed"
	}
	s.Logf("status ui viewer login=%s name=%s groups=%s via proxy %s", v.Login, v.Name, strings.Join(v.Groups, ","), state)
}

// headerValue reads one header. Missing is an empty string and true.
// A value with a line break or over max is false.
func headerValue(r *http.Request, name string, maxLen int) (string, bool) {
	if r == nil {
		return "", false
	}
	raw := r.Header.Get(name)
	if raw == "" {
		return "", true
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", true
	}
	if strings.ContainsAny(value, "\r\n") || len(value) > maxLen {
		return "", false
	}
	return value, true
}

func groupsHeader(r *http.Request, name string) ([]string, bool) {
	raw, ok := headerValue(r, name, maxGroupsHeader)
	if !ok {
		return nil, false
	}
	if raw == "" {
		return nil, true
	}
	var out []string
	seen := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		if strings.ContainsAny(item, "\r\n") || len(item) > maxIdentityLen {
			return nil, false
		}
		if _, ok := seen[item]; ok {
			continue
		}
		if len(out) >= maxGroups {
			return nil, false
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out, true
}

func hasCap(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

func hasAny(have, want []string) bool {
	if len(want) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(have))
	for _, item := range have {
		set[strings.TrimSpace(item)] = struct{}{}
	}
	for _, item := range want {
		if _, ok := set[strings.TrimSpace(item)]; ok {
			return true
		}
	}
	return false
}

type localKey struct{}

func markLocal(ctx context.Context) context.Context {
	return context.WithValue(ctx, localKey{}, true)
}

func isLocal(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(localKey{}).(bool)
	return v
}

func parseIP(host string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func prefixContains(prefixes []netip.Prefix, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func secureHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
}

func writeJSON(w http.ResponseWriter, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "encode failed", http.StatusInternalServerError)
		return
	}
	raw = []byte(Redact(string(raw)))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	_, _ = w.Write(raw)
}

func serveFile(w http.ResponseWriter, r *http.Request, name string) {
	data, err := fs.ReadFile(web, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	_, _ = w.Write(data) //nolint:gosec // embedded stylesheet, script, and page; not request data
}
