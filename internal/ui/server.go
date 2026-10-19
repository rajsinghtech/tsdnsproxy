package ui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed web/*
var web embed.FS

// WhoIs reports the capability names granted to a tailnet address.
// A nil slice and a nil error means the address is not an identified peer.
type WhoIs func(ctx context.Context, ip string) (caps []string, err error)

// LookupFunc answers a dry-run question. It must not contact an upstream
// unless req.Forward is true.
type LookupFunc func(ctx context.Context, req LookupRequest) (Lookup, error)

// Server is the tailnet status site.
type Server struct {
	Snapshot func() Snapshot
	Peers    func() []Peer
	Lookup   LookupFunc
	History  *Ring
	WhoIs    WhoIs
	ViewCap  string
	AuditCap string
}

// Handler is the read-only site. It rejects every method except GET and HEAD.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
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
	ln, err := listen()
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Handler:           s.Handler(),
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

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, false) {
		return
	}
	serveFile(w, r, "web/index.html")
}

func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, false) {
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
	if !s.allow(w, r, false) {
		return
	}
	snap := Snapshot{}
	if s.Snapshot != nil {
		snap = s.Snapshot()
	}
	snap.ViewCap = s.ViewCap
	snap.AuditCap = s.AuditCap
	if s.History != nil {
		snap.HistoryLimit = s.History.Size()
		snap.HistoryEnabled = s.History.Size() > 0
	}
	writeJSON(w, snap)
}

func (s *Server) peers(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, true) {
		return
	}
	list := []Peer{}
	if s.Peers != nil {
		list = s.Peers()
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSON(w, map[string]any{"peers": list})
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
	writeJSON(w, map[string]any{"peer": found, "queries": queries})
}

func (s *Server) queries(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, true) {
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
	})
}

func (s *Server) access(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, true) {
		return
	}
	report := Access{}
	if s.History != nil {
		report = s.History.Access()
	}
	writeJSON(w, report)
}

func (s *Server) lookup(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, false) {
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

func (s *Server) allow(w http.ResponseWriter, r *http.Request, audit bool) bool {
	if err := s.authorize(r, audit); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) authorize(r *http.Request, audit bool) error {
	if s == nil || s.WhoIs == nil {
		return errors.New("no identity")
	}
	ip := remoteIP(r)
	if ip == "" {
		return errors.New("no peer address")
	}
	caps, err := s.WhoIs(r.Context(), ip)
	if err != nil || caps == nil {
		return errors.New("not a tailnet peer")
	}
	if s.ViewCap != "" && !hasCap(caps, s.ViewCap) {
		return errors.New("missing view capability")
	}
	if audit && s.AuditCap != "" && !hasCap(caps, s.AuditCap) {
		return errors.New("missing audit capability")
	}
	return nil
}

func hasCap(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
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
