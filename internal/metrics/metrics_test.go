package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsHandler(t *testing.T) {
	m := New()
	m.Query("udp", "A", "NOERROR", 5*time.Millisecond)
	m.UpstreamError("10.0.0.53:53")
	m.Translation()
	m.Inflight(1)
	m.Refused()
	m.Dropped()
	rr := httptest.NewRecorder()
	m.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(rr.Body)
	text := string(body)
	for _, want := range []string{
		"tsdnsproxy_queries_total",
		"tsdnsproxy_query_duration_seconds",
		"tsdnsproxy_upstream_errors_total",
		"tsdnsproxy_translations_total",
		"tsdnsproxy_inflight",
		"tsdnsproxy_refused_total",
		"tsdnsproxy_dropped_total",
		`qtype="A"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s\n%s", want, text)
		}
	}
}

func TestNilMetrics(t *testing.T) {
	var m *Metrics
	m.Query("udp", "", "", time.Second)
	m.UpstreamError("x")
	m.Translation()
	m.Inflight(1)
	m.Refused()
	m.Dropped()
	if m.Handler() == nil {
		t.Fatal("nil handler")
	}
}
