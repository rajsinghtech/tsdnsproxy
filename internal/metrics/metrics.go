// Package metrics records DNS proxy counters and latency.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics is a private Prometheus registry for one process.
type Metrics struct {
	reg          *prometheus.Registry
	queries      *prometheus.CounterVec
	latency      *prometheus.HistogramVec
	upstreamErrs *prometheus.CounterVec
	translations prometheus.Counter
	inflight     prometheus.Gauge
	refused      prometheus.Counter
	dropped      prometheus.Counter
	cacheHits    prometheus.Counter
	cacheMisses  prometheus.Counter
	cacheEvicts  prometheus.Counter
}

// New registers the proxy metrics.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		queries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tsdnsproxy_queries_total",
			Help: "DNS queries by protocol, type, and result.",
		}, []string{"proto", "qtype", "rcode"}),
		latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tsdnsproxy_query_duration_seconds",
			Help:    "Time to answer a DNS query.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"proto"}),
		upstreamErrs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tsdnsproxy_upstream_errors_total",
			Help: "Failed queries to an upstream DNS server.",
		}, []string{"upstream"}),
		translations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tsdnsproxy_translations_total",
			Help: "Answers rewritten to a 4via6 address or an encoded-name AAAA.",
		}),
		inflight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tsdnsproxy_inflight",
			Help: "Queries being handled.",
		}),
		refused: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tsdnsproxy_refused_total",
			Help: "Queries refused by the rate limit.",
		}),
		dropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tsdnsproxy_dropped_total",
			Help: "Queries dropped because the worker pool was full.",
		}),
		cacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tsdnsproxy_cache_hits_total",
			Help: "DNS answers served from the response cache.",
		}),
		cacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tsdnsproxy_cache_misses_total",
			Help: "DNS answers that were not in the response cache.",
		}),
		cacheEvicts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tsdnsproxy_cache_evictions_total",
			Help: "DNS answers removed to stay within the cache size.",
		}),
	}
	reg.MustRegister(m.queries, m.latency, m.upstreamErrs, m.translations, m.inflight, m.refused, m.dropped, m.cacheHits, m.cacheMisses, m.cacheEvicts)
	return m
}

// Handler serves the registry in Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Query records one answered or rejected query.
func (m *Metrics) Query(proto, qtype, rcode string, d time.Duration) {
	if m == nil {
		return
	}
	if qtype == "" {
		qtype = "none"
	}
	if rcode == "" {
		rcode = "none"
	}
	m.queries.WithLabelValues(proto, qtype, rcode).Inc()
	m.latency.WithLabelValues(proto).Observe(d.Seconds())
}

// UpstreamError records one failed upstream exchange.
func (m *Metrics) UpstreamError(upstream string) {
	if m == nil || upstream == "" {
		return
	}
	m.upstreamErrs.WithLabelValues(upstream).Inc()
}

// Translation records one synthesized or translated address.
func (m *Metrics) Translation() {
	if m == nil {
		return
	}
	m.translations.Inc()
}

// Inflight adds delta to the in-flight gauge. delta is 1 or -1.
func (m *Metrics) Inflight(delta int) {
	if m == nil {
		return
	}
	m.inflight.Add(float64(delta))
}

// Refused records one rate-limited query.
func (m *Metrics) Refused() {
	if m == nil {
		return
	}
	m.refused.Inc()
}

// Dropped records one query that found the worker pool full.
func (m *Metrics) Dropped() {
	if m == nil {
		return
	}
	m.dropped.Inc()
}

// CacheHit records one answer served from the response cache.
func (m *Metrics) CacheHit() {
	if m == nil {
		return
	}
	m.cacheHits.Inc()
}

// CacheMiss records one answer that was not already cached.
func (m *Metrics) CacheMiss() {
	if m == nil {
		return
	}
	m.cacheMisses.Inc()
}

// CacheEviction records one answer dropped to stay within the cache size.
func (m *Metrics) CacheEviction(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.cacheEvicts.Add(float64(n))
}
