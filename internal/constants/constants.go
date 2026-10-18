package constants

import "time"

// DNS protocol constants
const (
	DNSMinMessageSize = 12 // DNS header size
	DNSMaxMessageSize = 65535
	DNSDefaultPort    = 53
)

// Server configuration
const (
	WorkerPoolSize         = 100
	QueryTimeout           = 10 * time.Second
	TCPConnectionTimeout   = 10 * time.Second
	UDPReadTimeout         = 100 * time.Millisecond
	HandlerShutdownTimeout = 5 * time.Second
)

// Startup and retry configuration
const (
	StartupMaxRetries     = 5
	TailnetMaxRetries     = 30
	TailnetRetryDelay     = time.Second
	DefaultCacheExpiry    = 5 * time.Minute
	HealthShutdownTimeout = 5 * time.Second
	// DefaultAnswerCacheSize is the number of DNS responses kept in memory.
	DefaultAnswerCacheSize = 4096
	// DefaultAnswerMinTTL is the shortest time a cached response is kept.
	DefaultAnswerMinTTL = 5 * time.Second
	// DefaultAnswerMaxTTL is the longest time a cached response is kept.
	DefaultAnswerMaxTTL = time.Hour
	// ServfailAnswerTTL is how long a server failure is remembered.
	ServfailAnswerTTL = 5 * time.Second
)

// Backend configuration
const (
	BackendMaxBackoffSeconds = 300
	BackendCleanupInterval   = 10 * time.Second
)
