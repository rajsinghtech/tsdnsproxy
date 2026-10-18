# Changelog

## Unreleased

### Breaking

- `-authkey` is now `-auth-key`. `TS_AUTHKEY` is unchanged.
- `-statedir` is now `-state-dir`. `TSDNSPROXY_STATE_DIR` is unchanged.
- `-controlurl` is now `-control-url`. `TS_CONTROLURL` is unchanged.
- `-cache-expiry` is now `-cache-ttl`. The environment variable is `TSDNSPROXY_CACHE_TTL` (a Go duration, default `5m`). The TTL must be greater than zero.
- `-verbose` and `TSDNSPROXY_VERBOSE` are gone. Use `-log-level` or `TSDNSPROXY_LOG_LEVEL`: `debug`, `info`, `warn`, or `error`. The default is `info`. `debug` is the old verbose mode.
- `-health-addr` and `TSDNSPROXY_HEALTH_ADDR` are gone. Use `-http-addr` or `TSDNSPROXY_HTTP_ADDR` (default `:8080`). That listener also serves `/metrics`.
- Upstream DNS tries UDP first. TCP is used when UDP fails or the UDP answer is truncated. Older builds always tried TCP first.
- A UDP answer that does not fit the client buffer is replaced with a truncated reply (`TC`). The buffer is 512 bytes when the query has no EDNS OPT, otherwise the advertised size, and never more than `-max-udp-bytes` (default 1232).
- `/health` returns 503 while the process is stopping or after the DNS server fails. It returns 200 during startup, before listeners bind. The JSON body includes `ready`, `listeners`, and tailnet state.
- `/ready` returns 200 only when at least one DNS listener is bound and the tailnet backend state is `Running`.
- A query must contain exactly one question. Names are limited to letters, digits, hyphen, and underscore.
- `-rate-limit` (`TSDNSPROXY_RATE_LIMIT`, queries per second per client, default `0` meaning off) refuses excess queries. `-rate-burst` defaults to 50.
- `-max-message-bytes` (`TSDNSPROXY_MAX_MESSAGE_BYTES`, default 65535) drops larger queries. `-max-inflight` defaults to 100. A TCP connection handles at most 128 queries and then closes.
- Logs are JSON. Text matching `tskey-` is replaced with `tskey-redacted`. Per-query lines are `debug`. Failures are `warn`.
- The container is distroless and runs as nonroot (uid 65532). `TSDNSPROXY_STATE_DIR` in the image is `/tmp/tsdnsproxy`.
- The Kubernetes examples run as uid 65532 with a read-only root filesystem and the runtime default seccomp profile. They no longer grant `create` on every Secret. The state Secret is declared in the manifest. The single-pod example sets `TSDNSPROXY_CAP_NAME=example.com/cap/dns` and hosts `svc:dns`.

### Added

- Prometheus metrics on `/metrics`: queries, latency, upstream errors, translations, in-flight queries, refusals, and drops.
- `-query-timeout` (`TSDNSPROXY_QUERY_TIMEOUT`, default `10s`) bounds one client query, including the upstream dial.
- `SIGHUP` reload, listener shutdown, and cache cleanup wait on context instead of sleeping through a stop.
- Fuzz targets for query handling and rules parsing. CI runs golangci-lint, `govulncheck`, the race detector, and a short fuzz pass.

### Fixed

- Split DNS pointed at this node's tailnet address is answered by tsdnsproxy. MagicDNS sends those queries to PeerAPI `/dns-query`, which tsnet previously resolved itself. They now use the same handler, rules, and source-address identity as port 53.
- Upstream dials use the query context. A dial that ignores cancellation is abandoned when the deadline passes, and a late connection is closed.
- Authoritative lookups use the query context instead of `context.Background`.
- IPv6 nameservers in `/etc/resolv.conf` are joined with a port correctly.
- A down upstream can no longer overflow the health backoff shift.
- Cache loads for one key share one call. A panicking load does not leave later lookups waiting. Closing a cache twice is safe.
- `Current` on a rules file returns a copy.
- Tailscale Service accept loops close the listener when the process is canceled, so shutdown does not wait for another connection.
- Server grants used for non-tailnet clients are refreshed on the cache TTL.
