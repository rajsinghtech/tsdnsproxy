# Changelog

## Unreleased

### Added

- The overview Capability line is shown only when a capability granted that viewer access. Trusted-proxy viewers, and viewers with no matching capability, do not see it. The configured capability name is unchanged.
- The status UI can also listen on the host network. `-ui-local-addr` (`TSDNSPROXY_UI_LOCAL_ADDR`, default empty) is an address such as `0.0.0.0:8081`, served with `net.Listen`. `-ui-trusted-proxy-cidrs` (`TSDNSPROXY_UI_TRUSTED_PROXY_CIDRS`) lists prefixes such as `10.0.0.0/8`. A connection from one of those prefixes uses the forwarded identity headers and does not call WhoIs. A missing user header is rejected. Any other address on the local listener is rejected and is not treated as a tailnet peer. The local address requires the CIDR list. `GET /healthz` returns 200 with an empty body and does not require a viewer.

## 1.2.0 - 2026-10-20

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

- The status UI can sit behind a trusted identity-aware proxy. `-ui-trusted-proxy-tags` (`TSDNSPROXY_UI_TRUSTED_PROXY_TAGS`) lists node tags, for example `tag:proxy`. Only a peer with one of those tags may supply `Tailscale-User-Login`, `Tailscale-User-Name`, and `X-Tailscale-Groups`. The header names are `-ui-user-header`, `-ui-name-header`, and `-ui-groups-header`. Other peers are direct viewers and those headers are ignored. A trusted proxy with no user header is rejected. `-ui-groups` and `-ui-audit-groups` require the proxied user to be in one of those groups for the site and for Peers, Queries, and Access. A direct viewer has no groups in WhoIs, so a group check passes only when that page's capability is set and the viewer holds it. When the new flags are empty, `-ui-cap` and `-ui-audit-cap` are unchanged. Proxied viewers are shown as `via proxy`.
- Static records answer a name from the rule and do not query upstream. A key is an exact name, or a single-label wildcard such as `*.apps.example.internal`. The wildcard matches `foo.apps.example.internal` and does not match `a.b.apps.example.internal`. It does not match the apex unless `apex` is true or the apex has its own rule. Other query types, and A or AAAA when that family is not configured, are NOERROR with no answers and a synthetic SOA. `allowsrc` refuses other clients. `allowips` and `denyips` filter A answers, including the built-in blocked ranges. An exact name beats a wildcard, and a longer name beats a shorter one. Static answers use the answer cache. The Rules tab and Lookup show them.
- A read-only status site on the tailnet at `-ui-addr` (`TSDNSPROXY_UI_ADDR`, default `:80`). `-ui-addr=` or `TSDNSPROXY_UI_ADDR=-` disables it. The site shows rules, learned peers, recent queries, access counts, backends, caches, listeners, and a dry-run lookup. `-ui-history` (`TSDNSPROXY_UI_HISTORY`, default 1000) is the query log size. `0` disables the log. `-ui-cap` optionally requires a capability for every page. `-ui-audit-cap` optionally requires a capability for Peers, Queries, and Access. Any identified tailnet peer can open the site when those capabilities are empty. Auth keys are not shown, and `tskey-` text is redacted.
- DNS answers are cached by default after rewrite and 4via6 translation. `-dns-cache` (`TSDNSPROXY_DNS_CACHE`, default `true`) turns the cache on. `-cache-size` (`TSDNSPROXY_CACHE_SIZE`, default 4096) is the number of entries. `0` disables the cache. `-cache-min-ttl` defaults to `5s` and `-cache-max-ttl` defaults to `1h`. The key is the question plus a hash of the effective rules, so one peer's grant is not served to a peer with different rules. SERVFAIL is kept for 5 seconds. Truncated responses are not stored. The message ID is rewritten per query and TTLs count down. Metrics `tsdnsproxy_cache_hits_total`, `tsdnsproxy_cache_misses_total`, and `tsdnsproxy_cache_evictions_total` count cache use.
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
