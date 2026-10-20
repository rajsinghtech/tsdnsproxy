# tsdnsproxy

tsdnsproxy is a DNS server for a Tailscale network. It answers queries on a tailnet address, and optionally on a Tailscale Service, using ACL grants or a rules file.

It can:

- pick upstream DNS servers from the caller's grant
- rewrite a name before forwarding
- turn matching IPv4 answers into Tailscale 4via6 addresses
- answer dashed IPv4 names such as `10-0-0-1.site.example` without an upstream
- dial an upstream through the tailnet or the host network

This project is built by the Tailscale community. It is not an official Tailscale product.

## Query path

1. Read the client address. On a tailnet listener, whois identifies the node. A rules file does not need whois to authorize the query. Split DNS aimed at this node's tailnet address does not use port 53: MagicDNS sends DNS-over-HTTPS to the node's PeerAPI path `/dns-query`. That request is answered here, and the peer's tailnet address is the client address.
2. Load the rules file, when one is set, and the grants under `-cap-name`.
3. Use the longest matching domain. A CIDR key matches the resolved IPv4 address instead of the query name. An ACL grant replaces a file rule for the same key unless `-rules-only` is set.
4. Forward, rewrite, translate, or synthesize the answer.
5. Cache that answer. The key is the question name, type, class, the DO and CD bits, and a hash of the effective rules. Peers with the same rules share an entry. A rule that reads the client address, such as `allowsrc` or `a` set to `direct`, also includes that address.
6. On UDP, shrink the answer to the client buffer and set `TC` when it does not fit. The client should retry over TCP.

## Run

### Docker

```bash
docker run -d \
  --name tsdnsproxy \
  -e TS_AUTHKEY=tskey-auth-REPLACE-ME \
  -e TSDNSPROXY_HOSTNAME=tsdnsproxy \
  -e TSDNSPROXY_LISTEN_ADDRS=tailscale \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 8080:8080/tcp \
  ghcr.io/rajsinghtech/tsdnsproxy:latest
```

The image is distroless and runs as uid 65532. `TSDNSPROXY_STATE_DIR` defaults to `/tmp/tsdnsproxy` in the image. Mount a volume there if you are not using `TSDNSPROXY_STATE`.

Release tags have no leading `v` (`1.1.5`). That release also moves `latest`. Builds of the default branch are tagged `main` and `sha-<short commit>` and do not move `latest`.

### Kubernetes

`k8s/deployment.yaml` is one pod. `k8s/service-ha.yaml` is a StatefulSet of two pods behind one Tailscale Service. Apply one of them, not both. They share the Role name.

```bash
kubectl apply -k k8s/
```

The single-pod manifest creates the state Secret `tsdnsproxy-state` and grants get, update, and patch on that name, plus create on Events. The pod runs as uid 65532 with a read-only root filesystem, dropped capabilities except `NET_BIND_SERVICE`, and the runtime default seccomp profile. `/tmp` is an emptyDir.

Set `TS_AUTHKEY` in the `tsdnsproxy-auth` Secret before applying. The kustomization placeholder is `tskey-auth-REPLACE-ME`.

### Binary

```bash
go install github.com/rajsinghtech/tsdnsproxy/cmd/tsdnsproxy@latest
tsdnsproxy -auth-key tskey-auth-REPLACE-ME
```

## Configuration

Flags and environment variables. Durations use Go syntax (`10s`, `5m`).

| Flag | Environment | Default |
| --- | --- | --- |
| `-auth-key` | `TS_AUTHKEY` | required |
| `-hostname` | `TSDNSPROXY_HOSTNAME` | `tsdnsproxy` |
| `-state-dir` | `TSDNSPROXY_STATE_DIR` | `/var/lib/tsdnsproxy` |
| `-state` | `TSDNSPROXY_STATE` | empty |
| `-control-url` | `TS_CONTROLURL` | empty |
| `-advertise-tags` | `TSDNSPROXY_ADVERTISE_TAGS` | empty |
| `-listen-addrs` | `TSDNSPROXY_LISTEN_ADDRS` | `tailscale` |
| `-service` | `TSDNSPROXY_SERVICE` | empty |
| `-override-dns` | `TSDNSPROXY_OVERRIDE_DNS` | host resolvers |
| `-dial` | `TSDNSPROXY_DIAL` | `tailnet` |
| `-accept-routes` | `TSDNSPROXY_ACCEPT_ROUTES` | `false` |
| `-cap-name` | `TSDNSPROXY_CAP_NAME` | `rajsingh.info/cap/tsdnsproxy` |
| `-rules-file` | `TSDNSPROXY_RULES_FILE` | empty |
| `-rules-only` | `TSDNSPROXY_RULES_ONLY` | `false` |
| `-cache-ttl` | `TSDNSPROXY_CACHE_TTL` | `5m` |
| `-dns-cache` | `TSDNSPROXY_DNS_CACHE` | `true` |
| `-cache-size` | `TSDNSPROXY_CACHE_SIZE` | `4096` |
| `-cache-min-ttl` | `TSDNSPROXY_CACHE_MIN_TTL` | `5s` |
| `-cache-max-ttl` | `TSDNSPROXY_CACHE_MAX_TTL` | `1h` |
| `-ui-addr` | `TSDNSPROXY_UI_ADDR` | `:80` |
| `-ui-history` | `TSDNSPROXY_UI_HISTORY` | `1000` |
| `-ui-cap` | `TSDNSPROXY_UI_CAP` | empty |
| `-ui-audit-cap` | `TSDNSPROXY_UI_AUDIT_CAP` | empty |
| `-ui-trusted-proxy-tags` | `TSDNSPROXY_UI_TRUSTED_PROXY_TAGS` | empty |
| `-ui-user-header` | `TSDNSPROXY_UI_USER_HEADER` | `Tailscale-User-Login` |
| `-ui-name-header` | `TSDNSPROXY_UI_NAME_HEADER` | `Tailscale-User-Name` |
| `-ui-groups-header` | `TSDNSPROXY_UI_GROUPS_HEADER` | `X-Tailscale-Groups` |
| `-ui-groups` | `TSDNSPROXY_UI_GROUPS` | empty |
| `-ui-audit-groups` | `TSDNSPROXY_UI_AUDIT_GROUPS` | empty |
| `-http-addr` | `TSDNSPROXY_HTTP_ADDR` | `:8080` |
| `-log-level` | `TSDNSPROXY_LOG_LEVEL` | `info` |
| `-query-timeout` | `TSDNSPROXY_QUERY_TIMEOUT` | `10s` |
| `-max-inflight` | `TSDNSPROXY_MAX_INFLIGHT` | `100` |
| `-max-message-bytes` | `TSDNSPROXY_MAX_MESSAGE_BYTES` | `65535` |
| `-max-udp-bytes` | `TSDNSPROXY_MAX_UDP_BYTES` | `1232` |
| `-rate-limit` | `TSDNSPROXY_RATE_LIMIT` | `0` (off) |
| `-rate-burst` | `TSDNSPROXY_RATE_BURST` | `50` |

`-state kube:secret-name` stores node state in that Kubernetes Secret. `arn:` selects AWS SSM.

`-listen-addrs` accepts `tailscale`, `0.0.0.0`, `127.0.0.1`, `[::]`, or `host:port`. `svc:dns` and `service:dns` in that list also host a Tailscale Service. Prefer `-service` for that.

Listen addresses other than wildcard and loopback are bound with tsnet.

`$(VAR)` and `${VAR}` in `-hostname` and `-state` expand from the environment. Kubernetes expands `$(POD_NAME)` before the process starts. The process expands the same text if it is still present.

See `CHANGELOG.md` for renamed flags.

`-cache-ttl` is the whois and grant cache. The answer cache uses the flags below.

## Answer cache

DNS answers are cached by default, after rewrite and 4via6 translation. The lifetime is the smallest TTL in the answer and authority sections, clamped by `-cache-min-ttl` and `-cache-max-ttl`. NXDOMAIN and NODATA use the SOA minimum, as in RFC 2308. SERVFAIL is kept for 5 seconds and is not raised to the minimum TTL. Truncated responses are not stored. Each client receives its own message ID, and record TTLs count down from the time the answer was stored.

The cache key is the question name, type, class, the DO and CD bits, and a hash of the effective rules. Peers with the same rules share an entry. A rule that reads the client address, such as `allowsrc` or `a` set to `direct`, also includes that address.

`-cache-size` is the number of stored responses. `0` turns the cache off. `-dns-cache=false` or `TSDNSPROXY_DNS_CACHE=false` also turns it off. Identical questions that miss together share one upstream lookup.

## Status UI

`-ui-addr` serves a read-only site with `tsnet.Listen` on the tailnet. The default is `:80`. It is not the pod HTTP port (`-http-addr`). `-ui-addr=` or `TSDNSPROXY_UI_ADDR=-` turns the site off.

The pages are Overview, Rules, Peers, Queries, Access, Backends, and Lookup. Assets are embedded. There is no CDN. The JSON endpoints are `/api/config`, `/api/peers`, `/api/queries`, `/api/access`, and `/api/lookup`.

Any identified tailnet peer can open the site. Set `-ui-cap` to a capability name, for example `example.com/cap/dns/ui`, to require that capability on the viewer's node. Peers, Queries, and Access show user identities, so they can be restricted further with `-ui-audit-cap`, for example `example.com/cap/dns/audit`. When `-ui-audit-cap` is empty, those pages use the same rule as the rest of the site.

`-ui-trusted-proxy-tags` is a comma-separated list of node tags, for example `tag:proxy`. When the TCP peer has one of those tags, the site reads the viewer from forwarded headers instead of treating the proxy node as the user. The default headers are `Tailscale-User-Login`, `Tailscale-User-Name`, and `X-Tailscale-Groups`. The groups header is a comma-separated list. `-ui-user-header`, `-ui-name-header`, and `-ui-groups-header` rename them. A peer that does not have a trusted tag is a direct viewer: the headers are ignored, so a client cannot spoof a login or a group. A trusted proxy with no user header is rejected. The proxy node is not a viewer on its own.

`-ui-groups`, for example `dns-admins,dns-readers`, requires a proxied user to be in one of those groups. `-ui-audit-groups` does the same for Peers, Queries, and Access. When `-ui-audit-groups` is empty, those pages use `-ui-groups`. Names match exactly.

WhoIs does not include groups, so a direct viewer has none. A direct viewer passes a group check only when that page's capability is configured and the viewer holds it. If a group list is set and the capability for that page is empty, direct viewers are denied. A proxied user who is outside the group is denied even when the proxy node holds the capability. When a capability is also set, the connecting peer must hold it, and a proxied user must still match the group.

When `-ui-trusted-proxy-tags`, `-ui-groups`, and `-ui-audit-groups` are empty, `-ui-cap` and `-ui-audit-cap` behave as before.

Peers, Queries, and Access show the viewer. A proxied viewer is marked `via proxy`, and the process logs that login.

`-ui-history` is how many recent queries are kept in memory. `0` disables the log. The log records the peer, the question, the matched rule, the action, the rcode, and whether the answer cache hit. It does not record auth keys. Text matching `tskey-` is replaced with `tskey-redacted`.

Lookup shows the matching rule for a name, type, and peer address. It does not query an upstream server unless **Resolve upstream** is checked (`forward=1` on `/api/lookup`).

`TSDNSPROXY_IMAGE` is optional text shown as the image name. It is not a credential.

## Grants and rules

Grants are read from one capability. The default name is `rajsingh.info/cap/tsdnsproxy`. Set `-cap-name` to a domain and path such as `example.com/cap/dns` to read a different key. An `http://` or `https://` prefix is accepted. Other capability names are ignored.

A rules file is one JSON or HuJSON object with the same shape as a single grant value. HuJSON allows comments and trailing commas. It applies to every client.

```bash
tsdnsproxy -auth-key tskey-auth-REPLACE-ME -rules-file /etc/tsdnsproxy/rules.json
```

```json
{
  "example.internal": {
    "dns": ["10.0.0.53:53"],
    "translateid": 1,
    "allowips": ["10.0.0.0/8"]
  }
}
```

With that rule, `10.0.0.1` is translated with site id 1. An A query returns no A record. The AAAA answer is `fd7a:115c:a1e0:b1a:0:1:a00:1`.

Whois still runs, and the caller is logged at `debug`. If whois fails, the file rules are used anyway. An ACL grant wins for any domain or CIDR it defines. `-rules-only` ignores ACL grants and requires a rules file.

The file is checked at startup. A bad file exits the process. `SIGHUP`, or replacing the file, reloads it. A bad reload keeps the previous rules. Rename the file into place so a reader never sees a partial document.

`example-acl.json` is a full ACL sample using `example.com/cap/dns`, `alice@example.com`, and `example.internal`.

### Fields

- `dns`: upstream servers, tried in order. Each entry may be `10.0.0.53:53`, `tailnet://10.0.0.53:53`, or `direct://10.0.0.53:53`.
- `rewrite`: suffix to substitute before forwarding. `api.example.ts.net` with zone `example.ts.net` and rewrite `example.internal` becomes `api.example.internal`.
- `translateid`:
  - omitted or negative: forward the query and return the upstream answer
  - `0`: authoritative, addresses unchanged
  - `1` through `65535`: authoritative, translate IPv4 to 4via6 with that site id
  - above `65535`: the grant is rejected
- `allowips` and `denyips`: limit which IPv4 answers are translated. `denyips` wins. A non-empty `allowips` list translates only addresses inside it.
- `ipnames`: synthesize dashed IPv4 names. It cannot be combined with `rewrite` or `translateid`.
- `static`: answer the name from configured A and AAAA records. See below.

Domain rules match themselves and any name under them. The longest match wins. A `static` key matches only the name it writes, or one label under a wildcard. An exact static name beats a wildcard, and a longer name beats a shorter one. A key that is a CIDR matches the resolved address. The longest matching prefix overrides the domain rule for that address. A prefix rule with `translateid` omitted or `0` leaves the address unchanged.

Addresses in `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4`, `255.255.255.255/32`, and `100.64.0.0/10` are not translated unless `allowips` covers them. An excluded A answer is returned unchanged, and the AAAA answer is empty. The same filter drops A records from a `static` rule.

### Static records

A `static` rule answers from the config. The query is not forwarded.

```json
{
  "app.example.internal": {
    "static": {
      "a": ["192.0.2.10"],
      "aaaa": ["2001:db8::10"],
      "ttl": 60
    }
  },
  "*.apps.example.internal": {
    "static": { "a": ["192.0.2.20"], "ttl": 30 }
  }
}
```

- A literal key matches that name only. `app.example.internal` does not answer `foo.app.example.internal`.
- `*.apps.example.internal` matches one extra label, such as `foo.apps.example.internal`. It does not match `a.b.apps.example.internal`.
- The wildcard does not match the apex `apps.example.internal` unless `"apex": true` is set, or the apex has its own rule. An exact rule for the apex wins over `apex`.
- Names match without regard to case or a trailing dot.
- `a` and `aaaa` list addresses. At least one address is required. `ttl` defaults to 300 and must be from 1 through 86400.
- A and AAAA queries return the addresses of that family. MX, TXT, and any other type are NOERROR with no answers (NODATA) and a synthetic SOA. An A or AAAA query is also NODATA when that family is not configured. An A query is NODATA when `allowips` or `denyips` remove every A record.
- `allowsrc` on the static object, when set, refuses clients outside those prefixes before an answer is built. An empty list allows every client.
- `allowips` and `denyips` stay on the grant and filter A answers. `denyips` wins. AAAA answers ignore `allowips`. An AAAA address covered by `denyips` is omitted.
- `static` cannot be combined with `dns`, `rewrite`, `translateid`, or `ipnames`, and the key cannot be a CIDR. A wildcard key is valid only with `static`.
- A name that matches no rule is forwarded as usual.

`allowsrc`, `allowips`, and `denyips` on the winning rule still apply. A single-label wildcard beats a zone rule of the same parent for that one label. Extra labels under the wildcard still use the zone rule.

The synthetic SOA is owned by the exact name, or by the wildcard parent. Its minimum is the static TTL, so NODATA can be cached. Positive static answers use the answer cache. `allowsrc` puts the client address in the cache key. The Rules tab and Lookup show the static addresses. Lookup does not query upstream unless resolve is requested.

### Encoded names

`10-0-0-1.site.example` is answered from the zone config. The label is four decimal octets separated by dashes, with no leading zeros. Nothing is sent upstream.

```json
{
  "site.example": {
    "ipnames": { "siteid": 1, "a": "never", "ttl": 300 }
  },
  "ip": {
    "ipnames": { "siteid": 1, "a": "never", "allowips": ["10.0.0.0/8"] }
  }
}
```

A one-label zone such as `ip` is valid. Do not put `translateid` on the same object.

- `siteid` is required, from 0 through 65535.
- `a` is `never` (default), `always`, or `direct`. `direct` returns an A record only when the client is inside `directsrc`. AAAA is still returned.
- `ttl` defaults to 300. `negttl` defaults to 60 and is the SOA minimum on negative answers.
- `allowips` limits which addresses a label may encode. The built-in ranges above are rejected unless `allowips` covers them. A rejected or malformed name is NXDOMAIN.
- `allowsrc`, when set, refuses clients outside those prefixes.
- Other query types, and A when A is off, are NODATA. The zone apex answers SOA.

Publish one split-DNS suffix per zone, aimed at this proxy. Do not add these zones as search domains. `a` set to `always` can stall address selection, which is why `direct` exists. A shared resolver caches one client's answer for others, so keep `ttl` low when using `direct`.

Synthesized answers are not cached.

## Dialing

A bare address uses `-dial`. The default is `tailnet`, which dials with `tsnet.Server.Dial`. `direct` dials on the host network. A `tailnet://` or `direct://` prefix on one address wins. UDP is tried first. TCP is used when UDP fails or the UDP answer has `TC` set.

`tailnet://10.0.0.53` is port 53. An unknown scheme is rejected.

Subnet routes stay off for a bare address under the default. `RouteAll` is set only when `-accept-routes` is set, when `-dial tailnet` or `TSDNSPROXY_DIAL=tailnet` is set explicitly, or when a backend uses `tailnet://`. A grant or rules reload that adds `tailnet://` does that on the first dial.

## Tailscale Service

`-service svc:dns` hosts TCP port 53 on the service VIP. UDP 53 stays on the node's own tailnet address (`-listen-addrs tailscale`). Clients of `dns.example.ts.net` must send TCP. The service does not answer UDP. MagicDNS does not always retry a silent VIP over TCP: the OS split path does not, and the `100.100.100.100` forwarder only starts TCP after the UDP attempt fails or waits 2 seconds.

`svc:dns@5353` changes the TCP port. `service:dns` is accepted as `svc:dns`. The node must advertise a tag. Startup fails when `-service` is set and `-advertise-tags` is empty. PROXY protocol v2 is on, so whois still sees the client address.

Before the process can serve the name, define the Service with endpoint `tcp:53`, let `tag:tsdnsproxy` host it through `autoApprovers.services` (or approve the host in the admin console), and grant clients `dst` `svc:dns` port 53.

`k8s/service-ha.yaml` runs two replicas. Each pod has its own hostname and state Secret (`kube:tsdnsproxy-state-$(POD_NAME)`). The Role names `tsdnsproxy-state-tsdnsproxy-0` and `tsdnsproxy-state-tsdnsproxy-1`, which is why the manifest is a StatefulSet.

## HTTP

`-http-addr` serves:

- `/health`: 200 while the process should keep running, including during startup. 503 while stopping or after the DNS server fails. JSON includes `status`, `ready`, `listeners`, and tailnet state.
- `/ready`: 200 only when a DNS listener is bound and the tailnet backend is `Running`. Otherwise 503 and the body `not ready`.
- `/metrics`: Prometheus text. Counters cover queries, latency, upstream errors, translations, in-flight work, refusals, drops, and answer-cache hits, misses, and evictions.

Query logs use the fields `proto`, `remote`, `name`, `type`, `rcode`, `duration`, and `err` when there is an error. Success is `debug`. `SERVFAIL` and `REFUSED` are `warn`.

## Development

```bash
go test -race ./...
go test -fuzz=FuzzHandleQuery -fuzztime=10s ./internal/dns/
golangci-lint run
govulncheck ./...
```

Go 1.27. CI runs the race detector, a short fuzz pass, golangci-lint, and `govulncheck`.

```bash
docker build -t tsdnsproxy:dev .
```

## License

[MIT License](LICENSE)
