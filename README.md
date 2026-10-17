# tsdnsproxy

A DNS proxy server for Tailscale networks that enables per-identity DNS routing, domain rewriting, and 4via6 translation based on ACL grants.

## Features

- **Per-identity DNS routing**: Route DNS requests to different backend servers based on the requesting node's identity
- **Domain rewriting**: Transparently rewrite domains (e.g., `cluster1.local` → `cluster.local`) before forwarding
- **4via6 translation**: Convert IPv4 addresses to Tailscale's 4via6 IPv6 addresses using site IDs
- **Backend failover**: Automatic failover between multiple DNS backends with health checking
- **Kubernetes support**: Native state storage in Kubernetes Secrets
- **Grant-based configuration**: Configure behavior through Tailscale ACL grants
- **Rules file**: Apply the same DNS rules to every client from a JSON or HuJSON file, without ACL grants

## How It Works

tsdnsproxy runs as a tsnet application on your tailnet, listening on configurable addresses (default: Tailscale IP port 53). When it receives DNS requests:

1. Identifies the requesting node using LocalAPI whois and logs the caller
2. Loads rules from the rules file, when one is configured, and DNS grants from the configured capability on the node
3. Matches the query domain against those rules. An ACL grant wins for a domain it defines unless rules-only is set
4. Applies configured transformations (rewrite, backend selection)
5. Forwards the query to the appropriate backend
6. Optionally translates IPv4 responses to 4via6 IPv6 addresses
7. Returns the response to the client

## ACL Grant Configuration

Configure DNS behavior through Tailscale ACL grants. The capability name defaults to `rajsingh.info/cap/tsdnsproxy`. Set `-cap-name` or `TSDNSPROXY_CAP_NAME` to read a different name, for example `example.com/cap/dns`. Grants under any other name are ignored.

- **dns**: Backend DNS servers to forward queries to (with failover)
- **rewrite**: optional - Rewrite domain before forwarding (e.g., `api.cluster1.local` → `api.cluster.local`)
- **translateid**: optional - Controls DNS handling mode:
  - **Omit or < 0**: Standard forwarding mode (forwards queries to backends, returns responses as-is)
  - **0**: Authoritative mode without 4via6 translation (resolves from backends, returns A/AAAA records directly). This must be explicit; omitting the field does not select it
  - **1–65535**: Authoritative mode with 4via6 translation (converts A records to AAAA using site ID)
  - **Above 65535**: Invalid. The grant is ignored and a warning is logged

```json
{
  "grants": [
    {
      "src": ["user@example.com", "group:engineering"],
      "dst": ["tag:tsdnsproxy"],
      "app": {
        "rajsingh.info/cap/tsdnsproxy": [
          {
            "cluster1.local": {
              "dns": ["10.1.0.10:53", "10.1.0.11:53"],
              "rewrite": "cluster.local",
              "translateid": 1
            },
            "cluster2.local": {
              "dns": ["10.2.0.10:53"],
              "translateid": -1
            }
          }
        ]
      }
    }
  ]
}
```

## Rules file

ACL grants are per identity. A rules file applies one set of rules to every client, so the proxy can run without grant capabilities.

`-rules-file` (`TSDNSPROXY_RULES_FILE`) points at a JSON or HuJSON file. HuJSON is JSON with comments and trailing commas. The file has the same shape as one grant value: a map of domain to `dns`, `rewrite`, `translateid`, `allowips`, `denyips`, and `ipnames`.

```bash
tsdnsproxy -authkey tskey-auth-YOUR-KEY -rules-file /etc/tsdnsproxy/rules.json
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

With that rule, an address `10.0.0.1` is translated with site id 1. An A query returns no A record. The AAAA answer is `fd7a:115c:a1e0:b1a:0:1:a00:1`.

An encoded-name zone in the same file needs no backend. The site id is `ipnames.siteid`. Do not also set `translateid` on that object. A one-label zone such as `ip` answers `10-1-2-3.ip`.

```json
{
  "ip": {
    "ipnames": {
      "siteid": 1,
      "a": "never",
      "allowips": ["10.0.0.0/8"]
    }
  }
}
```

`10-1-2-3.ip` AAAA is the 4via6 address for `10.1.2.3` at site id 1, `fd7a:115c:a1e0:b1a:0:1:a01:203`. An address outside `allowips`, or a malformed label, is NXDOMAIN. With `a` set to `never`, an A query is NODATA. `always` returns the IPv4 address. `direct` returns it only when the client is inside `directsrc`.

Whois still runs, and the caller is logged when verbose logging is on. Whois is not required to authorize the query. If it fails, the file rules are used anyway.

When the client also has ACL grants, the grant wins for any domain or CIDR it defines. The file still answers names the grant does not mention. `-rules-only` (`TSDNSPROXY_RULES_ONLY=true`) ignores ACL grants and uses the file alone. `-rules-only` requires a rules file.

The file is validated at startup. The process exits if it is missing, unreadable, or contains a rule that would be rejected as a grant. Send `SIGHUP`, or replace the file, to reload it. A bad reload keeps the previous rules and logs the error. Write the file by renaming it into place so a reader never sees a partial document.

The Kubernetes manifest mounts a ConfigMap at `/etc/tsdnsproxy/rules.json` and sets `TSDNSPROXY_RULES_FILE`.

## Installation

### Docker

```bash
docker run -d \
  --name tsdnsproxy \
  -e TS_AUTHKEY=tskey-auth-YOUR-KEY \
  -e TSDNSPROXY_HOSTNAME=tsdnsproxy \
  -e TSDNSPROXY_LISTEN_ADDRS=tailscale,0.0.0.0:53 \
  -p 53:53/udp \
  ghcr.io/rajsinghtech/tsdnsproxy:latest
```

Release images are tagged with the version and no leading `v` (`1.1.5`), and that same release also moves `latest`. Builds of the default branch are tagged `main` and `sha-<short commit>` and do not move `latest`. The manifests in `k8s/` pin the unprefixed release tag.

### Kubernetes

1. Update the auth key in `k8s/deployment.yaml`
2. Deploy using kubectl:

```bash
kubectl apply -k k8s/
```

`TSDNSPROXY_STATE=kube:tsdnsproxy-state` stores state in the Secret named `tsdnsproxy-state`. The Role grants get, update, and patch on that named Secret, and create on Secrets so the store can create it when it is missing.

`k8s/deployment.yaml` includes a ConfigMap mounted at `/etc/tsdnsproxy/rules.json`. Edit that ConfigMap to change the rules. The proxy reloads the file when it changes.

Or with kustomize:

```bash
kustomize build k8s/ | kubectl apply -f -
```

### Binary

```bash
go install github.com/rajsinghtech/tsdnsproxy/cmd/tsdnsproxy@latest
tsdnsproxy -authkey tskey-auth-YOUR-KEY
```

## Configuration

### Environment Variables

- `TS_AUTHKEY`: Tailscale authentication key (required)
- `TS_CONTROLURL`: Custom control server URL (optional)
- `TSDNSPROXY_HOSTNAME`: Hostname on tailnet (default: `tsdnsproxy`)
- `TSDNSPROXY_STATE_DIR`: State directory (default: `/var/lib/tsdnsproxy`)
- `TSDNSPROXY_STATE`: State storage backend. `kube:secret-name` stores state in that Kubernetes Secret. The ServiceAccount needs a Role with get, update, and patch on that named Secret, plus create on Secrets. An `arn:` value selects AWS SSM.
- `TSDNSPROXY_OVERRIDE_DNS`: Override host DNS servers (comma-separated, defaults to host's resolvers)
- `TSDNSPROXY_LISTEN_ADDRS`: Listen addresses (default: `tailscale`) - see Network Configuration
- `TSDNSPROXY_SERVICE`: Tailscale Service to host (`-service`), for example `svc:dns`. This is TCP port 53 unless the value ends in `@port`
- `TSDNSPROXY_HEALTH_ADDR`: Health check endpoint address (default: `:8080`)
- `TSDNSPROXY_ACCEPT_ROUTES`: Accept subnet routes and query DNS over tailnet (default: `false`)
- `TSDNSPROXY_ADVERTISE_TAGS`: ACL tags to advertise (comma-separated, default: none)
- `TSDNSPROXY_CAP_NAME`: Capability name for DNS grants (`-cap-name`, default: `rajsingh.info/cap/tsdnsproxy`). Set this to a domain and path such as `example.com/cap/dns` to match a different ACL grant key. Other capability names are ignored. An `http://` or `https://` prefix is also accepted.
- `TSDNSPROXY_VERBOSE`: Enable verbose logging (default: `false`)
- `TSDNSPROXY_RULES_FILE`: Path to a JSON or HuJSON rules file applied to every client
- `TSDNSPROXY_RULES_ONLY`: Ignore ACL grants and use only the rules file (default: `false`)

### Command Line Flags

```bash
tsdnsproxy \
  -authkey tskey-auth-YOUR-KEY \
  -hostname tsdnsproxy \
  -service svc:dns \
  -advertise-tags tag:tsdnsproxy \
  -listen-addrs tailscale \
  -statedir /var/lib/tsdnsproxy \
  -state kube:tsdnsproxy-state \
  -override-dns 8.8.8.8:53,8.8.4.4:53 \
  -rules-file /etc/tsdnsproxy/rules.json \
  -cache-expiry 5m \
  -health-addr :8080 \
  -cap-name rajsingh.info/cap/tsdnsproxy \
  -verbose
```

### Tailscale Service

`-service svc:dns` (or `TSDNSPROXY_SERVICE`) hosts DNS over TCP on the
service VIP. UDP 53 stays on the node's own Tailscale address
(`-listen-addrs tailscale`, which is the default). Clients that use the VIP,
or the MagicDNS name `dns.example.ts.net` on a tailnet whose suffix is
`example.ts.net`, must send DNS over TCP to port 53. The service does not
answer UDP. The name stays put when this node is replaced.
`tsnet.ListenService` advertises the node as a host of `svc:dns` and accepts
TCP port 53. PROXY protocol v2 is on, so whois still sees the client address.

`svc:<name>@<port>` changes the TCP port. `service:dns` is accepted and
treated as `svc:dns`. The same token can also be added to `-listen-addrs`.
A name listed in both places is hosted once.

The node must advertise a tag. For this example that is
`-advertise-tags tag:tsdnsproxy`. Startup fails if `-service` is set and no
tag is given.

Before the process can serve the name, an admin defines the Service and
approves this tag as a host:

- Service name: `svc:dns`
- Port on that Service: `tcp:53` (every port defined on the Service has to be advertised by the host)
- Tag: `tag:tsdnsproxy`, owned in `tagOwners`, and granted to the auth key or OAuth client so the node actually comes up tagged
- Host approval: `autoApprovers.services` maps `svc:dns` to `tag:tsdnsproxy`, or an admin approves the host in the console
- Client access: a grant with `dst` `svc:dns` and port `53`

```json
{
  "tagOwners": { "tag:tsdnsproxy": ["autogroup:member"] },
  "autoApprovers": {
    "services": { "svc:dns": ["tag:tsdnsproxy"] }
  },
  "grants": [
    {
      "src": ["autogroup:member"],
      "dst": ["svc:dns"],
      "ip": ["53"]
    }
  ]
}
```

Clients using the VIP need TCP DNS. In tailscale.com v1.104.1,
`ListenService` only has TCP and HTTP modes. Both open a local TCP socket,
and the serve config advertises TCP ports. UDP on a service VIP exists only
in Tun mode, which this API does not enable.

MagicDNS and split DNS do not always fall back to TCP when the nameserver is that VIP.

- If the operating system applies the split itself, it sends UDP straight to the VIP. That happens when every split domain uses the same IP resolvers and the OS can split. `Manager.compileConfig` then sets `OSConfig.Nameservers` to those IPs and returns. Windows and sandboxed Apple are not on that path. A missing UDP answer is a timeout. The OS retries over TCP only after a truncated UDP response, and this service never sends one.
- If the query goes through Tailscale's resolver at `100.100.100.100`, `forwarder.send` tries the upstream over UDP and starts TCP when that UDP attempt returns an error, or after 2 seconds if UDP is still waiting (`udpRaceTimeout`). A silent UDP VIP can then succeed over TCP, two seconds slower, unless `TS_DNS_FORWARD_SKIP_TCP_RETRY` or the control knob `DisableDNSForwarderTCPRetries` is set. A UDP answer that does arrive, including a truncated one, is returned as it is when the client asked over UDP.

Point split DNS at the node address when clients only send UDP. Point TCP clients at `dns.example.ts.net`.

## Domain Matching

Domains in grants act as wildcards:
- Grant for `cluster.local` matches:
  - `cluster.local`
  - `api.cluster.local`
  - `svc.api.cluster.local`

Most specific match wins:
- Query: `api.svc.cluster.local`
- Grants: `cluster.local`, `svc.cluster.local`
- Winner: `svc.cluster.local`

## DNS Handling Modes

tsdnsproxy supports three DNS handling modes controlled by the `translateid` field:

### Standard Forwarding Mode (`translateid` < 0 or omitted)

Queries are forwarded to backend DNS servers and responses are returned as-is. Use this for normal DNS proxying without modification.

```json
{
  "cluster.local": {
    "dns": ["10.0.0.10:53"],
    "rewrite": "svc.cluster.local",
    "translateid": -1
  }
}
```

**Behavior:**
- Forwards queries to backend servers
- Returns responses unchanged (A, AAAA, CNAME, etc.)
- Backend handles all query types
- Recommended for most use cases

### Authoritative Mode Without Translation (`translateid`: 0)

tsdnsproxy resolves queries authoritatively by querying backends directly and returning A/AAAA records without modification.

```json
{
  "cluster.local": {
    "dns": ["10.0.0.10:53"],
    "translateid": 0
  }
}
```

**Behavior:**
- Queries backend for A/AAAA records
- Returns records directly without forwarding full response
- Other query types return NODATA
- Use when you need authoritative responses without 4via6

### 4via6 Translation Mode (`translateid` 1–65535)

A records are converted to AAAA records using Tailscale's 4via6 format, allowing IPv4-only services to be accessed over Tailscale's IPv6 network.

```json
{
  "cluster.local": {
    "dns": ["10.0.0.10:53"],
    "translateid": 42
  }
}
```

**Behavior:**
- A queries return NODATA when the address is translated
- AAAA queries return a synthetic address
- IPv4 `10.1.2.3` with Site ID `42` → `fd7a:115c:a1e0:b1a:0:2a:a01:203`
- Addresses in `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4`, `255.255.255.255/32`, and `100.64.0.0/10` are not translated unless `allowips` covers them. An excluded A answer is returned unchanged, and the AAAA answer is empty

## Translation filters

`allowips` and `denyips` limit which resolved IPv4 addresses are translated. `denyips` always wins. A non-empty `allowips` list translates only addresses inside it. The built-in ranges above are skipped unless `allowips` covers them, which keeps shared `100.64.0.0/10` answers unchanged.

A grant key that is a CIDR matches the resolved address instead of the query name. The longest matching prefix wins and overrides the domain rule for that address. A prefix rule with `translateid` omitted or `0` leaves the address unchanged. A positive `translateid` translates with that site id.

```json
{
  "site-a.example": {
    "dns": ["10.1.0.10:53"],
    "translateid": 1,
    "allowips": ["10.0.0.0/8"],
    "denyips": ["10.1.50.0/24"]
  },
  "10.9.0.0/16": {
    "translateid": 2
  },
  "100.64.0.0/10": {
    "translateid": 0
  }
}
```

## Encoded IPv4 names

A zone can answer `10-0-0-1.site-a.example` with no per-host records. The single label is four decimal octets separated by dashes, with no leading zeros. Each zone has its own site id. The name cannot also set `rewrite` or `translateid`.

```json
{
  "site-a.example": {
    "ipnames": { "siteid": 1, "a": "never", "ttl": 300 }
  },
  "site-b.example": {
    "ipnames": {
      "siteid": 2,
      "a": "direct",
      "directsrc": ["192.168.10.0/24"],
      "allowips": ["10.0.0.0/8"],
      "allowsrc": ["192.0.2.0/24"],
      "negttl": 60
    }
  }
}
```

- `siteid` is required, from 0 through 65535.
- `a` is `never` (default), `always`, or `direct`. `direct` returns an A record only when the client address is inside `directsrc`. AAAA is still returned.
- `ttl` defaults to 300. `negttl` defaults to 60 and is the SOA minimum on negative answers.
- `allowips` limits which addresses a label may encode. The same built-in ranges used by translation filters are rejected unless `allowips` covers them. A rejected or malformed name is NXDOMAIN.
- `allowsrc`, when set, refuses clients outside those prefixes.
- Other query types, and A when A is off, are NODATA. The zone apex answers SOA and is NODATA for everything else.
- A zone is one or more labels. `ip` answers `10-1-2-3.ip`. `site-a.example` answers `10-1-2-3.site-a.example`. The same zone with different settings in two grants is dropped, and so are nested encoded-name zones. A normal rule may still be more specific than an encoded-name zone.

Publish one split-DNS suffix per zone, aimed at this proxy. The suffix covers every name under the zone. The split applies to the whole network; per-user control is the grant. Clients must accept the network's DNS. AAAA answers are only useful when a router advertises the translated prefix and clients accept those routes. Do not add these zones as search domains. `a` set to `always` can stall address selection, which is why `direct` exists. A shared resolver caches one client's answer for others, so keep `ttl` low when using `direct`.

Synthesized answers are not cached.

## Health Checks

- `/health`: Returns JSON health status
- `/ready`: Returns 200 when ready, 503 when not

## Example Use Cases

### Multi-Cluster Kubernetes

Route DNS for different clusters while maintaining consistent naming:

```json
{
  "prod.cluster.local": {
    "dns": ["10.1.0.10:53"],
    "rewrite": "cluster.local",
    "translateid": -1
  },
  "staging.cluster.local": {
    "dns": ["10.2.0.10:53"],
    "rewrite": "cluster.local",
    "translateid": -1
  }
}
```

Developers can use `api.cluster.local` and get routed to the correct cluster based on their identity. Using `translateid: -1` ensures standard DNS forwarding without modification.

### Split-Horizon DNS

Different teams see different DNS results:

```json
{
  "grants": [
    {
      "src": ["group:team-a"],
      "dst": ["tag:tsdnsproxy"],
      "app": {
        "rajsingh.info/cap/tsdnsproxy": [{
          "internal.local": {
            "dns": ["10.1.0.10:53"],
            "translateid": -1
          }
        }]
      }
    },
    {
      "src": ["group:team-b"],
      "dst": ["tag:tsdnsproxy"],
      "app": {
        "rajsingh.info/cap/tsdnsproxy": [{
          "internal.local": {
            "dns": ["10.2.0.10:53"],
            "translateid": -1
          }
        }]
      }
    }
  ]
}
```

### Split-Horizon DNS over 4via6

Forwarding DNS queries over 4via6 allows DNS servers to run on overlapping IP or CIDR ranges. Enable `TSDNSPROXY_ACCEPT_ROUTES` to accept the 4via6 subnets (this also enables the TS dialer).

```json
{
  "site1.vpc": {
    "dns": ["[fd7a:115c:a1e0:b1a:0:1:a0f:2]:53"],
    "translateid": 1
  },
  "site2.vpc": {
    "dns": ["[fd7a:115c:a1e0:b1a:0:2:a0f:2]:53"],
    "translateid": 2
  }
}
```

In this case, Both DNS server for `site1.vpc` and `site2.vpc` run on `10.15.0.2/16 but it will be queried over 4via6. This setup is useful when a service discovery differs between VPCs.

### IPv4-only Services via Tailscale IPv6

Access IPv4-only Kubernetes services over Tailscale's IPv6 network using 4via6 translation:

```json
{
  "site1.k8s": {
    "dns": ["10.1.0.10:53"],
    "rewrite": "svc.cluster.local",
    "translateid": 1
  },
  "site2.k8s": {
    "dns": ["10.2.0.10:53"],
    "rewrite": "svc.cluster.local",
    "translateid": 2
  }
}
```

Queries for `api.site1.k8s` return synthetic AAAA records that route to the IPv4 service via Tailscale.

## Development

### Building

```bash
go build -o tsdnsproxy ./cmd/tsdnsproxy
```

### Testing

```bash
go test ./...
```

### Docker Build

```bash
docker build -t tsdnsproxy:latest .
```

## Community

This project is built by the Tailscale community. It is not an official Tailscale product.

## License

[MIT License](LICENSE)
