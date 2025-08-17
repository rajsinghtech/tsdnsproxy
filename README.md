# tsdnsproxy

A DNS proxy server for Tailscale networks that enables per-identity DNS routing, domain rewriting, and 4via6 translation based on ACL grants.

## Features

- **Per-identity DNS routing**: Route DNS requests to different backend servers based on the requesting node's identity
- **Domain rewriting**: Transparently rewrite domains (e.g., `cluster1.local` → `cluster.local`) before forwarding
- **4via6 translation**: Convert IPv4 addresses to Tailscale's 4via6 IPv6 addresses using site IDs
- **Backend failover**: Automatic failover between multiple DNS backends with health checking
- **Kubernetes support**: Native state storage in Kubernetes Secrets
- **Grant-based configuration**: Configure behavior through Tailscale ACL grants

## How It Works

tsdnsproxy runs as a tsnet application on your tailnet, listening on configurable addresses (default: Tailscale IP port 53). When it receives DNS requests:

1. Identifies the requesting node using LocalAPI whois
2. Retrieves DNS grants from the node's capabilities
3. Matches the query domain against grant rules
4. Applies configured transformations (rewrite, backend selection)
5. Forwards the query to the appropriate backend
6. Optionally translates IPv4 responses to 4via6 IPv6 addresses
7. Returns the response to the client

## ACL Grant Configuration

Configure DNS behavior through Tailscale ACL grants:

- **dns**: Backend DNS servers to forward queries to (with failover)
- **rewrite**: optional - Rewrite domain before forwarding (e.g., `api.cluster1.local` → `api.cluster.local`)
- **translateid**: optional - Site ID for 4via6 translation of A records to AAAA records

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
              "translateid": 2
            }
          }
        ]
      }
    }
  ]
}
```

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

### Kubernetes

1. Update the auth key in `k8s/deployment.yaml`
2. Deploy using kubectl:

```bash
kubectl apply -k k8s/
```

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
- `TSDNSPROXY_STATE`: State storage backend (e.g., `kube:secret-name`)
- `TSDNSPROXY_DEFAULT_DNS`: Default DNS servers (comma-separated)
- `TSDNSPROXY_LISTEN_ADDRS`: Listen addresses (default: `tailscale`) - see Network Configuration
- `TSDNSPROXY_HEALTH_ADDR`: Health check endpoint address (default: `:8080`)
- `TSDNSPROXY_VERBOSE`: Enable verbose logging (default: `false`)

### Command Line Flags

```bash
tsdnsproxy \
  -authkey tskey-auth-YOUR-KEY \
  -hostname tsdnsproxy \
  -listen-addrs tailscale,0.0.0.0:53 \
  -statedir /var/lib/tsdnsproxy \
  -state kube:tsdnsproxy-state \
  -default-dns 8.8.8.8:53,8.8.4.4:53 \
  -cache-expiry 5m \
  -health-addr :8080 \
  -verbose
```

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

## 4via6 Translation

When `translateid` is set, A records are converted to AAAA records using Tailscale's 4via6 format:

- IPv4: `10.1.2.3`
- Site ID: `42`
- 4via6: `fd7a:115c:a1e0:b1a:0:2a:a01:203`

This allows IPv4-only services to be accessed over Tailscale's IPv6 network.

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
    "rewrite": "cluster.local"
  },
  "staging.cluster.local": {
    "dns": ["10.2.0.10:53"],
    "rewrite": "cluster.local"
  }
}
```

Developers can use `api.cluster.local` and get routed to the correct cluster based on their identity.

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
          "internal.local": {"dns": ["10.1.0.10:53"]}
        }]
      }
    },
    {
      "src": ["group:team-b"],
      "dst": ["tag:tsdnsproxy"],
      "app": {
        "rajsingh.info/cap/tsdnsproxy": [{
          "internal.local": {"dns": ["10.2.0.10:53"]}
        }]
      }
    }
  ]
}
```

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