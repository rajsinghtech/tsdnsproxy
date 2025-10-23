# Build stage with cross-compilation optimization
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Configure Go for cross-compilation
ARG TARGETOS
ARG TARGETARCH
ENV GOOS=$TARGETOS GOARCH=$TARGETARCH

# Configure Go module proxy for faster downloads
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Copy source code (only necessary directories)
COPY cmd/ ./cmd/
COPY internal/ ./internal/

# Build with native Go cross-compilation
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build \
    -ldflags="-w -s -extldflags '-static' -X main.version=${VERSION}" \
    -tags netgo \
    -o tsdnsproxy \
    ./cmd/tsdnsproxy

# Runtime stage - use alpine for writeable filesystem
FROM alpine:latest

# Install ca-certificates
RUN apk --no-cache add ca-certificates

# Create non-root user and state directory
RUN addgroup -g 1000 -S tsdnsproxy && \
    adduser -u 1000 -S tsdnsproxy -G tsdnsproxy && \
    mkdir -p /var/lib/tsdnsproxy && \
    chown -R tsdnsproxy:tsdnsproxy /var/lib/tsdnsproxy

# Copy binary
COPY --from=builder /build/tsdnsproxy /bin/tsdnsproxy

# Switch to non-root user
USER tsdnsproxy:tsdnsproxy

# Expose DNS and health check ports
EXPOSE 53/udp 53/tcp 8080/tcp

# Set default environment variables
ENV TSDNSPROXY_STATE_DIR=/var/lib/tsdnsproxy \
    TSDNSPROXY_HEALTH_ADDR=:8080

ENTRYPOINT ["/bin/tsdnsproxy"]