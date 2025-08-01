# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with optimizations for target architecture
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
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