# Build stage. The digest is golang:1.27-alpine.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

ARG TARGETOS
ARG TARGETARCH
ENV GOOS=$TARGETOS GOARCH=$TARGETARCH
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build \
    -ldflags="-w -s -extldflags '-static' -X main.version=${VERSION}" \
    -tags netgo \
    -o tsdnsproxy \
    ./cmd/tsdnsproxy

# Runtime stage. The digest is gcr.io/distroless/static-debian12:nonroot.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=builder /build/tsdnsproxy /bin/tsdnsproxy

USER nonroot:nonroot
WORKDIR /tmp

EXPOSE 53/udp 53/tcp 8080/tcp

ENV TSDNSPROXY_STATE_DIR=/tmp/tsdnsproxy \
    TSDNSPROXY_HTTP_ADDR=:8080

ENTRYPOINT ["/bin/tsdnsproxy"]
