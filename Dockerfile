# Base image with Go installed
FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm AS builder

WORKDIR /src

# Cache module downloads separately from application source changes.
COPY pocketbase/go.mod pocketbase/go.sum ./
RUN go mod download

COPY pocketbase/*.go ./
COPY pocketbase/lib ./lib
COPY pocketbase/migrations ./migrations
COPY pocketbase/observer ./observer
COPY pocketbase/routing ./routing
COPY pocketbase/cmd/route-diagnose ./cmd/route-diagnose
COPY pocketbase/parser ./parser
COPY pocketbase/debugtrace ./debugtrace
COPY pocketbase/labgate ./labgate
COPY pocketbase/netmeta ./netmeta

# Build the infra-reveal binary with CGO disabled
ENV CGO_ENABLED=0
ARG TARGETARCH
ARG TARGETVARIANT
RUN GOOS=linux GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} go build -trimpath -o /out/infra-reveal .
RUN GOOS=linux GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} go build -trimpath -o /out/route-diagnose ./cmd/route-diagnose

# The runtime platform matches TARGETARCH, including the existing ARMv7 Pi.
FROM debian:bookworm-slim

# Install required dependencies
RUN export DEBIAN_FRONTEND=noninteractive; \
    apt-get update --fix-missing && apt-get install -y --no-install-recommends \
    hostapd \
    iw \
    python3 \
    curl \
    net-tools \
    iptables \
    ipset \
    dnsmasq \
    macchanger \
    iproute2 \
    traceroute \
    scamper=20211212-1.1 \
    tcpdump \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /root

# GeoIP assets are supplied by the read-only runtime volume.
RUN mkdir -p /root/geoip

COPY entrypoint.sh /root/entrypoint.sh
COPY scripts/gateway-network.sh scripts/gateway-preflight.py /root/scripts/

# Copy the built binary from the builder stage last, so PocketBase changes only
# invalidate this small final layer after the builder has reused its caches.
COPY --from=builder /out/infra-reveal /root/pb/infra-reveal
COPY --from=builder /out/route-diagnose /usr/local/bin/route-diagnose

RUN chmod +x /root/entrypoint.sh /root/pb/infra-reveal

# Define the entrypoint
ENTRYPOINT ["/root/entrypoint.sh"]
