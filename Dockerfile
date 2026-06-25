# syntax=docker/dockerfile:1.7

# Base image with Go installed
FROM golang:1.23-bullseye AS builder

WORKDIR /src

# Cache module downloads separately from application source changes.
COPY pocketbase/go.mod pocketbase/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY pocketbase/*.go ./
COPY pocketbase/lib ./lib
COPY pocketbase/migrations ./migrations
COPY pocketbase/observer ./observer
COPY pocketbase/parser ./parser

# Build the infra-reveal binary with CGO disabled
ENV CGO_ENABLED=0
ARG GOARCH=arm64
ARG GOARM=7
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=linux GOARCH=${GOARCH} GOARM=${GOARM} go build -trimpath -o /out/infra-reveal .

# Use a minimal runtime image for the final container
FROM balenalib/rpi-raspbian:bullseye

# Install required dependencies
RUN apt-get update --fix-missing && apt-get install -y --no-install-recommends \
    hostapd \
    dbus \
    net-tools \
    iptables \
    dnsmasq \
    macchanger \
    iproute2 \
    traceroute \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /root

# Copy the stable runtime assets before the frequently changing binary.
COPY pocketbase/geoip /root/geoip

COPY --chmod=0755 entrypoint.sh /root/entrypoint.sh

COPY hostapd.conf /etc/hostapd/hostapd.conf
COPY hostapd /etc/default/hostapd
COPY dnsmasq.conf /etc/dnsmasq.conf

# Copy the built binary from the builder stage last, so PocketBase changes only
# invalidate this small final layer after the builder has reused its caches.
COPY --chmod=0755 --from=builder /out/infra-reveal /root/pb/infra-reveal

# Define the entrypoint
ENTRYPOINT ["/root/entrypoint.sh"]
