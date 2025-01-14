# Base image with Go installed
FROM golang:1.23-bullseye AS builder

# Set up the working directory
WORKDIR /app

# Copy the entire pocketbase folder into the image
COPY ./pocketbase /app

# Build the infra-reveal binary with CGO disabled
ENV CGO_ENABLED=0
RUN GOARCH=arm64 GOOS=linux go build -o /root/pb/infra-reveal .

# Use a minimal runtime image for the final container
FROM balenalib/rpi-raspbian:bullseye

# Install required dependencies
RUN apt-get update --fix-missing && apt-get install -y \
    hostapd \
    dbus \
    net-tools \
    iptables \
    dnsmasq \
    macchanger \
    iproute2 \
    && apt-get clean

# Copy the built binary from the builder stage
COPY --from=builder /root/pb/infra-reveal /root/pb/infra-reveal

# Set permissions for the binary
RUN chmod +x /root/pb/infra-reveal

# Copy the entrypoint script and other configuration files
COPY entrypoint.sh /root/entrypoint.sh
COPY hostapd.conf /etc/hostapd/hostapd.conf
COPY hostapd /etc/default/hostapd
COPY dnsmasq.conf /etc/dnsmasq.conf

# Set the working directory
WORKDIR /root

# Make entrypoint script executable
RUN chmod +x /root/entrypoint.sh

# Define the entrypoint
ENTRYPOINT ["/root/entrypoint.sh"]
