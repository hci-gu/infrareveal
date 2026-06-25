# ADR 0001: Build InfraReveal As A Metadata Gateway

Date: 2026-06-25

## Status

Accepted

## Context

The original implementation redirected TCP/80 and TCP/443 into a custom proxy and used TLS SNI as routing and observability input. That is fragile because SNI is not guaranteed to be visible, and Encrypted ClientHello can hide the real hostname from intermediaries. Without client trust certificates or endpoint cooperation, the gateway cannot see HTTPS headers, paths, cookies, or bodies.

The project goal is still useful if it shows what a Wi-Fi gateway can legitimately observe: flows, DNS lookups, visible protocol metadata, byte counts, destination context, route approximations, and uncertainty.

## Decision

InfraReveal will use normal NAT forwarding for client traffic and collect metadata as observations. The core product will not depend on transparent HTTPS interception or SNI-dependent upstream dialing.

The first observation sources are:

- dnsmasq logs for DNS queries and answers.
- conntrack sampling for flow metadata.

Derived hostname attribution and confidence labels are stored as separate `flow_attributions` records. DNS-to-flow matches are medium confidence; IP-only conclusions are low confidence; known encrypted DNS, tunnel, or QUIC-style reduced visibility ports are marked hidden.

Destination context is stored by observed destination IP. Route records are gateway-to-destination traceroute approximations and must not be described as the exact path a client application flow took.

## Consequences

Normal browsing should keep working without client certificate installation. Hostnames will be incomplete when clients use encrypted DNS, ECH, VPNs, Private Relay, or shared CDN infrastructure.

The dashboard must show uncertainty honestly. Later lab mode controls may intentionally shape client behavior, but those controls must be explicit and separate from default passive gateway observability.
