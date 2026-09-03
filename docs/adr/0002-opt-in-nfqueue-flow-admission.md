# ADR 0002: Opt-In NFQUEUE Flow Admission for Proxy Lab

Date: 2026-09-03

## Status

Accepted for the debug experiment. Disabled by default and excluded from the production dashboard.

## Context

Proxy Lab needs to demonstrate network traffic moving through a gateway and, in a controlled lesson, make the delay observable on one client. Passive `AF_PACKET`, conntrack, and dnsmasq observation cannot delay forwarding. Recreating the legacy transparent TLS proxy would reintroduce certificate deployment, encrypted-protocol blind spots, and a content-bearing interception path.

Queueing every packet of every client is also unsafe and hard to teach: kernel queue capacity is finite, normal applications retry quickly, one unavailable UI could stall the whole access point, and one browser action would require hundreds of repetitive approvals.

## Decision

Use Linux NFQUEUE as a narrow, optional policy edge with three isolated queues:

- Queue 42, flow admission: the first new outbound TCP SYN or UDP tuple for explicitly selected IPv4 clients. Retransmissions join one decision and a short terminal cache applies the verdict to later packets.
- Queue 43, strict diagnostics: every packet of one complete TCP/UDP five-tuple, both directions, with a 500 ms default watchdog.
- Queue 44, DNS diagnostics: selected client UDP/53 datagrams and new TCP/53 connections at INPUT before local dnsmasq.

The rule chains exist with empty membership before arming. All queue rules use `--queue-bypass`; the netlink queues request kernel fail-open; bounded controller overflow immediately accepts; every pending decision has an accept watchdog; drain/disarm accepts held packets before removing membership. The HTTP control plane requires a bearer token read from a file and an active session. Packet payload contents are neither exposed nor persisted.

Flow-level approval is the default because it creates one meaningful operator choice per connection attempt while bounding queue pressure. Strict all-packet approval is retained only for one exact tuple as a short diagnostic. DNS is separate because redirected queries terminate locally and never traverse the normal FORWARD hook.

## Consequences

The default gateway remains the passive metadata system described by ADR 0001. Enabling build/runtime support does not arm traffic. An operator must accept that selected clients can retry, time out, or fail while armed. The gateway cannot pause application timers or make all browsers behave alike.

Flow admission does not reveal URLs or encrypted contents. UDP “flow” boundaries are tuple/cache approximations. Strict mode can alter transport dynamics and is intentionally capped. DNS-over-HTTPS, DNS-over-TLS, VPNs, Private Relay, and other tunnels do not enter the classic DNS queue.

Target-kernel and client behaviour must be measured on the Raspberry Pi before a demonstration build is accepted. Unsupported or degraded kernels remain passive-only.
