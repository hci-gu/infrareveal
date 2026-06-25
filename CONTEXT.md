# InfraReveal Context

InfraReveal is a consent-based network metadata observability gateway.

## Domain Terms

- Gateway: the Raspberry Pi or small computer running the Wi-Fi access point, DHCP, DNS, NAT, observers, PocketBase, and dashboard.
- Client: a device connected to the InfraReveal Wi-Fi network.
- Flow: a sampled network connection from a client to a destination IP and port.
- Observation: raw metadata collected by the gateway, such as a DNS query or conntrack flow sample.
- Attribution: a derived conclusion that links a flow to a candidate hostname or destination context.
- Confidence: the strength of an attribution. Initial milestones collect observations only; later milestones add high, medium, low, and hidden confidence labels.
- Destination: the remote IP, port, protocol, and later provider or ASN context for a flow.
- Route: an approximate gateway-to-destination traceroute result. It is not the exact client application path.
- Lab mode: optional policy controls that intentionally change client network behavior to improve observability in a controlled experiment.

## Current Architecture Direction

The gateway forwards web traffic normally through NAT. It does not route HTTPS by SNI, decrypt HTTPS, or require client trust certificates.

The backend stores raw observations separately from future derived conclusions. Milestone 1 and 2 observations are:

- `flows`: sampled conntrack flow metadata.
- `dns_queries`: dnsmasq query and answer metadata.

Milestone 3 derived conclusions are:

- `flow_attributions`: candidate hostname, source signal, confidence, and explanation for a flow.

Milestone 5 destination context is:

- `destinations`: reverse DNS, provider label, and coarse GeoIP context keyed by observed destination IP.
- `routes`: gateway-to-destination traceroute approximations keyed by observed destination IP and port.

Attribution work consumes observations and writes separate derived records instead of overwriting raw observations.
