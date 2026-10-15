# Domain grouping

Captured activity with a usable DNS-attributed hostname belongs to its
registered-domain group, scoped to its client and session. For example,
`www.facebook.com` and `graph.facebook.com` both belong to `facebook.com`.
The Public Suffix List handles domains such as `example.co.uk` and isolates
different tenants of private suffixes such as `github.io`. Internationalized
domains are normalized to ASCII. IP addresses and invalid hostnames cannot form
domain groups.

## Explicit aliases

Edit `pocketbase/observer/domain_groups.json`. Each entry maps a registered alias domain or an exact hostname to the canonical
domain displayed as the group label:

```json
{
  "ios.chat.openai.com": "chatgpt.com",
  "oaistatic.com": "chatgpt.com",
  "fbcdn.net": "facebook.com",
  "discord.gg": "discord.com"
}
```

Registered-domain mappings include their subdomains. Exact hostname overrides take
precedence, but do not include sibling or descendant hostnames: `ios.chat.openai.com`
joins ChatGPT while `api.openai.com` keeps the `openai.com` group. A canonical domain does not need
to have been observed: `cdn.oaistatic.com` alone creates a `chatgpt.com` group.
Domains absent from the table automatically create their own groups.
Use normalized registered domains or exact hostnames, not brand fragments, URLs,
or wildcards. Targets must be registered domains.
Targets must be canonical; chains, self-references, and cycles are rejected.
The table is embedded into the backend binary, so edits require a backend rebuild
and restart. No frontend mapping table needs to be kept in sync.

The table is an explicit grouping policy, not proof of which application opened
a connection. In particular, shared providers should not be mapped wholesale to
one service. The original attributed hostname remains visible in the captured aggregate evidence.

## Membership and lifecycle

- Captured samples carry one client-scoped service label or an independent
  endpoint label. Core storage has no flow/attribution/association collections.
- Recent DNS answers support medium-confidence classification. Conflicting names
  on a shared endpoint retract provisional attribution to unknown. Time proximity
  and a shared provider do not prove a service relationship.
- Source ports and connection identities remain in bounded memory. They support
  generation/lease checks without becoming persistent membership records.
- Aliases and the Public Suffix List version are pinned in each session policy.
  The original DNS hostname and confidence remain in compact chunk evidence.
- Ten seconds of provisional samples may be corrected atomically. Older labels
  are sealed, including on restart; the UI never rewrites the full history.
- `activity_blocks` group payload-active intervals by client and canonical service.
  A quiet gap greater than 45 seconds starts another block. Unknown capture gaps
  also split blocks. Span and active time are separate; ACK-only packets do not
  extend the block. One connection may contribute to several visits.
- Rolling retention preserves crossing-block identity and original start while
  recomputing retained counters. Activity indicates observed service use, not
  browser focus or measured attention.

## Validation

Run `go test ./observer` in `pocketbase` and the workspace frontend tests. Cases
cover suffixes and aliases, delayed DNS, ambiguous shared IPs, byte conservation,
multiple visits, concurrent services, capture gaps, client/tuple reuse, sealed
history and retained block anchors. The accepted storage design is
[ADR 0003](../adr/0003-map-activity-storage.md).
