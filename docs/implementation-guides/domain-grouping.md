# Domain grouping

Every flow with a high- or medium-confidence attributed hostname belongs to its
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
one service. The original attributed hostname remains visible on the connection.

## Membership and lifecycle

- Domain membership requires usable hostname evidence. Missing, low-confidence,
  hidden, and invalid hostname evidence remains in Independent traffic.
- Membership uses `first_party` for the same registered domain and `domain_alias`
  for an explicit JSON mapping. Association confidence preserves hostname confidence.
- DNS timing, proximity to other connections, CNAME chains, and shared IPs/providers
  do not merge domains. There is no supported-service allowlist.
- A group has a stable key based on session, client, and canonical domain. Idle
  gaps do not split it, and discovering an earlier connection does not change its ID.
- The existing three-second correlator refreshes the current active session and
  replaces old temporal associations and obsolete groups. Allow for processing and
  frontend synchronization before a newly observed connection leaves Independent.
- Closed recordings retain their stored associations; deploying this change does
  not rewrite historical sessions. Frontends retain legacy relationship support.

The storage collection remains `activity_episodes` for API compatibility; it now
represents domain groups rather than inferred visits. No schema migration is needed.

## Validation

Run `go test ./observer` in `pocketbase`, and the frontend tests and builds from
the workspace root. Tests cover arbitrary domains, suffix handling, aliases,
simultaneous unrelated services, long gaps, client/session isolation, stable
keys, unknown traffic, JSON validation, and replacement of old persisted groups.
