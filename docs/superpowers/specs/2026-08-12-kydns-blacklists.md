# KyDNS Blacklists

Date: 2026-08-12  
Status: Proposed

## Goal

Add practical DNS blackhole filtering without changing KyDNS's primary job as a
local naming server. Filtering applies only to forwarded public-name queries;
authoritative local services, records, and reverse zones always remain usable.

The feature is a dedicated **Blacklists** tab. It is enabled by default and
has one prominent toggle to disable all filtering. Changes take effect without
a restart.

This is domain filtering, not traffic inspection, parental control, or a
malware guarantee. KyDNS does not inspect URL paths, TLS, HTTP content, or
client traffic.

## User model

The Blacklists tab contains:

- an enabled/disabled toggle and last refresh status;
- built-in lists, enabled by default, with name, description, source, entry
  count, last successful update, and error state;
- custom lists, each with a name, HTTPS URL, enabled toggle, refresh interval,
  and format (`domains`, `hosts`, or `adblock`);
- one-off **Allow** rules and one-off **Deny** rules;
- a test box that reports allowed, denied, or the named list that blocks a
  domain.

The tab warns when filtering is disabled, when a list has never loaded, or
when a custom list failed its latest refresh. Operators can refresh one list or
all lists immediately.

Built-in lists are shipped as a versioned manifest of maintained HTTPS sources.
The manifest records source, license/attribution, format, and expected content
type. A release can update it without changing policy code.

## Matching and precedence

Domains are normalized before matching: lower case, trailing dot removed, IDNA
converted to ASCII, and invalid names rejected. A rule for `ads.example`
matches that name and its subdomains, but not `badads.example`.

Resolution order is:

1. authoritative KyDNS data (local records and services);
2. an exact or parent-domain one-off deny rule;
3. an exact or parent-domain one-off allow rule;
4. an enabled custom or built-in list;
5. the normal forwarder.

An explicit deny wins over an explicit allow. The UI rejects duplicate and
conflicting one-off rules until the conflict is removed. More-specific rules
win over less-specific rules within the same rule kind. Filtering does not vary
by client view in this spec; per-view policy is a future feature.

Blocked names return local `NXDOMAIN` and are never sent upstream. The
response has no authoritative (`AA`) bit. Blocked results are cached for a
short configured TTL, default 60 seconds; an allow decision never substitutes
for the normal upstream answer.

## List ingestion

The parser accepts one domain per line, hosts-file lines such as
`0.0.0.0 example.test`, and Adblock-style domain rules. Comments, blank lines,
localhost/broadcast entries, IP addresses, and malformed names are ignored and
counted. Refresh is transactional: parse and validate the complete download,
then replace the previous snapshot. A failed download or parse keeps the
last known-good snapshot.

Downloads use HTTPS with certificate verification, bounded size, connect and
total timeouts, and redirect limits. KyDNS sends no query names, client
addresses, or identifying headers to list hosts. A configured URL is an
operator trust decision and is shown in the UI.

Built-in lists are refreshed on the best-effort 90-second foreground cadence,
with background catch-up on resume; actual downloads obey each list's refresh
interval and cache validators. Custom lists use the same scheduler. A list
outage must not make ordinary DNS fail: stale good data remains active until
replaced or explicitly disabled.

## Storage and query path

Persisted data: enabled state, list definitions, refresh metadata, one-off
rules, and the last known-good normalized rule snapshots. List contents are
data, not executable configuration. The DNS hot path reads an immutable policy
snapshot, rebuilt and atomically swapped after each policy change or refresh.

The forwarding pipeline becomes:

1. ACL check and authoritative lookup;
2. policy lookup for non-authoritative names;
3. return local `NXDOMAIN` when denied;
4. otherwise use the existing cache and upstream forwarder.

This ordering guarantees that a local service cannot be blackholed by a public
list and that a blocked query cannot leak to an upstream.

## API, CLI, and export

Add authenticated endpoints:

- `GET`/`PATCH` `/blacklists/settings`;
- `GET`/`POST`/`PATCH`/`DELETE` `/blacklists/lists`;
- `POST` `/blacklists/lists/{id}/refresh`;
- `GET`/`POST`/`DELETE` `/blacklists/rules/{allow|deny}`;
- `GET` `/blacklists/test?name=...`.

Add a `kydns blacklist` command family. YAML and JSON exports include policy
settings, list definitions, and one-off rules, but not downloaded list bodies
or credentials. Import validates the complete policy before replacing it;
merge preserves existing list data unless explicitly updated.

## Logging, privacy, and security

Log list lifecycle events, refresh outcomes, parse summaries, enable/disable,
and rule changes. Do not log downloaded content, URLs containing credentials,
client IPs, or query names by default. With query logging enabled, add
`policy` (`local`, `allow`, `deny`, list name, or `forwarded`) and retain the
existing separate client-IP opt-in. Counters expose blocked totals and counts
by list, not client identity.

Only authenticated administrators can change policy. List downloads are
untrusted input and require bounded memory, strict parser limits, and no code
execution. Fetch sources only over verified HTTPS.

The global toggle is atomic. Disabling filtering stops new blocks but does not
delete lists or rules; re-enabling restores valid snapshots immediately. If a
list is unavailable, its last good snapshot stays active and is marked stale.

## Verification

Required runnable checks cover normalization and suffix boundaries; precedence;
all three formats and malformed-line counts; transactional refresh and stale
snapshot retention; no upstream request for blocked names; API authorization;
export omission of list bodies/credentials; import validation; cache behavior;
blocked counters; and an integration test proving an allow exception and a
local record both win as specified.

## Related documents

- `README.md` — product scope
- `DESGINE.md` — architecture and query pipeline
- `LOGGING.md` — privacy-safe event requirements
- `SECURITY.md` — trust boundaries and input validation
- `CONTRIBUTING.md` — documentation and verification workflow
