# Logging

KyDNS must emit structured, privacy-safe application logs to standard output
and standard error. It must not build or require a KySecurity-specific log
database, log search system, or long-term retention service.

Operators may route container logs to an existing platform such as Loki,
OpenSearch, Elasticsearch, Graylog, or another OpenTelemetry-compatible
collector.

Log service registration changes, record changes, blacklist policy and list
refresh changes, DHCP and discovery failures, health-check results, policy
changes, and administrative actions. When replication ships, peer enrollment,
replication failures, and replication conflicts join that list. Query logs must
be configurable, minimized by default, and retained by the operator's logging
platform rather than KyDNS.

Query logging is off by default (`dns.log_queries`), and recording the client
IP is a separate opt-in (`dns.log_client_ip`), so turning on query logging does
not by itself record who asked.

Blacklist lifecycle events are `blacklist list refreshed`, `blacklist list
refresh failed` (with a reason, no response body), and `blacklist list
unchanged`, plus events for settings changes and rule additions/removals. When
query logging is enabled, each entry gains a `policy` field: `local` (the
authoritative lookup answered), `allow`, `deny`, the name of the list that
matched, or `forwarded` (no policy match).

Never log upstream credentials, private keys, full DNS answers when they reveal
sensitive private services, or raw request bodies. Do not send query history to
KySecurity services by default. A blacklist list URL may never embed
credentials; the field is rejected outright rather than accepted and redacted
later. Downloaded list content, list URLs, client IPs, and query names are
never logged by default. Blacklist counters (blocked-query totals and
per-list match counts) never carry client identity.

Do not add an embedded log database or product-specific log viewer. Operators
should use their existing logging platform for search, alerting, retention, and
access control.
