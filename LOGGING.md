# Logging

KyDNS must emit structured, privacy-safe application logs to standard output
and standard error. It must not build or require a KySecurity-specific log
database, log search system, or long-term retention service.

Operators may route container logs to an existing platform such as Loki,
OpenSearch, Elasticsearch, Graylog, or another OpenTelemetry-compatible
collector.

Log service registration changes, record changes, DHCP and discovery failures,
health-check results, policy changes, peer enrollment, replication failures,
replication conflicts, and administrative actions. Query logs must be
configurable, minimized by default, and retained by the operator's logging
platform rather than KyDNS.

Never log upstream credentials, private keys, full DNS answers when they reveal
sensitive private services, or raw request bodies. Do not send query history to
KySecurity services by default.

Do not add an embedded log database or product-specific log viewer. Operators
should use their existing logging platform for search, alerting, retention, and
access control.
