# ADR 0003: application checks plus independent egress

Status: accepted design; independent browser egress deployment remains unimplemented.

The bounded passive executor already checks scope, pins DNS resolution and limits response capture. Browser research requires a stronger independently enforced network boundary for redirects, subresources, service workers, WebSockets and DNS changes. Browser interception tests alone do not demonstrate that boundary.

Keep authenticated live research unavailable until the selected deployment profile passes egress tests. Model output may propose registered action templates but cannot run arbitrary shell/URLs or expand scope. Resource creation requires intent persistence before sending, bounded budgets and independent reconciliation. An uncertain write is not safe to retry blindly.

Shared stop semantics: prevent new admissions after a persisted epoch change, attempt to cancel in-flight work, and retain honest uncertain states. Do not promise exactly-once external side effects.
