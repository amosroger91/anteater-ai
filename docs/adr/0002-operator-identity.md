# ADR 0002: local session versus authenticated reviewer

Status: accepted design; existing local session retained.

The HttpOnly same-origin loopback cookie protects a local control surface. It does not authenticate organizational approval or distinguish people using the machine. Keep local scope review labeled accordingly. Report drafts do not become verified/submitted by virtue of being downloaded.

Before authenticated research or team operation, implement an operator identity with server-side roles and project ownership checks. Store immutable reviewer identity with policy/report revisions. Store account credentials through secret references, not in campaign JSON or browser state. Keep canonical application principals separate from operator identities.

Do not infer authorization from a discovered host, private browser sign-in, imported policy text or model output. Missing real-program inputs do not block fixture development.
