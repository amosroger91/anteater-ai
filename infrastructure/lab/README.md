# Anteater test labs

Two labs. The **synthetic lab** (here) is the deterministic, known-answer target for CI and the
Phase-0 proof. The **dev-box lab** (`192.168.60.26`) is the live integration target.

## 1. Synthetic lab (deterministic, offline)

Seeded, known bugs so the detector gate has vulnerable/patched pairs and the end-to-end loop has a
guaranteed finding. Never expose it to the internet.

```bash
docker compose -f infrastructure/lab/docker-compose.yml up -d
```

Hostnames resolve to the Docker host — add to `/etc/hosts` (or `C:\Windows\System32\drivers\etc\hosts`)
on the machine running Anteater:

```
127.0.0.1  lab-vuln.anteater.test lab-patched.anteater.test
```

Export Caddy's internal CA so Node validates TLS (no bypass):

```bash
docker compose -f infrastructure/lab/docker-compose.yml cp caddy:/data/caddy/pki/authorities/local/root.crt ./lab-ca.crt
export NODE_EXTRA_CA_CERTS="$PWD/infrastructure/lab/lab-ca.crt"
```

Seeded findings (vulnerable variant; the patched twin fixes each):

| Path | Bug | Detector |
| --- | --- | --- |
| `/.git/config` | exposed VCS | `exposed_vcs` |
| `/api/users/{id}` (header `X-User: 1`) | IDOR — user 1 reads user 2 | authenticated access-control |
| `/api/data` + `Origin` | CORS reflects origin w/ credentials | `cors_credentialed` |
| `/redirect?to=` | open redirect | `open_redirect` |
| (all responses) | missing security headers | coverage only (not submitted) |

`/me` returns an identity marker for session validation (`X-User: 1|2`).

## 2. Dev-box lab — 192.168.60.26 (n8n / Postgres / Portainer)

This is an owned dev/test VM on Proxmox, used as the live integration target. It is not CI — its state
is real and non-deterministic, so use it for integration runs, not for the detector gate.

**One-time prep before any active run:**

1. **Snapshot it in Proxmox** so anything is recoverable: `qm snapshot <vmid> pre-anteater`.
   Roll back with `qm rollback <vmid> pre-anteater`.
2. **Neutralize n8n outbound:** deactivate workflows, or confirm none hold live credentials — a fuzzed
   webhook can send real email / hit real APIs even from a dev box.
3. It runs on a private IP, which the egress guard blocks by design. Point Anteater at it only via:
   - a **hostname** (scope rejects bare IPs): add `192.168.60.26  lab.anteater.test` to hosts, and
   - the lab flag `ALLOW_PRIVATE_LAB_TARGETS=true` with `LAB_TARGET_HOSTS=lab.anteater.test` (see the
     Phase-0 wiring task in `docs/BOUNTY_EARNINGS_PLAN.md` — the flag must only relax the private-IP
     block for exactly these hosts, never for a real program), and
   - TLS on 443 (front n8n/portainer with a reverse proxy + internal CA, or test the HTTP services via
     the read-only recon path which reports them as exposure findings).

**What runs against it today:** read-only recon / exposure (`npm run posture:check -- https://lab.anteater.test`),
passive HTTP, discovery/change-detection. **What needs building first** (plan Phases 3–4): the
paid-severity detectors and authenticated IDOR testing. **Aggressive/fuzzing** (executing the pinned
Nuclei adapter with non-destructive tags) runs only after the Proxmox snapshot and n8n prep above.
