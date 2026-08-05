---
Name:   Zlepšenie efektivity honeypot nástroja pomocou zvýšenia úrovne interakcie
Eng:    Improving Honeypot Tool Efficiency by Increasing Interaction Level
Place:  Ústav počítačového inžinierstva a aplikovanej informatiky, FIIT STU
Oblasť: Kombinované bezpečnostné riešenia
# Honeypot IDS System — Technical & Operational Manual

**Zlepšenie efektivity honeypot nástroja pomocou zvýšenia úrovne interakcie**
**Improving Honeypot Tool Efficiency by Increasing Interaction Level**
Master's thesis, Ústav počítačového inžinierstva a aplikovanej informatiky, FIIT STU



This file is the single technical/functional manual for the project: what it is, how to run it, how it works in detail, what's known-broken, and what's left to do. It supersedes and merges the following (now removed) files: `CHECKLIST.md`, `CHECKLIST-MANUAL.md`, `PROMPT_TODO.md`, `walkthrough.md` (both the root and `openstack-work/` copies), `refactoring-plan.md`, `summary-for-claude.md`, `openstack-work/README.md`, `openstack-work/ELK_INTEGRATION.md`, `openstack-work/SQL_PROXY_ROUTING.md`, and `openstack-work/reverse_proxy_enhanced/HONEYPOT_ROUTING_TEST_CASES.md`. Thesis-scoped material (`COUNTERARGUMENTS.md`, `PLAN_DP1-3.md`, `master-thesis-rewrite-plan/`, and the LaTeX thesis itself) stays separate — see [§12](#12-thesis--academic-material).

Every claim below was checked against the running system or the current source as of this writing, not copied forward from older docs — see [§9](#9-known-issues--stale-documentation-corrections) for what was found stale in the files this replaces and corrected here.

---

## 1. Quick Reference

### What this is

A WordPress/WooCommerce e-commerce site with an OpenResty (Nginx + Lua) reverse proxy that scores every request in real time and transparently diverts suspicious traffic to one of three isolated honeypot instances instead of the real production site — while legitimate users never notice. Suricata IDS taps the network layer; Redis holds session/routing state; logs optionally ship to a separate SIEM host (Elasticsearch + Kibana) over mTLS via Vector.

### Two-host run order

This system spans **two separate hosts/VMs** — a detail easy to miss since they live in two disconnected top-level directories with no other cross-link (`openstack-work/` and `openstack-siem-work/`):

```bash
# 1. On the SIEM VM first:
sudo apt install docker docker-compose curl wget zip unzip git jq
cd openstack-siem-work/elk_dockerized/docker
sudo docker compose up
# wait for http://<siem-vm-ip>:5601/app/home#/ to be reachable

# 2. Then on the main/edge VM:
sudo apt install docker docker-compose curl wget zip unzip git jq
cd openstack-work
sudo docker compose up
```

The SIEM half is optional for local development — the main stack runs standalone without it; you only need it if you want shipped logs to land somewhere (see [§6](#6-observability-elk--siem)).

### First-time setup (main VM / local dev)

```bash
cd openstack-work
cp .env.example .env
vi .env    # set real passwords, or generate them:
sed -i "s/change_this_user_password_in_production/$(openssl rand -base64 32)/" .env
sed -i "s/change_this_redis_password_in_production/$(openssl rand -base64 32)/" .env
sed -i "s/change_this_internal_test_secret/$(openssl rand -hex 24)/" .env

# Foreground the first run (see the note under Known Issues about why
# `run_in_background`-style backgrounding of `docker compose up` can silently
# do nothing in some environments):
docker compose up -d --build
```

There is no `deploy.sh` or `test_system.sh` in this repository — despite being referenced by that name in the old `openstack-work/README.md` this file replaces, neither script exists. Use `docker compose` directly, as above.

### Common commands

```bash
# Restart after minor config/code changes
docker compose down && docker compose up -d

# Rebuild after Lua/Dockerfile changes — IMPORTANT: nginx.conf is baked into
# the reverse_proxy image at BUILD time (COPY'd in the Dockerfile), while
# reverse_proxy_enhanced/lua/*.lua is bind-mounted live. A plain `restart`
# picks up .lua edits but silently does NOT pick up nginx.conf edits — you
# need --build for those. This bit a live debugging session directly.
docker compose up -d --build reverse_proxy

# Nginx-only rebuild+restart, e.g. after a router.lua/nginx.conf change
docker compose stop reverse_proxy && docker compose build reverse_proxy && docker compose up -d reverse_proxy

# Flush all Redis state (sessions, threat_ips, pool assignments, rate limits)
docker compose exec -T session_store redis-cli -a "$(grep REDIS_PASSWORD .env | cut -d= -f2)" FLUSHALL

# Enable log shipping to the SIEM host (Vector is gated behind a Compose
# profile — plain `docker compose up` does NOT start it)
docker compose --profile elk up -d

# Purge everything and start clean (WARNING: removes ALL containers on the machine)
docker stop $(docker ps -a -q) ; docker rm -f $(docker ps -a -q) ; docker rmi $(docker images -q)
docker system prune -a --volumes --force
docker compose up -d
```

### Access points (local dev)

- `https://localhost/` — main site, intelligent routing between production/honeypot (self-signed cert, auto-generated on `init_setup`)
- `X-Route-Target` response header shows the routing decision, but **only when the request carries a matching `X-Internal-Test-Auth` header** (see [§5](#5-testing)) — this used to leak to every client until this session's fix; see [§9](#9-known-issues--stale-documentation-corrections).
- `docker compose logs -f reverse_proxy` — the single most useful log stream; every request logs its threat score, routing decision, and stage that triggered it.
- `tail -f suricata_logs/fast.log` / `eve.json` — IDS alerts (see [§9](#9-known-issues--stale-documentation-corrections) for the current known issue with this).

### Where things live

```
openstack-work/
├── reverse_proxy_enhanced/lua/   # the actual thesis contribution — see §4
├── reverse_proxy_enhanced/nginx.conf
├── production_eshop_files/       # real WordPress+WooCommerce+omega-storefront theme
├── production_eshop_files_fresh_for_diff/  # pristine copy, for diffing only
├── testing/                      # scenario_01-09.sh + BLIND_PENTEST_PROTOCOL.md — see §5
├── docker-compose.yml            # ~14 services, see §3
├── suricata_config/, suricata_rules/, suricata_logs/
├── vector/                       # local log shipper config (Vector, mTLS out to SIEM)
├── ssl_certificates/             # gitignored, regenerate on fresh clone
└── .env / .env.example

openstack-siem-work/elk_dockerized/   # SEPARATE docker-compose project — SIEM backend, own host
master-thesis-latex/                  # the thesis itself (LaTeX)
master-thesis-rewrite-plan/           # speculative research proposals — NOT yet implemented, see §12
architecture.canvas                   # Obsidian Canvas — full component diagram with responsibility/refactoring/overlap notes per node
```

---

## 2. What This Project Actually Does (assignment scope)

> Honeypot tools in cybersecurity serve to attract attackers and collect data about their behavior. Existing solutions often offer limited simulation capabilities which may deter attackers. […] Implement a proxy for redirecting suspicious visitors from production to honeypot environment including logging of attacker activity and data visualization. Address efficient initialization of honeypot instances customized for the attacker with data transfer and storage of changes by IP. As part of conceptualization and implementation integrate open-source honeypot solutions and honeytokens. […] Test the solution on a series of attack scenarios identified based on current trends in web security. Evaluate the effectiveness of the implemented solution by comparing the level of interaction against basic honeypot systems.

(Full bilingual assignment text and primary literature preserved in [§13](#13-primary-literature).)

In concrete terms, this repository builds: a WordPress/WooCommerce **production** site and three **honeypot** clones behind a single reverse proxy; real-time request scoring in Lua (OWASP WSTG patterns, 9 seeded CVEs, IP reputation, behavioral/automation signals); sticky per-IP honeypot pool binding so an attacker's session state persists; honeytokens; an attacker-sophistication classifier; a prompt-injection detector; AbuseIPDB integration; Suricata IDS; and an optional ELK/SIEM backend on a separate host.

---

## 3. Architecture

### 3.1 Request pipeline (the core of the thesis contribution)

Every non-static request goes through `nginx.conf`'s `access_by_lua_block`, which calls, in order:

1. **`threat_analyzer.analyze_request()`** — scores the request 0–100+ against URI patterns (SQLi/XSS/traversal/etc.), headers, CVE patterns, IP reputation, request method, and automation UA signatures. Also runs a Stage 7 prompt-injection probe.
2. **`session_handler`** — looks up or creates a Redis-backed session.
3. **`router.decide_route()`** — the actual production-vs-honeypot decision, a 10-stage pipeline (first match wins): static asset → sticky already-bound session → threat score ≥ threshold (80 default) → CVE match → vulnerable-plugin-path access → bad IP reputation → repeated admin-panel probing → cumulative suspicious-activity count → rapid automation → suspicious file upload → default production.
4. **`pool_router`** — if honeypot-bound, assigns/reuses a sticky pool (1/2/3) for that IP via Redis.
5. **`sophistication_analyzer.classify_session()`** — labels the session `scripted`/`manual`/`ai_assisted`/`unknown` from timing regularity, UA fingerprint, header completeness, and payload precision. Persisted to the session (and thus to ELK) only for already-suspicious/honeypot-bound traffic.
6. Session update, security-event logging, response headers.

`router.apply_botnet_slowdown()` (tarpit-style delay for confirmed scanners) runs just before the sophistication step.

### 3.2 The Lua module map — pure cores vs. I/O adapters

As of this session, the request-handling Lua code follows a deliberate **pipeline + ports-and-adapters** pattern (chosen over MVC — see `architecture.canvas`'s framework banner for the full reasoning): a `*_rules.lua` module holds pure decision logic with **zero `ngx.*`/`_G.*` dependency**, unit-testable with a plain `lua` interpreter; the original `*.lua` file is a thin adapter that pulls config/request context and does all Redis/nginx I/O.

| Adapter | Pure core | Tests | Responsibility |
|---|---|---|---|
| `threat_analyzer.lua` | `threat_rules.lua` | 37 | Request scoring |
| `router.lua` | `router_rules.lua` | 29 | Routing predicates (not the staged `decide_route()` itself — see below) |
| `vulnerability_handler.lua` | `vulnerability_rules.lua` | 16 | CVE + exploit-kit pattern matching |
| `upload_handler.lua` | `upload_rules.lua` | 32 | File-upload threat scoring |
| — | `prompt_injection_filter.lua` | 20 | OWASP LLM01-style detection (already pure by design, the original model for this pattern) |
| — | `sophistication_analyzer.lua` | (fixed, untested pre-session) | Attacker classification |
| — | `lua_pattern_utils.lua` | 9 | Shared `url_decode`/`escape_pattern`, deduplicated from 3 copies |

**143 unit tests total, all passing** (`cd openstack-work/reverse_proxy_enhanced/lua/tests && for f in test_*.lua; do lua "$f"; done`). `router.decide_route()` deliberately stays impure — its 10-stage pipeline interleaves session mutation with Redis/AbuseIPDB I/O too deeply to safely extract without risking a bug in the single most consequential function in the system; only its self-contained predicates (`is_static_asset`, `is_admin_access`, `is_rapid_automation`, `is_suspicious_upload`, `is_vulnerable_plugin_access`) were moved out.

**Not yet split** (assessed, lower value/higher risk than the above): `session_handler.lua`, `honeytoken_handler.lua`, `admin_handler.lua`, `abuseipdb_client.lua` are I/O-dominated with little pure logic. `pool_router.lua` is pure I/O with zero pattern-matching — no split needed, already clean.

Writing these tests surfaced **six real, previously-invisible bugs**, all fixed and verified live:
1. `sophistication_analyzer.lua`'s `signals` audit list was silently empty on any session under 3 requests (Lua `ipairs`-over-a-leading-`nil`-hole gotcha).
2. `router.lua`'s `assign_honeypot_pool()` clobbered session data (lost `user_agent`) before the sophistication classifier saw it.
3. `threat_analyzer.lua`'s `high_request_rate` IP-reputation signal was permanently dead — the counter it read was never written by anything.
4. **`router.lua` Stage 5 never matched a single hyphenated plugin slug** — i.e. every seeded vulnerable plugin except `cwmp` — because plugin names were concatenated unescaped into Lua patterns (`-` is a lazy-repeat magic character, not a literal hyphen there). Masked by an overlapping nginx-level regex `location` block that only covers `.php/.asp/.aspx/.jsp` files.
5. **A live HTTP 500**: any POST to `/wp-admin/admin-ajax.php` with a non-empty, upload-looking query string crashed (`%2e%2e%2f`/`%2e%2e/` read as invalid Lua pattern backreferences). Confirmed with a real request before/after the fix.
6. That crash was masking a **second** crash right behind it: `red:get('threat_ips') or '{}'` doesn't handle Redis's `ngx.null` "missing key" sentinel (truthy in Lua), so `cjson.decode` failed on any fresh/flushed Redis — present in 4 places across `admin_handler.lua`, `upload_handler.lua`, and `vulnerability_handler.lua`.

### 3.3 Docker Compose services (verified current, via `docker compose config --services`)

`init_setup`, `honeypot_db_migration`, `production_database`, `production_eshop`, `honeypot_database_1/2/3`, `honeypot_eshop_1/2/3`, `session_store` (Redis), `suricata_ids`, `backup_service`, `reverse_proxy`. **14 services total.** `vector` exists in `docker-compose.yml` but is gated behind `profiles: [elk]` — it does **not** start with a plain `docker compose up`; use `docker compose --profile elk up -d`.

Networks: `production_network`, `honeypot_network`, `monitoring_network`, `session_network`, `ids_network`, plus a `setup_network` that's defined but never assigned to any service (dead, harmless).

### 3.4 WordPress / WooCommerce layer

`production_eshop_files/` — real WordPress + WooCommerce + a custom `omega-storefront` theme + mu-plugins, served on the production path. `production_eshop_files_fresh_for_diff/` sits alongside it as a pristine reference copy for diffing (intentional, not stale duplication). Three honeypot pool instances mirror production's fingerprint (same DB name `production_database`, same theme/plugins) so an attacker sees a consistent fake environment once IP-bound via `pool_router.lua`.

**Known architectural gap**: `init_setup`'s file-copy step only copies once and skips entirely if the destination already has any content — so honeypot pool volumes silently drift from `production_eshop_files/` after first provisioning. Hit directly this session (pools were missing an entire theme + mu-plugins directory after a file was added post-provisioning); worked around manually via `docker cp`, not fixed at the architectural level.

### 3.5 Session, Redis & IP-based state

Redis (`session_store`) backs: session records (`session:*`), rate-limit counters (`ip:*`, plus a separate `attempt_key` namespace in `admin_handler.lua`), sticky pool assignments, and the shared `threat_ips` reputation map. Worker-local `ngx.shared` dicts cache session data for 5 minutes to cut Redis round-trips. The key-naming schema is currently only discoverable by grepping across ~6 Lua files — no single reference doc exists for it (candidate for a future addition here).

### 3.6 Suricata IDS

Real network-layer IDS, **AF_PACKET capture on `eth0`** inside its own `ids_network` (confirmed in `suricata_config/suricata.yaml` and the service definition — `privileged: true`, `NET_ADMIN`, `SYS_NICE`). This is the traditional network-tap approach, **not** the `ngx_http_mirror_module` application-layer-mirroring approach proposed in `master-thesis-rewrite-plan/` (see [§12](#12-thesis--academic-material)) — that proposal was never implemented; nginx.conf has no `mirror` directive.

**Known issue**: `suricata_ids` currently exits immediately (`Exited (0)`) in the local compose stack — not root-caused this session (flagged as optional/non-blocking; a healthcheck dependency on it elsewhere in `docker-compose.yml` is deliberately commented out so it doesn't block other services from starting). Needs a dedicated pass if the thesis testing chapter needs IDS-layer data.

---

## 4. Security Detection Capabilities

### 4.1 Seeded CVEs (honeypot-only, real published vulnerabilities with public exploit code — see `COUNTERARGUMENTS.md` Q11 for why these aren't "artificial")

| CVE | Plugin | Trigger |
|---|---|---|
| CVE-2023-28121 | WooCommerce Payments | `X-WCPAY-PLATFORM-CHECKOUT-USER` header |
| CVE-2023-2986 | Abandoned Cart Lite | `wcal_action=checkout_link` |
| CVE-2025-4403 | Drag-and-Drop Multiple File Upload | `dnd_codedropz_upload` + `supported_type` |
| CVE-2025-2266 | CWMP | `cwmpUpdateOptions` |
| CVE-2025-47577 / CVE-2024-8425 | Gift Voucher | `mwb_wgm_preview_mail` |
| CVE-2024-2387 | Advanced Form Integration | SQLi via `integration_id` |
| CVE-2025-10142 | PagSeguro Connect | file path traversal |
| CVE-2024-50508 | WP File Upload | directory traversal |

### 4.2 Generic detection

SQLi, XSS, command injection, LFI/RFI, directory traversal, malicious/scanner User-Agents (sqlmap, nikto, nmap, wpscan, etc.), automation tool fingerprints, WordPress user enumeration (`?author=N`, `/wp-json/wp/v2/users`), XML-RPC abuse, sensitive-file access (`wp-config.php`, backups).

### 4.3 This session's additions

- **AbuseIPDB integration** (`abuseipdb_client.lua`) — bulk blacklist fetch (worker-0, every 6h), on-demand reputation checks, and confirmed-attacker report-back gated by a deterministic reason whitelist (CVE match, vulnerable-plugin access, brute-force, rapid automation, suspicious upload) to keep report quality high.
- **Sophistication scoring** (`sophistication_analyzer.lua`) — see §3.2. Directly falsifiable by the blind pentest (§5.2): an AI-agent session should classify as `ai_assisted`. It didn't (see §5.2's findings) — an important, correctly-interpreted negative result, not a bug.
- **Prompt injection filter** (`prompt_injection_filter.lua`) — OWASP LLM01-style detection, standalone/defensive, not yet wired to any live LLM feature (none exists in this codebase — see §12's `NEW_PLAN.md §5.3.2` note).
- **Honeytokens** — fake credentials injected and tracked; reuse is a confirmed-compromise signal that forces max threat score.

---

## 5. Testing

### 5.1 Scripted scenarios (`testing/scenario_01-09*.sh`)

THM WooCommerce CVE-2023-28121 chain, OWASP WSTG categories 1–7, WPScan enumeration, Metasploit (routing + shell + SQLi + docker-takeover-contained-to-honeypot), production-hardening verification, DB password replacement, payment gateway coverage, backup-deletion attempt, and PentAGI-driven pentest coverage. All validate routing via the `X-Route-Target` header, which as of this session requires an `X-Internal-Test-Auth` header (see §9) — export `INTERNAL_TEST_SECRET` from `.env` in your shell before running any of them:

```bash
export INTERNAL_TEST_SECRET=$(grep INTERNAL_TEST_SECRET .env | cut -d= -f2)
./testing/scenario_01_thm_woocommerce.sh
```

Manual spot-checks:
```bash
curl -H "X-Internal-Test-Auth: ${INTERNAL_TEST_SECRET}" -H "User-Agent: sqlmap/1.0" https://localhost/ -k -I | grep -i x-route-target
curl -H "X-Internal-Test-Auth: ${INTERNAL_TEST_SECRET}" -X POST -H "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" https://localhost/wp-json/wp/v2/users -k
curl -H "X-Internal-Test-Auth: ${INTERNAL_TEST_SECRET}" "https://localhost/wp-content/plugins/woocommerce-payments/readme.txt" -k -I
```

The full attack-URL reference (path traversal, SQLi, XSS, command injection, malicious UAs, upload exploits, and the legitimate-URL control set that must stay on production) previously lived in `reverse_proxy_enhanced/HONEYPOT_ROUTING_TEST_CASES.md` — merged here; see the pattern tables in `threat_rules.lua`/`vulnerability_rules.lua` for the authoritative, current pattern set (the standalone doc had drifted from the code in places, e.g. it didn't reflect the header-auth gating added this session).

### 5.2 Blind pentest (task 4 — completed this session)

A context-isolated AI agent (fresh instance, zero knowledge of this repo) was briefed only with a generic "assess this e-commerce site" prompt and network access. Result: **rubric score 3/3, confirmed detection** — the agent independently found the deception from the server's own responses: TLS cert `O=HoneypotOrg`, cookie literally named `HONEYPOT_SESSION`, and the `X-Route-Target`/`X-Threat-Score` headers (since fixed — see §9). Full protocol and results: `testing/BLIND_PENTEST_PROTOCOL.md` and `testing/blind_pentest_report_run1.md`.

Cross-referenced against internal telemetry: the agent's session classified as `scripted` (not `ai_assisted`) — correct, not a bug: it was instructed to interact via plain `curl` only (for genuine blackbox isolation), which is indistinguishable at the network layer from a scripted scanner using the same tool. This is a real, documented limitation of the sophistication classifier worth stating explicitly in the thesis: it detects a *tooling fingerprint*, not "was an LLM involved" in the abstract.

### 5.3 Unit tests

143 tests across 5 suites (`tests/test_*.lua`), zero `ngx.*` dependency, runnable with a plain `lua` interpreter — see §3.2.

---

## 6. Observability (ELK / SIEM)

Two-host split (see §1): a local **Vector** agent (`openstack-work/vector/vector.yaml`, profile-gated) tails Docker/nginx/Suricata/Redis logs and ships them over mTLS to a **Vector aggregator** on the SIEM host, which re-emits to **Elasticsearch**, visualized in **Kibana**. Nothing today documents this cross-host relationship outside two lines in §1 of this file — a standalone `ARCHITECTURE.md` cross-linking both projects' own READMEs would help a reader who lands in either directory alone.

Indices: `honeypot-ids-*` (Suricata EVE JSON — alerts, HTTP transactions, DNS, TLS, flows) and `honeypot-nginx-*` (nginx access/security logs + Lua security events — routing decisions, threat scores, CVE matches). Recommended Kibana dashboards: real-time threat overview, IDS alerts, session analysis, attack patterns. None of this is built yet in Kibana itself — still open work (see §8).

To enable: set `ELK_ENABLED=true` plus `ELASTICSEARCH_HOST`/`PORT`/credentials in `.env`, install the ES CA cert to `vector/certs/ca.crt`, then `docker compose --profile elk up -d`. Expected data volume: ~200–750 MB/day combined.

---

## 7. Refactoring History & Framework Choice

See `architecture.canvas` (open the repo root as an Obsidian vault) for the full component-by-component diagram — 37 nodes, responsibility/refactoring-needs/overlap-to-fuse notes on every one, color-coded by status.

Short version: this isn't one application, so MVC doesn't fit — it's three subsystems with their own idioms (a WordPress app with its own hook/theme conventions, Docker-Compose infra, and the actual thesis contribution: the Lua detection pipeline). For that pipeline, the chosen pattern is a **numbered middleware chain built from pure decision cores + thin I/O adapters** (§3.2). `lua_pattern_utils.lua` is the one concrete code-level "fuse" executed this session, consolidating `url_decode`/`escape_pattern`, which had drifted into 3 independent copies.

Two other real duplication/overlap findings, not (yet) fixed at the code level:
- Two near-identical `header_filter_by_lua_block`s in `nginx.conf` (`[HEADER_FILTER]` server-level and `[LOCATION / HEADER]` location-level) do almost the same thing.
- Three modules (`session_handler.lua`, `threat_rules.lua`/`sophistication_analyzer.lua`) each independently interpret the same User-Agent string for different purposes — a shared UA-classification utility would remove that repetition.

---

## 8. Roadmap (merged from `CHECKLIST.md` + `PROMPT_TODO.md` — deduplicated; the two had substantially overlapping pooling/hardening/testing content)

### Done
- Multi-instance honeypot pooling with per-IP sticky routing (docker-compose replicas, `pool_router.lua`)
- OWASP WSTG vulnerability integration with Suricata + Nginx Lua
- API-level + attempted SQL-level honeypot integration (SQL-level: scaffolded, never completed — see §9)
- Honeytokens
- Botnet slowdown (tarpit delays)
- AbuseIPDB, sophistication scoring, prompt injection filter, blind pentest evaluation (this session)
- Pure/adapter Lua refactor + 143 unit tests (this session)

### Still open
- Production hardening: disable XML-RPC, hotlink protection, obfuscate publicly-queryable service versions (WooCommerce/WordPress/Nginx), backup automation, hardened honeypot Docker service (contain a docker takeover to the single compromised container), a custom hardening script
- ELK Dashboards (Kibana side is unbuilt — see §6)
- Code-level docs beyond what exists in Lua comments
- Diagrams: pooling architecture, hardening-vs-best-practices, test-scenario coverage map, proactive-defense overview (partially superseded by `architecture.canvas`, which covers the last of these)
- Data preparation for research use (interaction-depth metrics, session duration comparisons — see `COUNTERARGUMENTS.md` Q18)
- Bonus/exploratory ideas (not committed to): a Honeypot Setup Frontend (toggle features/settings pre-deployment); single-WordPress-frontend-with-dual-database research comparison (see §9 — the SQL-proxy attempt already showed why this is hard); an LLM feature that fetches latest CVEs and generates matching Lua detection rules

### WordPress plugins still to preinstall
WooCommerce Cart Abandonment Recovery, WPify Slovensko/Česko, HubSpot Chatbot, Elementor, 2FA, WP REST API, Wordfence, a mail plugin, Stripe, Cloudflare.

---

## 9. Known Issues & Stale-Documentation Corrections

Verified this session by checking claims against running code — these are corrections to earlier documentation (now removed) that had drifted from reality, plus genuinely open bugs:

- **SQL Proxy Routing was never completed, despite being documented as if finished.** The old `SQL_PROXY_ROUTING.md` described a single-WordPress-frontend, dual-database architecture (`X-DB-Target` header → custom `wp-content/db.php` drop-in) in full technical detail, with test scripts, logs, and a "Version 1.0.0" marker. In reality: `wp-content/db.php` **does not exist**, and the only code that would set `X-DB-Target` (`router.lua`'s `apply_routing_decision()`) is **dead code, never called**. Only the Docker network topology (both WordPress instances reachable on both DB networks) was actually put in place. This matches `COUNTERARGUMENTS.md` Q1, which correctly states the SQL-proxy approach was "considered" but deemed infeasible — the two documents contradicted each other; this file now reflects the correct, current state (two-instance Nginx routing, no SQL proxy).
- **The old `openstack-work/README.md`'s architecture diagram and integration guide described a Node.js Session Manager and a Python Threat Intel service as live, working components**, with detailed request-flow code samples. Both are confirmed **dead code** — `docker-compose.yml` explicitly comments them out with `# DEAD CODE:` markers, alongside `traffic_mirror`, `log_aggregator`, and `file_sync` (also referenced as a working "continuous 5-minute sync" feature in that same old README). The actual system does all of this directly in Lua + Redis, described accurately in §3 above.
- **`deploy.sh`, `test_system.sh`, and `test_sql_routing.sh` do not exist** despite being referenced as primary entry points in old docs. Use `docker compose` directly (§1).
- **`nginx.conf` is baked into the Docker image at build time** while `reverse_proxy_enhanced/lua/*.lua` is bind-mounted live — `docker compose restart` silently does not pick up nginx.conf edits, only `--build` does. Discovered mid-session while debugging what looked like a code change having no effect.
- **`init_setup`'s file-copy is one-shot** — honeypot pool volumes drift from `production_eshop_files/` after first provisioning (§3.4).
- **The IPv4-only whitelist** (`_G.utils.is_ip_whitelisted` in `init.lua`) doesn't match IPv6 — `127.0.0.1/32` never matches loopback over IPv6 (`::1`). Prefer `curl -4` when testing locally.
- **`suricata_ids` exits immediately** in the local stack (§3.6) — not root-caused.
- **The `X-Route-Target`/`X-Threat-Score` leak is fixed** (this session) — previously returned to every client on every response, which is exactly what let the blind-pentest agent (§5.2) partially confirm the deception. Now gated behind `X-Internal-Test-Auth` (`INTERNAL_TEST_SECRET` in `.env`); fails closed if unset.
- **The self-signed TLS cert's `O=HoneypotOrg` and the `HONEYPOT_SESSION` cookie name are real, tracked, self-incriminating values**, not local-testing artifacts — confirmed by the blind pentest (§5.2). Not fixed this session; flagged as a genuine finding.

---

## 10. Session History (condensed changelog, superseding the raw AI-session handoff notes this replaces)

- **AbuseIPDB integration**: bulk blacklist + on-demand checks + gated report-back. Required adding `ca-certificates` to the reverse_proxy Dockerfile (Alpine's OpenResty image has no CA bundle by default, breaking outbound HTTPS cosockets) and copying the bundle to `/usr/local/openresty/` specifically, since docker-compose bind-mounts shadow both `/etc/nginx` and `/etc/ssl/certs` at runtime.
- **Sophistication scoring, prompt injection filter**: see §4.3.
- **Blind pentest evaluation**: see §5.2.
- **Local deployment stood up** (the `arch` VM referenced in older docs/`~/.ssh/config` is stale/gone) — required regenerating SSL certs on the host (the containerized `init_setup` cert-gen hung/split unpredictably, not fully diagnosed), importing the SQL dump into all four MySQL instances, fixing `siteurl`/`home` in `wp_options` (dumped as `http://openstack.local`), and adding `FS_METHOD=direct` to `wp-config.php` (a real, pre-existing bug — WordPress was attempting FTP-based filesystem access with no FTP configured).
- **Lua pure/adapter refactor + `lua_pattern_utils.lua` fuse**: see §3.2 and §7.

---

## 11. Related documentation still living in their own files

- `architecture.canvas` — full system diagram (Obsidian Canvas)
- `testing/BLIND_PENTEST_PROTOCOL.md`, `testing/blind_pentest_report_run1.md` — blind pentest protocol + results
- `openstack-work/elk-siem-testing.md` — a separate, substantial prior academic report (SIEM/ELK technology evaluation: SecurityOnion, Splunk, QRadar, Wazuh comparison; Logstash JSON-parsing fragility findings that motivated switching to Vector) — kept as-is rather than merged in, since it's a complete, citation-backed academic deliverable in its own voice
- `master-thesis-rewrite-plan/` — speculative, **not-yet-implemented** research proposals; see §12
- `openstack-siem-work/elk_dockerized/README.md` — the SIEM sub-project's own setup doc

---

## 12. Thesis & Academic Material

Not merged into this file (intentionally out of scope — this file is technical/functional, not thesis-like):

- `COUNTERARGUMENTS.md` — 41 anticipated committee questions + counterarguments
- `PLAN_DP1.md` / `PLAN_DP2.md` / `PLAN_DP3.md` — semester milestone plans (DP1 analysis, DP2 implementation, DP3 testing phases)
- `master-thesis-latex/` — the thesis itself
- `master-thesis-rewrite-plan/NEW_PLAN.md`, `THESIS_PLAN.md`, `HN_Honeypot.md`, `HN_Kibana.md`, `HN_Suricata.md` — an AI-research-assisted "Shadow Honeypot" rewrite proposal. **Important**: this describes a *possible future direction*, not the current implementation — e.g. it proposes Suricata integration via `ngx_http_mirror_module` traffic mirroring, but the actual system uses AF_PACKET network capture (§3.6); it proposes LLM-driven dynamic response generation, which doesn't exist yet (`prompt_injection_filter.lua` is defensive-only, no LLM feature consumes it). See `future-claude-prompts.md` for how much of this proposal is still worth pursuing vs. superseded by what's actually been built.

See `future-claude-prompts.md` at the repo root for detailed, actionable prompts to complete the WIP thesis chapters.

---

## 13. Primary Literature

[1] SRINIVASA, Shishir, PEDERSEN, Jens M. a VASILOMANOLAKIS, Emmanouil, 2023. Gotta Catch 'em All: A Multistage Framework for Honeypot Fingerprinting. Digital Threats. Roč. 4, č. 3. DOI: 10.1145/3584976

[2] NINTSIOU, Maria, GRIGORIOU, Elisavet, KARYPIDIS, Paris Alexandros, SAOULIDIS, Theocharis, FOUNTOUKIDIS, Eleftherios a SARIGIANNIDIS, Panagiotis, 2023. Threat intelligence using Digital Twin honeypots in Cybersecurity. In: IEEE International Conference on Cyber Security and Resilience (CSR). s. 530-537. DOI: 10.1109/CSR57506.2023.10224997
