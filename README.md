<p align="center">
  <img src="dashboard/resources/app_icon.svg" alt="Honeypot IDS System logo" width="96" height="96">
</p>

<h1 align="center">Honeypot IDS System</h1>
<p align="center">
  <em>Zlepšenie efektivity honeypot nástroja pomocou zvýšenia úrovne interakcie</em><br>
  <em>Improving Honeypot Tool Efficiency by Increasing Interaction Level</em>
</p>

---
Name:   Zlepšenie efektivity honeypot nástroja pomocou zvýšenia úrovne interakcie
Eng:    Improving Honeypot Tool Efficiency by Increasing Interaction Level
Place:  Ústav počítačového inžinierstva a aplikovanej informatiky, FIIT STU
Oblasť: Kombinované bezpečnostné riešenia

# Technical & Operational Manual

This file is the single technical/functional manual for the project: what it is, how to run it, how it works in detail, what's known-broken, and what's left to do. It supersedes and merges the following (now removed) files: `CHECKLIST.md`, `CHECKLIST-MANUAL.md`, `PROMPT_TODO.md`, `walkthrough.md` (both the root and `ids/` copies), `refactoring-plan.md`, `summary-for-claude.md`, `ids/README.md`, `ids/ELK_INTEGRATION.md`, `ids/SQL_PROXY_ROUTING.md`, and `ids/reverse_proxy_enhanced/HONEYPOT_ROUTING_TEST_CASES.md`. Thesis-scoped material (the LaTeX thesis under `master-thesis-latex/`) stays separate — see [§12](#12-thesis--academic-material). `COUNTERARGUMENTS.md`, `PLAN_DP1-3.md`, and `master-thesis-rewrite-plan/` are cited a few times below for historical context but no longer exist in the repository (removed in a later cleanup pass — see §12's note).

Every claim below was checked against the running system or the current source as of this writing, not copied forward from older docs — see [§9](#9-known-issues--stale-documentation-corrections) for what was found stale in the files this replaces and corrected here.

---

## 1. Quick Reference

### What this is

A WordPress/WooCommerce e-commerce site with an OpenResty (Nginx + Lua) reverse proxy that scores every request in real time and transparently diverts suspicious traffic to one of three isolated honeypot instances instead of the real production site — while legitimate users never notice. Suricata IDS taps the network layer; Redis holds session/routing state; logs optionally ship to a separate SIEM host (Elasticsearch + Kibana) over mTLS via Vector.

### Two-host run order

This system spans **two separate hosts/VMs**, each its own independent `docker-compose.yml` project (`ids/` and `siem/`) with no shared files or networks — see `ARCHITECTURE.md` at the repo root for the full write-up (data-flow diagram, why the split is a deliberate security boundary rather than an accident, and exactly how to run both together on a single host for testing without merging them):

```bash
# 1. On the SIEM VM first:
sudo apt install docker docker-compose curl wget zip unzip git jq
cd siem/certs/root-ca && ./gen_elk_certs.sh && cd ../../docker
sudo docker compose up
# wait for http://<siem-vm-ip>:5601/app/home#/ to be reachable

# 2. Then on the main/edge VM:
sudo apt install docker docker-compose curl wget zip unzip git jq
cd ids
sudo docker compose up
```

The SIEM half is optional for local development — the main stack runs standalone without it; you only need it if you want shipped logs to land somewhere (see [§6](#6-observability-elk--siem)). For running *both* halves together on one machine (e.g. to actually test the log pipeline rather than just the honeypot itself), see `ARCHITECTURE.md`'s "Running both on one host" section — verified working this session, including two real bugs it surfaced in the SIEM side that also affected the genuine two-host deployment.

**Or skip the CLI entirely**: `dashboard/` is a PyQt6 desktop app (`cd dashboard && ./run.sh`, sets up its own venv on first run) that does all of the above through a GUI — a setup wizard for both `.env` files, Start/Restart/Stop/Purge for each project (local and, if configured, a real remote host over SSH), a live auto-refreshing health diagram of every container with per-service restart/logs/open-web-UI/open-shell actions, and per-service certificate regeneration. See `dashboard/README.md`.

### First-time setup (main VM / local dev)

```bash
cd ids
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

There is no `deploy.sh` or `test_system.sh` in this repository — despite being referenced by that name in the old `ids/README.md` this file replaces, neither script exists. Use `docker compose` directly, as above.

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

# Reset the demo storefront (production + all 3 honeypot pools) to a clean
# seeded state -- WordPress/WooCommerce/Elementor reinstalled from scratch,
# honeypot pools re-synced immediately after. Useful after running exploits
# against it. See §3.4.1.
FORCE_RESEED=1 docker compose up production_db_seed && docker compose restart honeypot_content_sync

# List/label/delete/export/import backup_service's backups from the CLI
# (the dashboard's Backups page does the same thing, either works). See §3.4.2.
./backups/manage_backups.sh list
```

### Access points (local dev)

- `https://localhost/` — main site, intelligent routing between production/honeypot (self-signed cert, auto-generated on `init_setup`)
- `X-Route-Target` response header shows the routing decision, but **only when the request carries a matching `X-Internal-Test-Auth` header** (see [§5](#5-testing)) — this used to leak to every client until this session's fix; see [§9](#9-known-issues--stale-documentation-corrections).
- `docker compose logs -f reverse_proxy` — the single most useful log stream; every request logs its threat score, routing decision, and stage that triggered it.
- `tail -f suricata_logs/fast.log` / `eve.json` — IDS alerts (see [§9](#9-known-issues--stale-documentation-corrections) for the current known issue with this).

### Where things live

```
ids/
├── reverse_proxy_enhanced/lua/   # the actual thesis contribution — see §4
├── reverse_proxy_enhanced/nginx.conf
├── production_eshop_files/       # real WordPress+WooCommerce+omega-storefront theme
├── production_eshop_files_fresh_for_diff/  # pristine copy, for diffing only
├── testing/                      # scenario_01-09.sh + BLIND_PENTEST_PROTOCOL.md — see §5
├── docker-compose.yml            # ~14 services, see §3
├── suricata_config/, suricata_rules/, suricata_logs/
├── vector/                       # local log shipper config (Vector, mTLS out to SIEM)
├── scripts/redis_key_audit.sh    # live Redis keyspace vs. §3.5's documented schema — see §3.5
├── scripts/hardening_audit.sh    # live production-hardening checks (XML-RPC, hotlink, versions, backups, container caps) — see §9.3
├── ssl_certificates/             # gitignored, regenerate on fresh clone
└── .env / .env.example

siem/   # SEPARATE docker-compose project — SIEM backend, own host
ARCHITECTURE.md                       # the two-host split: why, data flow, single-host testing — see §1/§6
dashboard/                            # PyQt6 GUI: start/stop/health/certs/settings for both projects, local+remote — see dashboard/README.md
master-thesis-latex/                  # the thesis itself (LaTeX)
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

As of this session, the request-handling Lua code follows a deliberate **pipeline + ports-and-adapters** pattern (chosen over MVC for a codebase this size — understandable structure, testable without a running nginx/Redis stack): a `*_rules.lua` module holds pure decision logic with **zero `ngx.*`/`_G.*` dependency**, unit-testable with a plain `lua` interpreter; the original `*.lua` file is a thin adapter that pulls config/request context and does all Redis/nginx I/O.

| Adapter | Pure core | Tests | Responsibility |
|---|---|---|---|
| `threat_analyzer.lua` | `threat_rules.lua` | 37 | Request scoring |
| `router.lua` | `router_rules.lua` | 29 | Routing predicates (not the staged `decide_route()` itself — see below) |
| `vulnerability_handler.lua` | `vulnerability_rules.lua` | 16 | CVE + exploit-kit pattern matching |
| `upload_handler.lua` | `upload_rules.lua` | 32 | File-upload threat scoring |
| `session_handler.lua` | `session_rules.lua` | 21 | Session anomaly detection + honeypot-routing eligibility |
| `admin_handler.lua` | `admin_rules.lua` | 37 | Login/brute-force scoring, admin-pattern detection, ajax-action matching, credential-stuffing scoring |
| `honeytoken_handler.lua` | `honeytoken_rules.lua` | 9 | Token-in-corpus matching |
| `abuseipdb_client.lua` | `abuseipdb_rules.lua` | 14 | Report-eligibility + category mapping |
| — | `prompt_injection_filter.lua` | 20 | OWASP LLM01-style detection (already pure by design, the original model for this pattern) |
| — | `sophistication_analyzer.lua` | (fixed, untested pre-session) | Attacker classification |
| — | `lua_pattern_utils.lua` | 9 | Shared `url_decode`/`escape_pattern`, deduplicated from 3 copies |

**224 unit tests total, all passing** (`cd ids/reverse_proxy_enhanced/lua/tests && for f in test_*.lua; do lua "$f"; done`). `router.decide_route()` deliberately stays impure — its 10-stage pipeline interleaves session mutation with Redis/AbuseIPDB I/O too deeply to safely extract without risking a bug in the single most consequential function in the system; only its self-contained predicates (`is_static_asset`, `is_admin_access`, `is_rapid_automation`, `is_suspicious_upload`, `is_vulnerable_plugin_access`) were moved out.

**Every `architecture.canvas` refactor candidate is now either split or confirmed to need no split.** The four adapters above (`session_handler.lua`, `admin_handler.lua`, `honeytoken_handler.lua`, `abuseipdb_client.lua`) were originally assessed as "I/O-dominated, lower value" and left unsplit — a later pass found genuinely pure decision cores in all four anyway (81 new tests) once the `ngx.*`/`_G.*` reads were turned into parameters. One real bug surfaced doing it: `session_handler.lua` had its own third, never-reconciled copy of the static-asset check (`router_rules.lua` and `threat_rules.lua` already document reconciling two disagreeing copies of this same check) that still didn't strip the query string, undercounting `request_count` for static-asset loads with cache-busting query strings. `pool_router.lua` is the one node that was assessed and correctly left alone both times — 100% Redis I/O, zero pattern-matching, no pure core exists to extract.

Writing these tests surfaced **six real, previously-invisible bugs**, all fixed and verified live:
1. `sophistication_analyzer.lua`'s `signals` audit list was silently empty on any session under 3 requests (Lua `ipairs`-over-a-leading-`nil`-hole gotcha).
2. `router.lua`'s `assign_honeypot_pool()` clobbered session data (lost `user_agent`) before the sophistication classifier saw it.
3. `threat_analyzer.lua`'s `high_request_rate` IP-reputation signal was permanently dead — the counter it read was never written by anything.
4. **`router.lua` Stage 5 never matched a single hyphenated plugin slug** — i.e. every seeded vulnerable plugin except `cwmp` — because plugin names were concatenated unescaped into Lua patterns (`-` is a lazy-repeat magic character, not a literal hyphen there). Masked by an overlapping nginx-level regex `location` block that only covers `.php/.asp/.aspx/.jsp` files.
5. **A live HTTP 500**: any POST to `/wp-admin/admin-ajax.php` with a non-empty, upload-looking query string crashed (`%2e%2e%2f`/`%2e%2e/` read as invalid Lua pattern backreferences). Confirmed with a real request before/after the fix.
6. That crash was masking a **second** crash right behind it: `red:get('threat_ips') or '{}'` doesn't handle Redis's `ngx.null` "missing key" sentinel (truthy in Lua), so `cjson.decode` failed on any fresh/flushed Redis — present in 4 places across `admin_handler.lua`, `upload_handler.lua`, and `vulnerability_handler.lua`.

### 3.3 Docker Compose services (verified current, via `docker compose config --services`)

`init_setup`, `honeypot_db_migration`, `production_database`, `production_db_seed`, `production_eshop`, `honeypot_database_1/2/3`, `honeypot_db_seed_1/2/3`, `honeypot_eshop_1/2/3`, `session_store` (Redis), `suricata_ids`, `backup_service`, `reverse_proxy`, `honeypot_content_sync`. **18 services total.** `vector` exists in `docker-compose.yml` but is gated behind `profiles: [elk]` — it does **not** start with a plain `docker compose up`; use `docker compose --profile elk up -d`.

`production_db_seed`/`honeypot_db_seed_1/2/3` are one-shot (they run once and exit 0) — see §3.4.1 for what they do and why they exist.

Networks: `production_network`, `honeypot_network`, `monitoring_network`, `session_network`, `ids_network`, plus a `setup_network` that's defined but never assigned to any service (dead, harmless).

### 3.4 WordPress / WooCommerce layer

`production_eshop_files/` — real WordPress + WooCommerce + a custom `omega-storefront` theme + mu-plugins, served on the production path. `production_eshop_files_fresh_for_diff/` sits alongside it as a pristine reference copy for diffing (intentional, not stale duplication). Three honeypot pool instances mirror production's fingerprint (same DB name `production_database`, same theme/plugins) so an attacker sees a consistent fake environment once IP-bound via `pool_router.lua`.

**Fixed (was: known architectural gap)**: `init_setup`'s WordPress file-copy step now uses `rsync -a` and re-runs on every `docker compose up`, instead of the old one-shot `tar` copy that skipped entirely once a destination had any content — that used to make honeypot pool volumes silently drift from `production_eshop_files/` after first provisioning (hit directly earlier this session: pools were missing an entire theme + mu-plugins directory after a file was added post-provisioning, worked around manually via `docker cp`). The sync deliberately does **not** use `--delete`: it's a one-directional add/update from source, so files that exist only in a pool's volume (attacker-uploaded webshells under `wp-content/uploads`, other forensic artifacts from a real session) are left untouched — verified live by planting a file in a pool, re-running `init_setup`, and confirming it survived. `production-hardening.php` removal still runs after every sync (it re-reads from source each time now, so the removal has to be re-applied every run, not just once). Database data directories (`copy_files`, not `sync_files`) intentionally kept the old one-shot skip-if-populated behavior — that data is live, mutable MySQL state where an always-resync policy would be actively wrong, not just unnecessary.

**Plugin roster** (as of this session — installed directly via WP core's `activate_plugin()`/`ZipArchive` against `wp-load.php`, not `wp-cli`; see the note on why below):

| Plugin | Slug | Production | Honeypot pools |
|---|---|---|---|
| Cart Abandonment Recovery for WooCommerce | `woo-cart-abandonment-recovery` | active | active |
| WPify Woo (CZ/SK: CRN/VAT, Heureka, QR payments, etc. — this is what "WPify Slovensko/Česko" actually ships as, a single unified free plugin, not two separate ones) | `wpify-woo` | active | active |
| HubSpot All-In-One Marketing (forms/popups/live chat — this is HubSpot's actual chatbot plugin) | `leadin` | active | active |
| Elementor | `elementor` | active | active |
| WP Mail SMTP (reliable transactional-email delivery; MailPoet was already installed/active separately for newsletters — different purpose, kept both) | `wp-mail-smtp` | active | active |
| Cloudflare (official) | `cloudflare` | active | active |
| Two-Factor (official core-contributor 2FA plugin) | `two-factor` | active | **installed, not activated** |
| Wordfence Security | `wordfence` | active | **installed, not activated** |

Stripe (`woocommerce-gateway-stripe`) was already installed and active before this session — no action needed. "WP REST API" wasn't installed as a separate plugin: WordPress core has shipped the REST API natively since 4.7 (2016), it's already fully live (the seeded CVE-2023-28121 pattern in `vulnerability_rules.lua` specifically targets `/wp-json/wp/v2/users`), and there's no actively-maintained standalone plugin that would add anything a fresh install of that name doesn't already have.

**Wordfence and Two-Factor are deliberately left inactive on all three honeypot pools** (though the plugin *files* are synced there like everything else, so an attacker enumerating installed plugins via `readme.txt`/asset-path probing sees the same fingerprint as production). Both are defensive/blocking plugins — Wordfence's firewall and login-attempt limiting, Two-Factor's mandatory second login step — activating either would work directly against the honeypot's purpose of staying genuinely exploitable. This is the same reasoning `init_setup` already applies by stripping `production-hardening.php` from honeypot pool files; it just couldn't be done at the file level here since these are real third-party plugins attackers can also just download and diff against, so the split happens in each pool's own `active_plugins` DB option instead (each honeypot pool has always had its own independent database, populated once from a separate SQL dump import — see §10 — so this doesn't need a new mechanism, just a per-pool activation pass, done manually this session via the script below).

**`wp-cli` now works — an earlier session's "why not `wp-cli`" writeup here was wrong about the root cause and has been superseded.** That writeup correctly found and fixed one bug (`production-hardening.php`'s `rest_endpoints` filter assumed every entry under a REST route was a `methods`/`callback`/`permission_callback` array, but `WP_REST_Server::get_routes()` also stores a `'schema'` entry per route — a plain 2-element callable, not that shape), but concluded the *second*, deeper crash it then hit (`call_user_func(): argument #1 must be a valid callback, array must have exactly two members`, inside WordPress core's `WP_REST_Server::get_data_for_route()`) was "a genuine `WC_CLI_Runner`/WordPress-core/PHP 8.1 compatibility gap" unrelated to the hardening mu-plugin, and gave up on `wp-cli` entirely in favor of a hand-rolled PHP script. **It was the same bug, one step further in**: the first fix's `is_array($handler)` check let the `'schema'` entry through too (a 2-element callable *is* an array), so the code still wrote a `permission_callback` string key into it — turning a valid 2-element PHP callable into an invalid 3-element array, which is exactly what "`array must have exactly two members`" means. Confirmed live by bisecting (temporarily removing the mu-plugin entirely made `wp plugin activate woocommerce` succeed). **Properly fixed** by checking for a `callback` key specifically (`! is_array($handler) || ! isset($handler['callback'])`), which correctly distinguishes a real per-HTTP-method handler array (always has one) from the `'schema'` entry (never does) instead of just checking `is_array()`. Verified live end-to-end: `wp core install`, `wp plugin activate woocommerce`, and every subsequent `wp` command all now work cleanly with the hardening filter still fully active (re-verified `/wp/v2/users` is still auth-gated). This is what `scripts/seed_wordpress_db.sh` (§3.4.1) is built on.

**Not configured — needs real credentials, deliberately not fabricated**: Cloudflare (API token + zone), Wordfence (license key), HubSpot/`leadin` (account connection), WP Mail SMTP (an actual SMTP provider), Elementor Pro (license, if the paid tier is ever wanted). All are active with their free-tier defaults and will show a normal WordPress "connect your account" admin notice until configured.

#### 3.4.1 Ready-to-attack storefront on a fresh clone (`production_db_seed` / `honeypot_db_seed_1/2/3`)

**The problem**: `production_eshop_files/` (core, plugins, themes, uploads) is fully git-tracked, so a fresh clone already has the entire WordPress *codebase* — but `production_database` and all three `honeypot_database_N` start with zero tables (confirmed live: `production_database` had a bare `mysqldump` header/footer with no `CREATE TABLE` at all; the honeypot pools had only their own `honeypot_ip_assignments`/`honeypot_pool_events`/`honeypot_pool_registry` bookkeeping tables, never any `wp_*` one). Nothing had ever run `wp core install` against any of the four. This is also the actual root cause of the recurring `WordPress database error: Table '...wp_options' doesn't exist` — it's WordPress core failing on the very first option read, on *any* request, not an Elementor-specific bug (Elementor's `elementor_meta_generator_tag` option write just happened to be the one shown in the report, because it's an early `init`-hooked write) — and it recurred on a clock because `wp_install_state.lua`'s own 30s health probe (`init_worker.lua`) hits `wp-admin/install.php` on every cycle.

**The fix**: `scripts/seed_wordpress_db.sh`, run once per database by a one-shot `wordpress:cli-php8.1` service (`production_db_seed`, `honeypot_db_seed_1/2/3`) that the corresponding eshop container now `depends_on: condition: service_completed_successfully` — so `production_eshop`/`honeypot_eshop_N` can never start serving requests (or be health-probed) against a schemaless database again. The script runs `wp core install`, activates the theme + WooCommerce + Elementor (deliberately *not* every other installed plugin — see the script's own comment: activating Wordfence/Jetpack/etc. for real would work against the honeypot's purpose or hang on an unreachable external connection, and classic pre-auth plugin CVEs target the PHP file path directly regardless of WordPress "active" status anyway), and — production only — imports WooCommerce's own official sample product catalog (`wp-content/plugins/woocommerce/sample-data/sample_products.xml`, ~18 products) and authors two Elementor-built pages (home + About Us, one set as the static front page) via `scripts/seed_elementor_pages.sh`. Idempotent (bails out immediately if already installed); pass `FORCE_RESEED=1` to wipe and rebuild from scratch (see the dashboard's Backups page "Reset demo store" button, or the one-liner in [§1](#1-quick-reference)'s Common Commands).

**Why not a committed SQL dump / git-lfs binary** (the originally-requested approach): `ids/backups/.gitattributes` already routes `db/*.sql.gz`/`wp/*.tar.gz` through git-lfs, but GitHub's free LFS tier is only 1GB storage / 1GB bandwidth *per month*, total, across the whole repo — a real WordPress file archive backup is already 143–232MB *per generation* (§3.4.2), and a real WooCommerce+Elementor DB dump would add more on top. A few KB of plain-text, `git diff`-reviewable WP-CLI commands that deterministically rebuild the same state from the already-committed plugin/theme code sidesteps that entirely, and needs no regeneration when the demo content changes — just edit the script.

**Honeypot pools need the exact same fix, for a subtler reason**: `honeypot_content_sync`'s replication (`scripts/replicate_content_to_honeypot.sh`) does a *scoped* `DELETE`+`INSERT` into **existing** tables — it mirrors content rows, it never creates schema. Without `honeypot_db_seed_1/2/3` first, every replication cycle against all three pools would fail (`Table '...wp_postmeta' doesn't exist`) regardless of production's own state. `honeypot_content_sync` now `depends_on` all four seed services completing, so its very first cycle already has both a real source (production) and real destinations (all three pools) to work with — verified live: a fresh `docker compose up` (then a manual `docker compose restart honeypot_content_sync` to trigger a cycle immediately instead of waiting out `REPLICATION_INTERVAL_SECONDS`) leaves production and all three pools at an identical 18-product catalog, and `production_db_seed`/every `restore_db_command` invocation in the dashboard now chains a `honeypot_content_sync` restart automatically for the same reason. **Status is always visible**, not just assumed: the triggering command's own echoed progress streams live into whichever panel ran it (the dashboard's Backups page, or your terminal for the CLI one-liner), and the Health page's "Content sync activity" panel parses `honeypot_content_sync`'s own per-pool `starting`/`complete`/`failed` log lines out of the same restart's live log tail — so a stuck or failing pool is visible immediately, not silently assumed to have worked.

Honeypot pools set `IMPORT_SAMPLE_CONTENT=0` (no independent WooCommerce sample import, no Elementor authoring) — a honeypot pool is meant to have content *identical* to production, mirrored by `honeypot_content_sync`, not its own separately-authored copy; `WP_SITE_URL` is also deliberately identical across all four (not pool-specific), matching `pool_router.lua`'s whole premise that an attacker sees the same public fingerprint regardless of which pool they land on.

#### 3.4.2 Backup lifecycle: label, delete, export, import (not just from the dashboard)

`backup_service`'s nightly dumps (`ids/backups/{db,wp}/*.gz`, §9.3) can now be labeled, deleted, exported to a local file, and re-imported — from the dashboard's Backups page *or* from the command line via `ids/backups/manage_backups.sh` (`list`/`label`/`delete`/`export`/`import`), which reads and writes the exact same `labels.json` manifest inside `backup_service` (`docker compose exec`) that the dashboard does, so a label set from one shows up in the other immediately. See the script's own header comment for exact usage. The same page also has the "Reset demo store" action described in §3.4.1.

`ids/backups/.gitattributes` already routed `db/*.sql.gz`/`wp/*.tar.gz` through git-lfs, but the root `.gitignore`'s blanket `*.sql.gz`/`*.tar.gz` rules were silently shadowing that — `git check-ignore` confirmed every real backup file was ignored regardless, so despite the LFS plumbing existing, zero backup files had ever actually reached git. **Fixed** with narrow negation exceptions (`!ids/backups/db/*.sql.gz`, `!ids/backups/wp/*.tar.gz`) — this does not mean backups are committed automatically (nothing changed about what gets `git add`ed by default), it means a backup you've deliberately chosen to keep (labeled, then `git add`ed) actually can be, rather than being invisibly dropped regardless of intent.

### 3.5 Session, Redis & IP-based state

There are **two separate key-value stores** in play, and a recurring source of confusion (`ip:*` and `attempt_key`, previously miscategorized as Redis in an earlier version of this section, are actually neither) is that a name alone doesn't tell you which one a given key lives in:

- **Redis (`session_store` container)** — durable, shared across all `reverse_proxy` worker processes and survives a container restart.
- **`ngx.shared` dicts** — four separate in-process memory regions (`sessions`, `threat_intel`, `rate_limit`, `honeypot_routes`; sized in `nginx.conf`'s `lua_shared_dict` directives), shared across worker processes *within one nginx container* but **not** durable — lost on reload/restart, and not shared with any other `reverse_proxy` replica if one is ever added.

This schema was reconstructed by reading all ~10 Lua files that touch either store (there is no other source of truth for it) — verify against the code directly if a key's exact behavior matters, since this table can drift the same way the code itself did.

**Redis keys** (`session_store`, `SELECT 0` unless noted):

| Key / pattern | Type | TTL | Written by | Read by |
|---|---|---|---|---|
| `session:<session_id>` | string (JSON) | `config.session.max_idle_time` (`SETEX`) | `session_handler.lua` | `session_handler.lua` |
| `active_sessions` | set | none | `session_handler.lua` (`SADD` on create) | **nothing** — write-only, never read by any Lua code |
| `compromised_sessions` | set | 24h, reset on every `SADD` (whole-set TTL, not per-member) | `session_handler.lua` | **nothing** — write-only |
| `threat_ips` | string (single JSON blob, `{ip: {raw_score, reason, updated, ...}}`) | **none — unbounded growth**, never trimmed or expired | `init_worker.lua` (Suricata alert parser), `admin_handler.lua`, `vulnerability_handler.lua` (×2), `upload_handler.lua`, `abuseipdb_client.lua` | same five files (each does a read-modify-write cycle) |
| `honeytoken:<token_id>` | string (JSON) | 2592000s (30d) | `honeytoken_handler.lua` | `honeytoken_handler.lua` |
| `honeypot_pool_ip:<ip>` | string (pool number) | 86400s (24h), refreshed on every hit | `pool_router.lua` | `pool_router.lua` — sticky pool assignment |
| `honeypot_pool:counter` | string (int, `INCR`) | none | `pool_router.lua` | `pool_router.lua` — round-robin pool assignment |
| `admin_access_logs` | list | none, capped to 1000 via `LTRIM` | `admin_handler.lua` | `admin_handler.lua` (`LRANGE`, last 100, for the admin log view) |
| `vulnerability_events` | list | none, capped to 1000 via `LTRIM` | `vulnerability_handler.lua` | **nothing** — write-only forensic trail |
| `vulnerability_scans` | list | none, capped to 1000 via `LTRIM` | `vulnerability_handler.lua` | **nothing** — write-only forensic trail |
| `cve:<cve_id>` | list | 30d, capped to 100 via `LTRIM` | `vulnerability_handler.lua` | **nothing** — write-only forensic trail |
| `vuln_by_ip:<ip>` | list | 7d, capped to 100; a `cleanup_old_vulnerability_data()` job backfills the TTL on any key missing one | `vulnerability_handler.lua` | same cleanup job (`KEYS vuln_by_ip:*` scan) |
| `vuln_stats` | hash (`HINCRBY` counters: `total_attempts`, `unique_ips`, one field per CVE) | none | `vulnerability_handler.lua` | `vulnerability_handler.lua` (`get_vulnerability_stats()`, `HGETALL`) |
| `suspicious_uploads` | list | none, capped to 1000 via `LTRIM` | `upload_handler.lua` | `upload_handler.lua` (`LRANGE`, for the upload security report) |
| `suricata_alerts` | list | none, capped to ~1000 via `LTRIM` | `init_worker.lua` (Suricata `fast.log` tailer) | **nothing** — write-only forensic trail |
| `suricata_log_position` | string (byte offset int) | none | `init_worker.lua` | `init_worker.lua` — bookmark for tailing `fast.log` across timer runs |

**`ngx.shared` dict keys** (in-process, per-`reverse_proxy`-container, lost on reload):

| Dict | Key pattern | TTL | Purpose |
|---|---|---|---|
| `sessions` | `session:<session_id>` (same prefix as the Redis key — deliberate, makes the two easy to cross-reference) | 300s (5 min) | Fast local mirror of the Redis session record, to skip a Redis round-trip on every request |
| `threat_intel` | `threat_ips` (same key name as the Redis key it mirrors — a single JSON blob, not a real hash) | none | The copy `threat_analyzer.lua` actually reads on the hot request path — it **never queries Redis directly**, for latency |
| `threat_intel` | `health:<backend_name>` | 300s (5 min, set in `health_check.lua`) | Backend health-check status (`health_check.lua` reuses the `threat_intel` dict rather than a dedicated one — worth knowing if you're hunting for health data and only think to check `rate_limit`) |
| `threat_intel` | `abuseipdb_checked:<ip>`, `abuseipdb_reported:<ip>` | 3600s / 86400s respectively | AbuseIPDB on-demand-check and report-back de-duplication, so the same IP isn't queried/reported more than once per window |
| `threat_intel` | `abuseipdb_quota_date`, `abuseipdb_quota_count` | none (date-keyed, self-resetting daily) | Daily AbuseIPDB API call budget tracking |
| `threat_intel` | `malicious_agents` | none | Known-malicious User-Agent reputation list |
| `rate_limit` | `ip:<ip>` | rolling 60s window | Per-IP request-rate counter, read by `threat_analyzer.lua`'s `update_rate_limit()` |
| `rate_limit` | `admin_attempts:<ip>` (this is the `attempt_key` local variable in `admin_handler.lua` — not a separate Redis namespace) | 1800s (30 min) | Admin-login brute-force attempt counter |
| `honeypot_routes` | `pool_ip:<ip>` (**note**: different prefix string than Redis's `honeypot_pool_ip:<ip>` for the same data — `pool_ip:` vs `honeypot_pool_ip:`, easy to typo one into the other while grepping) | 300s (5 min) | Fast local mirror of the sticky pool assignment |

**Findings from building this table** (real, previously undocumented, found by tracing every read/write rather than assuming symmetry):
- **Fixed this session**: `init_worker.lua`'s Suricata-alert handler, and two call sites each in `vulnerability_handler.lua` and `upload_handler.lua`, updated Redis's `threat_ips` but never mirrored the write into the `threat_intel` shared dict — meaning Suricata detections, vulnerability-scan detections, and suspicious-upload detections were all being durably recorded but had **zero effect on live request routing/scoring**, since `threat_analyzer.lua` only ever reads the shared-dict copy. Only `admin_handler.lua` and `abuseipdb_client.lua` were keeping both copies in sync. All four now mirror the write, matching the existing pattern.
- **Fixed this session**: `init_worker.lua`'s Suricata handler read `threat_ips` without checking Redis's `ngx.null` sentinel (the same `red:get()`-returns-truthy-userdata-not-nil bug already fixed in four other places this session) — could crash on a fresh/flushed Redis.
- **Fixed this session**: `init_worker.lua`'s session-cleanup timer iterated `ngx.shared.sessions`' own keys (already `"session:<id>"`) and then called `red:del("session:" .. key)`, double-prefixing to `"session:session:<id>"` — a silent no-op that never actually deleted the Redis-side record. Harmless in practice (the Redis key has its own matching TTL and expires on its own), but not what the code was trying to do.
- **Fixed 2026-08-09**: `threat_ips[ip].score` renamed to `raw_score` across every writer (`init_worker.lua`, `admin_handler.lua`, `vulnerability_handler.lua` ×2, `upload_handler.lua`, `abuseipdb_client.lua`) and reader (`threat_analyzer.lua`, `suricata_rules.decayed_score()`, the dashboard's `redis_inspect.get_threat_scores()`). The un-renamed field name was a real source of confusion: `raw_score` only ever goes up (capped at 100) and is what you see reading Redis directly, while what a request's own score actually gets is `suricata_rules.decayed_score()`'s time-decayed view of it — seeing 100 in Redis and a much smaller contribution in `reverse_proxy`'s logs for the same IP is expected behavior (decay), not a bug, but the shared field name `score` for both numbers made that easy to mistake for one.
- **Fixed 2026-08-09**: Suricata alerts whose `src_ip` is a private/loopback address (RFC1918 + `127.0.0.0/8`) are no longer written into `threat_ips` at all (`suricata_rules.is_private_ip()`, used in `init_worker.lua`'s `parse_suricata_logs()`). Confirmed live: `suricata_ids` runs with `network_mode: host` + `interface: any` (see §9.2), so it sees every hop of a proxied request, not just the client→`reverse_proxy` leg — a request through the stack was generating a SECOND alert for its `reverse_proxy`→backend hop, misattributed to `reverse_proxy`'s own internal bridge address (e.g. `172.21.0.9`/`172.21.0.10` scored 100 in `threat_ips`, with no real external actor behind either). That address can never match a real request's `remote_ip` (`check_ip_reputation()` always looks up nginx's own client-facing `ngx.var.remote_addr`), so the entry was pure noise, not a working reputation signal — the raw alert is still recorded to `suricata_alerts` either way, only the `threat_ips` write is now skipped for these.
- **Not fixed, just documented**: `active_sessions`, `compromised_sessions`, `vulnerability_events`, `vulnerability_scans`, `cve:*`, and `suricata_alerts` are all write-only — populated on every relevant event, never read by any code path. They function as raw forensic trails inspectable via `redis-cli`/the audit script below, not as live application state. This may be intentional (data for the "ELK Dashboards" gap noted in §10's "Still open" list to eventually visualize) rather than a bug — flagged here since it wasn't obvious without reading every file.
- **Not fixed, just documented**: `threat_ips` (both the Redis blob and its shared-dict mirror) grows forever — no per-entry expiry, no cap. For a real long-running deployment this is worth revisiting (e.g. drop entries not updated in N days), but wasn't in scope for this pass.

**Live verification**: `ids/scripts/redis_key_audit.sh` connects to the running `session_store` container and prints every key currently present, grouped by the prefixes documented above (with type, TTL, and count per group), plus a "keys present but not in this table" section so the table and the live system can be diffed against each other going forward instead of silently drifting apart again.

### 3.6 Suricata IDS

Real network-layer IDS, **PCAP capture on the `any` pseudo-device**, running with `network_mode: host` (confirmed in `suricata_config/suricata.yaml` and the service definition — `privileged: true`, `NET_ADMIN`, `SYS_NICE`). This is the traditional network-tap approach, **not** the `ngx_http_mirror_module` application-layer-mirroring approach proposed in `master-thesis-rewrite-plan/` (see [§12](#12-thesis--academic-material)) — that proposal was assessed but not needed once host networking proved sufficient; `nginx.conf` has no `mirror` directive.

**Update**: the `Exited (0)` crash-on-startup issue, the Docker-bridge traffic-visibility gap, and a `HOME_NET`/`EXTERNAL_NET` rule-direction gap that together made it produce zero alerts are all root-caused and fixed — see §9.2 for the full chain. The container now runs continuously and healthy, sees real application traffic, and fires correct alerts (32 alerts across 18 rule types verified live against a full attack sequence in `attack-test-2026-08-05-v2.log`).

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

A context-isolated AI agent (fresh instance, zero knowledge of this repo) was briefed only with a generic "assess this e-commerce site" prompt and network access. Result: **rubric score 3/3, confirmed detection** — the agent independently found the deception from the server's own responses: TLS cert `O=HoneypotOrg`, cookie literally named `HONEYPOT_SESSION`, and the `X-Route-Target`/`X-Threat-Score` headers (since fixed — see §9). Full protocol and results: `ids/testing/BLIND_PENTEST_PROTOCOL.md` and `ids/testing/blind_pentest_report_run1.md`.

Cross-referenced against internal telemetry: the agent's session classified as `scripted` (not `ai_assisted`) — correct, not a bug: it was instructed to interact via plain `curl` only (for genuine blackbox isolation), which is indistinguishable at the network layer from a scripted scanner using the same tool. This is a real, documented limitation of the sophistication classifier worth stating explicitly in the thesis: it detects a *tooling fingerprint*, not "was an LLM involved" in the abstract.

### 5.3 Unit tests

224 tests across 10 suites (`tests/test_*.lua`), zero `ngx.*` dependency, runnable with a plain `lua` interpreter — see §3.2.

---

## 6. Observability (ELK / SIEM)

Two-host split (see §1, and now `ARCHITECTURE.md` at the repo root for the full data-flow diagram and single-host testing instructions — added this session, closing the gap this paragraph used to describe): a local **Vector** agent (`ids/vector/vector.yaml`, profile-gated) tails Docker/nginx/Suricata/Redis logs and ships them over mTLS to a **Vector aggregator** on the SIEM host, which re-emits to **Elasticsearch**, visualized in **Kibana**.

**Verified live end-to-end this session** (previously designed but never actually run/tested together): brought up both `docker-compose.yml` projects on one host (see `ARCHITECTURE.md` for how, without merging them), generated real traffic, and confirmed real documents landing in Elasticsearch with a Kibana data view (`honeypot-*`) able to query them. Two real bugs found and fixed along the way — the aggregator's own Docker healthcheck used `wget`, which doesn't exist in its image, so it always reported unhealthy regardless of Vector's actual state; and the aggregator's TLS server certificate had no Subject Alternative Names, so hostname verification failed for every connection method *except* the literal string `vector` — including the real two-host deployment's own default (an IP address). See `ARCHITECTURE.md` for both fixes in detail.

Indices: **`honeypot-{log_type}-%Y.%m.%d`**, one per day per log category (`honeypot-nginx_access-*`, `honeypot-nginx_error-*`, `honeypot-nginx_security-*`, `honeypot-suricata-*` [EVE JSON], `honeypot-suricata_fast-*` [alerts only], `honeypot-docker-*`, `honeypot-redis-*`) — `log_type` is tagged by the edge shipper on every event and the aggregator's Elasticsearch sink now actually uses it. **Fixed this session**: the sink's index name was the literal placeholder string `hello-world-index` — every event of every type and every day landed in one single untyped, non-rotating index; this had presumably never been exercised end-to-end before, since a placeholder that blatant would fail obvious review otherwise. A `honeypot-*` Kibana data view now exists and can query all of them together.

**Fixed this session — `nginx_security` log lines were shipped as opaque raw text.** `nginx.conf`'s `security` log format (§4) already includes `route`, `threat_score`, and `suspicious` per request — genuinely the most important fields for a "threat overview" — but the aggregator's `vector.yaml` only ever stored the whole line as one unparsed `message` string, so none of it was queryable or aggregatable in Kibana. Added a VRL regex parse step to the aggregator's `enrich` transform (both the common nginx combined-log-format prefix shared with `nginx_access`, and the `security`-specific `session_id`/`route`/`threat_score`/`suspicious` suffix), with `status`/`body_bytes_sent`/`threat_score` cast to actual numbers and `suspicious` to an actual boolean, not strings. Verified live: generated fresh mixed traffic (clean UA, scanner UAs, an XML-RPC probe, a SQLi-shaped query string) and confirmed real, correctly-typed fields (`route: "honeypot"`, `threat_score: 100`, `suspicious: true`, etc.) in the resulting documents.

**Four Kibana dashboards now exist** (Saved Objects API, classic visualization type — 26 visualizations total, `siem/kibana/build_dashboards.py` / `saved_objects/honeypot-dashboards.ndjson`), all live and querying real data:
- **"Honeypot: IDS Alerts (Suricata)"** — total alert count, alerts-over-time, alerts by category (pie), alerts by severity, top alert signatures, top source IPs. Verified against real data from this session's attack testing: 78+ alerts across 18 distinct signatures (`High Rate HTTP Requests`, `WordPress Login Brute Force`, `XMLRPC Amplification Attack`, etc.).
- **"Honeypot: Web Traffic & Threat Overview"** — total requests, requests-over-time split by route (production vs. honeypot), route distribution (pie), threat-score histogram, top requested URIs, top User-Agents, top IPs flagged suspicious.
- **"Honeypot: Session Analysis"** (added this session — was blocked on session-level data not reaching Elasticsearch, see below) — distinct session count, sessions active over time, a requests+duration-per-session table (request count plus min/max timestamp per `session_id`), top sessions by peak threat score, and attacker-sophistication classification (pie + confidence-over-time) sourced from `attacker_sophistication_classified` events.
- **"Honeypot: Attack Patterns"** (added this session) — total/over-time/by-type breakdown of every `log_security_event()`-sourced event (honeytoken hits, session compromise, CVE pattern matches, high-threat requests, honeypot routing decisions), honeypot routing reasons (pie), top CVEs detected, top attacking IPs, honeytoken hits by type.

**Fixed this session — session-level data now actually reaches Elasticsearch**, closing the gap that blocked the two dashboards above. Three separate, previously-undocumented bugs, found by tracing the pipeline end-to-end and verified live (real traffic → real ES documents → real Kibana aggregations):
- **`init.lua`'s `_G.utils.log_security_event()`** (honeytoken hits, session compromise, CVE matches, high-threat requests, honeypot routing decisions, sophistication classification — everything in §4/§9's detection pipeline) writes a JSON blob into the nginx error log, which the edge shipper already tagged and shipped as `nginx_error` — but the aggregator's `enrich` transform never parsed it, so it landed in Elasticsearch as one opaque `message` string, same class of bug the `nginx_security` fix below it addresses for a different log. Fixed by adding a VRL parse step (`siem/vector/vector.yaml`) that extracts the JSON, hoists `event_type` to `security_event_type` and the rest to `security_event.*`, and hoists `session_id` specifically to the SAME field name `nginx_security`'s own parse uses, so both log types can be correlated on one field.
- **`security` log format was logging the wrong cookie.** `nginx.conf`'s `security` access_log format captured `session_id="$cookie_PHPSESSID"` — WordPress's own incidental PHP session cookie, essentially always empty for a plain page view — instead of `$cookie_HONEYPOT_SESSION`, the cookie this system's own `session_handler.lua`/`init.lua` (`_G.config.session.cookie_name`) actually sets and every real `session_id` in Redis and in `log_security_event()`'s own events is keyed on. Confirmed live: before the fix, `session_id` was `"-"` on requests that already had a real, stable `HONEYPOT_SESSION` cookie assigned — the field was silently disconnected from the rest of the system's session tracking. `nginx.conf` is baked into the `reverse_proxy` image at build time (§9), so this needed a rebuild, not just a restart.
- **`cjson.encode({})` mapping-conflict landmine.** Lua can't distinguish an empty array from an empty object — a zero-length table is genuinely ambiguous — so `cjson.encode()` defaults to serializing it as `{}`. Confirmed live: `high_threat_request`'s `cves` field being `{}` on the first event of the day locked Elasticsearch's mapping for that field as `object` for the rest of that day's index; any later event with a real, non-empty `cves`/`patterns`/`signals` array for the same field would have been silently rejected by the bulk API (same class of mapping conflict the Docker-label dot-flattening fix below already deals with) — a real bug that just hadn't been triggered by real CVE-array data yet this session. Fixed at the source in `log_security_event()`: every empty-table value in `details` is now tagged with `cjson.empty_array_mt` before encoding, so it always serializes as `[]`.

To enable: set `ELK_ENABLED=true` plus `VECTOR_HOST`/`ELASTICSEARCH_HOST`/`PORT`/credentials in `.env`, install the ES CA cert to `vector/certs/ca.crt`, then `docker compose --profile elk up -d`. For single-host local testing (both compose projects on one machine, no real SIEM VM), `VECTOR_HOST` needs to actually be set to `host.docker.internal` — it shipped as the unfilled placeholder `your-siem-vm.example.com` (which fails DNS resolution and silently drops every log) until this session; see `ARCHITECTURE.md`'s single-host testing section. Expected data volume: ~200–750 MB/day combined.

---

## 7. Refactoring History & Framework Choice

See `architecture.canvas` (open the repo root as an Obsidian vault) for the full component-by-component diagram — 39 component nodes, responsibility/refactoring-needs/overlap-to-fuse notes on every one, color-coded by status, plus three additional diagram sections added this session (pooling architecture, hardening-vs-best-practices, test-scenario coverage map — §8's roadmap items). It was lost for a stretch of this project's history (never committed to git, removed during an uncommitted cleanup pass) and has since been restored and brought up to date with everything described in this file, including this session's fixes. §3.2 and this section summarize the same information in prose below.

Short version: this isn't one application, so MVC doesn't fit — it's three subsystems with their own idioms (a WordPress app with its own hook/theme conventions, Docker-Compose infra, and the actual thesis contribution: the Lua detection pipeline). For that pipeline, the chosen pattern is a **numbered middleware chain built from pure decision cores + thin I/O adapters** (§3.2). `lua_pattern_utils.lua` is one concrete code-level "fuse" executed this session, consolidating `url_decode`/`escape_pattern`, which had drifted into 3 independent copies. A second, later fuse: `session_handler.lua`'s own copy of the static-asset check (a third, never-reconciled duplicate of the same `router_rules.lua`/`threat_rules.lua` check) was replaced with a direct call to `router_rules.is_static_asset()`.

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
- Pure/adapter Lua refactor + 224 unit tests (this session, across two passes — see §7)
- Production hardening: XML-RPC, hotlink protection, version obfuscation, backup automation, container containment, `scripts/hardening_audit.sh` (this session — see §9.3)
- ELK Dashboards, all 4 recommended dashboards (this session — IDS Alerts and Web Traffic & Threat Overview from an earlier session, Session Analysis and Attack Patterns added this session after fixing the session-level-data gap that blocked them — see §6)
- WordPress plugins to preinstall (this session — see below)

### Still open
- Code-level docs beyond what exists in Lua comments
- Diagrams: pooling architecture, hardening-vs-best-practices, test-scenario coverage map (this session — see `architecture.canvas`, restored and updated in an earlier session, covers the proactive-defense overview — see §7)
- Data preparation for research use (interaction-depth metrics, session duration comparisons — see `COUNTERARGUMENTS.md` Q18)
- Bonus/exploratory ideas (not committed to): a Honeypot Setup Frontend (toggle features/settings pre-deployment); single-WordPress-frontend-with-dual-database research comparison (see §9 — the SQL-proxy attempt already showed why this is hard); an LLM feature that fetches latest CVEs and generates matching Lua detection rules

### WordPress plugins to preinstall (done this session)
WooCommerce Cart Abandonment Recovery, WPify Slovensko/Česko, HubSpot Chatbot, Elementor, 2FA, WP REST API, Wordfence, a mail plugin, Stripe, Cloudflare. Verified this session: 9 of these 10 were **already present** under `wp-content/plugins/` (just not under the exact names this list uses) — `woo-cart-abandonment-recovery`, `wpify-woo` (WPify Woo Czech — literally the "Slovensko/Česko" plugin, adds Czech/Slovak-specific WooCommerce features), `leadin` (HubSpot's plugin was renamed from "Leadin" to "HubSpot All-In-One Marketing", still the `leadin` slug), `elementor` (already active), `two-factor`, `wordfence`, `wp-mail-smtp`, `woocommerce-gateway-stripe`, `cloudflare`. Only **WP REST API** (the standalone pre-core-merge `rest-api` plugin — real historical CVEs predate the 2016 core merge, good honeypot bait) was genuinely missing; added under `wp-content/plugins/rest-api/`. Left installed-but-inactive like the others already were, matching `seed_wordpress_db.sh`'s documented philosophy: only WooCommerce/Elementor are actually activated, everything else stays reachable-but-inactive since most pre-auth plugin CVEs target the PHP files directly, not `wp_options`' activation flag, and activating security/firewall plugins for real (Wordfence) or ones with external dependencies (Jetpack, HubSpot) risks side effects with no upside for a honeypot.

---

## 9. Known Issues & Stale-Documentation Corrections

Verified this session by checking claims against running code — these are corrections to earlier documentation (now removed) that had drifted from reality, plus genuinely open bugs:

- **SQL Proxy Routing was never completed, despite being documented as if finished.** The old `SQL_PROXY_ROUTING.md` described a single-WordPress-frontend, dual-database architecture (`X-DB-Target` header → custom `wp-content/db.php` drop-in) in full technical detail, with test scripts, logs, and a "Version 1.0.0" marker. In reality: `wp-content/db.php` **does not exist**, and the only code that would set `X-DB-Target` (`router.lua`'s `apply_routing_decision()`) is **dead code, never called**. Only the Docker network topology (both WordPress instances reachable on both DB networks) was actually put in place. This matches `COUNTERARGUMENTS.md` Q1, which correctly states the SQL-proxy approach was "considered" but deemed infeasible — the two documents contradicted each other; this file now reflects the correct, current state (two-instance Nginx routing, no SQL proxy).
- **The old `ids/README.md`'s architecture diagram and integration guide described a Node.js Session Manager and a Python Threat Intel service as live, working components**, with detailed request-flow code samples. Both are confirmed **dead code** — `docker-compose.yml` explicitly comments them out with `# DEAD CODE:` markers, alongside `traffic_mirror`, `log_aggregator`, and `file_sync` (also referenced as a working "continuous 5-minute sync" feature in that same old README). The actual system does all of this directly in Lua + Redis, described accurately in §3 above.
- **`deploy.sh`, `test_system.sh`, and `test_sql_routing.sh` do not exist** despite being referenced as primary entry points in old docs. Use `docker compose` directly (§1).
- **`nginx.conf` is baked into the Docker image at build time** while `reverse_proxy_enhanced/lua/*.lua` is bind-mounted live — `docker compose restart` silently does not pick up nginx.conf edits, only `--build` does. Discovered mid-session while debugging what looked like a code change having no effect.
- **`init_setup`'s file-copy is one-shot** — honeypot pool volumes drift from `production_eshop_files/` after first provisioning (§3.4).
- **The IPv4-only whitelist** (`_G.utils.is_ip_whitelisted` in `init.lua`) doesn't match IPv6 — `127.0.0.1/32` never matches loopback over IPv6 (`::1`). Prefer `curl -4` when testing locally.
- **`suricata_ids` exits immediately** in the local stack — **fixed**, see §9.2. It runs continuously, sees real traffic, and produces correct alerts.
- **The `X-Route-Target`/`X-Threat-Score` leak is fixed** (this session) — previously returned to every client on every response, which is exactly what let the blind-pentest agent (§5.2) partially confirm the deception. Now gated behind `X-Internal-Test-Auth` (`INTERNAL_TEST_SECRET` in `.env`); fails closed if unset.
- **The self-signed TLS cert's `O=HoneypotOrg` and the `HONEYPOT_SESSION` cookie name are real, tracked, self-incriminating values**, not local-testing artifacts — confirmed by the blind pentest (§5.2). Not fixed this session; flagged as a genuine finding.

### 9.1 Fixed after analyzing `check-me.log` (a real capture from an earlier, pre-pooling deployment; gitignored like all `*.log` files, no longer present in the working tree)

That log showed three concrete robustness problems, all root-caused against current code and fixed:

- **The health-check timer ran once per nginx worker instead of once total.** `init_worker.lua`'s recurring `ngx.timer.every(10, ...)` health-check registration sat outside the `if ngx.worker.id() == 0` guard that correctly scopes the AbuseIPDB/session-cleanup/Suricata-log-parser tasks a few lines below it. With the container's 4 workers, every backend was checked ~4× per interval instead of once, and — because all workers' timers fire at roughly the same relative offset — their checks landed in the same narrow instant. That let a single moment of real, transient contention trip "3 consecutive failures" across *different workers'* simultaneous checks almost instantly, instead of requiring genuine sustained unavailability across ~3 real 10s intervals as the threshold is meant to represent. `check-me.log` shows exactly this: `production_backend` got marked **UNHEALTHY** at the precise moment a legitimate user's page load (30+ concurrent asset requests) was in progress and backend response times had climbed past 5s under normal PHP-FPM/DB contention — a false positive, not a real outage. Fixed by moving the timer registration inside the worker-0 guard; verified live (only `worker=0` now fires the tick, once per 10s).
- **`HEALTH_CHECK_TIMEOUT` was declared but never actually used** — `check_backend()` hardcoded its own literal `2000ms` instead of reading the constant. Fixed to read it, and raised the value to `5000ms` to give legitimate load bursts (like the one above) enough headroom before a health check treats them as a failure. (`HEALTH_CHECK_INTERVAL` had the same problem — the `10` in `ngx.timer.every(10, ...)` was a separate literal, not a reference to the constant — also fixed.)
- **Plain HTTP (port 80) requests logged three `"using uninitialized variable"` warnings per request** on top of the access-log line — `$route_decision`/`$threat_score`/`$suspicious_activity` are given defaults in the main HTTPS server block but the HTTP→HTTPS redirect block never set them, and the global `security` access_log format (`http{}` block) references them for every server block. This would spam heavily under real background internet-scan traffic, which `check-me.log` shows does reach port 80 (including a raw TLS ClientHello sent to the HTTP port, correctly rejected with 400). Fixed by adding the same three `set` defaults to the redirect block; verified live (zero uninitialized-variable warnings on a plain HTTP request post-fix).

**Investigated and confirmed already correct, not re-fixed**: the log also showed a real scanner IP (`167.99.135.214`) getting a hard `403` for a mismatched `Host` header before ever reaching the Lua threat-scoring pipeline — losing an intelligence-gathering opportunity for exactly the kind of traffic this system exists to observe. Current `nginx.conf` already has this fixed (comment: `"REMOVED: Lua routing handles all threat detection"`) — verified live: a request with a non-matching `Host` header now runs the full `threat_analyzer` pipeline instead of being rejected outright. Also confirmed already correct: `pool_router.lua`'s `is_pool_healthy()`/`find_healthy_pool()` genuinely does consult the health-check status to fail over between honeypot pools (its own header comment is accurate) — this only applies to the honeypot pools, not production, since production has no equivalent fallback target; nginx's own `upstream { max_fails=5 fail_timeout=10s }` independently covers production failover.

**Fixed** (was: not fixed, still open at the time `check-me.log` was captured): no Suricata alert correlation was visible anywhere in `check-me.log` despite genuinely attack-shaped traffic in the same window — consistent with the (at the time) still-open `suricata_ids` `Exited (0)` issue above. See §9.2 for the full root-cause chain: the crash, then a traffic-visibility gap, then a rule-logic gap, all now fixed and verified producing real alerts.

### 9.2 `suricata_ids`: crash, traffic visibility, and rule-logic — all fixed (`attack-test-2026-08-05.log`, `attack-test-2026-08-05-v2.log`, repo root)

Brought the full stack up, generated a deliberate mixed attack sequence (recon, 8 scanner User-Agents, SQLi, XSS, path traversal, command injection, all 7 seeded CVE probes, WordPress-specific attacks, vulnerable-plugin access, a file-upload exploit attempt, admin brute-force, and a 40-request concurrent burst), and saved the full `docker compose logs` output (3194 lines, all services) to `attack-test-2026-08-05.log`. Two real findings came out of it.

**Fixed: `suricata_ids` crash-looped since before this session, root-caused to two independent bugs — both in the container's startup command, not Suricata itself:**

1. The `jasonish/suricata` image's own `/docker-entrypoint.sh` does `exec $@` **unquoted** to pass through a custom command. `docker-compose.yml`'s `command:` was a single `sh -c "<big multi-line script>"` string; the unquoted `$@` word-split that entire string on whitespace/newlines, so `sh -c` only ever received `"echo"` as its actual script (the very first token) — everything else silently became discarded positional parameters. The container ran essentially `sh -c echo`, produced no output, and exited in well under a second, every time. Confirmed by reproducing it in complete isolation (`docker run jasonish/suricata:latest sh -c "echo hello; ..."` — zero output) and by showing the exact same trivial script worked correctly the moment the image's entrypoint was bypassed (`--entrypoint sh`).
2. Fixed by adding an explicit `entrypoint: ["/bin/sh", "-c"]` override — but that surfaced a **second**, closely related bug one layer up: Compose itself shell-splits a bare multi-line `command: |` scalar into separate exec-form array elements when paired with an exec-form `entrypoint:`, reproducing the identical corruption. Fixed by wrapping `command:` as a one-item YAML list (`command: [- |  <script>]`) so the whole script stays a single opaque string all the way to `sh -c`.
3. Once the script actually ran, a **third**, unrelated bug surfaced: `suricata -c ... --af-packet eth0 -l ...` — `suricata --help` confirms the real flag syntax is `--af-packet[=<dev>]`, requiring an `=` to attach an interface name. The space-separated `eth0` was instead parsed as a separate positional argument, which Suricata treats as an ad-hoc BPF filter expression to compile — producing `failed to compile BPF "eth0": can't parse filter expression: syntax error` (a real, specific, previously-unseen error, once the first two bugs stopped masking it entirely). Fixed by dropping the value and using bare `--af-packet`, since `suricata_config/suricata.yaml`'s own `af-packet:` section already fully specifies `interface: eth0` — bare `--af-packet` reads it from there, which is also the more maintainable form (interface named in one place, not two).

All three verified live, one at a time: `suricata_ids` now shows `Up ... (healthy)` continuously, with `[info] threads: Threads created ... Engine started.` in its logs, and `suricata_logs/eve.json`/`fast.log` are being written to.

**Fixed (was: a real architectural gap) — Suricata traffic visibility.** Even running correctly, Suricata initially detected **zero** alerts against the entire attack sequence above. `suricata_logs/fast.log` (alert-only) was completely empty; `eve.json` contained only `stats`/`flow`/`netflow`/`anomaly` events — no `http`, `dns`, `tls`, or `alert` events at all, despite the traffic including SQLi, XSS, 8 scanner User-Agents, and all 7 seeded CVE probes. Root cause: `reverse_proxy` and `suricata_ids` were both members of `ids_network` (confirmed via `docker inspect`), but shared bridge-network *membership* does not mean shared *traffic visibility* — each container's virtual NIC only receives frames addressed to itself (unicast), not a copy of the bridge's total traffic, absent an explicit mirror/span. Real client traffic reaches `reverse_proxy` via published ports (host→container DNAT), and `reverse_proxy`'s own backend traffic flows over `production_network`/`honeypot_network` — neither path ever touched `ids_network`. Suricata's AF_PACKET capture on its own `eth0` was consequently only exposed to background noise on its own interface (ARP, broadcast, its own minimal traffic), never the actual HTTP requests.

This was exactly the problem `master-thesis-rewrite-plan/NEW_PLAN.md` §3 researched (Docker bridge visibility is a well-known, genuinely hard IDS problem) and proposed two solutions for. Implemented the simpler of the two: **`network_mode: host`** for the `suricata_ids` container (removed it from `ids_network`/`monitoring_network` entirely) — sees all host traffic directly, at the cost of container network isolation for this one service, which is an acceptable tradeoff for a detection-only sidecar that doesn't itself terminate any traffic. (The alternative — application-layer mirroring via nginx's `ngx_http_mirror_module` into `nginx.conf`'s core request-handling location blocks — was assessed but not needed once `network_mode: host` proved sufficient; remains a documented alternative for a from-scratch container-isolated design, in `master-thesis-rewrite-plan/NEW_PLAN.md` §3.)

`network_mode: host` surfaced two further problems, both fixed and verified live:
- **AF_PACKET doesn't support `interface: any`.** AF_PACKET is a raw Linux socket API bound to one real interface index, unlike libpcap; with host networking, the actual interface is one of several dynamically-named bridge devices (`br-<hash>`, one per compose network) with no stable, predictable name across a fresh `docker compose up`. Switched capture mode entirely to **PCAP** (`--pcap` CLI flag, `pcap: [{interface: any, promisc: yes, bpf-filter: "ip or ip6 or arp", checksum-checks: no}]` in `suricata.yaml`) — libpcap's `any` pseudo-device (the same one `tcpdump -i any` uses) captures across every interface at once regardless of name.
- **Zero alerts despite confirmed packet capture.** `eve.json` showed real `http`/`tls` events and `suricata.log` confirmed all 70 rules loaded, but `fast.log` stayed empty. Root cause: every rule required `$EXTERNAL_NET -> $HOME_NET` direction, and `HOME_NET` only listed Docker subnets — test traffic against `https://127.0.0.1/` (the only realistic way to exercise this stack now that the `arch` VM referenced elsewhere in this repo's history is confirmed gone) never matched. Added `127.0.0.0/8` to `HOME_NET` — which then broke matching from the other side, since a loopback connection has *identical* src=dst=`127.0.0.1`, and `EXTERNAL_NET` is defined as `!$HOME_NET`, so the source could no longer ever be classified `EXTERNAL_NET` simultaneously. Fixed by changing all 70 rules' source specifier from `$EXTERNAL_NET` to `any` (standard asset/destination-centric detection practice — matches attacks reaching `HOME_NET` regardless of where they originate). Separately, 7 rules (SQLi, XSS, traversal, command-injection, file-inclusion) were missing the `http_uri` sticky-buffer modifier, so they only matched literal unencoded substrings and missed percent-encoded payloads (e.g. `%3Cscript%3E`); added `http_uri;` to each.

Verified live in `attack-test-2026-08-05-v2.log`: **32 alerts across 18 distinct rule types** fired correctly against a fresh 10-phase attack run, including `High Rate HTTP Requests`, `WordPress Admin/Login Brute Force`, `Honeypot Trigger - Rapid Vulnerability Scanning`, `WordPress User Enumeration`, `XMLRPC Amplification Attack`, `Honeypot Trigger - Automated Tool Detection`, `Suspicious PHP File Upload`, `Admin Panel Discovery`, `Malicious User Agent` (WPScan/Nmap/Nikto/SQLMap), `XSS Script Tag`, `SQL Injection - Union Select`, `WooCommerce Payments Plugin Access`, `WordPress Config File Access Attempt`, and `CVE-2023-2986 Abandoned Cart Lite Exploit Attempt`.

**Fixed: zero request-rate limiting anywhere in the stack.** The same attack run included a 40-request fully-concurrent burst from one IP — all 40 returned `200`, with no throttling of any kind. `nginx.conf` had no `limit_req`/`limit_conn` directive anywhere; the Lua-level "rapid automation detected" signal (Stage 9 of `router.lua`'s routing pipeline) is a *detection* signal that affects which backend a request is routed to, not a request-blocking mechanism — a request that trips it still gets fully processed by a real backend regardless, so it provided zero actual protection against a request flood consuming real PHP-FPM/DB resources. Added a baseline `limit_req_zone` (20 req/s per IP, burst 60, `nodelay`) at the `http{}` level, applied in the main HTTPS server block. The burst value was chosen deliberately generous — `check-me.log` shows a real WooCommerce page load legitimately firing 30+ near-simultaneous static-asset requests, and this must not throttle that. Verified live: a 30-concurrent-request burst (matching that real page-load pattern) still returns all `200`s; a 150-request flood now gets a meaningful fraction of `429`s while the legitimate front of the burst still completes. **Known limitation, not fixed**: this new nginx-level limit does not currently exempt the existing Lua-level IP whitelist (`_G.utils.is_ip_whitelisted`, Tailscale/STUBA/etc.) — that whitelist is session/Lua-level and doesn't automatically extend to this separate, lower-level nginx mechanism.

### 9.3 Production hardening pass (this session) — and a build-vs-bind-mount bug that made nginx.conf edits silently no-op

Went through the "Still open" production-hardening checklist item by item. Several turned out to already be substantially implemented (XML-RPC disable and version-fingerprint stripping at the WordPress layer, hotlink protection, container capability hardening on the honeypot pools) — this section covers what was actually missing or broken, verified live in each case, not just what the code appeared to do.

**Found and fixed: a real infrastructure bug that made nginx.conf edits silently invisible.** `reverse_proxy`'s Dockerfile did `COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf` at *build* time, baking the config into the image. Separately, `docker-compose.yml` bind-mounts `./reverse_proxy_enhanced:/etc/nginx` at *runtime*, which updates a live copy at `/etc/nginx/nginx.conf` — a **different path**. OpenResty's default `CMD` (`openresty -g "daemon off;"`, no `-c` flag) boots from its own compiled-in default prefix, `/usr/local/openresty/nginx/conf/nginx.conf` — the stale, build-time-only copy — never the bind-mounted one. `nginx -s reload` and `docker compose restart` both dutifully reloaded the *stale* config every time; only a full image rebuild ever picked up an nginx.conf edit. Confirmed live: added a new location block, ran `nginx -t` (passed) and `nginx -s reload`/`docker compose restart` repeatedly, and the change never took effect — `nginx -T` (full effective config dump) simply didn't contain it, while a `grep` of the bind-mounted file did. Lua files were never affected by this (`lua_package_path "/etc/nginx/lua/?.lua;;"` correctly points at the bind-mounted path, which is why every Lua edit all session worked with a plain restart) — this was specific to the single master `nginx.conf` file having its own separate baked-in copy at a different path. **Fixed** by removing the `COPY nginx.conf` line and changing `CMD` to `openresty -c /etc/nginx/nginx.conf -g "daemon off;"`, making the bind-mounted file authoritative like everything else in the image. Rebuilt the image once (`docker compose build reverse_proxy`) and confirmed live that edits now take effect with a plain reload — no future edit should need a rebuild again. **Everything else described in this section was re-verified live against the *rebuilt* container, not assumed working from source alone.**

**Fixed: XML-RPC — nginx-layer block was a comment with no code behind it, and the WordPress-layer defense had a real gap of its own.** `nginx.conf` had a comment block claiming "Block direct access to xmlrpc.php on the production instance... a faster defence that never reaches the PHP worker" directly above the static-asset location — but no actual `location`/`return` directive existed anywhere in the file to back it up (confirmed via `grep -n "location.*xmlrpc"` — zero matches). A naive `location = /xmlrpc.php { return 403; }` would have been wrong here: it would fire during nginx's rewrite phase, before the routing decision (production vs. honeypot) exists, and would have blocked honeypot-bound xmlrpc.php probes too — which the same comment explicitly says must stay reachable ("intentionally left accessible on honeypot instances"). Fixed instead inside the main `access_by_lua_block`, right after `routing_decision` is computed: if the target is `"production"` and the URI matches `^/xmlrpc%.php`, return 403 with the same message the mu-plugin uses, before `proxy_pass` ever runs — the request still goes through full threat-scoring/session-tracking first (so the attempt is captured and scored like any other), it just never reaches PHP-FPM if it would have landed on production. Verified live (with a then-still-clean test IP): a clean-UA GET got `403 XML-RPC services are disabled on this server.` on the nginx layer; a WPScan-UA POST with a `system.multicall` body still got a normal `200` + `HONEYPOT_SESSION` cookie, unblocked.

While verifying that, found the WordPress-layer defense wasn't as complete as its own comments claimed either. `xmlrpc_enabled` (filtered to `false`) and the empty `xmlrpc_methods` list *do* correctly remove every WordPress-specific method — confirmed live by POSTing `wp.getUsersBlogs` directly at `production_eshop` (bypassing nginx entirely) and getting a `-32601 method does not exist` fault back. But the `xmlrpc_call` action — which the file's own comment described as "belt-and-suspenders: even if the `xmlrpc_enabled` filter is bypassed... this action will still abort the request" — turned out not to fire at all for the base IXR_Server introspection methods (`system.listMethods`, `system.multicall`, `system.getCapabilities`), which are handled by a different internal dispatch path that WordPress's own action hook doesn't wrap. Confirmed live: POSTing `system.listMethods` directly at `production_eshop` returned a normal, fully-formed `methodResponse` listing those three methods, not a 403. Not independently exploitable on its own (every method `system.multicall` could have amplified into is confirmed gone, per the `wp.getUsersBlogs` test above), but "XML-RPC completely disabled" should mean the endpoint doesn't respond *at all*, not "responds to everything except the individual methods we happened to remove." Fixed with an unconditional check at the very top of `production-hardening.php` (`substr($_SERVER['SCRIPT_NAME'], -11) === '/xmlrpc.php'` → immediate 403), independent of which internal WordPress/IXR class ends up dispatching a given method name. Re-verified live: `system.listMethods` now also gets `403` directly against `production_eshop`; the same request against a honeypot pool still gets a full, normal `methodResponse` (attack surface correctly untouched there).

**A note on testing this repeatedly**: running the same curl-based checks against `reverse_proxy` many times in a row from one IP is itself exactly the kind of rapid, scripted, repeated traffic `threat_analyzer.lua`'s automation detection exists to flag — after enough of this session's own testing, the test IP legitimately accumulated enough score to start getting pool-routed to honeypot even with a plain browser User-Agent, which would make a naive repeatable "production must always 403" check flaky (not because the defense broke, but because the routing system correctly stopped trusting that IP). `scripts/hardening_audit.sh`'s XML-RPC checks are therefore written to hit `production_eshop`/the honeypot pool containers directly rather than through the full `reverse_proxy` routing pipeline, so they stay deterministic regardless of how many times the script itself has already run.

**Verified working, no fix needed: hotlink protection.** Already implemented (`valid_referers none blocked server_names;` scoped to image/media static assets, `if ($invalid_referer) { return 403; }`). Verified live: a request for a real product image with `Referer: https://evil-hotlinker.example.com/` gets `403`; the same request with no `Referer` gets `200`.

**Verified working, extended: version fingerprint obfuscation.** `production-hardening.php` already strips the WordPress and WooCommerce `<meta name="generator">` tags, `?ver=` query strings, the `/wp-json/` version field, and `nginx.conf` already sets `server_tokens off` + rewrites the `Server` header to a bare `nginx`. Installing Elementor and HubSpot's `leadin` plugin this session (see §3.4) reintroduced two new leaks the existing hardening predates and doesn't cover:
- Elementor prints its own `<meta name="generator" content="Elementor X.Y.Z; ...">`, hooked via a bound object method (`add_action('wp_head', [$this, 'render_generator_tag'])`) that can't be removed with `remove_action()` the way the plain-function WordPress/WooCommerce hooks can. **Fixed**: Elementor has its own first-class disable option (`get_option('elementor_meta_generator_tag') === '1'` suppresses it entirely); `production-hardening.php` now sets it via `update_option()`. Verified live: zero `generator` meta tags on production; all three (WordPress, WooCommerce, Elementor) still present on the honeypot pools, unaffected (correct — that's the realistic fingerprint attackers are meant to see there).
- HubSpot's `leadin` plugin prints `<!-- HubSpot WordPress Plugin vX.Y.Z: embed JS disabled as a portalId has not yet been configured -->` on every page while unconfigured (our current state, since no real HubSpot account is connected — see §3.4). Also a bound-object `wp_head` hook, but with no equivalent official disable option. **Not fixed** — the only real fix available is output-buffering the whole `wp_head` action to strip one specific HTML comment, which is a meaningfully riskier technique for a much narrower disclosure (a third-party plugin name + version in an HTML comment, not a `<meta>` tag actively used by fingerprinting scanners the way WP/WC/Elementor's generator tags are) than anything else in this file. Documented here rather than implemented; will also resolve itself naturally once a real HubSpot account is ever connected.

**Found and fixed: backup automation was completely non-functional — three independent bugs, each silently masking the next.** `backup_service` had been running for hours logging what looked like normal operation, with zero backup files ever actually produced:
1. `chmod +x /backup.sh` in the container's startup command failed every run (`Read-only file system` — the script is bind-mounted `:ro`) and was simply unnecessary dead code (the host file is already `0755`). Removed.
2. `mkdir "${DB_BACKUP_DIR}"`/`"${WP_BACKUP_DIR}"` failed with `Permission denied` on every run: `./backups/` is a host bind mount owned by the host user, and `backup_service` runs as root with `cap_drop: ALL` — which also strips `CAP_DAC_OVERRIDE`, the specific capability that normally lets root bypass a directory's Unix permission bits it doesn't own. Fixed with a scoped `cap_add: [DAC_OVERRIDE]` (the one capability actually needed here, not a blanket re-grant).
3. Once past that, `mktemp /tmp/mysql-backup-XXXXXX.cnf` failed with `Invalid argument` — BusyBox's `mktemp` (this runs on Alpine) requires the template to end in `XXXXXX` with nothing after it, unlike GNU `mktemp`, which allows a suffix. Fixed by dropping `.cnf` from the template (no functional need for the extension).
4. Once the script finally ran to completion, `mysqldump | gzip -9 > file` was found to silently succeed even when `mysqldump` itself failed — the `if cmd1 | cmd2; then` check reflects only `cmd2`'s (gzip's) exit status without `set -o pipefail`, and gzip happily "succeeds" compressing zero bytes of input. This had been masking a **fifth**, real bug the whole time: `mysqldump` was failing on every run with `TLS/SSL error: Certificate verification failure` (MySQL 8+ enables TLS by default with an auto-generated, untrusted self-signed cert) — meaning every "successful" backup for however long this had been broken was an empty 4KB `.sql.gz` with zero SQL content. Fixed with `set -o pipefail` (confirmed supported by this BusyBox `ash`) so a real mysqldump failure now correctly fails the whole step, plus `--skip-ssl` on the `mysqldump` invocation itself (a private container-to-container connection on `production_network`, not internet-exposed, so this is a scoped, deliberate tradeoff). Also added `--no-tablespaces` to silence a separate, benign-but-noisy `PROCESS privilege` warning from the same command (the backup DB user is an application-scoped account, not root/SUPER; tablespace metadata isn't needed to restore this database).

Verified live end-to-end after all four fixes: `docker compose exec backup_service /backup.sh` now produces a genuine 231.6MB WordPress file archive and a 564–576KB database dump (126 `CREATE TABLE` statements, confirmed by decompressing and grepping it) with a clean success log and no errors.

**Found and fixed: `production_eshop` had zero container hardening at all.** Every other service in `docker-compose.yml` (both database families, all three honeypot pools, `backup_service`) already had `cap_drop: [ALL]` + a minimal `cap_add`, `no-new-privileges`, and resource ceilings. `production_eshop` — the container actually serving real traffic, running the same large third-party-plugin-heavy PHP application — had none of it: full default Docker capabilities, no memory/CPU/pids limit. Fixed with the same minimal capability set already used for `honeypot_eshop_1` (Apache+PHP needs the same things regardless of which side it's on: `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`, `NET_BIND_SERVICE`, `KILL`), `no-new-privileges`, and `mem_limit: 1024m` / `cpus: "1.0"` / `pids_limit: 300`.

**Found and fixed: the honeypot pools' existing memory/CPU ceilings had become too tight** — a side effect of installing the new plugin roster (§3.4) on all three pools. Confirmed live via `docker stats`: all three pools were sitting at ~434–436MB *idle*, right up against the old `mem_limit: 512m` ceiling with essentially no headroom; one pool was observed pegged at 300%+ CPU with its own Docker healthcheck timing out from cgroup memory-pressure thrashing, not an application bug. Bumped `honeypot_eshop_1/2/3` to match `production_eshop`'s new ceiling (`mem_limit: 1024m`, `cpus: "1.0"`) — partly to fix the thrashing, partly because an attacker who fingerprints response latency shouldn't find the honeypot side measurably slower under routine load than production handles fine, which would itself be a tell.

**New: `scripts/hardening_audit.sh`** — the "custom hardening script" from the checklist. Live-checks all of the above against the running stack rather than trusting the source: XML-RPC (production 403s, honeypot still reachable), hotlink protection (blocked cross-site, allowed direct), version fingerprint obfuscation (Server header, zero generator meta tags on production), backup automation (most recent log entry says success *and* the newest dump is a plausible size — the exact "succeeded but empty" failure mode found above), and container containment (`cap_drop`/`no-new-privileges` present on production + all three honeypot pools). Exits non-zero if anything fails, so it's usable as a CI-style gate, not just a manual report. All checks currently pass.

---

## 10. Session History (condensed changelog, superseding the raw AI-session handoff notes this replaces)

- **AbuseIPDB integration**: bulk blacklist + on-demand checks + gated report-back. Required adding `ca-certificates` to the reverse_proxy Dockerfile (Alpine's OpenResty image has no CA bundle by default, breaking outbound HTTPS cosockets) and copying the bundle to `/usr/local/openresty/` specifically, since docker-compose bind-mounts shadow both `/etc/nginx` and `/etc/ssl/certs` at runtime.
- **Sophistication scoring, prompt injection filter**: see §4.3.
- **Blind pentest evaluation**: see §5.2.
- **Local deployment stood up** (the `arch` VM referenced in older docs/`~/.ssh/config` is stale/gone) — required regenerating SSL certs on the host (the containerized `init_setup` cert-gen hung/split unpredictably, not fully diagnosed), importing the SQL dump into all four MySQL instances, fixing `siteurl`/`home` in `wp_options` (dumped as `http://openstack.local`), and adding `FS_METHOD=direct` to `wp-config.php` (a real, pre-existing bug — WordPress was attempting FTP-based filesystem access with no FTP configured).
- **Lua pure/adapter refactor + `lua_pattern_utils.lua` fuse**: see §3.2 and §7.
- **All remaining `architecture.canvas` refactor candidates completed**: `session_rules.lua`, `admin_rules.lua`, `honeytoken_rules.lua`, `abuseipdb_rules.lua` — 4 new pure modules, 81 new unit tests (224 total, up from 143). `pool_router.lua` re-assessed and confirmed to need no split (100% Redis I/O, no pure core exists). Found and fixed a third undiscovered duplicate of the static-asset query-string-stripping check (`session_handler.lua`'s own copy, the one that was never reconciled when the other two were). Verified live end-to-end (admin access, login POST, admin-ajax, all session/threat paths) with zero Lua errors; `scripts/hardening_audit.sh` and `scripts/redis_key_audit.sh` both still fully green. See §7 / `architecture.canvas`.
- **`architecture.canvas` restored and brought current**, then **dead code and stale duplicates it flagged were actually removed**: `elk_logger.lua` (confirmed dead code — never `require`d anywhere, its own header comment said so) and `admin_handler.lua.backup`/`admin_handler.lua.bak` (byte-identical to each other, both a stale pre-fix snapshot of the real file) deleted outright. Verified live: clean `reverse_proxy` restart, homepage `200`, no Lua errors, `scripts/hardening_audit.sh` all green. The canvas itself updated accordingly (40 → 38 nodes, both removed nodes' edges pruned) — see §7.
- **`ARCHITECTURE.md` written**, closing the "two-host split is undocumented" gap `architecture.canvas` had flagged — data-flow diagram, why the split is a real security boundary, and (going further than originally recommended) exact steps to run both projects together on one host for testing. Verified by actually doing it: brought both stacks up simultaneously, found and fixed three real, previously-unexercised SIEM-side bugs in the process (aggregator healthcheck using a binary that doesn't exist in its image; TLS cert with no SANs, silently broken for the real two-host deployment too, not just local testing; an Elasticsearch index sink still pointed at a literal `hello-world-index` placeholder) — see §1/§6.
- **Two Kibana dashboards built** ("IDS Alerts", "Web Traffic & Threat Overview") after fixing `nginx_security` log parsing (the aggregator was shipping `route`/`threat_score`/`suspicious` as one opaque text blob) — see §6.
- **Session-level data pipeline fixed, two more Kibana dashboards built** ("Session Analysis", "Attack Patterns" — see §6): the aggregator's `enrich` transform never parsed `log_security_event()`'s JSON out of the `nginx_error` log (same class of bug the `nginx_security` fix addressed for a different log); `nginx.conf`'s `security` log format was logging `$cookie_PHPSESSID` (WordPress's own, essentially always-empty cookie) instead of `$cookie_HONEYPOT_SESSION` (this system's actual session-tracking cookie), silently disconnecting the log's `session_id` field from the rest of the system; and `cjson.encode({})`'s array/object ambiguity was locking Elasticsearch's mapping for `cves`/`patterns`/`signals` from whichever event reached it first, ready to silently drop every later event with real array data for the same field. All three found by tracing the pipeline end-to-end and fixed at the source, not papered over downstream.
- **Dashboard Start/Restart progress bars added**: `docker compose up -d`/`restart` return almost immediately, well before containers with healthchecks actually become healthy — the Services page's per-target panels and the Health page's per-service Restart now show a progress bar driven by live container status (containers ready / total, red on unhealthy/exited-with-error) instead of leaving Start/Restart looking finished the instant the command exits.
- **`.env`'s `VECTOR_HOST` fixed for local single-host testing**: shipped as the unfilled placeholder `your-siem-vm.example.com`, which fails DNS resolution and silently drops every shipped log — now `host.docker.internal`, per `ARCHITECTURE.md`'s documented single-host testing procedure.
- **Dashboard: automatic per-service error badge on the Health diagram**: a red "!N" badge appears in a node's bottom-right corner the moment any log line for that service contains "error" (case-insensitive), N counting up live. `ui/error_monitor.py` taps the Services page's existing always-running combined log tail (no extra `docker compose logs` process spun up), parsing `docker compose logs`' own `<service>-<replica> | message` line prefix; counts reset per-target whenever that target's tail restarts, so the same `--tail=50` scrollback isn't recounted on every Start/Restart. Shared between the Services and Health pages via one `ErrorLogMonitor` instance (`ui/main_window.py`), so it keeps counting regardless of which page is currently open.
- **WordPress plugins to preinstall**: 9 of 10 were already present under different names than the roadmap's list used (see §8); the one genuine gap (`rest-api`, the standalone pre-core-merge WP REST API plugin) added, installed-but-inactive like the rest.
- **`dashboard/` — a PyQt6 GUI control panel** for both projects, local or remote (SSH): setup wizard, Start/Restart/Stop/Purge, a live health diagram color-coded per container with per-service restart/logs/open-web-UI/open-shell, per-service certificate regeneration, and a `.env` editor. `core/` (command construction, `.env` parsing, cert generation) has no PyQt imports and was verified directly against the real repo — real `.env` round-tripping, real `docker compose ps` parsing, a real certificate regeneration confirmed end-to-end (new cert → copied to edge host → `vector` restarted → mTLS reconnected → confirmed via Elasticsearch document count) — before any UI code was written on top of it. See `dashboard/README.md`.

---

## 11. Related documentation still living in their own files

- `ids/testing/BLIND_PENTEST_PROTOCOL.md`, `ids/testing/blind_pentest_report_run1.md` — blind pentest protocol + results
- `architecture.canvas` (Obsidian Canvas, full system diagram — 39 component nodes/28 edges plus 3 additional diagram sections/32 nodes/17 edges added this session, responsibility/refactoring/overlap notes per node, color-coded by status) — restored and brought current after being lost for a stretch of this project's history; open the repo root as an Obsidian vault to browse it
- `ids/elk-siem-testing.md` and `master-thesis-rewrite-plan/` were both referenced from earlier versions of this file but **no longer exist in the repository** — neither was ever committed to git, and both were lost during a later, uncommitted cleanup pass.
- `siem/README.md` — the SIEM sub-project's own setup doc

---

## 12. Thesis & Academic Material

Not merged into this file (intentionally out of scope — this file is technical/functional, not thesis-like):

- `master-thesis-latex/` — the thesis itself (`main.tex`, chapters under `content/`, `appendices/`, `bib/`, `assets/`).

**Note on repo history**: earlier working notes referenced elsewhere in this file's changelog (§10) — `COUNTERARGUMENTS.md`, `PLAN_DP1/2/3.md`, `master-thesis-rewrite-plan/` (the "Shadow Honeypot" rewrite proposal, including its `ngx_http_mirror_module`-based Suricata integration idea), and `future-claude-prompts.md` — were removed from the repository root during a later cleanup pass and no longer exist. Where those old proposals are still relevant, the outcome is documented directly in the sections above (e.g. §3.6/§9.2 for what was actually implemented for Suricata traffic visibility, which ended up being `network_mode: host` + PCAP rather than nginx-level mirroring).

---

## 13. Primary Literature

[1] SRINIVASA, Shishir, PEDERSEN, Jens M. a VASILOMANOLAKIS, Emmanouil, 2023. Gotta Catch 'em All: A Multistage Framework for Honeypot Fingerprinting. Digital Threats. Roč. 4, č. 3. DOI: 10.1145/3584976

[2] NINTSIOU, Maria, GRIGORIOU, Elisavet, KARYPIDIS, Paris Alexandros, SAOULIDIS, Theocharis, FOUNTOUKIDIS, Eleftherios a SARIGIANNIDIS, Panagiotis, 2023. Threat intelligence using Digital Twin honeypots in Cybersecurity. In: IEEE International Conference on Cyber Security and Resilience (CSR). s. 530-537. DOI: 10.1109/CSR57506.2023.10224997
