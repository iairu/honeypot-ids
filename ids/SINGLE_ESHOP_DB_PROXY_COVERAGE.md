# Single-eshop / two-database topology — coverage & gaps

Branch: `db-proxy-single-eshop`.

## What changed

The honeynet no longer runs a separate WordPress + MySQL pool per attacker.
There is now **one** WordPress instance (`production_eshop`) and **two**
databases:

| Before (pool topology) | After (this branch) |
|---|---|
| `production_eshop` + `honeypot_eshop_1/2/3` (4 WordPress containers) | `production_eshop` only (1) |
| `production_database` + `honeypot_database_1/2/3` (4 MySQL) | `production_database` + `honeypot_database` (2) |
| `honeypot_db_seed_1/2/3` + `honeypot_db_migration` | `honeypot_db_init` (clone-of-prod + scrub) |
| `pool_router.lua` picks a backend **container** per IP | `db.php` picks a **database** per request |

`reverse_proxy` still runs the full threat-analysis pipeline. Its per-session
decision (`route_decision` = `production` | `honeypot`) is passed to the single
WordPress as the **`X-Honeypot-Backend`** request header (`proxy_set_header`, so
a client copy is always overwritten). The WordPress **db drop-in**
`wp-content/db.php` reads that header and connects `$wpdb` to the production or
the honeypot database accordingly. The honeypot database is a scrubbed clone of
production (`honeypot_db_init` dumps production → honeypot, then applies
`honeypot_database_migrations/`), kept fresh by `honeypot_content_sync`.

Container count dropped from ~15 to 8 running services — the requested
"less demanding system".

### Verified live
- Benign request → `route_decision=production` → **production DB**.
- After an exploit flags the IP → `route_decision=honeypot` → **honeypot DB**
  (served the honeypot's marker content, not production's).
- **Forged-header defense:** a client sending `X-Honeypot-Backend: production`
  while flagged is still served the honeypot DB — the proxy overrides it, so an
  attacker cannot escape the honeypot by forging the header.
- Honeypot clone's `wp_users` are scrubbed to dummy accounts (`admin/webmaster/
  editor`, dummy hashes); production's real users/hashes are never in it.

## What IS covered (database-layer isolation)

Anything whose effect is a database read/write is fully isolated — a
honeypot-routed session only ever touches the scrubbed clone:

| Preset | Why it's covered |
|---|---|
| CVE-2024-2387 (Advanced Form Integration **SQLi**) | Injection executes against the honeypot DB; exfiltrates only dummy rows. |
| CVE-2023-28121 (WooCommerce Payments auth bypass → REST `/users`) | Reads honeypot `wp_users` (dummy accounts). |
| GENERIC-WP-003 (author enumeration) | Same — dummy users only. |
| CVE-2025-2266 (CWMP unauth `wp_options` write) | Writes the honeypot DB's options, never production's. |
| CVE-2023-2986 (Abandoned Cart token forgery) | DB-scoped; honeypot data only. |
| GENERIC-WP-002 (install.php), GENERIC-WP-004 (XML-RPC) | App/DB-layer on the honeypot-routed session. |

Data exfiltration, SQL injection, credential dumping, and option tampering are
the class this design protects against, and it does so with far fewer
containers.

## What is NOT covered (gaps to report)

The two sides now share **one filesystem and one PHP runtime**. The database is
switched per request; **files and code execution are not.** Every attack whose
effect is on disk or in the process is therefore *not* isolated.

### 1. Filesystem attacks hit the real, shared WordPress files
| Preset | Effect that escapes isolation |
|---|---|
| CVE-2025-4403 (Drag & Drop **file upload** MIME bypass) | Webshell/file lands in the shared `wp-content/uploads`, reachable by production visitors. |
| CVE-2025-47577 (Gift Voucher **upload → RCE**) | Same upload path **and** code execution (see #3). |
| CVE-2024-50508 (WP File Upload **path traversal** read/write) | Reads/writes arbitrary paths on the shared container filesystem. |
| CVE-2025-10142 (PagSeguro **path traversal**, `../../etc/passwd`) | Reads the shared container filesystem, identical for both sides. |
| GENERIC-WP-001 (**wp-config.php disclosure**) | Leaks the file that contains the **production** DB credentials (production is the default backend), so the attacker can then connect to the real DB directly. |

A webshell an attacker uploads on a honeypot-routed request is written to the
same `wp-content/uploads` production serves. When it is later requested with no
threat signal (`route_decision=production`), it executes **against the
production database** — the isolation is silently bypassed.

### 2. Persistence / integrity of the shared code and config
Plugin/theme file edits, `.htaccess` changes, dropped mu-plugins, and any other
on-disk modification made on a honeypot request persist for **all** traffic,
production included. The old per-pool filesystem contained this; a single shared
`./production_eshop_files` bind mount does not.

### 3. Remote code execution defeats the model entirely (fundamental)
Once an attacker achieves code execution in the shared PHP process (e.g.
CVE-2025-47577), the per-request header routing is meaningless:
- `wp-config.php` and the container environment expose **both** the production
  (`DB_*` / `WORDPRESS_DB_*`) and honeypot (`HONEYPOT_DB_*`) credentials.
- The container is attached to `production_network`, so the attacker's code can
  open its own connection straight to `production_database` regardless of the
  `X-Honeypot-Backend` header.

No per-request DB switch can contain an attacker who controls the process doing
the switching. This is the core, unavoidable limitation of collapsing the pools
into one runtime.

### 4. Shared-resource / availability coupling
One container serves both sides, so a resource-exhaustion or fork-bomb payload
on a honeypot request degrades **production** too (CPU/memory/pids are shared).
The pools previously isolated this per instance.

### 5. Deception surface is thinner
The honeypot and production are byte-identical code responding from the same
host, differing only in DB contents. Timing/side-channel fingerprinting that
could previously be muddied by separate pool instances now has a single target;
a sophisticated attacker who compares on-disk artifacts across "sessions" sees
one machine.

## Recommended mitigations (if pursued further)

- **Contain RCE/file impact without re-adding pools:** run the container with a
  read-only root filesystem + `tmpfs` for the few writable paths, and route
  honeypot uploads to a per-request/tmp upload dir via an `upload_dir` filter.
  This blunts persistence but cannot stop an RCE from reading prod creds.
- **Remove production credentials from the honeypot's reach:** give the honeypot
  DB its own user/password (not the production one) and load production
  credentials only when actually production-routed — reduces, but does not
  eliminate, the wp-config disclosure / RCE credential-leak (#1, #3).
- **Accept the split:** keep this DB-proxy design for the DB-layer attack
  classes it covers well, and treat file/RCE-class CVEs as *out of scope* for
  isolation on this topology (detect-and-alert only via Suricata/ELK), which is
  the honest security posture given the single shared runtime.
