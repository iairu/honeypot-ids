# Database proxy level honeypot layer

The ids stack can run its honeypot at one of two layers. You choose the layer in
the dashboard's Services page ("Honeypot layer"), or with the compose file you pass:

| Layer | Compose file | What gets switched per suspicious session |
|---|---|---|
| WordPress proxy level (default, recommended) | `docker-compose.yml` | The whole backend: the proxy routes to separate honeypot WordPress containers (pools). |
| Database proxy level | `docker-compose.db-proxy.yml` | Only the database: one `production_eshop` serves everything, and `wp-content/db.php` connects it to the production or the honeypot database. |

```sh
# by hand, from ids/
docker compose up -d --remove-orphans                                # reverse proxy level
docker compose -f docker-compose.db-proxy.yml up -d --remove-orphans # database proxy level
```

Both layers use the same compose project name, `.env` and data. Switching with
`--remove-orphans` replaces the services that differ and removes the other
layer's extra services. The honeypot database volume is the exception: this
layer uses `honeypot_database_proxy_data`.

## Files that belong to this layer

This folder contains whole-file replacements, at the same relative paths as the
default copies. `docker-compose.db-proxy.yml` bind-mounts each one over the
shared version:

- `reverse_proxy_enhanced/nginx.conf`: no pool upstreams, and every location proxies to `production_backend`.
- `reverse_proxy_enhanced/proxy_params`: sets `X-Honeypot-Backend` from the Lua routing decision. It always overwrites the header, so a client can't forge it.
- `reverse_proxy_enhanced/lua/health_check.lua` and `lua/init_worker.lua`: set `POOL_COUNT` to 0, so nothing probes or pre-warms pools that don't exist.
- `scripts/replicate_content_to_honeypot.sh`: syncs content into the single `honeypot_database`.
- `honeypot_database_migrations/01_clean-honeypot-data.sql`: DELETEs that tolerate missing tables, for the clone-of-production database.

Two files can't be overlaid because they don't exist in the default tree, and
Docker would create empty placeholders for them on the host. They live in the
shared `production_eshop_files/` instead and do nothing unless
`HONEYPOT_LAYER=database`, which only this layer's compose file sets:

- `production_eshop_files/wp-content/db.php`: the per-request database router.
- `production_eshop_files/wp-content/mu-plugins/honeypot-db-backend-header.php`: adds `X-DB-*` debug headers for the dashboard. It requires `INTERNAL_TEST_SECRET`.

`production-hardening.php` has a guard that skips hardening on requests routed
to the honeypot database. The guard depends on a constant that only `db.php`
defines, so it has no effect in the default layer.

When you change one of the shared originals (for example `init_worker.lua`),
check whether the copy here needs the same change.

## What this layer cannot isolate

See [COVERAGE.md](COVERAGE.md). In short, file uploads, path traversal,
config disclosure and RCE reach the shared filesystem and PHP runtime, not the
switched database. In this layer the dashboard's Exploits page greys out those
presets.
