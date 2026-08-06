# Honeypot / SIEM Dashboard

A PyQt6 desktop app for controlling both compose projects in this repo
(`openstack-work` and `openstack-siem-work`) without hand-typing `docker
compose` commands — local or remote (SSH), with live health status, log
viewing, certificate management, and `.env` editing.

## Run it

```bash
cd dashboard
./run.sh
```

First run creates a venv (`dashboard/venv/`, gitignored) and installs
`requirements.txt` into it automatically, then launches the app. Every
run after that just launches it directly — `run.sh` only does the
venv/install step once.

Alternatively, double-click (or `xdg-desktop-menu install`) the included
`Dashboard.desktop` launcher for a normal GUI-app entry (menu/dock icon,
no terminal window) instead of running `run.sh` from a shell. It calls
`run.sh` with an absolute path baked in for this checkout
(`/home/ondrej/Desktop/DP_Repository/dashboard`), so if you clone the
repo somewhere else, edit its `Exec=`/`Path=` lines to match.

On first launch (no `state.json` yet), a setup wizard walks through
creating/populating both projects' `.env` files, optional remote SSH
config, and optional initial certificate generation. It's also reachable
anytime afterward from **Settings → Re-run setup wizard…** without losing
existing values (it loads current `.env` content rather than blanking it).

## Pages

- **Services** — Start / Restart / Stop / Purge for each project, local
  and (if configured in Settings) remote, with a live status summary next
  to the buttons ("all N up" turns green once every container is either
  running or a cleanly-completed one-shot job — it doesn't stay stuck on
  "N-2/N up" just because `init_setup`/`honeypot_db_migration` finished
  and exited, as expected) and command output streamed below. *Purge* runs
  `docker compose down -v` (deletes volumes) and always asks for
  confirmation first.
- **Health** — a live, auto-refreshing (every 5s) diagram of every
  container across all configured targets, grouped by project/target and
  connected by lines showing the real relationships between services
  (reverse proxy → backends → databases, edge Vector → SIEM Vector
  aggregator → Elasticsearch → Kibana, etc.). Node color = status (see
  the in-app legend: healthy / running-no-healthcheck / unhealthy /
  exited-ok / exited-with-error / down — a container that exited with code
  0 counts as "up", not down: run-once-and-exit jobs like `init_setup` and
  `honeypot_db_migration` finishing cleanly is their expected end state).
  Two small icons sit directly on every node, no click-through required:
  top-left **⬇** exports that container's logs to a file under
  `dashboard/logs/` (prompts for a line count, 0 = the entire log), and
  top-right **↗** (shown only on nodes with a web UI — Kibana,
  Elasticsearch, `reverse_proxy`, and every eshop container, since nginx is
  their only reachable entrypoint) opens it in your browser directly.
  Click the rest of a node for its detail panel: **Restart**, **View
  logs** (live-tailed), **Open web UI**, and **Open shell** (launches
  `docker exec -it <container> sh -c 'exec bash || exec sh'` in your
  terminal emulator — over SSH first for remote targets).
- **Certificates** — regenerate the SIEM CA + all service certs, or just
  one service's cert (reusing the existing CA rather than rotating it),
  or the edge host's nginx self-signed SSL cert. Regenerating the
  `vector-agent` client cert (or everything) automatically re-copies it
  to the edge host's `vector/certs/` directory. See `../ARCHITECTURE.md`
  for why the SIEM side uses a private CA this way.
- **Settings** — edit either project's real `.env` file directly (secret
  fields are password-masked with a show/hide toggle and a "Generate"
  button for a fresh random value), and configure/test remote SSH access
  per project.

## Remote (SSH) targets

Each project can independently have a remote target configured (Settings,
or the wizard): host, port, SSH user, private key path, and the project's
directory path *on that remote host*. When configured, that target shows
up alongside the local one everywhere (Services, Health) — this is how
the real two-host deployment this project is designed for (see
`../ARCHITECTURE.md`) gets controlled from one place, including from the
edge host toward a genuinely separate SIEM VM.

## State

`dashboard/state.json` (gitignored) holds window geometry, which page you
were last on, and remote-connection settings. It does **not** hold
`.env` contents — those live in the real `.env` files this app edits
directly (`openstack-work/.env`, `openstack-siem-work/elk_dockerized/docker/.env`),
so `docker compose` and this app are always looking at the same
configuration.

## Layout

```
dashboard/
  main.py              # entry point
  run.sh                # venv bootstrap + launch
  Dashboard.desktop     # XDG launcher entry (menu/dock icon)
  requirements.txt
  core/                  # no PyQt imports here -- pure logic, testable headless
    paths.py              # repo path resolution
    env_file.py             # comment-preserving .env parser/writer
    state.py                  # app state persistence (state.json)
    docker_ctl.py              # local/remote docker compose command construction
    cert_ctl.py                  # certificate generation (openssl, direct)
    web_links.py                  # which services have a browsable web UI
    shell_ctl.py                   # docker exec / ssh shell command construction
  ui/                     # PyQt6 widgets
    main_window.py, wizard.py, page_services.py, page_health.py,
    page_certs.py, page_settings.py, health_diagram.py, env_editor.py,
    remote_config_widget.py, process_runner.py, status_poller.py
```

`core/` has no PyQt6 imports at all — every module in it was verified
directly from a plain Python REPL against the real repo (real `.env`
round-tripping, real `docker compose ps` parsing, a real cert
regeneration verified end-to-end against the actually-running SIEM
stack) before any UI code was written on top of it.
