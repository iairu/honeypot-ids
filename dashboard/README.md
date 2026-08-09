# Honeypot / SIEM Dashboard

A PyQt6 desktop app for controlling both compose projects in this repo
(`ids` and `siem`) without hand-typing `docker
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

On first launch (no `state.json` yet), a setup wizard walks through the
remote/local choice for each project first, then its `.env` (every run
visits every page now — a project marked remote doesn't skip .env editing,
it fetches the .env LIVE from that remote host over SSH and prefills the
same form with it, instead of a local file; missing entirely on a fresh
remote host prefills an empty form rather than failing, and Next saves
straight back to the remote host, not locally), then optional initial
certificate generation. A step-timeline strip at the top of every page
shows the whole run at a glance (✓ done / ● current, adapting to black or
white depending on the actual light/dark theme / dimmed upcoming, with
"(remote)" appended to a project's .env step when it's remote-sourced).
The wizard is also reachable anytime afterward from **Settings → Re-run
setup wizard…** without losing existing values.

## Pages

- **Services** — Start / Restart / Stop / Purge for each project, local
  and (if configured in Settings) remote, with a live status summary next
  to the buttons ("all N up" turns green once every container is either
  running or a cleanly-completed one-shot job — it doesn't stay stuck on
  "N-2/N up" just because `init_setup`/`honeypot_db_migration` finished
  and exited, as expected). Each panel auto-tails combined logs
  (`docker compose logs --tail=50 -f`) the moment it's shown — no need to
  click anything first, and for a remote target with bad SSH config this
  surfaces the connectivity problem immediately. Clicking Start/Restart/
  Stop/Purge takes over that same panel for the command's own output, then
  automatically goes back to auto-tailing once the command finishes (Start
  uses `up -d`, which exits almost immediately once containers are up —
  without this the panel would just sit showing "process exited with code
  0" instead of what the containers are actually doing). A single
  **Download logs…** button exports that target's whole combined log to a
  file under `dashboard/logs/` (prompts for a line count, 0 = everything).
  *Purge* runs `docker compose down -v` (deletes volumes) and always asks
  for confirmation first. Closing the app while a Start/Restart/Stop/Purge
  is still running (not the auto-tail, which is harmless to interrupt)
  asks for confirmation first.
- **Health** — a live, auto-refreshing (every 5s by default — adjustable
  in Settings → General) diagram of every
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
  Clicking a node also immediately starts live-tailing its logs in the
  detail panel — no separate "View logs" click needed (the button's still
  there to re-trigger it manually if you want). Detail panel: **Restart**,
  **View logs**, **Open web UI**, and **Open shell** (launches
  `docker exec -it <container> sh -c 'exec bash || exec sh'` in your
  terminal emulator — over SSH first for remote targets). Every log
  console in the app (Services, Health, Certificates) has **Pause**
  (holds the view still — including across the process finishing — while
  still buffering everything that arrives) and **Catch up** (flushes the
  buffer immediately without leaving pause mode, so you can jump to "now"
  and keep reading from there without it scrolling away again).
- **Certificates** — regenerate the SIEM CA + all service certs, or just
  one service's cert (reusing the existing CA rather than rotating it),
  or the edge host's nginx self-signed SSL cert. Regenerating the
  `vector-agent` client cert (or everything) automatically re-copies it
  to the edge host's `vector/certs/` directory. Buttons and the output
  console sit side by side (not stacked) so every cert group is visible
  without scrolling. See `../ARCHITECTURE.md` for why the SIEM side uses a
  private CA this way.
- **Settings** — each project's `.env` tab has a **Local / Remote** dropdown
  (secret fields are password-masked with a show/hide toggle and a
  "Generate" button for a fresh random value either way): Local edits the
  real local file as before; Remote (only selectable once that project's
  remote connection is configured and tested — greyed out otherwise, and
  switching to it turns grey/red if the fetch fails) fetches the .env live
  from the remote host over SSH into the same form, and Save writes it
  straight back there instead of touching the local file. A **Refresh**
  button re-fetches from whichever source is currently selected, discarding
  unsaved edits in the form. Also: configure/test remote SSH access per
  project, adjust the Health/Services status-refresh interval and toggle
  unhealthy-container tray notifications (**General** tab), and
  **export/import** the whole configuration — both `.env` files' values
  plus both remote (SSH) settings — as one JSON file, for backup or moving
  this setup to a fresh checkout instead of re-typing everything by hand.
  Import only changes keys actually present in the file (same
  comment-preserving editing this whole app uses elsewhere); other
  existing `.env` keys and comments are untouched. The exported file
  contains real secrets in plaintext — store it securely, never commit it.

## System tray

If the desktop environment has one, a tray icon appears with **Show
dashboard** and **Quit**, and posts a notification when a container
transitions into unhealthy or exited-with-error (toggle in Settings →
General). Closing the main window still fully quits the app as before —
the tray doesn't change that, it's a notification/quick-access surface,
not a minimize-to-tray mode.

## Remote (SSH) targets

Each project can independently have a remote target configured (Settings,
or the wizard): host, port, SSH user, private key path, and the project's
directory path *on that remote host*. When configured, that target shows
up alongside the local one everywhere (Services, Health) — this is how
the real two-host deployment this project is designed for (see
`../ARCHITECTURE.md`) gets controlled from one place, including from the
edge host toward a genuinely separate SIEM VM.

A remote target needs its own `.env` (and generally the rest of the
project) already in place on that host for `docker compose` to work there.
Once **Test connection** succeeds, two actions appear on that same remote
config (in the wizard's Remote page and in Settings — clearly labeled per
project, so with both projects' remote config shown side by side it's
always obvious which goes where):

- **Upload `<project>/.env` to remote…** — `scp`s the LOCAL `.env` file to
  `<remote_path>/.env`, overwriting whatever's there, after a confirmation
  prompt (secrets included, sent as-is). For editing a remote `.env`
  in-place instead of overwriting it wholesale, use the Local/Remote
  toggle on the Settings `.env` tabs (or the wizard) instead — this button
  is for pushing a specific known-good local copy.
- **Upload entire `<project>` to remote…** — syncs the WHOLE project
  directory (code, compose files, certs, everything needed to actually run
  `docker compose up` there — not just `.env`) via `rsync` over the same
  SSH connection, with a live progress bar. Runtime-generated data is
  excluded so it isn't blindly copied alongside the actual project
  (backups, container logs, database/Redis volumes, and a
  local-diffing-only file snapshot — confirmed live: `ids/backups/`
  alone was 1.2GB, `suricata_logs/` 378MB, neither belongs in "deploy the
  project"). If the remote directory already has files in it, you're asked
  to confirm before anything is overwritten. Needs `rsync` installed
  locally (not on the remote host).

## State

`dashboard/state.json` (gitignored) holds window geometry, which page you
were last on, remote-connection settings, the status-poll interval, and
the tray-notification toggle. It does **not** hold `.env` contents — those
live in the real `.env` files this app edits directly (`ids/.env`,
`siem/docker/.env`), so `docker compose` and
this app are always looking at the same configuration. For a portable
backup of the *whole* setup (env values + remote config together), use
Settings → Export/Import instead of copying `state.json` by hand.

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
    settings_bundle.py              # export/import bundle (.env values + remote config)
    env_upload.py                    # .env transfer: scp a local file, or fetch/send TEXT over ssh
    project_upload.py                 # rsync a whole project directory to a remote host
  ui/                     # PyQt6 widgets
    main_window.py, wizard.py, page_services.py, page_health.py,
    page_certs.py, page_settings.py, health_diagram.py, env_editor.py,
    remote_config_widget.py, process_runner.py, status_poller.py,
    log_export.py         # shared "export logs to a file" (Health + Services)
    env_source_tab.py     # Settings' per-project .env tab (Local/Remote toggle)
```

`core/` has no PyQt6 imports at all — every module in it was verified
directly from a plain Python REPL against the real repo (real `.env`
round-tripping, real `docker compose ps` parsing, a real cert
regeneration verified end-to-end against the actually-running SIEM
stack) before any UI code was written on top of it.
