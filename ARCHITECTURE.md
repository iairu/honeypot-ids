# Architecture: two hosts, two independent `docker compose` projects

This repository contains **two separate systems**, each with its own `docker-compose.yml`, meant to run on **two separate hosts**:

| | Directory | Role | Compose project |
|---|---|---|---|
| **Edge host** | `ids/` | The honeypot itself: reverse proxy, WordPress (production + 3 honeypot pools), Redis, Suricata, a local Vector log shipper | `honeypot-ids-system-v1` |
| **SIEM host** | `siem/` | Log storage/analysis: Elasticsearch, Kibana, a Vector aggregator that receives the edge host's logs | (directory-named, no explicit project name) |

This isn't an accident of two people building unrelated things — it's a deliberate security boundary. The edge host is the one an attacker can realistically get code execution on (that's the whole point of a honeypot); the SIEM host holds the actual telemetry about what attackers did. Merging them into one `docker-compose.yml` on one host would mean a honeypot compromise is one Docker-socket-mount or network-hop away from the incident data describing that same compromise. Keeping them on separate hosts, connected by one narrow, authenticated, outbound-only channel (the edge Vector shipper pushing to the SIEM Vector aggregator over mTLS on port 6000), is what makes the boundary real rather than nominal.

**Until this file existed**, nothing explained this relationship anywhere except two lines in `README.md`'s Run section — a reader landing in either directory alone (which is exactly how you *would* land in one of them, since they're separate compose projects with no shared files) had no way to discover the other half existed. `architecture.canvas`'s `n24-callout` node flagged this explicitly as an undocumented cross-project relationship; this file is that fix.

## Data flow

```
┌─────────────────────────── Edge host (ids/) ───────────────────────────┐
│                                                                                      │
│  attacker/customer → reverse_proxy (nginx+Lua) → production_eshop / honeypot pools  │
│                            │                              │                         │
│                     nginx access/error/security logs      │                         │
│                            │                        Suricata (IDS) → eve.json/fast.log
│                            │                              │                         │
│                            ▼                              ▼                         │
│                     ┌──────────────────────────────────────────┐                    │
│                     │  vector (shipper, profile: elk)           │                   │
│                     │  tails: docker logs, nginx logs,          │                   │
│                     │  suricata eve.json/fast.log, redis logs   │                   │
│                     └──────────────────┬─────────────────────┘                      │
└────────────────────────────────────────┼────────────────────────────────────────────┘
                                          │ mTLS, port 6000
                                          │ (client cert: vector-agent.crt/key)
                                          ▼
┌────────────────────── SIEM host (siem/) ─────────────┐
│                     ┌──────────────────────────────────────────┐                    │
│                     │  vector (aggregator)                      │                   │
│                     │  verifies client cert, tags/enriches,     │                   │
│                     │  writes to honeypot-{log_type}-%Y.%m.%d   │                   │
│                     └──────────────────┬─────────────────────┘                      │
│                                        ▼                                            │
│                                 Elasticsearch (es01)                                │
│                                        │                                            │
│                                        ▼                                            │
│                                    Kibana                                           │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

Every log event picked up by the edge shipper is tagged with `log_type` (`docker`, `nginx_access`, `nginx_error`, `nginx_security`, `suricata`, `suricata_fast`, `redis`) before it ever leaves the edge host; the aggregator's Elasticsearch sink uses that field to route each event into its own daily index (`honeypot-nginx_access-2026.08.05`, `honeypot-suricata-2026.08.05`, etc.) — fixed this session; it used to write everything into a single literal `hello-world-index` placeholder that was never replaced with real index logic.

## Running for real (two hosts)

1. **SIEM host**: `cd siem/certs/root-ca && ./gen_elk_certs.sh` (generates a CA + certs for `es01`/`kibana`/`vector`, and a `vector-agent` client cert bundle under `../../vector/certs/vector-agent/`), then `cd ../../docker && docker compose up -d`.
2. Copy `siem/vector/certs/vector-agent/{ca.crt,vector-agent.crt,vector-agent.key}` to the **edge host**'s `ids/vector/certs/` (this is a manual step by design — the client cert should never live in the same place as the CA's private key, and the two hosts don't share a filesystem).
3. **Edge host**: set `VECTOR_HOST` to the SIEM host's real address (defaults to a placeholder IP, `147.175.151.193`, in `ids/vector/vector.yaml` — override it via `.env` or the environment) and bring the `elk` profile up: `docker compose --profile elk up -d vector`.
4. If the SIEM host's real address differs from what's in `VECTOR_SAN` in `gen_elk_certs.sh` (currently `vector`, `localhost`, `host.docker.internal`, `127.0.0.1`, `147.175.151.193`), add it there and re-run the script — the aggregator's server certificate needs the address the edge shipper actually connects through as a Subject Alternative Name, or TLS hostname verification will fail (this bit single-host testing below until the SAN list was added — see that section for the exact error).

## Running both on one host (testing / development)

The two compose projects don't need to be merged to test them together — they already don't conflict on ports (`80`/`443` for the edge stack vs. `9200`/`5601`/`6000` for the SIEM stack), container names, or networks (each project gets its own bridge network; nothing is shared by default). The only thing standing between "two independent stacks happen to be running on the same machine" and "the edge shipper is actually delivering logs to the SIEM stack" is that they're on different Docker networks with no way to resolve each other by container name. Verified working this session:

1. Bring up the SIEM stack: `cd siem/certs/root-ca && ./gen_elk_certs.sh && cd ../../docker && docker compose up -d`. Wait for `es01`, `kibana`, and `vector` to all report healthy (`docker ps` — first boot pulls the Elasticsearch and Kibana images, which are large; expect several minutes).
2. Copy the `vector-agent` client cert bundle to the edge host's cert directory (same as production step 2 above — on one host this is just a local `cp`, not a cross-host transfer):
   ```
   cp siem/vector/certs/vector-agent/{ca.crt,vector-agent.crt,vector-agent.key} ids/vector/certs/
   ```
3. Bring up the edge stack as normal (`cd ids && docker compose up -d`), then start the Vector shipper pointed at the SIEM stack via the host's own network stack instead of a remote IP:
   ```
   VECTOR_HOST=host.docker.internal VECTOR_PORT=6000 docker compose --profile elk up -d vector
   ```
   `ids/docker-compose.yml`'s `vector` service has `extra_hosts: ["host.docker.internal:host-gateway"]` specifically for this — it's what lets the edge shipper container reach a port the SIEM stack published on the same physical/VM host, without joining the two compose projects onto a shared Docker network (which would be a bigger, more invasive change purely for a dev/test convenience). This has zero effect on the real two-host deployment above: `host.docker.internal` is just an unused DNS alias there.
4. Confirm data is flowing: `docker compose logs vector` on the edge side should show `Healthcheck passed.` (not "Retrying after error" / TLS failures); on the SIEM side, `docker exec es01 curl -s --cacert /usr/share/elasticsearch/config/certs/ca/ca.crt -u elastic:<password> "https://es01:9200/_cat/indices?v"` should show real, growing `honeypot-*` indices with non-zero `docs.count`.

### Two real bugs found getting this far, both fixed

- **Vector aggregator's own healthcheck was permanently broken** (`docker ps` always showed `unhealthy` even though Vector itself was fine): the healthcheck used `wget`, which doesn't exist in the `timberio/vector:*-debian` image (confirmed via `docker inspect`'s health log: `exec: "wget": executable file not found in $PATH`). Fixed by using `bash`'s `/dev/tcp` instead (confirmed present in the image; confirmed `/bin/sh` in this image is `dash`, which does *not* support `/dev/tcp`, so the fix explicitly invokes `bash -c`, not `CMD-SHELL`, which runs via `/bin/sh`).
- **TLS hostname verification failure when the edge shipper connects via anything other than the literal string `"vector"`**: the aggregator's server certificate only had a bare CN, no Subject Alternative Names, so it only validated for a client connecting via the exact hostname `vector` — which neither `host.docker.internal` (single-host testing) nor the real deployment's default IP address `147.175.151.193` (two-host production — this was silently broken there too, not just in the testing path) ever matched. Fixed by adding a proper SAN list to the `vector` aggregator's certificate (`DNS:vector, DNS:localhost, DNS:host.docker.internal, IP:127.0.0.1, IP:147.175.151.193`) in `gen_elk_certs.sh`, rather than disabling hostname verification — this is a private CA minted specifically for this one shipper↔aggregator pairing, so CA-chain trust is already the real security boundary, and there was no reason to give up hostname checking too when just listing the legitimate hostnames fixes it properly.
- **The Elasticsearch sink's index name was the literal placeholder `hello-world-index`** (`vector/vector.yaml`) — every log type from every day landed in one single, non-rotating, untyped index. Fixed to `honeypot-{{ log_type }}-%Y.%m.%d`, using the `log_type` field the edge shipper already tags every event with but which the aggregator was never actually using.

## Dashboards

`nginx_security` log lines (see `ids/reverse_proxy_enhanced/nginx.conf`'s `log_format security`) carry the most operationally interesting fields for a honeypot — `route` (production vs. honeypot), `threat_score`, `suspicious` — but the aggregator used to ship the whole line as one opaque `message` string, making none of it queryable. Fixed by adding a VRL regex parse step to `vector/vector.yaml`'s `enrich` transform (splits the shared nginx combined-log-format prefix from the `security`-specific suffix, and type-casts `status`/`body_bytes_sent`/`threat_score` to numbers and `suspicious` to a boolean rather than leaving them as strings).

Two Kibana dashboards were built on top of this (via the Saved Objects API — `POST /api/saved_objects/visualization` and `.../dashboard`, classic visualization type for schema stability across versions, referencing the single `honeypot-*` data view with a per-panel `log_type:` query filter rather than separate per-index data views):

- **"Honeypot: IDS Alerts (Suricata)"**: total alert count, alerts over time, alerts by category, alerts by severity, top signatures, top source IPs.
- **"Honeypot: Web Traffic & Threat Overview"**: total requests, requests over time split by route, production-vs-honeypot routing pie, threat-score histogram, top URIs, top User-Agents, top IPs flagged suspicious.

Both verified against real data generated by exercising the edge stack (mixed clean/scanner/SQLi-shaped traffic), not just checked for successful object creation — the underlying Elasticsearch aggregations were queried directly and confirmed to return real, non-empty, correctly-bucketed results before being wired into panels.

**Bug caught during that verification**: the `honeypot-*` data view spans every shipped log type by wildcard (docker, suricata, nginx_access, nginx_security, nginx_error, redis each land in their own `honeypot-<log_type>-YYYY.MM.DD` index, but one data view covers all of them). A panel with no explicit filter doesn't implicitly scope itself to "the index this dashboard is about" — "Total Requests" with no query counted 21,207 docs across every log type where only 166 were real nginx_security requests, and `event_type:"alert"` alone (no `log_type` filter) picked up 44 cross-type matches vs. 41 real Suricata alerts (a docker-sourced log line's message text free-text-matched "alert" too, since `event_type` is a `text` field, not a `keyword`-only one). Fixed by giving every one of the 13 panels an explicit `log_type:"..."` term in its query — see `siem/kibana/build_dashboards.py`'s `_IDS_Q`/`_WEB_Q`.

**Persistence**: both dashboards, their data view, and all 13 panel visualizations are committed as a Saved Objects NDJSON export (`siem/kibana/saved_objects/honeypot-dashboards.ndjson`) and re-imported automatically (`overwrite=true`, idempotent) by the `kibana_dashboards_setup` compose service on every `docker compose up` — a `down -v` purge no longer loses them. That service also sets Kibana's default landing page (`defaultRoute`) to the Web Traffic dashboard; that setting is applied via a direct API call rather than shipped in the NDJSON, since Kibana stores it as a `config` saved object keyed by the exact running version string, so an exported copy would silently stop applying the moment `STACK_VERSION` changes. To change a panel, edit it live in Kibana then re-run `siem/kibana/build_dashboards.py` (rebuilds all 16 objects from source) and re-export, or hand-edit the NDJSON directly for a small change.

**Not built**: session-analysis and attack-pattern dashboards (grouping by session, sophistication classification, attacker dwell time) — that data currently lives only in Redis (`session:*`, see `README.md` §3.5), not Elasticsearch. Shipping it would need either a new Vector source reading from Redis, or the Lua pipeline itself emitting session-summary events somewhere Vector can tail — neither exists yet.

## See also

- `README.md` §1 (Architecture Overview) and §6 (SIEM/ELK Integration) for the edge host's full detail.
- `siem/README.md` for the SIEM project's own (minimal) setup notes.
- `architecture.canvas` (open the repo root as an Obsidian vault) — `g-edge`/`g-siem` groups and the nodes around them for the component-level diagram this file's data-flow section summarizes in prose.
