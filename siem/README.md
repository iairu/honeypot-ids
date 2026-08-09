# elk-dockerized
Repository contains ELK secure installation in docker environment

**This is one half of a two-host system.** The other half is `ids/` (the honeypot itself) at the repository root — see `../ARCHITECTURE.md` for why they're split across two hosts, the full data-flow diagram, and how to run both together on a single host for testing. See `../README.md` §6 for how the shipped log data is structured once it lands here (index naming, what's in each log type).

## Usage
1. Run `./gen_elk_certs.sh` in `certs/root-ca/` — creates a CA, signs certs for `es01`/`kibana`/`vector`/`vector-agent`, and copies them into each service's own `certs/` directory. The `vector-agent` client certificate (under `vector/certs/vector-agent/`) needs to be copied to the *other* host's `ids/vector/certs/` directory before its Vector shipper can connect — see `../ARCHITECTURE.md` for the exact steps, both for a real two-host deployment and for single-host testing.
2. Run `docker compose up -d` (from `docker/`). First boot pulls the Elasticsearch and Kibana images, which are large — expect several minutes.
3. Enjoy or Cry&Debug

## Known-fixed issues (see `../ARCHITECTURE.md` for full detail)
- The `vector` service's Docker healthcheck used to always report `unhealthy` regardless of whether Vector itself was actually fine — it invoked `wget`, which isn't in the `timberio/vector:*-debian` image. Fixed to use `bash`'s `/dev/tcp` instead.
- The `vector` service's TLS certificate used to only validate for a client connecting via the literal hostname `vector` — which broke both single-host testing (`host.docker.internal`) and the real two-host deployment's own default `VECTOR_HOST` (a raw IP). Fixed by adding a proper Subject Alternative Name list to `certs/root-ca/gen_elk_certs.sh`'s `vector` cert generation.
- The Elasticsearch sink's index name (`vector/vector.yaml`) used to be the literal placeholder `hello-world-index` — every log type and every day landed in one single index. Fixed to `honeypot-{log_type}-%Y.%m.%d`, using the `log_type` field the edge shipper already tags every event with.
- `nginx_security` log lines (the ones carrying `route`/`threat_score`/`suspicious` — the actually interesting fields) were shipped as one opaque raw-text `message` string, unqueryable in Kibana. Added a VRL parse step to `vector/vector.yaml`'s `enrich` transform to extract real, correctly-typed fields.

## Dashboards
Two Kibana dashboards exist (built via the Saved Objects API, not manually in the UI — see `../ARCHITECTURE.md`'s Dashboards section): **"Honeypot: IDS Alerts (Suricata)"** and **"Honeypot: Web Traffic & Threat Overview"**. A `honeypot-*` data view (time field `timestamp`) covers every shipped index. Session-analysis / attack-pattern dashboards don't exist yet — that data currently lives only in the edge host's Redis, not here.

## Known pre-existing issues, not fixed
- **Cert/key files in `certs/`, `elasticsearch/certs/`, `kibana/certs/`, `vector/certs/` (including the CA's own private key, `certs/root-ca/certs/rootCA.key`) are tracked in git.** Discovered while regenerating them this session — not introduced by this session's changes, but worth deciding whether to `.gitignore` them and scrub git history.
- **`.env`'s `ELASTIC_PASSWORD`/`KIBANA_PASSWORD`/`VECTOR_PASSWORD` are checked-in placeholder values** (`changemepls` etc.), same category of issue as above.
- **`honeypot-docker-*` index silently fails to ingest anything**: Elasticsearch rejects every `docker_logs`-sourced document with `illegal_argument_exception: can't merge a non object mapping [label.com.docker.compose.project] with an object mapping` — a field-mapping conflict from Docker container labels, present since before this session (the index always showed 0 documents). Not investigated further; out of scope for the nginx/Suricata dashboard work this pass covered.
