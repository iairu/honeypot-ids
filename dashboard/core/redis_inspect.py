"""Redis introspection for the "session_store" service (ids /
edge project) -- backs ui/page_redis.py's table+graph viewer.

Goes through `docker compose exec session_store redis-cli ...` (locally or
over SSH for a remote edge target, via Target.build() -- same plumbing
every other docker-facing feature in this app already uses) rather than a
direct redis-py TCP connection: session_store has no published host port
by design (only reachable on the internal docker network, see
docker-compose.yml), so a direct client connection isn't even possible
without punching a hole in that isolation just for this dashboard.
`docker compose exec` also sidesteps having to know/guess the actual
compose-generated container name (e.g. "honeypot-ids-system-v1-
session_store-1") -- it resolves the service name within the right
project context the same way Target.build() already does for every other
compose command.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from core.docker_ctl import Target
from core.env_upload import EnvUploadError, load_project_env
from core.proc import run_checked
from core.state import RemoteConfig

REDIS_SERVICE = "session_store"

# Single round-trip: SCAN is the "right" way to list keys without blocking
# the single-threaded server, but for the per-key TYPE/TTL/size table this
# app needs, doing N docker-exec round-trips (real subprocess/SSH latency
# each) for N keys would make the page feel broken on anything but a
# trivial keyspace. This dev/test keyspace is small enough that a plain
# KEYS-based server-side Lua script (one round-trip total, computed
# entirely inside redis) is both simpler and correct enough -- it's the
# same tradeoff admin tooling makes routinely at this scale.
_LIST_KEYS_SCRIPT = (
    'local keys = redis.call("KEYS", ARGV[1]) '
    "local result = {} "
    "for i, k in ipairs(keys) do "
    '  local t = redis.call("TYPE", k)["ok"] '
    '  local ttl = redis.call("TTL", k) '
    "  local size = 0 "
    '  if t == "string" then size = redis.call("STRLEN", k) '
    '  elseif t == "list" then size = redis.call("LLEN", k) '
    '  elseif t == "set" then size = redis.call("SCARD", k) '
    '  elseif t == "hash" then size = redis.call("HLEN", k) '
    '  elseif t == "zset" then size = redis.call("ZCARD", k) '
    "  end "
    "  table.insert(result, k) "
    "  table.insert(result, t) "
    "  table.insert(result, tostring(ttl)) "
    "  table.insert(result, tostring(size)) "
    "end "
    "return result"
)


# Clears threat_ips entries, and the sessions (with their per-session pool
# assignments and fingerprint pointers), of any IP that can only be internal-to-this-docker-host traffic (RFC1918 private
# ranges + loopback) -- the dashboard's own exploit-runner curls, manual
# browser testing done directly on this machine, container-to-container
# health checks, and Suricata's own host-network visibility all show up as
# one of these (confirmed live throughout this project's development: the
# shared client IP for anything hitting a published port from the host
# itself is the docker bridge gateway address, e.g. 172.21.0.1). A genuine
# external attacker reaching a real two-host deployment's published port
# keeps their real public source IP -- Docker's DNAT preserves it on that
# leg -- so this can never touch real attacker data, only this dev
# environment's own self-generated noise.
#
# All three stores done server-side in one round-trip (not N docker-exec
# calls) via Lua: KEYS+DEL for the private-IP-matching session:* records and
# their honeypot_pool_session:* / fp_session:* keys, and a filter-then-SET (or DEL if now empty)
# for threat_ips, which is a single JSON blob keyed by IP rather than one
# redis key per IP.
_UNPOISON_SCRIPT = r"""
local function is_local_ip(ip)
    local a, b = ip:match("^(%d+)%.(%d+)%.%d+%.%d+$")
    if not a then return false end
    a, b = tonumber(a), tonumber(b)
    if a == 10 or a == 127 then return true end
    if a == 172 and b >= 16 and b <= 31 then return true end
    if a == 192 and b == 168 then return true end
    return false
end

local removed_sessions = 0
local removed_ids = {}
local session_keys = redis.call("KEYS", "session:*")
for _, key in ipairs(session_keys) do
    local val = redis.call("GET", key)
    if val then
        local ok, data = pcall(cjson.decode, val)
        if ok and type(data) == "table" and data.ip_address and is_local_ip(data.ip_address) then
            redis.call("DEL", key)
            removed_sessions = removed_sessions + 1
            removed_ids[key:sub(#"session:" + 1)] = true
        end
    end
end

-- Pools are assigned per session (honeypot_pool_session:<session id>): drop
-- the assignments of the sessions removed above, and the passive-fingerprint
-- pointers (fp_session:<fingerprint>) that would recover them.
local removed_pools = {}
for _, key in ipairs(redis.call("KEYS", "honeypot_pool_session:*")) do
    local sid = key:sub(#"honeypot_pool_session:" + 1)
    if removed_ids[sid] then
        redis.call("DEL", key)
        table.insert(removed_pools, sid)
    end
end
for _, key in ipairs(redis.call("KEYS", "fp_session:*")) do
    if removed_ids[redis.call("GET", key) or ""] then
        redis.call("DEL", key)
    end
end

local removed_threat_ips = {}
local threat_raw = redis.call("GET", "threat_ips")
if threat_raw then
    local ok, data = pcall(cjson.decode, threat_raw)
    if ok and type(data) == "table" then
        local kept = {}
        local any_removed = false
        for ip, v in pairs(data) do
            if is_local_ip(ip) then
                table.insert(removed_threat_ips, ip)
                any_removed = true
            else
                kept[ip] = v
            end
        end
        if any_removed then
            local is_empty = true
            for _ in pairs(kept) do
                is_empty = false
            end
            if is_empty then
                redis.call("DEL", "threat_ips")
            else
                redis.call("SET", "threat_ips", cjson.encode(kept))
            end
        end
    end
end

return cjson.encode({
    sessions_removed = removed_sessions,
    pool_assignments_removed = removed_pools,
    threat_ips_removed = removed_threat_ips,
})
"""


class RedisInspectError(Exception):
    pass


@dataclass(frozen=True)
class RedisKeyInfo:
    name: str
    type: str
    ttl: int  # -1 = no expiry
    size: int  # strlen/llen/scard/hlen/zcard depending on type


def _get_redis_password(remote: RemoteConfig | None, timeout: float = 10.0) -> str:
    try:
        env = load_project_env("edge", remote, timeout=timeout)
    except EnvUploadError as e:
        raise RedisInspectError(f"Could not read remote .env: {e}")
    password = env.get("REDIS_PASSWORD")
    if not password:
        if remote is None and not env.path.exists():
            raise RedisInspectError(f"{env.path} not found -- run the setup wizard first.")
        raise RedisInspectError("REDIS_PASSWORD not set in .env")
    return password


def _run_redis_cli(
    remote: RemoteConfig | None, *args: str, raw: bool = True, timeout: float = 15.0,
) -> str:
    password = _get_redis_password(remote, timeout=timeout)
    target = Target(project="edge", remote=remote)
    raw_flag = ["--raw"] if raw else ["--no-raw"]
    argv, cwd = target.build(
        "exec", "-T", REDIS_SERVICE, "redis-cli", "-a", password, *raw_flag, *args,
    )
    try:
        result = run_checked(argv, error=RedisInspectError, cwd=cwd, timeout=timeout, what="redis-cli")
    except RedisInspectError as e:
        # The "-a" password warning goes to stderr -- strip it out of a
        # failure message so the actual error is what the user sees.
        message = re.sub(r"^Warning: Using a password.*\n?", "", str(e), flags=re.MULTILINE).strip()
        raise RedisInspectError(message or str(e))
    # stdout is already clean (the warning only ever goes to stderr).
    return result.stdout


def list_keys(remote: RemoteConfig | None, pattern: str = "*", timeout: float = 15.0) -> list[RedisKeyInfo]:
    out = _run_redis_cli(remote, "EVAL", _LIST_KEYS_SCRIPT, "0", pattern, timeout=timeout)
    lines = out.splitlines()

    infos = []
    for i in range(0, len(lines) - 3, 4):
        name, key_type, ttl_str, size_str = lines[i:i + 4]
        try:
            ttl = int(ttl_str)
        except ValueError:
            ttl = -1
        try:
            size = int(size_str)
        except ValueError:
            size = 0
        infos.append(RedisKeyInfo(name=name, type=key_type, ttl=ttl, size=size))
    return sorted(infos, key=lambda k: k.name)


def get_value(remote: RemoteConfig | None, key: str, key_type: str, timeout: float = 15.0) -> str:
    """Raw value text for a key, JSON-pretty-printed when it parses as
    JSON (most of this project's redis values are cjson-encoded -- see
    threat_ips/session:* throughout reverse_proxy_enhanced/lua)."""
    if key_type == "string":
        text = _run_redis_cli(remote, "GET", key, timeout=timeout)
    elif key_type == "list":
        text = _run_redis_cli(remote, "LRANGE", key, "0", "-1", timeout=timeout)
    elif key_type == "set":
        text = _run_redis_cli(remote, "SMEMBERS", key, timeout=timeout)
    elif key_type == "hash":
        text = _run_redis_cli(remote, "HGETALL", key, timeout=timeout)
    elif key_type == "zset":
        text = _run_redis_cli(remote, "ZRANGE", key, "0", "-1", "WITHSCORES", timeout=timeout)
    else:
        text = _run_redis_cli(remote, "GET", key, timeout=timeout)

    text = text.strip()
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text
    return json.dumps(parsed, indent=2, sort_keys=True)


def get_threat_scores(remote: RemoteConfig | None, timeout: float = 15.0) -> dict[str, int]:
    """{ip: raw_score} from the "threat_ips" key (see router.lua/
    init_worker.lua), for page_redis.py's bar chart. This is the raw,
    ever-only-increasing stored value (capped at 100) -- NOT the same
    number threat_analyzer.lua actually applies to a request's score,
    which is a time-decayed view of this (suricata_rules.decayed_score()),
    smaller once any time has passed since `updated`. Seeing a bigger
    number here than in reverse_proxy's own logs for the same IP is
    expected, not a bug. Empty dict if the key doesn't exist yet or
    doesn't parse -- both are normal states (a freshly-started stack has
    no threat data yet), not errors."""
    try:
        text = _run_redis_cli(remote, "GET", "threat_ips", timeout=timeout).strip()
    except RedisInspectError:
        return {}
    if not text:
        return {}
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}
    scores = {}
    for ip, entry in data.items():
        if isinstance(entry, dict) and "raw_score" in entry:
            scores[ip] = int(entry["raw_score"])
    return scores


def clear_local_threat_state(remote: RemoteConfig | None, timeout: float = 15.0) -> dict:
    """Un-poisons threat_ips/session/pool-assignment state for the shared
    host IP (see _UNPOISON_SCRIPT) so exploit testing always starts from a
    clean, production-routed session -- run this before/after running
    exploits from the Exploits page. Returns a summary dict:
    {"sessions_removed": int, "pool_assignments_removed": [session id, ...],
    "threat_ips_removed": [ip, ...]}."""
    out = _run_redis_cli(remote, "EVAL", _UNPOISON_SCRIPT, "0", timeout=timeout).strip()
    try:
        return json.loads(out)
    except (json.JSONDecodeError, ValueError):
        raise RedisInspectError(f"Unexpected response from unpoison script: {out!r}")


def dbsize(remote: RemoteConfig | None, timeout: float = 10.0) -> int:
    try:
        return int(_run_redis_cli(remote, "DBSIZE", timeout=timeout).strip())
    except (RedisInspectError, ValueError):
        return 0


def flush_all(remote: RemoteConfig | None, timeout: float = 15.0) -> None:
    """Wipes EVERY key in session_store's Redis -- equivalent to `redis-cli
    FLUSHALL` (same command this project's own README documents as the
    "flush all Redis state" one-liner). Used by page_redis.py's "Reset
    Redis KV store" button: this is where router.lua's session-level
    scoring lives (session:*), threat_analyzer.lua's IP-reputation
    classification (threat_ips, fed by Suricata/admin/vulnerability/
    AbuseIPDB detections), pool_router.lua's sticky pool assignments
    (honeypot_pool_session:*), and rate limiting -- unlike
    clear_local_threat_state()'s targeted un-poisoning of just this
    host's own local/test IP, this clears every IP's state, real or
    test. No coming back from this short of the state rebuilding itself
    from live traffic."""
    _run_redis_cli(remote, "FLUSHALL", timeout=timeout)


# Deletes every key except the honeypot pool registry (honeypot_pool:ready /
# :free / :owner:* / :pw:* ...), which pool_manager owns. "honeypot_pool_session:*"
# (a different prefix) IS deleted: that is the per-IP assignment, i.e. threat
# state.
_FLUSH_THREAT_SCRIPT = """
local n = 0
for _, k in ipairs(redis.call('KEYS', '*')) do
  if string.sub(k, 1, 14) ~= 'honeypot_pool:' then
    redis.call('DEL', k)
    n = n + 1
  end
end
return n
"""


def flush_threat_state(remote: RemoteConfig | None, timeout: float = 15.0) -> int:
    """Like flush_all(), but keeps the honeypot pool registry that pool_manager
    maintains. flush_all() would make every pool look unregistered until the
    manager re-adopts them (and lose runtime pools' database passwords).
    Returns the number of keys deleted."""
    out = _run_redis_cli(remote, "EVAL", _FLUSH_THREAT_SCRIPT, "0", timeout=timeout).strip()
    try:
        return int(out)
    except ValueError:
        raise RedisInspectError(f"Unexpected response from flush script: {out!r}")


def session_decision_raw(remote: RemoteConfig | None, session_id: str,
                         timeout: float = 15.0) -> tuple[str, str, str]:
    """(session:<id> JSON, honeypot_pool_session:<id> value, the session's score
    in honeypot_pool:waiting -- set while it borrows a pool until its own is
    built) in one redis-cli call; an empty string where there is none."""
    script = ("return {redis.call('GET', KEYS[1]) or '', redis.call('GET', KEYS[2]) or '', "
              "redis.call('ZSCORE', KEYS[3], ARGV[1]) or ''}")
    out = _run_redis_cli(remote, "EVAL", script, "3", f"session:{session_id}",
                         f"honeypot_pool_session:{session_id}", "honeypot_pool:waiting",
                         session_id, timeout=timeout)
    lines = out.split("\n")
    lines += [""] * (3 - len(lines))
    return lines[0].strip(), lines[1].strip(), lines[2].strip()


def pool_state(remote: RemoteConfig | None, timeout: float = 15.0) -> dict:
    """Snapshot of the honeypot pool registry: ready pools, free (unowned)
    pools, per-pool owner counts, sessions waiting for a pool that is being
    built for them, and why pool_manager is not growing the pool (the `capped`
    reason), if it is not."""
    def ints(text: str) -> list[int]:
        return sorted(int(x) for x in text.split() if x.strip().isdigit())
    ready = ints(_run_redis_cli(remote, "SMEMBERS", "honeypot_pool:ready", timeout=timeout))
    free = ints(_run_redis_cli(remote, "ZRANGE", "honeypot_pool:free", "0", "-1", timeout=timeout))
    owners = {}
    for n in ready:
        owners[n] = int(_run_redis_cli(remote, "SCARD", f"honeypot_pool:owner:{n}",
                                       timeout=timeout).strip() or 0)
    capped = _run_redis_cli(remote, "GET", "honeypot_pool:capped", timeout=timeout).strip()
    reused = _run_redis_cli(remote, "GET", "honeypot_pool:counter", timeout=timeout).strip()
    waiting = _run_redis_cli(remote, "ZCARD", "honeypot_pool:waiting", timeout=timeout).strip()
    try:
        status = json.loads(_run_redis_cli(remote, "GET", "honeypot_pool:status",
                                           timeout=timeout).strip() or "{}")
    except ValueError:
        status = {}
    return {"ready": ready, "free": free, "owners": owners, "capped": capped,
            "waiting": int(waiting) if waiting.isdigit() else 0,
            "reused_assignments": int(reused) if reused.isdigit() else 0,
            # pool_manager's own view: budget, room for more pools, builds in
            # progress ({pool: start epoch}); {} when the manager is not running.
            "status": status if isinstance(status, dict) else {}}


def server_time(remote: RemoteConfig | None, timeout: float = 10.0) -> float:
    """Redis' clock (epoch seconds) -- the edge host's, which pool_manager's
    event timestamps use too."""
    parts = _run_redis_cli(remote, "TIME", timeout=timeout).split()
    return int(parts[0]) + int(parts[1]) / 1e6


def pool_events(remote: RemoteConfig | None, timeout: float = 15.0) -> list[dict]:
    """pool_manager's event log (builds with phase timings, hand-offs with wait
    times, resource-limit transitions), oldest first."""
    out = []
    for line in _run_redis_cli(remote, "LRANGE", "honeypot_pool:events", "0", "-1",
                               timeout=timeout).splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and "at" in e:
            out.append(e)
    return out


def set_pool_reserve(remote: RemoteConfig | None, pools: int, ttl: int = 1800,
                     timeout: float = 10.0) -> None:
    """Ask pool_manager to keep `pools` unowned pools ready (on top of
    POOL_SPARES, within the resource limit); 0 withdraws the request. The TTL
    makes a forgotten request expire on its own."""
    if pools > 0:
        _run_redis_cli(remote, "SET", "honeypot_pool:reserve", str(pools), "EX", str(ttl),
                       timeout=timeout)
    else:
        _run_redis_cli(remote, "DEL", "honeypot_pool:reserve", timeout=timeout)
