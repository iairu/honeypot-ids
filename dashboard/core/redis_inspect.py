"""Redis introspection for the "session_store" service (openstack-work /
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
import subprocess
from dataclasses import dataclass

from core.docker_ctl import Target
from core.env_upload import download_env_text
from core.paths import EDGE_ENV_FILE
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


# Clears threat_ips / session:* / honeypot_pool_ip:* entries for any IP
# that can only be internal-to-this-docker-host traffic (RFC1918 private
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
# calls) via Lua: KEYS+DEL for the private-IP-matching session:*/
# honeypot_pool_ip:* records, and a filter-then-SET (or DEL if now empty)
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
local session_keys = redis.call("KEYS", "session:*")
for _, key in ipairs(session_keys) do
    local val = redis.call("GET", key)
    if val then
        local ok, data = pcall(cjson.decode, val)
        if ok and type(data) == "table" and data.ip_address and is_local_ip(data.ip_address) then
            redis.call("DEL", key)
            removed_sessions = removed_sessions + 1
        end
    end
end

local removed_pools = {}
local pool_keys = redis.call("KEYS", "honeypot_pool_ip:*")
for _, key in ipairs(pool_keys) do
    local ip = key:sub(#"honeypot_pool_ip:" + 1)
    if is_local_ip(ip) then
        redis.call("DEL", key)
        table.insert(removed_pools, ip)
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
    if remote is None:
        if not EDGE_ENV_FILE.exists():
            raise RedisInspectError(f"{EDGE_ENV_FILE} not found -- run the setup wizard first.")
        text = EDGE_ENV_FILE.read_text()
    else:
        try:
            text = download_env_text("edge", remote, timeout=timeout)
        except Exception as e:
            raise RedisInspectError(f"Could not read remote .env: {e}")

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("REDIS_PASSWORD="):
            return line.split("=", 1)[1].strip()
    raise RedisInspectError("REDIS_PASSWORD not set in .env")


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
        result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RedisInspectError("redis-cli timed out.")
    except OSError as e:
        raise RedisInspectError(f"Could not run redis-cli: {e}")

    if result.returncode != 0:
        stderr = re.sub(r"^Warning: Using a password.*\n?", "", result.stderr).strip()
        raise RedisInspectError(stderr or f"redis-cli exited with code {result.returncode}")

    # The "-a" password warning goes to stderr, not stdout, so stdout is
    # already clean -- no stripping needed there.
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
    {"sessions_removed": int, "pool_assignments_removed": [ip, ...],
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
