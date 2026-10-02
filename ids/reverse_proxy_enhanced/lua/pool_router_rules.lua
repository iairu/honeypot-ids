-- pool_router_rules.lua - Pure pool-assignment logic used by pool_router.lua
--
-- PURPOSE:
--   Holds the standalone, side-effect-free pieces of the honeynet pooling
--   algorithm: clamping/round-robin arithmetic, the pool -> upstream/
--   service/database naming convention, and the "pick a healthy pool"
--   fallback search. Factored out with the same intent as router_rules.lua:
--   no ngx.* dependency, no reliance on _G.config/_G.redis_pool, plain-
--   `lua`-interpreter testable (see tests/test_pool_router_rules.lua).
--
--   Redis I/O (the actual IP->pool assignment persistence) and the
--   ngx.shared-backed health cache stay in pool_router.lua -- this module
--   only holds the arithmetic/naming/search logic that sits around that I/O,
--   which is exactly the part most likely to silently break the "every
--   attacker gets one, and only one, consistently-assigned isolated pool"
--   guarantee if it regresses.
--
-- NAMING CONVENTION (must match docker-compose.yml exactly -- see
-- honeypot_eshop_N / honeypot_database_N / honeypot_backend_N service and
-- upstream names there):
--   pool N -> service    honeypot_eshop_N
--   pool N -> database   honeypot_database_N
--   pool N -> upstream   honeypot_backend_N

local _M = {}

-- ---------------------------------------------------------------------------
-- Dynamic pool pool: Redis key schema shared with ids/pool_manager
-- ---------------------------------------------------------------------------
-- pool_manager (the container that creates/destroys honeypot_eshop_N +
-- honeypot_database_N pairs) and pool_router.lua agree on these names.
--   honeypot_pool:ready      SET   pool numbers that are provisioned + healthy
--   honeypot_pool:free       ZSET  ready pools with no owner yet (score = N)
--   honeypot_pool:owner:<N>  SET   IPs currently assigned to pool N
--   honeypot_pool:counter    INT   round-robin counter (reuse path)
--   honeypot_pool:provision  LIST  "an attacker was just assigned" wake-ups
--   honeypot_pool:capped     STR   set (with TTL) by pool_manager while the
--                                  host is too loaded to start another pool
_M.READY_KEY = "honeypot_pool:ready"
_M.FREE_KEY = "honeypot_pool:free"
_M.OWNER_PREFIX = "honeypot_pool:owner:"
_M.COUNTER_KEY = "honeypot_pool:counter"
_M.PROVISION_KEY = "honeypot_pool:provision"
_M.CAPPED_KEY = "honeypot_pool:capped"

-- Pools 1..STATIC_POOL_COUNT are declared in docker-compose.yml with a
-- matching nginx `upstream honeypot_backend_N` block. Higher numbers are
-- created at runtime by pool_manager and reached by container DNS name.
_M.STATIC_POOL_COUNT = 3

-- Hard sanity ceiling for any pool number read back from Redis.
_M.MAX_POOL_NUMBER = 64

--- Atomic assignment, run in Redis with EVAL so concurrent nginx workers can
--- never hand one free pool to two attackers.
---
--- KEYS[1] = honeypot_pool_ip:<IP>   ARGV[1] = IP
--- KEYS[2] = free ZSET               ARGV[2] = assignment TTL (seconds)
--- KEYS[3] = ready SET
--- KEYS[4] = round-robin counter
--- KEYS[5] = provision LIST
---
--- 1. IP already assigned          -> keep its pool ("existing"), refresh TTL.
--- 2. A free ready pool exists     -> that pool becomes the IP's alone
---                                    ("exclusive"), and a wake-up is queued so
---                                    pool_manager builds the next spare.
--- 3. No free pool (all owned, or the host is too loaded to build more)
---                                 -> reuse: round-robin over the ready pools
---                                    ("shared"); still queues a wake-up.
--- 4. No ready pool at all         -> returns {0, "none"}.
---
--- Returns {pool_number, mode}.
_M.ASSIGN_SCRIPT = [[
local ttl = tonumber(ARGV[2])
local existing = redis.call('GET', KEYS[1])
if existing then
  redis.call('EXPIRE', KEYS[1], ttl)
  return {tonumber(existing), 'existing'}
end
local pool, mode
while true do
  local popped = redis.call('ZPOPMIN', KEYS[2])
  if not popped or #popped == 0 then break end
  if redis.call('SISMEMBER', KEYS[3], popped[1]) == 1 then
    pool = tonumber(popped[1])
    mode = 'exclusive'
    break
  end
end
if not pool then
  local ready = redis.call('SMEMBERS', KEYS[3])
  if #ready == 0 then
    return {0, 'none'}
  end
  local nums = {}
  for i, v in ipairs(ready) do nums[i] = tonumber(v) end
  table.sort(nums)
  local c = redis.call('INCR', KEYS[4])
  pool = nums[((c - 1) % #nums) + 1]
  mode = 'shared'
end
redis.call('SET', KEYS[1], tostring(pool), 'EX', ttl)
redis.call('SADD', 'honeypot_pool:owner:' .. pool, ARGV[1])
redis.call('RPUSH', KEYS[5], ARGV[1])
redis.call('LTRIM', KEYS[5], -100, -1)
return {pool, mode}
]]

--- Clamp pool_num to [1..pool_count], defaulting to 1 on invalid input
--- (nil, non-numeric, out of range).
---
--- @param  pool_num    any      Candidate pool number (string or number).
--- @param  pool_count  integer  Total number of pools.
--- @return integer  A valid pool number in [1..pool_count].
function _M.clamp_pool(pool_num, pool_count)
    pool_num = tonumber(pool_num)
    if not pool_num or pool_num < 1 or pool_num > pool_count then
        return 1
    end
    return math.floor(pool_num)
end

--- Map a monotonically increasing Redis counter value to a pool number via
--- 1-indexed modular round-robin.
---
--- @param  counter     integer  Result of the atomic Redis INCR.
--- @param  pool_count  integer  Total number of pools.
--- @return integer  Pool number in [1..pool_count].
function _M.pool_from_counter(counter, pool_count)
    return ((counter - 1) % pool_count) + 1
end

--- @return string  nginx upstream name for a pool, e.g. "honeypot_backend_2".
function _M.upstream_for_pool(pool_num)
    return "honeypot_backend_" .. pool_num
end

--- What nginx should proxy_pass to for a pool. Static pools keep their
--- `honeypot_backend_N` upstream block (keepalive etc.); pools created at
--- runtime have no upstream block, so they are reached by container DNS name
--- (nginx resolves it through the `resolver` directive).
---
--- @param  pool_num  integer
--- @return string
function _M.proxy_target_for_pool(pool_num)
    if pool_num <= _M.STATIC_POOL_COUNT then
        return _M.upstream_for_pool(pool_num)
    end
    return _M.service_for_pool(pool_num)
end

--- @return string  docker-compose service name for a pool's WordPress
---                 container, e.g. "honeypot_eshop_2".
function _M.service_for_pool(pool_num)
    return "honeypot_eshop_" .. pool_num
end

--- @return string  docker-compose service name for a pool's database
---                 container, e.g. "honeypot_database_2".
function _M.database_for_pool(pool_num)
    return "honeypot_database_" .. pool_num
end

--- Human-readable label for an nginx upstream name, for log lines.
---
--- honeypot_backend_N is only an nginx upstream block; there is no container
--- or compose service by that name, so a log line like "Backend
--- honeypot_backend_2 marked as UNHEALTHY" pointed people at something they
--- could not find in `docker compose ps` or the dashboard. This names the
--- containers the upstream actually reaches instead, keeping the upstream
--- name in brackets for anyone grepping nginx.conf.
---
---   honeypot_backend_2  -> "honeypot pool 2 (honeypot_eshop_2 + honeypot_database_2) [honeypot_backend_2]"
---   production_backend  -> "production_eshop [production_backend]"
---   anything else       -> returned unchanged
---
--- @param  upstream  string  nginx upstream name.
--- @return string
function _M.describe_upstream(upstream)
    if type(upstream) ~= "string" then
        return tostring(upstream)
    end
    local n = upstream:match("^honeypot_backend_(%d+)$") or upstream:match("^honeypot_eshop_(%d+)$")
    if n then
        return "honeypot pool " .. n .. " (" .. _M.service_for_pool(n) .. " + "
            .. _M.database_for_pool(n) .. ") [" .. upstream .. "]"
    end
    if upstream == "production_backend" then
        return "production_eshop [production_backend]"
    end
    return upstream
end

--- Starting from `preferred_pool`, search all pools in order and return the
--- first one `is_healthy(candidate)` reports as healthy. Falls back to
--- `preferred_pool` itself if none report healthy, so callers can let the
--- downstream request fail naturally (e.g. nginx returning 502) rather than
--- silently routing nowhere.
---
--- @param  preferred_pool  integer   The pool this IP is actually assigned to.
--- @param  pool_count      integer   Total number of pools.
--- @param  is_healthy      function  is_healthy(pool_num) -> boolean.
--- @return integer, boolean  The chosen pool number, and whether it differs
---                            from preferred_pool (i.e. a fallback occurred).
function _M.find_healthy_pool(preferred_pool, pool_count, is_healthy)
    -- pool_count may also be a list of pool numbers (dynamic pools are not
    -- necessarily contiguous); the search then walks that list in order,
    -- starting at preferred_pool's position.
    local ids = pool_count
    if type(pool_count) ~= "table" then
        ids = {}
        for i = 1, pool_count do ids[i] = i end
    end
    local start = 1
    for i, id in ipairs(ids) do
        if id == preferred_pool then start = i break end
    end
    for offset = 0, #ids - 1 do
        local candidate = ids[((start - 1 + offset) % #ids) + 1]
        if is_healthy(candidate) then
            return candidate, candidate ~= preferred_pool
        end
    end
    return preferred_pool, false
end

--- Parse the comma-separated pool list pool_router mirrors into the shared
--- dict ("1,2,3,5") into a sorted array of valid pool numbers.
---
--- @param  csv  string|nil
--- @return table  Sorted pool numbers; falls back to 1..STATIC_POOL_COUNT.
function _M.parse_pool_list(csv)
    local ids, seen = {}, {}
    for token in tostring(csv or ""):gmatch("%d+") do
        local n = tonumber(token)
        if n >= 1 and n <= _M.MAX_POOL_NUMBER and not seen[n] then
            seen[n] = true
            ids[#ids + 1] = n
        end
    end
    if #ids == 0 then
        for i = 1, _M.STATIC_POOL_COUNT do ids[i] = i end
    end
    table.sort(ids)
    return ids
end

--- Pure decision of whether a recorded health-check status should be
--- treated as "healthy", given the parsed status table (already
--- cjson-decoded by the caller) and the current time. Mirrors
--- pool_router.lua's is_pool_healthy() staleness/default rules exactly:
---   - no status recorded yet             -> healthy (never checked)
---   - status recorded but stale (>60s)   -> healthy (avoid blocking on a
---                                            timer that hasn't fired)
---   - status.healthy explicitly false    -> unhealthy
---   - anything else                      -> healthy
---
--- @param  status  table|nil  Decoded health status, or nil if none recorded.
--- @param  now     integer    Current time (ngx.time()).
--- @return boolean
function _M.is_health_status_healthy(status, now)
    if type(status) ~= "table" then
        return true
    end
    if status.last_check and (now - status.last_check) > 60 then
        return true
    end
    return status.healthy ~= false
end

return _M
