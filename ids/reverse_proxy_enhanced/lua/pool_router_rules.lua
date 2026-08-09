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
    for offset = 0, pool_count - 1 do
        local candidate = ((preferred_pool - 1 + offset) % pool_count) + 1
        if is_healthy(candidate) then
            return candidate, candidate ~= preferred_pool
        end
    end
    return preferred_pool, false
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
