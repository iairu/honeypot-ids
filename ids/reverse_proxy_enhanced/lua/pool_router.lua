-- pool_router.lua - Honeypot Pool Routing and Assignment Module
--
-- PURPOSE:
--   Implements the honeynet pooling architecture: each attacking IP address is
--   permanently assigned to a specific honeypot pool instance (honeypot_eshop_N +
--   honeypot_database_N). This gives every attacker their own isolated WordPress
--   environment so their actions cannot cross-contaminate other attacker sessions.
--
-- ARCHITECTURE:
--   - POOL_COUNT honeypot pool instances run as separate Docker services.
--   - Assignment is determined by a round-robin counter stored atomically in Redis
--     (INCR is atomic, so no race conditions under concurrent workers).
--   - Once assigned, the IP→pool mapping is stored in Redis with a 24-hour TTL so
--     the same attacker always hits the same fake environment across separate sessions.
--   - A fast per-request local cache (ngx.shared.honeypot_routes) avoids Redis
--     lookups on every request from a known IP.
--   - If a pool instance is found to be unhealthy (tracked via health_check.lua),
--     the router transparently falls back to the next healthy pool without changing
--     the stored assignment; the original assignment is restored as soon as the pool
--     recovers.
--   - If Redis is completely unavailable the module falls back to pool 1 so that
--     traffic continues to flow rather than returning errors.
--
-- REDIS KEY SCHEMA:
--   honeypot_pool_ip:<IP>      → pool number (string "1".."N"), TTL POOL_ASSIGNMENT_TTL
--   honeypot_pool:counter      → monotonically increasing integer for round-robin
--
-- SHARED DICT USAGE:
--   ngx.shared.honeypot_routes  key "pool_ip:<IP>" → pool number, 5-min local cache
--
-- USAGE (from router.lua):
--   local pool_router = require "pool_router"
--   local pool_num   = pool_router.get_or_assign_pool(remote_ip)
--   local upstream   = pool_router.get_upstream_for_pool(pool_num)

local cjson = require "cjson"
local rules = require "pool_router_rules"

local _M = {}

-- ---------------------------------------------------------------------------
-- Configuration constants
-- ---------------------------------------------------------------------------

-- Total number of honeypot pool instances defined in docker-compose.yml.
-- Pool services are expected to be named: honeypot_eshop_1 … honeypot_eshop_N
-- and their nginx upstreams:            honeypot_backend_1 … honeypot_backend_N
-- If you scale the pool, bump this number and add the matching services/upstreams.
local POOL_COUNT = 3

-- Redis key used to store the per-IP pool assignment.
local POOL_ASSIGNMENT_KEY_PREFIX = "honeypot_pool_ip:"

-- Redis key for the shared round-robin counter across all nginx workers/processes.
local POOL_COUNTER_KEY = "honeypot_pool:counter"

-- How long (seconds) an IP→pool assignment is retained in Redis.
-- After expiry the IP can be assigned to any pool again (acceptable for honeypots).
-- 24 hours is long enough to cover any realistic attack session.
local POOL_ASSIGNMENT_TTL = 86400

-- Local shared-dict cache TTL in seconds (5 minutes).
-- Keeps Redis round-trips off the hot path for known IPs.
local LOCAL_CACHE_TTL = 300

-- Prefix used in ngx.shared.honeypot_routes for cached pool assignments.
local LOCAL_CACHE_KEY_PREFIX = "pool_ip:"

-- ---------------------------------------------------------------------------
-- Internal helpers
-- ---------------------------------------------------------------------------

-- Clamp pool_num to [1..POOL_COUNT], defaulting to 1 on invalid input.
-- Pure arithmetic lives in pool_router_rules.lua (see tests/test_pool_router_rules.lua).
local function clamp_pool(pool_num)
    return rules.clamp_pool(pool_num, POOL_COUNT)
end

-- Return the cached pool number for ip_address from the local shared dict,
-- or nil if the entry is absent / expired.
local function get_from_local_cache(ip_address)
    local dict = ngx.shared.honeypot_routes
    if not dict then return nil end

    local cached = dict:get(LOCAL_CACHE_KEY_PREFIX .. ip_address)
    if cached then
        return clamp_pool(cached)
    end
    return nil
end

-- Store the pool number for ip_address in the local shared dict.
local function set_local_cache(ip_address, pool_num)
    local dict = ngx.shared.honeypot_routes
    if not dict then return end

    local ok, err, forcible = dict:set(
        LOCAL_CACHE_KEY_PREFIX .. ip_address,
        tostring(pool_num),
        LOCAL_CACHE_TTL
    )
    if not ok then
        ngx.log(ngx.WARN,
            "[POOL] Local cache set failed for IP ", ip_address, ": ", err,
            (forcible and " (forcible eviction)" or ""))
    end
end

-- Check whether a pool instance is considered healthy according to the health
-- status recorded by health_check.lua in ngx.shared.threat_intel.
-- Returns true when the status is unknown (assume healthy to avoid blocking traffic).
-- Staleness/default rules are pure logic in pool_router_rules.is_health_status_healthy.
--
-- Also folds in the pool's REPLICATION state: while
-- scripts/replicate_content_to_honeypot.sh is applying its sync to this
-- pool's database, the pool is treated exactly like a temporarily unhealthy
-- backend -- NOT because it's actually down, but so that find_healthy_pool()
-- transparently steers both new attacker assignments and existing
-- session lookups to a different, ready pool for the few seconds the sync
-- takes, then automatically resumes on this pool once its flag clears. This
-- reuses the existing failover mechanism rather than adding new blocking
-- logic; see that script's header comment for the other half of this.
-- init_worker.lua mirrors the Redis-side honeypot_pool_replicating:<N> flag
-- into this same shared dict on a short timer, so this check itself stays
-- Redis-free on the hot path.
local function is_pool_healthy(pool_num)
    local health_dict = ngx.shared.threat_intel
    if not health_dict then return true end -- no data → optimistic

    if health_dict:get("replicating:honeypot_backend_" .. pool_num) == "1" then
        return false
    end

    local status_json = health_dict:get("health:honeypot_backend_" .. pool_num)
    if not status_json then
        return true -- never checked yet → assume healthy
    end

    local ok, status = pcall(cjson.decode, status_json)
    if not ok then
        return true -- malformed entry → optimistic
    end

    return rules.is_health_status_healthy(status, ngx.time())
end

-- Starting from `preferred_pool`, iterate through all pools in order and return
-- the first healthy one.  If none are healthy, return preferred_pool anyway so
-- nginx can handle the failure naturally (returns 502 etc.).
-- Search order/fallback logic is pure in pool_router_rules.find_healthy_pool.
local function find_healthy_pool(preferred_pool)
    local candidate, is_fallback = rules.find_healthy_pool(preferred_pool, POOL_COUNT, is_pool_healthy)

    if is_fallback then
        ngx.log(ngx.WARN,
            "[POOL] Preferred pool ", preferred_pool, " is unhealthy; ",
            "falling back to pool ", candidate, " (temporary, assignment unchanged)")
    elseif candidate == preferred_pool and not is_pool_healthy(preferred_pool) then
        -- All pools report unhealthy – route to the assigned pool and let nginx
        -- return the appropriate error to the attacker.
        ngx.log(ngx.ERR,
            "[POOL] All ", POOL_COUNT, " honeypot pools appear unhealthy; ",
            "routing to assigned pool ", preferred_pool, " anyway")
    end

    return candidate
end

-- ---------------------------------------------------------------------------
-- Public API
-- ---------------------------------------------------------------------------

--- Return the number of pool instances this module manages.
function _M.get_pool_count()
    return POOL_COUNT
end

--- Return the nginx upstream name for a given pool number.
---
--- @param  pool_num  integer  Pool number in range [1..POOL_COUNT].
--- @return string  Upstream name, e.g. "honeypot_backend_2".
function _M.get_upstream_for_pool(pool_num)
    pool_num = clamp_pool(pool_num)
    return rules.upstream_for_pool(pool_num)
end

--- Retrieve an existing IP→pool assignment or create a new one via round-robin.
---
--- The assignment is stored in Redis with POOL_ASSIGNMENT_TTL and also in the
--- local shared dict for fast subsequent lookups.  The function is safe to call
--- on every request: Redis is only contacted when the local cache misses.
---
--- On any Redis error the function degrades gracefully to pool 1.
---
--- @param  ip_address  string  The remote client IP address.
--- @return integer  The assigned pool number in range [1..POOL_COUNT].
function _M.get_or_assign_pool(ip_address)
    if not ip_address or ip_address == "" then
        ngx.log(ngx.WARN, "[POOL] Empty IP address supplied; defaulting to pool 1")
        return 1
    end

    -- 1. Fast path: local in-worker cache (no Redis round-trip)
    local cached = get_from_local_cache(ip_address)
    if cached then
        ngx.log(ngx.DEBUG, "[POOL] Local cache hit for IP ", ip_address, " → pool ", cached)
        return find_healthy_pool(cached)
    end

    -- 2. Slow path: query Redis for a previously stored assignment
    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR,
            "[POOL] Redis unavailable (", err, "); defaulting IP ", ip_address, " to pool 1")
        return 1
    end

    local redis_key = POOL_ASSIGNMENT_KEY_PREFIX .. ip_address
    local existing_pool, redis_err = red:get(redis_key)

    if existing_pool and existing_pool ~= ngx.null then
        -- Assignment already exists in Redis; restore it to local cache and return.
        local pool_num = clamp_pool(existing_pool)
        _G.redis_pool.close_connection(red)

        set_local_cache(ip_address, pool_num)

        ngx.log(ngx.INFO,
            "[POOL] Restored existing assignment for IP ", ip_address, " → pool ", pool_num)
        return find_healthy_pool(pool_num)
    end

    -- 3. Brand-new IP: assign via atomic round-robin counter in Redis.
    --    INCR is atomic across all nginx workers and processes, ensuring that
    --    concurrent requests from different workers never produce duplicate assignments.
    local counter, incr_err = red:incr(POOL_COUNTER_KEY)
    if not counter then
        ngx.log(ngx.ERR,
            "[POOL] Redis INCR failed (", incr_err, "); defaulting IP ", ip_address, " to pool 1")
        _G.redis_pool.close_connection(red)
        return 1
    end

    -- Map counter to pool number using modular arithmetic (1-indexed).
    local pool_num = rules.pool_from_counter(counter, POOL_COUNT)

    -- Persist the assignment with TTL so the same IP always hits the same pool.
    local set_ok, set_err = red:setex(redis_key, POOL_ASSIGNMENT_TTL, tostring(pool_num))
    if not set_ok then
        ngx.log(ngx.WARN,
            "[POOL] Could not persist assignment for IP ", ip_address, " (", set_err, "); ",
            "pool ", pool_num, " will be used for this request only")
    end

    _G.redis_pool.close_connection(red)

    -- Populate local cache to avoid Redis on the next request from this IP.
    set_local_cache(ip_address, pool_num)

    ngx.log(ngx.INFO,
        "[POOL] NEW assignment: IP ", ip_address, " → pool ", pool_num,
        " (counter=", counter, ", total_pools=", POOL_COUNT, ")")

    return find_healthy_pool(pool_num)
end

--- Extend the TTL of an IP's pool assignment without changing the pool number.
--- Call this on each honeypot-bound request to prevent active sessions from expiring.
---
--- @param  ip_address  string  The remote client IP address.
--- @return boolean  true on success, false if Redis was unreachable.
function _M.refresh_assignment_ttl(ip_address)
    if not ip_address or ip_address == "" then return false end

    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.WARN, "[POOL] Cannot refresh TTL for ", ip_address, ": ", err)
        return false
    end

    red:expire(POOL_ASSIGNMENT_KEY_PREFIX .. ip_address, POOL_ASSIGNMENT_TTL)
    _G.redis_pool.close_connection(red)
    return true
end

--- Look up the current pool assignment for an IP without creating a new one.
--- Used for logging and analytics where a side-effect-free query is needed.
---
--- @param  ip_address  string  The remote client IP address.
--- @return integer|nil  Pool number, or nil if no assignment exists.
function _M.get_pool_assignment(ip_address)
    if not ip_address or ip_address == "" then return nil end

    -- Check local cache first.
    local cached = get_from_local_cache(ip_address)
    if cached then return cached end

    local red, err = _G.redis_pool.get_connection()
    if not red then return nil end

    local pool_num = red:get(POOL_ASSIGNMENT_KEY_PREFIX .. ip_address)
    _G.redis_pool.close_connection(red)

    if pool_num and pool_num ~= ngx.null then
        return clamp_pool(pool_num)
    end
    return nil
end

--- Collect runtime statistics for all pools (used by monitoring / health endpoint).
---
--- @return table  Stats object, or nil + error string on failure.
function _M.get_pool_stats()
    local red, err = _G.redis_pool.get_connection()
    if not red then
        return nil, "Redis unavailable: " .. (err or "unknown")
    end

    -- Total number of IP assignments ever made (monotonic counter).
    local total_assignments_raw = red:get(POOL_COUNTER_KEY)
    _G.redis_pool.close_connection(red)

    local total_assignments = tonumber(total_assignments_raw) or 0

    local pools = {}
    for i = 1, POOL_COUNT do
        pools[i] = {
            pool_id    = i,
            upstream   = rules.upstream_for_pool(i),
            service    = rules.service_for_pool(i),
            database   = rules.database_for_pool(i),
            healthy    = is_pool_healthy(i),
        }
    end

    return {
        pool_count        = POOL_COUNT,
        total_assignments = total_assignments,
        pools             = pools,
    }
end

return _M