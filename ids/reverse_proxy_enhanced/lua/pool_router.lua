-- pool_router.lua - Honeypot Pool Routing and Assignment Module
--
-- PURPOSE:
--   Implements the honeynet pooling architecture: each attacker SESSION (not
--   IP address -- see session_handler.lua for how a session is kept and
--   recovered) is permanently assigned to a specific honeypot pool instance (honeypot_eshop_N +
--   honeypot_database_N). This gives every attacker their own isolated WordPress
--   environment so their actions cannot cross-contaminate other attacker sessions.
--
-- ARCHITECTURE:
--   - Honeypot pools are numbered 1..N. Pools 1-3 are declared in
--     docker-compose.yml; further pools are created at runtime by the
--     pool_manager container (ids/pool_manager/) and registered in Redis once
--     healthy (honeypot_pool:ready). The set of usable pools is therefore read
--     from Redis, not hard-coded.
--   - EXCLUSIVE assignment: a new attacker session is handed a free ready pool
--     that no other session owns (atomic Redis EVAL, see pool_router_rules.ASSIGN_SCRIPT,
--     so concurrent nginx workers cannot give one pool to two attackers).
--   - SPARE provisioning: every assignment also queues a wake-up on
--     honeypot_pool:provision; pool_manager then builds an additional
--     honeypot_eshop_N + honeypot_database_N pair so one is ready for the next
--     attacker.
--   - SCALE-UP: if no pool is free but pool_manager may still grow (below its
--     resource budget), the session borrows a ready pool round-robin for the
--     moment and joins honeypot_pool:waiting; pool_manager builds pools for
--     the waiting sessions (several in parallel) and moves each one to its
--     own pool as soon as that pool is healthy. Pending sessions are cached
--     locally for a few seconds only, so the move takes effect quickly.
--   - REUSE at the resource limit: once pool_manager has capped growth
--     (resource budget / POOL_MAX reached, or the host is low on memory/CPU/
--     disk), a new session is assigned to an existing ready pool in strict
--     round-robin order and shares it for good. That is the only case in
--     which two attackers end up sharing a pool.
--   - Once assigned, the session->pool mapping lives in Redis with a 24-hour TTL so
--     the same attacker always hits the same fake environment across sessions.
--   - A fast per-request local cache (ngx.shared.honeypot_routes) avoids Redis
--     lookups on every request from a known session.
--   - If a pool instance is found to be unhealthy (tracked via health_check.lua),
--     the router transparently falls back to the next healthy pool without changing
--     the stored assignment; the original assignment is restored as soon as the pool
--     recovers.
--   - If Redis is completely unavailable the module falls back to pool 1 so that
--     traffic continues to flow rather than returning errors.
--
-- REDIS KEY SCHEMA: see pool_router_rules.lua (honeypot_pool:ready / :free /
--   :owner:<N> / :counter / :provision / :capped / :waiting) plus
--   honeypot_pool_session:<SID> -> pool number, TTL POOL_ASSIGNMENT_TTL.
--
-- SHARED DICT USAGE:
--   ngx.shared.honeypot_routes  key "pool_session:<SID>" -> pool number, 5-min local cache
--   ngx.shared.threat_intel     key "pool_list"    -> "1,2,3,5" ready pool numbers,
--                                                    mirrored from Redis by
--                                                    refresh_pool_list() on a timer
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

-- Pool services are named honeypot_eshop_N / honeypot_database_N. Pools
-- 1..rules.STATIC_POOL_COUNT also have an nginx `upstream honeypot_backend_N`
-- block; runtime pools are reached by container DNS name (see
-- pool_router_rules.proxy_target_for_pool).

-- Shared-dict key holding the comma-separated list of ready pool numbers.
local POOL_LIST_KEY = "pool_list"

-- Redis key used to store the per-session pool assignment.
local POOL_ASSIGNMENT_KEY_PREFIX = "honeypot_pool_session:"


-- How long (seconds) a session→pool assignment is retained in Redis.
-- After expiry the session can be assigned to any pool again (acceptable for honeypots).
-- 24 hours is long enough to cover any realistic attack session.
local POOL_ASSIGNMENT_TTL = 86400

-- Local shared-dict cache TTL in seconds (5 minutes).
-- Keeps Redis round-trips off the hot path for known sessions.
local LOCAL_CACHE_TTL = 300

-- Local cache TTL for a session still waiting for a pool of its own: short,
-- so the move pool_manager makes once that pool is ready is seen quickly.
local PENDING_CACHE_TTL = 3

-- Prefix used in ngx.shared.honeypot_routes for cached pool assignments.
local LOCAL_CACHE_KEY_PREFIX = "pool_session:"

-- ---------------------------------------------------------------------------
-- Internal helpers
-- ---------------------------------------------------------------------------

-- Clamp pool_num to [1..MAX_POOL_NUMBER], defaulting to 1 on invalid input.
-- Pure arithmetic lives in pool_router_rules.lua (see tests/test_pool_router_rules.lua).
local function clamp_pool(pool_num)
    return rules.clamp_pool(pool_num, rules.MAX_POOL_NUMBER)
end

-- Sorted list of ready pool numbers (read from the shared dict; falls back to
-- the static pools until the first refresh_pool_list() has run).
local function pool_ids()
    local dict = ngx.shared.threat_intel
    return rules.parse_pool_list(dict and dict:get(POOL_LIST_KEY) or nil)
end

-- Return the cached pool number for owner from the local shared dict,
-- or nil if the entry is absent / expired.
local function get_from_local_cache(owner)
    local dict = ngx.shared.honeypot_routes
    if not dict then return nil end

    local cached = dict:get(LOCAL_CACHE_KEY_PREFIX .. owner)
    if cached then
        return clamp_pool(cached)
    end
    return nil
end

-- Store the pool number for owner in the local shared dict.
local function set_local_cache(owner, pool_num, ttl)
    local dict = ngx.shared.honeypot_routes
    if not dict then return end

    local ok, err, forcible = dict:set(
        LOCAL_CACHE_KEY_PREFIX .. owner,
        tostring(pool_num),
        ttl or LOCAL_CACHE_TTL
    )
    if not ok then
        ngx.log(ngx.WARN,
            "[POOL] Local cache set failed for session ", owner, ": ", err,
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
    local ids = pool_ids()
    local candidate, is_fallback = rules.find_healthy_pool(preferred_pool, ids, is_pool_healthy)

    if is_fallback then
        ngx.log(ngx.WARN,
            "[POOL] Preferred pool ", preferred_pool, " is unhealthy; ",
            "falling back to pool ", candidate, " (temporary, assignment unchanged)")
    elseif candidate == preferred_pool and not is_pool_healthy(preferred_pool) then
        -- All pools report unhealthy – route to the assigned pool and let nginx
        -- return the appropriate error to the attacker.
        ngx.log(ngx.ERR,
            "[POOL] All ", #ids, " honeypot pools appear unhealthy; ",
            "routing to assigned pool ", preferred_pool, " anyway")
    end

    return candidate
end

-- ---------------------------------------------------------------------------
-- Public API
-- ---------------------------------------------------------------------------

--- Return the number of pool instances this module manages.
function _M.get_pool_count()
    return #pool_ids()
end

--- Ready pool numbers, sorted (for health checks / pre-warming / monitoring).
function _M.get_pool_ids()
    return pool_ids()
end

--- Mirror honeypot_pool:ready from Redis into the shared dict. Called from a
--- worker-0 timer in init_worker.lua so request handling never needs Redis just
--- to learn which pools exist.
---
--- @return boolean  true when the list was refreshed.
function _M.refresh_pool_list()
    local dict = ngx.shared.threat_intel
    if not dict then return false end
    local red = _G.redis_pool.get_connection()
    if not red then return false end
    local members = red:smembers(rules.READY_KEY)
    _G.redis_pool.close_connection(red)
    if type(members) ~= "table" then return false end
    dict:set(POOL_LIST_KEY, table.concat(rules.parse_pool_list(table.concat(members, ",")), ","))
    return true
end

--- Return the nginx upstream name for a given pool number.
---
--- @param  pool_num  integer  Pool number (a static or runtime pool).
--- @return string  proxy_pass target: "honeypot_backend_2" for a static pool,
---                  "honeypot_eshop_5" (container DNS name) for a runtime pool.
function _M.get_upstream_for_pool(pool_num)
    pool_num = clamp_pool(pool_num)
    return rules.proxy_target_for_pool(pool_num)
end

--- Retrieve an existing session→pool assignment or create a new one via round-robin.
---
--- The assignment is stored in Redis with POOL_ASSIGNMENT_TTL and also in the
--- local shared dict for fast subsequent lookups.  The function is safe to call
--- on every request: Redis is only contacted when the local cache misses.
---
--- On any Redis error the function degrades gracefully to pool 1.
---
--- @param  owner  string  The session id that owns the pool.
--- @return integer  The assigned pool number.
function _M.get_or_assign_pool(owner)
    if not owner or owner == "" then
        ngx.log(ngx.WARN, "[POOL] Empty session id supplied; defaulting to pool 1")
        return 1
    end

    -- 1. Fast path: local in-worker cache (no Redis round-trip)
    local cached = get_from_local_cache(owner)
    if cached then
        ngx.log(ngx.DEBUG, "[POOL] Local cache hit for session ", owner, " → pool ", cached)
        return find_healthy_pool(cached)
    end

    -- 2. Slow path: query Redis for a previously stored assignment
    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR,
            "[POOL] Redis unavailable (", err, "); defaulting session ", owner, " to pool 1")
        return 1
    end

    local redis_key = POOL_ASSIGNMENT_KEY_PREFIX .. owner
    local existing_pool, redis_err = red:get(redis_key)

    if existing_pool and existing_pool ~= ngx.null then
        -- Assignment already exists in Redis; restore it to local cache and return.
        -- A session still waiting for its own pool is cached only briefly.
        local pool_num = clamp_pool(existing_pool)
        local waiting = red:zscore(rules.WAITING_KEY, owner)
        _G.redis_pool.close_connection(red)

        set_local_cache(owner, pool_num,
            (waiting and waiting ~= ngx.null) and PENDING_CACHE_TTL or nil)

        ngx.log(ngx.INFO,
            "[POOL] Restored existing assignment for session ", owner, " → pool ", pool_num)
        return find_healthy_pool(pool_num)
    end

    -- 3. Brand-new session: one atomic EVAL hands out a free ready pool exclusively
    --    (and queues a spare-pool wake-up for pool_manager), or -- when no pool
    --    is free -- borrows a ready pool round-robin while one is built for it
    --    ("pending"), or shares one for good at the resource limit ("shared").
    --    See ASSIGN_SCRIPT.
    local res, eval_err = red:eval(
        rules.ASSIGN_SCRIPT, 7,
        redis_key, rules.FREE_KEY, rules.READY_KEY, rules.COUNTER_KEY, rules.PROVISION_KEY,
        rules.CAPPED_KEY, rules.WAITING_KEY,
        owner, POOL_ASSIGNMENT_TTL, rules.MAX_WAITING)
    _G.redis_pool.close_connection(red)

    local pool_num = type(res) == "table" and tonumber(res[1]) or nil
    local mode = type(res) == "table" and res[2] or nil
    if not pool_num or pool_num < 1 then
        ngx.log(ngx.ERR,
            "[POOL] No ready honeypot pool for session ", owner, " (",
            eval_err or mode or "unknown", "); defaulting to pool 1")
        return 1
    end
    pool_num = clamp_pool(pool_num)

    -- Populate local cache to avoid Redis on the next request from this session.
    set_local_cache(owner, pool_num, mode == "pending" and PENDING_CACHE_TTL or nil)

    if mode == "shared" then
        ngx.log(ngx.WARN,
            "[POOL] NEW assignment (SHARED, resource limit reached): session ",
            owner, " -> pool ", pool_num)
    elseif mode == "pending" then
        ngx.log(ngx.INFO,
            "[POOL] NEW assignment (PENDING, scaling up): session ", owner,
            " borrows pool ", pool_num, " until its own pool is built")
    else
        ngx.log(ngx.INFO,
            "[POOL] NEW assignment (", mode, "): session ", owner, " -> pool ", pool_num,
            "; spare pool requested")
    end

    return find_healthy_pool(pool_num)
end

--- Extend the TTL of a session's pool assignment without changing the pool number.
--- Call this on each honeypot-bound request to prevent active sessions from expiring.
---
--- @param  owner  string  The session id that owns the pool.
--- @return boolean  true on success, false if Redis was unreachable.
function _M.refresh_assignment_ttl(owner)
    if not owner or owner == "" then return false end

    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.WARN, "[POOL] Cannot refresh TTL for session ", owner, ": ", err)
        return false
    end

    red:expire(POOL_ASSIGNMENT_KEY_PREFIX .. owner, POOL_ASSIGNMENT_TTL)
    _G.redis_pool.close_connection(red)
    return true
end

--- Look up the current pool assignment for a session without creating a new one.
--- Used for logging and analytics where a side-effect-free query is needed.
---
--- @param  owner  string  The session id that owns the pool.
--- @return integer|nil  Pool number, or nil if no assignment exists.
function _M.get_pool_assignment(owner)
    if not owner or owner == "" then return nil end

    -- Check local cache first.
    local cached = get_from_local_cache(owner)
    if cached then return cached end

    local red, err = _G.redis_pool.get_connection()
    if not red then return nil end

    local pool_num = red:get(POOL_ASSIGNMENT_KEY_PREFIX .. owner)
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

    local total_assignments = tonumber(red:get(rules.COUNTER_KEY)) or 0
    local free = red:zrange(rules.FREE_KEY, 0, -1)
    local capped = red:get(rules.CAPPED_KEY)
    local pending = red:llen(rules.PROVISION_KEY)
    local waiting = red:zcard(rules.WAITING_KEY)
    local pools = {}
    local free_set = {}
    for _, n in ipairs(type(free) == "table" and free or {}) do free_set[tonumber(n)] = true end
    for _, i in ipairs(pool_ids()) do
        local owners = red:scard(rules.OWNER_PREFIX .. i)
        pools[#pools + 1] = {
            pool_id    = i,
            upstream   = rules.proxy_target_for_pool(i),
            service    = rules.service_for_pool(i),
            database   = rules.database_for_pool(i),
            healthy    = is_pool_healthy(i),
            free       = free_set[i] or false,
            owners     = tonumber(owners) or 0,
        }
    end
    _G.redis_pool.close_connection(red)

    return {
        pool_count          = #pools,
        reuse_assignments   = total_assignments,
        spare_requests      = tonumber(pending) or 0,
        waiting_sessions    = tonumber(waiting) or 0,
        growth_capped       = (capped and capped ~= ngx.null) and capped or false,
        pools               = pools,
    }
end

return _M