-- test_pool_router_rules.lua - Standalone unit tests
--
-- Runs under a plain `lua` interpreter (no OpenResty/ngx/redis required),
-- since pool_router_rules.lua has no ngx.*/_G.* dependency by design.
--
-- Usage:
--   cd openstack-work/reverse_proxy_enhanced/lua/tests
--   lua test_pool_router_rules.lua
--
-- This is the "comprehensive test that all database pools are properly
-- bound to honeypot container" and "session bind per attacker to a single
-- container" test referenced from architecture.canvas. What it covers:
--
--   1. Naming convention (upstream_for_pool/service_for_pool/database_for_pool)
--      produces a unique, collision-free 1:1 mapping for every pool, and
--      matches docker-compose.yml's honeypot_eshop_N/honeypot_database_N/
--      honeypot_backend_N naming exactly.
--   2. clamp_pool/pool_from_counter never produce a pool number outside
--      [1..POOL_COUNT], and pool_from_counter is a true round-robin cycle
--      (each pool gets exactly one slot per POOL_COUNT consecutive counter
--      values) -- this is the mechanism that keeps a given attacker IP
--      permanently bound to ONE pool (pool_router.get_or_assign_pool()
--      stores this value in Redis with a 24h TTL and never recomputes it
--      for a known IP; see pool_router.lua's module docstring).
--   3. find_healthy_pool's fallback search never returns a pool number
--      outside range, prefers the assigned pool when healthy, and degrades
--      predictably when it and others are unhealthy.
--
-- What this does NOT cover (see openstack-work/testing/test_pool_isolation.sh
-- for the live/runtime half of "properly bound"): that each honeypot_eshop_N
-- container can actually only authenticate against its own honeypot_database_N
-- at the credential level, not just in naming/config.

package.path = "../?.lua;" .. package.path
local rules = require "pool_router_rules"

local passed, failed = 0, 0

local function check(name, condition)
    if condition then
        passed = passed + 1
        print("  [PASS] " .. name)
    else
        failed = failed + 1
        print("  [FAIL] " .. name)
    end
end

local POOL_COUNT = 3

print("== naming convention: unique, collision-free, matches docker-compose.yml ==")
do
    local upstreams, services, databases = {}, {}, {}
    for i = 1, POOL_COUNT do
        upstreams[i] = rules.upstream_for_pool(i)
        services[i] = rules.service_for_pool(i)
        databases[i] = rules.database_for_pool(i)
    end

    check("upstream names match docker-compose.yml convention",
          upstreams[1] == "honeypot_backend_1" and
          upstreams[2] == "honeypot_backend_2" and
          upstreams[3] == "honeypot_backend_3")

    check("service names match docker-compose.yml convention",
          services[1] == "honeypot_eshop_1" and
          services[2] == "honeypot_eshop_2" and
          services[3] == "honeypot_eshop_3")

    check("database names match docker-compose.yml convention",
          databases[1] == "honeypot_database_1" and
          databases[2] == "honeypot_database_2" and
          databases[3] == "honeypot_database_3")

    -- "properly bound" requires every pool's database name to be unique --
    -- if two pool numbers ever mapped to the same database_for_pool() value,
    -- two independent attacker pools would share one database.
    local seen = {}
    local all_unique = true
    for i = 1, POOL_COUNT do
        if seen[databases[i]] then all_unique = false end
        seen[databases[i]] = true
    end
    check("every pool's database name is unique (no shared DB binding)", all_unique)

    -- Every pool's service, database, and upstream name must all carry the
    -- SAME pool number suffix as each other -- this is what "bound to
    -- honeypot container" means concretely: pool N's eshop only ever maps
    -- to pool N's database and pool N's upstream, never pool M's.
    local suffix_matches = true
    for i = 1, POOL_COUNT do
        local suffix = tostring(i)
        if services[i]:sub(-#suffix) ~= suffix
            or databases[i]:sub(-#suffix) ~= suffix
            or upstreams[i]:sub(-#suffix) ~= suffix then
            suffix_matches = false
        end
    end
    check("service/database/upstream names for a pool all share the same pool index",
          suffix_matches)
end

print("== clamp_pool() ==")
do
    check("valid pool number passes through unchanged", rules.clamp_pool(2, POOL_COUNT) == 2)
    check("nil defaults to 1", rules.clamp_pool(nil, POOL_COUNT) == 1)
    check("0 defaults to 1", rules.clamp_pool(0, POOL_COUNT) == 1)
    check("negative defaults to 1", rules.clamp_pool(-5, POOL_COUNT) == 1)
    check("above pool_count defaults to 1", rules.clamp_pool(POOL_COUNT + 1, POOL_COUNT) == 1)
    check("non-numeric string defaults to 1", rules.clamp_pool("abc", POOL_COUNT) == 1)
    check("numeric string is coerced", rules.clamp_pool("3", POOL_COUNT) == 3)
    check("fractional pool number is floored", rules.clamp_pool(2.9, POOL_COUNT) == 2)

    for _, count in ipairs({ 1, 3, 5 }) do
        for pool = 1, count do
            check(string.format("clamp_pool(%d, %d) stays in range", pool, count),
                  rules.clamp_pool(pool, count) >= 1 and rules.clamp_pool(pool, count) <= count)
        end
    end
end

print("== pool_from_counter(): stable round-robin, never out of range ==")
do
    check("counter 1 -> pool 1", rules.pool_from_counter(1, POOL_COUNT) == 1)
    check("counter 2 -> pool 2", rules.pool_from_counter(2, POOL_COUNT) == 2)
    check("counter 3 -> pool 3", rules.pool_from_counter(3, POOL_COUNT) == 3)
    check("counter 4 wraps to pool 1", rules.pool_from_counter(4, POOL_COUNT) == 1)
    check("counter 6 wraps to pool 3", rules.pool_from_counter(6, POOL_COUNT) == 3)

    -- Every attacker IP gets a counter value once (INCR) and that pool
    -- assignment is what's persisted in Redis for 24h -- if the mapping
    -- ever produced a value outside [1..POOL_COUNT] a brand-new attacker
    -- IP could be assigned to a pool that doesn't exist.
    local out_of_range = false
    local histogram = {}
    for counter = 1, 300 do
        local pool = rules.pool_from_counter(counter, POOL_COUNT)
        if pool < 1 or pool > POOL_COUNT then out_of_range = true end
        histogram[pool] = (histogram[pool] or 0) + 1
    end
    check("300 consecutive counters never produce an out-of-range pool", not out_of_range)

    -- A true round-robin cycle must distribute new attacker IPs evenly
    -- across pools (not skew all new assignments onto one pool).
    local even = true
    for pool = 1, POOL_COUNT do
        if histogram[pool] ~= 100 then even = false end
    end
    check("300 counters distribute exactly evenly across 3 pools (100 each)", even)
end

print("== find_healthy_pool(): fallback search ==")
do
    local function all_healthy() return true end
    local function none_healthy() return false end

    local pool, is_fallback = rules.find_healthy_pool(2, POOL_COUNT, all_healthy)
    check("assigned pool returned as-is when healthy (no fallback)",
          pool == 2 and is_fallback == false)

    local only_1_healthy = function(n) return n == 1 end
    pool, is_fallback = rules.find_healthy_pool(2, POOL_COUNT, only_1_healthy)
    check("falls forward-then-wraps to the nearest healthy pool",
          pool == 1 and is_fallback == true)

    pool, is_fallback = rules.find_healthy_pool(3, POOL_COUNT, none_healthy)
    check("all-unhealthy degrades to the originally assigned pool (not some other one)",
          pool == 3 and is_fallback == false)

    -- The fallback must never silently reassign an attacker to a
    -- permanently different pool -- session_data.honeypot_pool in Redis is
    -- untouched by find_healthy_pool; this is a per-request routing
    -- decision only.
    for preferred = 1, POOL_COUNT do
        local p = rules.find_healthy_pool(preferred, POOL_COUNT, all_healthy)
        check(string.format("preferred pool %d never overridden when it's healthy", preferred),
              p == preferred)
    end
end

print("== is_health_status_healthy() ==")
do
    check("no status recorded -> healthy (never checked)",
          rules.is_health_status_healthy(nil, 1000) == true)

    check("non-table status -> healthy (malformed/optimistic)",
          rules.is_health_status_healthy("garbage", 1000) == true)

    check("fresh status, healthy=true -> healthy",
          rules.is_health_status_healthy({ healthy = true, last_check = 995 }, 1000) == true)

    check("fresh status, healthy=false -> unhealthy",
          rules.is_health_status_healthy({ healthy = false, last_check = 995 }, 1000) == false)

    check("fresh status, healthy field absent -> healthy (default)",
          rules.is_health_status_healthy({ last_check = 995 }, 1000) == true)

    check("stale status (>60s old), healthy=false -> treated as healthy anyway",
          rules.is_health_status_healthy({ healthy = false, last_check = 900 }, 1000) == true)

    check("exactly 60s old is NOT yet stale (> not >=)",
          rules.is_health_status_healthy({ healthy = false, last_check = 940 }, 1000) == false)
end

print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
