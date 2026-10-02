-- test_pool_assignment.lua - Standalone tests for the exclusive, dynamic
-- honeypot pool assignment (pool_router_rules.ASSIGN_SCRIPT).
--
-- Runs under a plain `lua`/luajit interpreter: the Redis EVAL script is
-- executed against a tiny in-memory fake of the handful of Redis commands it
-- uses, so this tests the REAL script text that pool_router.lua sends to Redis.
--
-- Guarantees checked:
--   1. While a free ready pool exists, every new attacker IP gets a pool that
--      no other IP owns ("exclusive"), and the same IP always keeps its pool.
--   2. Each exclusive assignment queues a wake-up for pool_manager, which is
--      what builds the next spare pool.
--   3. When no pool is free (all owned, or pool_manager is capped by host
--      resources) new IPs reuse ready pools in strict round-robin ("shared").
--   4. A pool pool_manager registers later (a new spare) is picked up by the
--      next attacker; stale/unready entries in the free set are never handed out.
--   5. No ready pool at all -> {0, "none"} rather than a made-up pool.

package.path = "../?.lua;" .. package.path
local rules = require "pool_router_rules"

local passed, failed = 0, 0
local function check(name, condition)
    if condition then passed = passed + 1; print("  [PASS] " .. name)
    else failed = failed + 1; print("  [FAIL] " .. name) end
end

-- ---- minimal in-memory Redis ---------------------------------------------
local function new_redis()
    local kv, sets, zsets, lists, ttl = {}, {}, {}, {}, {}
    local r = { kv = kv, sets = sets, zsets = zsets, lists = lists, ttl = ttl }
    local function sorted_zset(z)
        local items = {}
        for m, sc in pairs(z) do items[#items + 1] = { m = m, s = sc } end
        table.sort(items, function(a, b) if a.s ~= b.s then return a.s < b.s end return a.m < b.m end)
        return items
    end
    local cmds = {}
    function cmds.GET(k) return kv[k] or false end
    function cmds.SET(k, v, ex, t) kv[k] = v; if ex == "EX" then ttl[k] = tonumber(t) end return "OK" end
    function cmds.EXPIRE(k, t) ttl[k] = tonumber(t); return 1 end
    function cmds.INCR(k) kv[k] = tostring((tonumber(kv[k]) or 0) + 1); return tonumber(kv[k]) end
    function cmds.SADD(k, v) sets[k] = sets[k] or {}; sets[k][tostring(v)] = true; return 1 end
    function cmds.SISMEMBER(k, v) return (sets[k] and sets[k][tostring(v)]) and 1 or 0 end
    function cmds.SMEMBERS(k)
        local out = {}
        for v in pairs(sets[k] or {}) do out[#out + 1] = v end
        table.sort(out)
        return out
    end
    function cmds.ZADD(k, score, m) zsets[k] = zsets[k] or {}; zsets[k][tostring(m)] = tonumber(score); return 1 end
    function cmds.ZPOPMIN(k)
        local z = zsets[k] or {}
        local items = sorted_zset(z)
        if #items == 0 then return {} end
        z[items[1].m] = nil
        return { items[1].m, tostring(items[1].s) }
    end
    function cmds.RPUSH(k, v) lists[k] = lists[k] or {}; table.insert(lists[k], v); return #lists[k] end
    function cmds.LTRIM(k, a, b)
        local l = lists[k] or {}
        local n = #l
        if a < 0 then a = n + a end
        local out = {}
        for i = a + 1, n do out[#out + 1] = l[i] end
        lists[k] = out
        return "OK"
    end
    local env = setmetatable({ redis = { call = function(c, ...) return cmds[c](...) end } },
                             { __index = _G })
    -- Lua 5.1 (LuaJIT) loads then setfenv()s; 5.2+ takes the env in load().
    local function run_script()
        if setfenv then
            local chunk = assert(loadstring(rules.ASSIGN_SCRIPT))
            setfenv(chunk, env)
            return chunk()
        end
        return assert(load(rules.ASSIGN_SCRIPT, "assign", "t", env))()
    end
    function r.assign(ip, ttl_s)
        env.KEYS = { "honeypot_pool_ip:" .. ip, rules.FREE_KEY, rules.READY_KEY,
                     rules.COUNTER_KEY, rules.PROVISION_KEY }
        env.ARGV = { ip, tostring(ttl_s or 86400) }
        local res = run_script()
        return res[1], res[2]
    end
    function r.add_pool(n, owned)
        cmds.SADD(rules.READY_KEY, n)
        if not owned then cmds.ZADD(rules.FREE_KEY, n, n) end
    end
    return r
end

print("== exclusive assignment: one attacker per pool ==")
do
    local r = new_redis()
    for n = 1, 3 do r.add_pool(n) end
    local owner = {}
    local ok_unique = true
    for i = 1, 3 do
        local pool, mode = r.assign("10.0.0." .. i)
        if mode ~= "exclusive" or owner[pool] then ok_unique = false end
        owner[pool] = "10.0.0." .. i
    end
    check("3 attackers -> 3 distinct pools, all exclusive", ok_unique)
    check("lowest free pool is handed out first (1,2,3)",
          owner[1] == "10.0.0.1" and owner[2] == "10.0.0.2" and owner[3] == "10.0.0.3")
    local p, m = r.assign("10.0.0.2")
    check("a known IP keeps its pool", p == 2 and m == "existing")
    check("each exclusive assignment queued a pool_manager wake-up", #r.lists[rules.PROVISION_KEY] == 3)
    check("owner set holds exactly the one attacker",
          r.sets[rules.OWNER_PREFIX .. "1"]["10.0.0.1"] and next(r.sets[rules.OWNER_PREFIX .. "1"], "10.0.0.1") == nil)
    check("assignment TTL is applied", r.ttl["honeypot_pool_ip:10.0.0.1"] == 86400)
end

print("== spare pool added after an assignment is used by the next attacker ==")
do
    local r = new_redis()
    for n = 1, 3 do r.add_pool(n) end
    for i = 1, 3 do r.assign("10.0.1." .. i) end
    r.add_pool(4)  -- pool_manager finished building a spare
    local p, m = r.assign("10.0.1.4")
    check("4th attacker gets the new spare exclusively", p == 4 and m == "exclusive")
end

print("== no free pool (all owned / host capped): strict round-robin reuse ==")
do
    local r = new_redis()
    for n = 1, 3 do r.add_pool(n) end
    for i = 1, 3 do r.assign("10.0.2." .. i) end
    local got = {}
    for i = 4, 9 do
        local p, m = r.assign("10.0.2." .. i)
        got[#got + 1] = p
        if m ~= "shared" then got.bad = true end
    end
    check("reuse mode is 'shared'", not got.bad)
    check("reuse cycles 1,2,3,1,2,3", table.concat(got, ",") == "1,2,3,1,2,3")
    r.assign("10.0.2.10")
    check("reuse still queues a wake-up (manager may be able to build more later)",
          #r.lists[rules.PROVISION_KEY] >= 10)
end

print("== stale / unready free entries are never handed out ==")
do
    local r = new_redis()
    r.add_pool(2)
    r.zsets[rules.FREE_KEY]["1"] = 1   -- pool 1 is in free but NOT ready (was destroyed)
    local p, m = r.assign("10.0.3.1")
    check("unready pool 1 skipped, ready pool 2 used", p == 2 and m == "exclusive")
end

print("== nothing ready ==")
do
    local r = new_redis()
    local p, m = r.assign("10.0.4.1")
    check("returns pool 0 / 'none'", p == 0 and m == "none")
    check("nothing recorded for the IP", r.kv["honeypot_pool_ip:10.0.4.1"] == nil)
end

print("== proxy target + pool list helpers ==")
do
    check("static pools keep their upstream block", rules.proxy_target_for_pool(3) == "honeypot_backend_3")
    check("runtime pools are reached by container name", rules.proxy_target_for_pool(4) == "honeypot_eshop_4")
    check("describe_upstream understands runtime pool names",
          rules.describe_upstream("honeypot_eshop_5"):find("honeypot_database_5", 1, true) ~= nil)
    local ids = rules.parse_pool_list("5,1,3,3,abc,99999")
    check("parse_pool_list sorts, dedupes, drops out-of-range", table.concat(ids, ",") == "1,3,5")
    check("empty list falls back to the static pools", table.concat(rules.parse_pool_list(""), ",") == "1,2,3")
    local healthy = { [5] = true }
    local c, fb = rules.find_healthy_pool(1, {1, 3, 5}, function(n) return healthy[n] end)
    check("find_healthy_pool walks a non-contiguous list", c == 5 and fb == true)
end

print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
