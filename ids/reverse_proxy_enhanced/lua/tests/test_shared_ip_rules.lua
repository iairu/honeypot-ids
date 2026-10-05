-- test_shared_ip_rules.lua - Standalone unit tests
--
-- Runs under a plain `lua` interpreter. Covers shared_ip_rules.lua (how much
-- an address's reputation counts on a shared / carrier-grade NAT address) and
-- checks that the proxy keeps a client's own behaviour on its session, not
-- its address, so one attacker can't raise the score of users sharing it.
--
-- Usage:
--   cd ids/reverse_proxy_enhanced/lua/tests
--   lua test_shared_ip_rules.lua

package.path = "../?.lua;" .. package.path
local rules = require "shared_ip_rules"

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

print("== track: distinct sessions per address ==")
do
    local state, n = rules.track(nil, "attacker", 1000, 3600)
    check("first session on an address -> 1", n == 1)
    state, n = rules.track(state, "attacker", 1010, 3600)
    check("same session again -> still 1", n == 1)
    state, n = rules.track(state, "neighbour", 1020, 3600)
    check("second session -> 2", n == 2)
    local _, later = rules.track(state, "neighbour", 1000 + 3700, 3600)
    check("sessions idle longer than the window drop out", later == 1)
    local _, pruned = rules.track(state, nil, 1030, 3600)
    check("nil actor only prunes", pruned == 2)
    local _, bad = rules.track("garbage", "a", 1, 10)
    check("bad stored state is ignored", bad == 1)
end

print("== is_shared ==")
check("1 session is not shared (min 2)", not rules.is_shared(1, 2))
check("2 sessions are shared (min 2)", rules.is_shared(2, 2))
check("nil count is not shared", not rules.is_shared(nil, 2))

print("== contribution ==")
do
    local s, why = rules.contribution(80, true, 10)
    check("shared address: reputation not counted", s == 0 and why == "shared_ip")
    s, why = rules.contribution(80, false, 10)
    check("unshared address: capped", s == 10 and why == "capped")
    s, why = rules.contribution(6, false, 10)
    check("below the cap: unchanged", s == 6 and why == nil)
    s, why = rules.contribution(-20, true, 10)
    check("whitelist (negative) passes through even when shared", s == -20 and why == nil)
    s = rules.contribution(nil, false, 10)
    check("no reputation -> 0", s == 0)
end

print("== CGNAT scenario ==")
do
    -- Attacker and a customer share 198.51.100.1. Suricata flagged the
    -- address (decayed score 90) because of the attacker's exploit traffic.
    local cap, min_sessions, window = 10, 2, 3600
    local state = rules.track(nil, "attacker", 100, window)
    local _, n = rules.track(state, "customer", 160, window)
    local customer_score = rules.contribution(90, rules.is_shared(n, min_sessions), cap)
    check("customer gets nothing from the attacker's alerts", customer_score == 0)

    -- The customer arrives after the attacker's session went idle: the
    -- address looks unshared, but the cap keeps it below router.lua's
    -- "new signal" bar (> 10), so it can't divert or accumulate.
    local _, alone = rules.track(nil, "customer", 100 + window + 10, window)
    local later_score = rules.contribution(90, rules.is_shared(alone, min_sessions), cap)
    check("customer alone later: at most the cap", later_score == cap)
    check("cap never counts as a new signal on its own (router: fresh > 10)", not (later_score > 10))
end

print("== proxy wiring (both honeypot layers) ==")
local function read(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local s = f:read("*a")
    f:close()
    return s
end

local function code_only(src)
    local out = {}
    for line in (src .. "\n"):gmatch("(.-)\n") do
        line = line:gsub("%-%-.*$", "")
        if not line:match("^%s*#") then
            out[#out + 1] = line
        end
    end
    return table.concat(out, "\n")
end

for _, dir in ipairs({ "../..", "../../../db_proxy/reverse_proxy_enhanced" }) do
    local conf = read(dir .. "/nginx.conf")
    check(dir .. "/nginx.conf exists", conf ~= nil)
    if conf then
        local code = code_only(conf)
        local sess = code:find("ngx.ctx.session_id = session_id", 1, true)
        local analyze = code:find("threat_analyzer.analyze_request(", 1, true)
        check(dir .. ": session is resolved before threat analysis", sess and analyze and sess < analyze)
        check(dir .. ": admin attempts are counted per session",
              code:find("ngx.var.remote_addr, admin_uri, ngx.ctx.session_id)", 1, true) ~= nil)
        check(dir .. ": rate limit is keyed per session (address fallback)",
              code:find("limit_req_zone $rate_limit_key", 1, true) ~= nil
              and code:find("limit_req_zone $binary_remote_addr", 1, true) == nil)
    end
end

do
    local ta = code_only(read("../threat_analyzer.lua") or "")
    check("threat_analyzer: rate window keyed per actor", ta:find('"actor:" .. actor', 1, true) ~= nil)
    check("threat_analyzer: timing streak keyed per session",
          ta:find('"timing:" .. (ngx.ctx.session_id', 1, true) ~= nil)
    check("threat_analyzer: address reputation goes through shared_ip_rules",
          ta:find("shared_ip_rules.contribution(", 1, true) ~= nil)

    local admin = code_only(read("../admin_handler.lua") or "")
    check("admin_handler: no longer writes the address's reputation",
          admin:find("increment_threat_score", 1, true) == nil
          and admin:find("red:set('threat_ips'", 1, true) == nil)
    check("admin_handler: brute force tracked per actor",
          admin:find("check_brute_force_attempts(actor)", 1, true) ~= nil)

    local upload = code_only(read("../upload_handler.lua") or "")
    check("upload_handler: no longer writes the address's reputation",
          upload:find("threat_intel.persist", 1, true) == nil)
end

print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
