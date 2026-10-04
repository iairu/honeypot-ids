#!/usr/bin/env lua
-- test_no_tarpit.lua -- the proxy must never hold a request back.
-- A per-route delay (the old apply_botnet_slowdown tarpit) lets an attacker
-- tell the honeypot from production by latency, so no code on the request
-- path may sleep. Only health_check.lua and init_worker.lua sleep, and they
-- run in background worker timers, never inside a request.
-- Runs under a plain `lua` interpreter.

local passed, failed = 0, 0
local function check(name, cond)
    if cond then
        passed = passed + 1
        print("  [PASS] " .. name)
    else
        failed = failed + 1
        print("  [FAIL] " .. name)
    end
end

local function read(path)
    local f = assert(io.open(path, "r"))
    local s = f:read("*a")
    f:close()
    return s
end

-- Drops Lua "--" comments so documentation about the removed tarpit is fine.
local function code_only(src)
    local out = {}
    for line in (src .. "\n"):gmatch("(.-)\n") do
        out[#out + 1] = (line:gsub("%-%-.*$", ""))
    end
    return table.concat(out, "\n")
end

local BACKGROUND_ONLY = { ["health_check.lua"] = true, ["init_worker.lua"] = true }
local LUA_FILES = {
    "abuseipdb_client.lua", "abuseipdb_rules.lua", "admin_handler.lua",
    "admin_rules.lua", "decay_policy.lua", "honeytoken_handler.lua",
    "honeytoken_rules.lua", "init.lua", "ip_rules.lua", "lua_pattern_utils.lua",
    "pool_router.lua", "pool_router_rules.lua", "prompt_injection_filter.lua",
    "router.lua", "router_rules.lua", "session_handler.lua", "session_rules.lua",
    "sophistication_analyzer.lua", "suricata_rules.lua", "threat_analyzer.lua",
    "threat_intel.lua", "threat_rules.lua", "upload_handler.lua", "upload_rules.lua",
    "vulnerability_handler.lua", "vulnerability_rules.lua", "wp_install_state.lua",
}

print("== request-path Lua modules never sleep ==")
for _, name in ipairs(LUA_FILES) do
    assert(not BACKGROUND_ONLY[name])
    local src = code_only(read("../" .. name))
    check(name .. " has no ngx.sleep", not src:find("ngx%.sleep"))
end

print("== router has no tarpit ==")
local router_src = code_only(read("../router.lua"))
check("router.lua defines no apply_botnet_slowdown",
      not router_src:find("apply_botnet_slowdown"))

print("== nginx.conf files never call the tarpit or sleep ==")
for _, path in ipairs({ "../../nginx.conf", "../../../db_proxy/reverse_proxy_enhanced/nginx.conf" }) do
    local src = code_only(read(path))
    check(path .. " has no apply_botnet_slowdown", not src:find("apply_botnet_slowdown"))
    check(path .. " has no ngx.sleep", not src:find("ngx%.sleep"))
end

print("")
print(passed .. " passed, " .. failed .. " failed")
os.exit(failed == 0 and 0 or 1)
