-- test_test_client_rules.lua - Standalone unit tests
--
-- Runs under a plain `lua` interpreter. Covers test_client_rules.lua (the
-- secret-gated X-Test-Client-IP override the dashboard's Pool Test page uses
-- to run several simulated attackers from one machine) and checks that both
-- nginx.conf copies wire it up: $client_ip resolved once per request, used for
-- routing, and the header never forwarded to an eshop.
--
-- Usage:
--   cd ids/reverse_proxy_enhanced/lua/tests
--   lua test_test_client_rules.lua

package.path = "../?.lua;" .. package.path
local rules = require "test_client_rules"

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

local GW = "172.18.0.1"
local SECRET = "s3cret"

print("== is_test_ip: only 198.18.0.0/15 ==")
check("198.18.0.11 is a test address", rules.is_test_ip("198.18.0.11"))
check("198.19.255.255 is a test address", rules.is_test_ip("198.19.255.255"))
check("198.17.0.1 is not", not rules.is_test_ip("198.17.0.1"))
check("198.20.0.1 is not", not rules.is_test_ip("198.20.0.1"))
check("127.0.0.1 is not", not rules.is_test_ip("127.0.0.1"))
check("a real address is not", not rules.is_test_ip("8.8.8.8"))
check("out-of-range octet is rejected", not rules.is_test_ip("198.18.0.256"))
check("trailing junk is rejected", not rules.is_test_ip("198.18.0.1, 8.8.8.8"))
check("IPv6 is rejected", not rules.is_test_ip("::1"))
check("nil is rejected", not rules.is_test_ip(nil))

print("== resolve: header honoured only with the secret ==")
do
    local ip, sim = rules.resolve(GW, "198.18.0.11", SECRET, SECRET)
    check("secret + test address -> simulated client", ip == "198.18.0.11" and sim == true)

    ip, sim = rules.resolve(GW, "198.18.0.11", "wrong", SECRET)
    check("wrong secret -> remote_addr", ip == GW and sim == false)

    ip, sim = rules.resolve(GW, "198.18.0.11", nil, SECRET)
    check("no secret presented -> remote_addr", ip == GW and sim == false)

    ip, sim = rules.resolve(GW, "198.18.0.11", "", "")
    check("no secret configured -> remote_addr (even if an empty one is presented)",
          ip == GW and sim == false)

    ip, sim = rules.resolve(GW, "198.18.0.11", nil, nil)
    check("secret unset -> remote_addr", ip == GW and sim == false)

    ip, sim = rules.resolve(GW, "127.0.0.1", SECRET, SECRET)
    check("secret cannot claim a whitelisted address", ip == GW and sim == false)

    ip, sim = rules.resolve(GW, "203.0.113.9", SECRET, SECRET)
    check("secret cannot claim another real address", ip == GW and sim == false)

    ip, sim = rules.resolve(GW, nil, SECRET, SECRET)
    check("no header -> remote_addr", ip == GW and sim == false)

    ip, sim = rules.resolve(GW, { "198.18.0.12", "198.18.0.13" }, SECRET, SECRET)
    check("repeated header -> first value", ip == "198.18.0.12" and sim == true)
end

print("== nginx.conf wiring (both honeypot layers) ==")
local function read(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local s = f:read("*a")
    f:close()
    return s
end

for _, dir in ipairs({ "../..", "../../../db_proxy/reverse_proxy_enhanced" }) do
    local conf = read(dir .. "/nginx.conf")
    local params = read(dir .. "/proxy_params")
    check(dir .. "/nginx.conf exists", conf ~= nil)
    check(dir .. "/proxy_params exists", params ~= nil)
    if conf and params then
        check(dir .. ": $client_ip resolved with test_client_rules",
              conf:find("set_by_lua_block $client_ip", 1, true) ~= nil
              and conf:find('require("test_client_rules")', 1, true) ~= nil)
        check(dir .. ": routing decision uses $client_ip",
              conf:find("router.decide_route(session_data, threat_result, ngx.var.client_ip", 1, true) ~= nil)
        check(dir .. ": session recovery uses $client_ip",
              conf:find("get_session_id_for_ip(ngx.var.client_ip)", 1, true) ~= nil)
        check(dir .. ": access logs record $client_ip",
              conf:find("log_format main '$client_ip", 1, true) ~= nil
              and conf:find("log_format security '$client_ip", 1, true) ~= nil)
        check(dir .. ": X-Test-Client-IP is not forwarded to the eshops",
              params:find('proxy_set_header X-Test-Client-IP "";', 1, true) ~= nil)
    end
end

print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
