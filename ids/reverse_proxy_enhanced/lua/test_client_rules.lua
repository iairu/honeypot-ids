-- test_client_rules.lua - Simulated client addresses for local multi-attacker tests
--
-- PURPOSE:
--   The dashboard's Pool Test page runs three "attackers" side by side from
--   one machine. To the reverse proxy every one of them arrives from the same
--   address (the Docker bridge gateway), and nearly everything here is keyed
--   on the client address: the honeypot pool assignment (pool_router.lua),
--   the IP -> session recovery that makes clearing cookies useless
--   (session_handler.get_session_id_for_ip), and the IP reputation in
--   threat_intel. Three browsers on one address would therefore collapse into
--   ONE session on ONE pool, which is the correct behaviour for real traffic
--   but makes a pool test impossible.
--
--   A request that presents the INTERNAL_TEST_SECRET (X-Internal-Test-Auth,
--   the same secret that gates the X-Route-Target debug headers and
--   /internal-threat-reset) may name the client address it stands for in
--   X-Test-Client-IP. nginx.conf resolves $client_ip from it once per request
--   (set_by_lua_block) and the routing pipeline uses $client_ip wherever it
--   used $remote_addr, so each simulated attacker gets its own session, its
--   own reputation and its own pool exactly as three real attackers would.
--
-- SAFETY:
--   - No secret configured, or the wrong one presented: the header is
--     ignored and $client_ip is $remote_addr.
--   - Only addresses in 198.18.0.0/15 are accepted (RFC 2544, reserved for
--     benchmarking; never a real internet host). Even with the secret a
--     client cannot pose as a real address: not a whitelisted one such as
--     127.0.0.1, and not someone else's, to steal their pool or poison their
--     reputation.
--   - abuseipdb_client.lua never checks or reports these addresses.
--
-- Pure module: no ngx.* dependency (see tests/test_test_client_rules.lua).

local _M = {}

_M.HEADER = "X-Test-Client-IP"

--- Whether `ip` is a simulated test-client address (IPv4 in 198.18.0.0/15).
---
--- @param  ip  any
--- @return boolean
function _M.is_test_ip(ip)
    if type(ip) ~= "string" then
        return false
    end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then
        return false
    end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if c > 255 or d > 255 then
        return false
    end
    return a == 198 and (b == 18 or b == 19)
end

--- The client address the routing pipeline should use for this request.
---
--- @param  remote_addr  string      nginx $remote_addr.
--- @param  header_ip    string|nil  The X-Test-Client-IP request header.
--- @param  presented    string|nil  The X-Internal-Test-Auth request header.
--- @param  secret       string|nil  _G.config.internal_test_secret.
--- @return string   The effective client address.
--- @return boolean  true when it is a simulated test client.
function _M.resolve(remote_addr, header_ip, presented, secret)
    if type(secret) ~= "string" or secret == "" or presented ~= secret then
        return remote_addr, false
    end
    if type(header_ip) == "table" then
        header_ip = header_ip[1]   -- header sent twice: take the first
    end
    if not _M.is_test_ip(header_ip) then
        return remote_addr, false
    end
    return header_ip, true
end

return _M
