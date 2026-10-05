-- test_session_identity_rules.lua - Standalone unit tests
--
-- Runs under a plain `lua` interpreter. Covers session_identity_rules.lua
-- (signed session cookie + passive recovery fingerprint) and checks that both
-- nginx.conf copies use it: the cookie is verified rather than trusted, the
-- Set-Cookie is signed, and no session id is read from WordPress's
-- client-chosen PHPSESSID cookie.
--
-- Usage:
--   cd ids/reverse_proxy_enhanced/lua/tests
--   lua test_session_identity_rules.lua

package.path = "../?.lua;" .. package.path
local rules = require "session_identity_rules"

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

-- Stand-in MAC: deterministic, key-dependent, hex. (The proxy uses
-- HMAC-SHA1 via ngx.hmac_sha1; only determinism and key-dependence matter here.)
local function mac_with(key)
    return function(id)
        local h = 0
        local s = key .. "|" .. id
        for i = 1, #s do h = (h * 31 + s:byte(i)) % 4294967296 end
        return string.format("%08x%08x", h, (h * 7 + #s) % 4294967296)
    end
end
local mac = mac_with("server-key")

local ID = "0123456789abcdef0123456789abcdef"
local ID2 = "fedcba9876543210fedcba9876543210"

print("== session ids ==")
check("generated-style id is valid", rules.is_valid_id(ID))
check("too short is invalid", not rules.is_valid_id("abc123"))
check("non-hex is invalid", not rules.is_valid_id(string.rep("z", 32)))
check("nil is invalid", not rules.is_valid_id(nil))

print("== signed cookie ==")
do
    local cookie = rules.sign(ID, mac)
    check("cookie is id.mac", cookie:sub(1, #ID + 1) == ID .. ".")

    local id, status = rules.verify(cookie, mac)
    check("own cookie verifies", id == ID and status == "valid")

    id, status = rules.verify(nil, mac)
    check("no cookie -> missing", id == nil and status == "missing")

    id, status = rules.verify("", mac)
    check("empty cookie -> missing", id == nil and status == "missing")

    -- Attacker swaps in another session id but keeps the MAC.
    local forged = ID2 .. cookie:sub(#ID + 1)
    id, status = rules.verify(forged, mac)
    check("edited id is rejected", id == nil and status == "bad_signature")

    -- Attacker edits one character of the MAC.
    local last = cookie:sub(-1)
    local flipped = cookie:sub(1, -2) .. (last == "0" and "1" or "0")
    id, status = rules.verify(flipped, mac)
    check("edited MAC is rejected", id == nil and status == "bad_signature")

    -- A bare id (the old unsigned cookie format) is not accepted.
    id, status = rules.verify(ID, mac)
    check("unsigned cookie is rejected", id == nil and status == "malformed")

    id, status = rules.verify(ID .. "." .. mac(ID) .. ".x", mac)
    check("extra segment is rejected", id == nil and status == "malformed")

    id, status = rules.verify("../../etc.abc", mac)
    check("garbage is rejected", id == nil and status == "malformed")

    -- Signed under another key (e.g. before a key change): rejected.
    id, status = rules.verify(rules.sign(ID, mac_with("old-key")), mac)
    check("cookie from another key is rejected", id == nil and status == "bad_signature")
end

print("== recovery fingerprint ==")
do
    local base = {
        ip = "203.0.113.5", ssl_protocol = "TLSv1.3",
        ssl_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
        ssl_curves = "X25519:prime256v1", http_version = "HTTP/2.0",
        user_agent = "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0",
        accept_language = "en-US,en;q=0.9", accept_encoding = "gzip, deflate, br",
        ch_ua = '"Chromium";v="130", "Not?A_Brand";v="99"', ch_ua_platform = '"Linux"', ch_ua_mobile = "?0",
    }
    local function with(changes)
        local t = {}
        for k, v in pairs(base) do t[k] = v end
        for k, v in pairs(changes) do t[k] = v end
        return t
    end

    local a = rules.fingerprint_source(base, true)
    check("same client -> same fingerprint", a == rules.fingerprint_source(with({}), true))
    check("fingerprint does not use the cookie (none is passed in)", a ~= nil)
    check("different User-Agent -> different fingerprint",
          a ~= rules.fingerprint_source(with({ user_agent = "curl/8.5.0" }), true))
    check("different Accept-Language -> different fingerprint",
          a ~= rules.fingerprint_source(with({ accept_language = "sk-SK" }), true))
    check("different TLS cipher offer -> different fingerprint",
          a ~= rules.fingerprint_source(with({ ssl_ciphers = "ECDHE-RSA-AES128-GCM-SHA256" }), true))
    check("different client-hint platform -> different fingerprint",
          a ~= rules.fingerprint_source(with({ ch_ua_platform = '"Windows"' }), true))
    check("different HTTP version -> different fingerprint",
          a ~= rules.fingerprint_source(with({ http_version = "HTTP/1.1" }), true))

    check("with IP: another address is another fingerprint",
          a ~= rules.fingerprint_source(with({ ip = "198.51.100.7" }), true))
    local n1 = rules.fingerprint_source(base, false)
    check("without IP: address is ignored",
          n1 == rules.fingerprint_source(with({ ip = "198.51.100.7" }), false))
    check("without IP: other fields still count",
          n1 ~= rules.fingerprint_source(with({ user_agent = "curl/8.5.0" }), false))

    check("no User-Agent and no TLS -> not fingerprintable",
          rules.fingerprint_source({ ip = "203.0.113.5", http_version = "HTTP/1.1" }, true) == nil)
    check("TLS alone is enough",
          rules.fingerprint_source({ ssl_ciphers = "TLS_AES_128_GCM_SHA256" }, false) ~= nil)
    check("nil fields are safe", rules.fingerprint_source(nil, true) == nil)
end

print("== nginx.conf wiring (both honeypot layers) ==")
local function read(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local s = f:read("*a")
    f:close()
    return s
end

-- Drop Lua/nginx comments so prose about the old behaviour doesn't count.
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
        check(dir .. ": session cookie is verified",
              code:find("session_handler.read_session_cookie()", 1, true) ~= nil)
        check(dir .. ": cookie-less clients are recovered by fingerprint",
              code:find("get_session_id_for_fingerprint()", 1, true) ~= nil)
        check(dir .. ": no IP -> session recovery",
              code:find("get_session_id_for_ip", 1, true) == nil)
        check(dir .. ": PHPSESSID is never a session id",
              code:find("cookie_PHPSESSID", 1, true) == nil)
        local _, signed = code:gsub('require%("session_handler"%)%.cookie_value%(ngx%.var%.new_session_id%)', "")
        -- Every session cookie the proxy builds embeds a signed value, and the only
        -- things ever written to the Set-Cookie header are that cookie or the
        -- upstream's own cookies passed through (the header is appended to, never
        -- overwritten, so WooCommerce's cart session survives).
        local _, builds = code:gsub('cookie_name%s*%.%.%s*"="', "")
        local assignments_ok = true
        for rhs in code:gmatch('%["Set%-Cookie"%]%s*=%s*([^\n]+)') do
            if not (rhs:find("sid_cookie", 1, true) or rhs:find("upstream_cookies", 1, true)) then
                assignments_ok = false
            end
        end
        check(dir .. ": every Set-Cookie is signed",
              signed >= 2 and signed == builds and assignments_ok)
        check(dir .. ": pools are assigned per session",
              code:find("get_or_assign_pool(ngx.var.remote_addr)", 1, true) == nil)
        check(dir .. ": signing key reaches Lua", conf:find("env SESSION_SIGNING_KEY;", 1, true) ~= nil)
    end
end

print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
