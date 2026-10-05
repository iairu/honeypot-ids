-- session_identity_rules.lua - Pure logic for who an attacker is
--
-- PURPOSE:
--   Attackers are told apart by their SESSION, not by their IP address: two
--   attackers behind one NAT address are two sessions (two honeypot pools),
--   and an attacker keeps their session when their address changes. That
--   only holds if the attacker can neither edit their session nor shed it.
--   Two mechanisms, used together:
--
--   1. Signed session cookie (can't be edited or forged).
--      The cookie carries only a random 128-bit session id plus an HMAC of it
--      under a server-side key: "<id>.<mac>". Everything the router knows
--      about the session (score, honeypot binding, pool) stays server-side in
--      Redis, so there is nothing in the browser to edit. Changing the id
--      breaks the MAC; a cookie with a bad MAC is never looked up. With a
--      stable key (SESSION_SIGNING_KEY) a bad MAC is reported as tampering.
--
--   2. Passive server-side fingerprint (can't be cleared).
--      Clearing cookies / localStorage / a private window removes the cookie,
--      so a request WITHOUT one is matched to an existing session through a
--      fingerprint the client never stores: its TLS ClientHello (protocol,
--      offered cipher suites, curves), HTTP version, User-Agent,
--      Accept-Language and Accept-Encoding. Clearing browser storage changes
--      none of these, so the same client lands back in its own session. The
--      client IP is one more input by default (recovery_uses_ip): without it,
--      every visitor running the same browser build would collapse into one
--      session, sending real customers into an attacker's honeypot. IP is
--      only ever part of this recovery key -- two clients with different
--      fingerprints behind one IP are still separate sessions.
--
--   Shared addresses (carrier-grade NAT): two users on one public address who
--   run the identical browser build with the same languages produce the same
--   recovery key. To keep a neighbour from being merged into an attacker's
--   session, the key also carries the low-entropy client hints Chromium sends
--   on every HTTPS request (Sec-CH-UA brand list, platform, mobile), and the
--   fingerprint -> session binding only lives recovery_window seconds after
--   the session's last request (session_handler.bind_fingerprint_to_session).
--   An attacker who clears cookies mid-attack is still recovered; a
--   neighbour with an identical browser is only merged if they arrive while
--   that session is active.
--
--   What this cannot do: an attacker who clears storage AND changes client
--   (another browser or tool, a different TLS stack or headers) presents a
--   new fingerprint and starts a new session. No server-side mechanism can
--   link two clients that share nothing.
--
-- Pure module: no ngx.* dependency. The HMAC and hash functions are passed in
-- by session_handler.lua (see tests/test_session_identity_rules.lua).

local _M = {}

-- Session ids are 16 random bytes, hex encoded.
_M.ID_PATTERN = "^%x+$"
_M.ID_LENGTH = 32

-- Recovery-key inputs, in a fixed order. ssl_* come from nginx's $ssl_protocol,
-- $ssl_ciphers (the cipher suites the CLIENT offered) and $ssl_curves; ch_* are
-- the Sec-CH-UA, Sec-CH-UA-Platform and Sec-CH-UA-Mobile request headers
-- (empty for browsers that don't send client hints).
_M.FINGERPRINT_FIELDS = {
    "ssl_protocol", "ssl_ciphers", "ssl_curves", "http_version",
    "user_agent", "accept_language", "accept_encoding",
    "ch_ua", "ch_ua_platform", "ch_ua_mobile",
}

--- Whether `id` looks like a session id this proxy generated.
function _M.is_valid_id(id)
    return type(id) == "string" and #id == _M.ID_LENGTH and id:match(_M.ID_PATTERN) ~= nil
end

-- Compare two strings in time independent of where they first differ.
local function equal_constant_time(a, b)
    if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then
        return false
    end
    local diff = 0
    for i = 1, #a do
        if a:byte(i) ~= b:byte(i) then
            diff = diff + 1
        end
    end
    return diff == 0
end

--- Cookie value for session `id`: "<id>.<mac>".
---
--- @param  id      string    Session id.
--- @param  mac_fn  function  mac_fn(id) -> hex HMAC of id under the signing key.
--- @return string
function _M.sign(id, mac_fn)
    return id .. "." .. mac_fn(id)
end

--- Read a session cookie.
---
--- @param  cookie  string|nil  The cookie's value as received.
--- @param  mac_fn  function    Same as for sign().
--- @return string|nil  The session id when the cookie is valid, else nil.
--- @return string      "valid" | "missing" | "malformed" | "bad_signature"
function _M.verify(cookie, mac_fn)
    if cookie == nil or cookie == "" then
        return nil, "missing"
    end
    if type(cookie) ~= "string" then
        return nil, "malformed"
    end
    local id, mac = cookie:match("^([^.]+)%.([^.]+)$")
    if not id or not _M.is_valid_id(id) then
        return nil, "malformed"
    end
    if not equal_constant_time(mac, mac_fn(id)) then
        return nil, "bad_signature"
    end
    return id, "valid"
end

--- Canonical string the recovery fingerprint is a hash of.
---
--- @param  fields  table    Values keyed by FINGERPRINT_FIELDS names, plus
---                          `ip` (used only when use_ip is true).
--- @param  use_ip  boolean  Include the client IP (see header comment).
--- @return string|nil  nil when the request carries too little to fingerprint
---                     (no User-Agent and no TLS details): matching such
---                     requests would merge unrelated clients.
function _M.fingerprint_source(fields, use_ip)
    fields = fields or {}
    local has_ua = type(fields.user_agent) == "string" and fields.user_agent ~= ""
    local has_tls = type(fields.ssl_ciphers) == "string" and fields.ssl_ciphers ~= ""
    if not has_ua and not has_tls then
        return nil
    end
    local parts = {}
    if use_ip then
        parts[#parts + 1] = "ip=" .. tostring(fields.ip or "")
    end
    for _, name in ipairs(_M.FINGERPRINT_FIELDS) do
        local v = fields[name]
        parts[#parts + 1] = name .. "=" .. (type(v) == "string" and v or "")
    end
    return table.concat(parts, "\n")
end

return _M
