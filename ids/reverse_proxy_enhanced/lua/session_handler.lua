-- session_handler.lua - Session management module for Nginx Lua
-- Handles session creation, retrieval, updates, and routing decisions
--
-- Adapter half of the pure/adapter split with session_rules.lua: this file
-- does all the Redis/shared-dict I/O and ngx.log calls; session_rules.lua
-- holds the actual anomaly-detection and honeypot-routing decision logic
-- (zero ngx.*/_G.* dependency, plain-`lua`-interpreter testable).

local cjson = require "cjson"
local resty_sha1 = require "resty.sha1"
local resty_random = require "resty.random"
local str = require "resty.string"
local identity_rules = require "session_identity_rules"
local session_rules = require "session_rules"
local router_rules = require "router_rules"

local _M = {}

-- Generate a session ID: 16 bytes from OpenSSL's CSPRNG, hex encoded.
-- (It used to be sha1(time .. math.random() .. worker pid), which is
-- guessable: the time is public, math.random is a predictable PRNG and pids
-- are small.)
function _M.generate_session_id()
    local bytes = resty_random.bytes(16, true) or resty_random.bytes(16)
    return str.to_hex(bytes)
end

-- ---------------------------------------------------------------------------
-- Signed session cookie (see session_identity_rules.lua).
-- ---------------------------------------------------------------------------

local function mac(id)
    return str.to_hex(ngx.hmac_sha1(_G.config.session.signing_key, id))
end

--- SERVERID cookie value for a session id: "<id>.<HMAC>".
function _M.cookie_value(session_id)
    return identity_rules.sign(session_id, mac)
end

--- The session id from this request's SERVERID cookie, if it is genuine.
--- @return string|nil  session id (nil unless the cookie verified)
--- @return string      "valid" | "missing" | "malformed" | "bad_signature"
function _M.read_session_cookie()
    return identity_rules.verify(ngx.var["cookie_" .. _G.config.session.cookie_name], mac)
end

-- ---------------------------------------------------------------------------
-- Passive fingerprint -> session_id binding.
--
-- A session cookie is trivial for a client to discard (clear cookies,
-- private window, localStorage wipe) -- without a server-side fallback,
-- that alone would be enough to walk away from an elevated threat_score
-- or a honeypot_bound=true session and come back in as a brand-new,
-- zero-score visitor. Every session creation and update refreshes an
-- "fp_session:<fingerprint>" Redis pointer at the session's own TTL, where
-- the fingerprint is built from what the client SENDS but never stores
-- (TLS ClientHello, HTTP version, User-Agent, Accept-Language/-Encoding and,
-- by default, the IP -- see session_identity_rules.lua), so nginx.conf's
-- session lookup can recover the SAME session for a returning client that
-- cleared its storage, before ever generating a fresh one.
-- ---------------------------------------------------------------------------

--- This request's recovery fingerprint (hex), or nil when the request
--- carries too little to fingerprint. Computed once per request.
function _M.request_fingerprint()
    local ctx = ngx.ctx
    if ctx.recovery_fingerprint ~= nil then
        return ctx.recovery_fingerprint or nil
    end
    local v = ngx.var
    local source = identity_rules.fingerprint_source({
        ip = v.remote_addr,
        ssl_protocol = v.ssl_protocol,
        ssl_ciphers = v.ssl_ciphers,
        ssl_curves = v.ssl_curves,
        http_version = v.server_protocol,
        user_agent = v.http_user_agent,
        accept_language = v.http_accept_language,
        accept_encoding = v.http_accept_encoding,
    }, _G.config.session.recovery_uses_ip)
    if not source then
        ctx.recovery_fingerprint = false
        return nil
    end
    local sha1 = resty_sha1:new()
    sha1:update(source)
    local fp = str.to_hex(sha1:final())
    ctx.recovery_fingerprint = fp
    return fp
end

function _M.get_session_id_for_fingerprint()
    local fp = _M.request_fingerprint()
    if not fp then
        return nil
    end

    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR, "[SESSION] Failed to connect to Redis for fingerprint->session lookup: ", err)
        return nil
    end

    local session_id, get_err = red:get("fp_session:" .. fp)
    _G.redis_pool.close_connection(red)

    if get_err then
        ngx.log(ngx.ERR, "[SESSION] Redis error during fingerprint->session lookup: ", get_err)
        return nil
    end
    if session_id and session_id ~= ngx.null and identity_rules.is_valid_id(session_id) then
        return session_id
    end
    return nil
end

--- Point this request's fingerprint at session_id (refreshes its TTL).
function _M.bind_fingerprint_to_session(session_id)
    local fp = _M.request_fingerprint()
    if not fp or not session_id then
        return
    end

    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR, "[SESSION] Failed to connect to Redis for fingerprint->session bind: ", err)
        return
    end

    red:setex("fp_session:" .. fp, _G.config.session.max_idle_time, session_id)
    _G.redis_pool.close_connection(red)
end

-- Get session data from Redis and local cache
function _M.get_session(session_id)
    if not session_id then
        return nil
    end
    
    -- Try local cache first
    local sessions_dict = ngx.shared.sessions
    local cached_session = sessions_dict:get("session:" .. session_id)
    if cached_session then
        local session_data = cjson.decode(cached_session)
        -- Check if session is still valid
        if session_data.expires and ngx.time() < session_data.expires then
            return session_data
        else
            -- Remove expired session from cache
            sessions_dict:delete("session:" .. session_id)
        end
    end
    
    -- Fallback to Redis
    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR, "Failed to connect to Redis for session retrieval: ", err)
        return nil
    end
    
    local session_json, err = red:get("session:" .. session_id)
    _G.redis_pool.close_connection(red)
    
    if session_json and session_json ~= ngx.null then
        local session_data = cjson.decode(session_json)
        
        -- Cache in local memory for faster access
        sessions_dict:set("session:" .. session_id, session_json, 300) -- Cache for 5 minutes
        
        return session_data
    end
    
    return nil
end

-- Create a new session
function _M.create_session(ip_address, user_agent, initial_route, provided_session_id)
    -- Use provided session_id or generate new one
    local session_id = provided_session_id or _M.generate_session_id()
    local current_time = ngx.time()
    
    local session_data = {
        id = session_id,
        created_at = current_time,
        last_activity = current_time,
        expires = current_time + _G.config.session.max_idle_time,
        ip_address = ip_address,
        user_agent = user_agent or "",
        route_preference = initial_route or "production",
        threat_score = 0,
        suspicious_activities = {},
        request_count = 0,
        compromised = false,
        honeypot_bound = false,
        metadata = {
            first_uri = ngx.var.request_uri,
            browser_fingerprint = _M.generate_browser_fingerprint(user_agent),
            geo_location = nil -- Could be populated by GeoIP service
        }
    }
    
    -- Store in Redis
    local red, err = _G.redis_pool.get_connection()
    if red then
        local session_json = cjson.encode(session_data)
        red:setex("session:" .. session_id, _G.config.session.max_idle_time, session_json)
        
        -- Also store in session index for analytics
        red:sadd("active_sessions", session_id)
        
        _G.redis_pool.close_connection(red)
        
        -- Cache locally
        local sessions_dict = ngx.shared.sessions
        sessions_dict:set("session:" .. session_id, session_json, 300)

        -- So a later cookie-clear by this same client can recover this
        -- exact session instead of starting over at threat_score=0 -- see
        -- the "Passive fingerprint -> session_id binding" comment above.
        _M.bind_fingerprint_to_session(session_id)

        ngx.log(ngx.INFO, "[SESSION] ✅ Created new session: ", session_id, " for IP: ", ip_address,
                " | User-Agent: ", (user_agent or "none"):sub(1, 50), " | Initial Route: ", initial_route or "production")
    else
        ngx.log(ngx.ERR, "[SESSION] ❌ Failed to store session in Redis: ", err)
    end
    
    return session_data
end

-- Check if current request is for a static asset.
--
-- Delegates to router_rules.is_static_asset() rather than maintaining its
-- own copy. This used to be a THIRD independent implementation of the same
-- check (router_rules.lua and threat_rules.lua already document having had
-- two that disagreed on whether to strip the query string before matching,
-- and were reconciled) -- this one was never reconciled and still didn't
-- strip it, so e.g. "image.png?v=123" wasn't recognized as static here even
-- though the other two modules correctly classify it as one, causing
-- update_session() below to increment request_count for what should have
-- been treated as a static asset load.
function _M.is_static_asset_request()
    return router_rules.is_static_asset(ngx.var.request_uri, _G.config.threat.static_asset_patterns)
end

-- Update existing session data
function _M.update_session(session_id, updates)
    local session_data = _M.get_session(session_id)
    if not session_data then
        ngx.log(ngx.WARN, "[SESSION] ⚠️  Attempted to update non-existent session: ", session_id)
        return false
    end
    
    -- Log what's being updated
    local update_keys = {}
    for key, _ in pairs(updates) do
        table.insert(update_keys, key)
    end
    ngx.log(ngx.INFO, "[SESSION] 🔄 Updating session: ", session_id, " | Fields: ", table.concat(update_keys, ", "))
    
    -- Apply updates
    for key, value in pairs(updates) do
        session_data[key] = value
    end
    
    -- Update timestamps
    session_data.last_activity = ngx.time()
    session_data.expires = ngx.time() + _G.config.session.max_idle_time
    
    -- Only increment request count for non-static assets to avoid false positives
    if not _M.is_static_asset_request() then
        session_data.request_count = (session_data.request_count or 0) + 1
    end
    
    -- Store updated session
    local red, err = _G.redis_pool.get_connection()
    if red then
        local session_json = cjson.encode(session_data)
        red:setex("session:" .. session_id, _G.config.session.max_idle_time, session_json)
        _G.redis_pool.close_connection(red)
        
        -- Update local cache
        local sessions_dict = ngx.shared.sessions
        sessions_dict:set("session:" .. session_id, session_json, 300)

        -- Refresh the fingerprint->session binding alongside the session's
        -- own TTL, from THIS request: it stays alive exactly as long as the
        -- session does, and follows the client if its fingerprint changes
        -- while it still holds the signed cookie.
        _M.bind_fingerprint_to_session(session_id)

        ngx.log(ngx.INFO, "[SESSION] ✅ Session updated successfully | ID: ", session_id,
                " | Request Count: ", session_data.request_count or 0, 
                " | Threat Score: ", session_data.threat_score or 0,
                " | Route: ", session_data.route_preference or "production")
        
        return true
    else
        ngx.log(ngx.ERR, "[SESSION] ❌ Failed to update session in Redis: ", err)
        return false
    end
end

-- Mark session as compromised and bind to honeypot
function _M.mark_compromised(session_id, reason)
    local updates = {
        compromised = true,
        honeypot_bound = true,
        route_preference = "honeypot",
        compromise_reason = reason,
        compromise_timestamp = ngx.time()
    }
    
    -- Add to suspicious activities log
    local session_data = _M.get_session(session_id)
    if session_data then
        if not session_data.suspicious_activities then
            session_data.suspicious_activities = {}
        end
        
        table.insert(session_data.suspicious_activities, {
            timestamp = ngx.time(),
            activity = "session_compromised",
            reason = reason,
            ip = ngx.var.remote_addr,
            uri = ngx.var.request_uri
        })
        
        updates.suspicious_activities = session_data.suspicious_activities
    end
    
    local success = _M.update_session(session_id, updates)
    
    if success then
        ngx.log(ngx.ERR, "[SESSION] 🚨 SESSION COMPROMISED | ID: ", session_id, 
                " | Reason: ", reason, " | IP: ", ngx.var.remote_addr, " | URI: ", ngx.var.request_uri)
        
        -- Log security event
        _G.utils.log_security_event("session_compromised", {
            session_id = session_id,
            reason = reason,
            ip = ngx.var.remote_addr,
            user_agent = ngx.var.http_user_agent
        })
        
        -- Store in Redis set for quick lookups
        local red, err = _G.redis_pool.get_connection()
        if red then
            red:sadd("compromised_sessions", session_id)
            red:expire("compromised_sessions", 86400) -- Expire after 24 hours
            _G.redis_pool.close_connection(red)
        end
    end
    
    return success
end

-- Check if session should be routed to honeypot.
-- Thin adapter over session_rules.should_route_to_honeypot() -- fetches the
-- config threshold and whitelist result the pure function needs, then
-- delegates the actual decision.
function _M.should_route_to_honeypot(session_data)
    local is_whitelisted = session_data
        and _G.utils.is_ip_whitelisted(session_data.ip_address)
        or false
    return session_rules.should_route_to_honeypot(
        session_data, _G.config.threat.honeypot_threshold, is_whitelisted, ngx.time())
end

-- Generate browser fingerprint for tracking
function _M.generate_browser_fingerprint(user_agent)
    if not user_agent then
        return nil
    end
    
    local sha1 = resty_sha1:new()
    sha1:update(user_agent)
    
    -- Add additional headers if available
    local accept = ngx.var.http_accept or ""
    local accept_language = ngx.var.http_accept_language or ""
    local accept_encoding = ngx.var.http_accept_encoding or ""
    
    sha1:update(accept .. accept_language .. accept_encoding)
    
    local digest = sha1:final()
    return str.to_hex(digest):sub(1, 16) -- Use first 16 characters
end

-- Analyze session for anomalies.
-- Thin adapter over session_rules.analyze_session_anomalies() -- fetches
-- the current IP/UA, decodes the malicious-agents list from the shared
-- dict, and delegates the actual detection; then re-derives the same
-- per-anomaly detail (old IP, which agent matched, request-rate figures)
-- from data already in scope to keep the original log messages intact,
-- since the pure function itself can't call ngx.log.
function _M.analyze_session_anomalies(session_data)
    if not session_data then
        return {}
    end

    local current_ip = ngx.var.remote_addr
    local current_ua = ngx.var.http_user_agent or ""
    local current_time = ngx.time()

    local malicious_agents = nil
    local malicious_agents_json = ngx.shared.threat_intel:get("malicious_agents")
    if malicious_agents_json then
        malicious_agents = cjson.decode(malicious_agents_json)
    end

    local anomalies = session_rules.analyze_session_anomalies(
        session_data, current_ip, current_ua, malicious_agents, current_time)

    for _, anomaly in ipairs(anomalies) do
        if anomaly == "ip_change" then
            ngx.log(ngx.WARN, "[SESSION] ⚠️  IP address changed | Session: ", session_data.id or "unknown",
                    " | Old: ", session_data.ip_address, " | New: ", current_ip)
        elseif anomaly == "user_agent_change" then
            ngx.log(ngx.WARN, "[SESSION] ⚠️  User-Agent changed | Session: ", session_data.id or "unknown")
        elseif anomaly == "malicious_user_agent" then
            local ua_lower = string.lower(current_ua)
            local matched_agent = "unknown"
            for _, agent in ipairs(malicious_agents or {}) do
                if string.find(ua_lower, string.lower(agent)) then
                    matched_agent = agent
                    break
                end
            end
            ngx.log(ngx.ERR, "[SESSION] 🚨 Malicious User-Agent detected | Agent: ", matched_agent,
                    " | Session: ", session_data.id or "unknown")
        elseif anomaly == "rapid_requests" then
            local time_diff = current_time - (session_data.last_activity or current_time)
            ngx.log(ngx.WARN, "[SESSION] ⚠️  Rapid requests detected | Session: ", session_data.id or "unknown",
                    " | Count: ", session_data.request_count, " | Time diff: ", time_diff, "s")
        end
    end

    return anomalies
end

-- Clean up expired sessions
function _M.cleanup_expired_sessions()
    local sessions_dict = ngx.shared.sessions
    local keys = sessions_dict:get_keys(1000)
    local current_time = ngx.time()
    local cleaned = 0
    
    for _, key in ipairs(keys) do
        local session_json = sessions_dict:get(key)
        if session_json then
            local session_data = cjson.decode(session_json)
            if session_data.expires and current_time > session_data.expires then
                sessions_dict:delete(key)
                cleaned = cleaned + 1
            end
        end
    end
    
    return cleaned
end

return _M