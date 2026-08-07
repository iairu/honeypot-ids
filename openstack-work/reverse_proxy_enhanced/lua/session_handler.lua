-- session_handler.lua - Session management module for Nginx Lua
-- Handles session creation, retrieval, updates, and routing decisions
--
-- Adapter half of the pure/adapter split with session_rules.lua: this file
-- does all the Redis/shared-dict I/O and ngx.log calls; session_rules.lua
-- holds the actual anomaly-detection and honeypot-routing decision logic
-- (zero ngx.*/_G.* dependency, plain-`lua`-interpreter testable).

local cjson = require "cjson"
local resty_sha1 = require "resty.sha1"
local str = require "resty.string"
local session_rules = require "session_rules"
local router_rules = require "router_rules"

local _M = {}

-- Generate a cryptographically secure session ID
function _M.generate_session_id()
    local sha1 = resty_sha1:new()
    local random_data = tostring(ngx.time()) .. tostring(math.random()) .. tostring(ngx.worker.pid())
    sha1:update(random_data)
    local digest = sha1:final()
    return str.to_hex(digest)
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

-- ---------------------------------------------------------------------------
-- IP -> session_id binding.
--
-- A session cookie is trivial for a client to discard (clear cookies,
-- private window, localStorage wipe) -- without a server-side fallback,
-- that alone used to be enough to walk away from an elevated threat_score
-- or a honeypot_bound=true session and come back in as a brand-new,
-- zero-score visitor: nginx.conf's session lookup only ever knew about the
-- cookie, so no cookie meant session_handler.create_session() ran again
-- from scratch (see router.lua's "Session bootstrap" comment). Pool
-- assignment (pool_router.lua) was already IP-sticky, but the SESSION's
-- own accumulated score/honeypot_bound flag was not, so Stage 2's sticky-
-- honeypot re-check silently never fired for a cookie-cleared return
-- visit even though the attacker landed on the exact same honeypot pool.
--
-- get_session_id_for_ip()/bind_ip_to_session() close that gap: every
-- session creation and update refreshes an "ip_session:<ip>" Redis
-- pointer at the session's own TTL, so nginx.conf's session lookup can
-- recover the SAME session_id for a returning IP even with zero cookie
-- state, before ever falling back to generating a fresh one.
-- ---------------------------------------------------------------------------

function _M.get_session_id_for_ip(ip)
    if not ip then
        return nil
    end

    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR, "[SESSION] Failed to connect to Redis for IP->session lookup: ", err)
        return nil
    end

    local session_id, get_err = red:get("ip_session:" .. ip)
    _G.redis_pool.close_connection(red)

    if get_err then
        ngx.log(ngx.ERR, "[SESSION] Redis error during IP->session lookup: ", get_err)
        return nil
    end
    if session_id and session_id ~= ngx.null then
        return session_id
    end
    return nil
end

function _M.bind_ip_to_session(ip, session_id)
    if not ip or not session_id then
        return
    end

    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR, "[SESSION] Failed to connect to Redis for IP->session bind: ", err)
        return
    end

    red:setex("ip_session:" .. ip, _G.config.session.max_idle_time, session_id)
    _G.redis_pool.close_connection(red)
end

-- Sanity check, not a gate, for a session recovered via IP rather than
-- cookie: does the current request's browser fingerprint still look like
-- the same client the session was created for? The SAME browser clearing
-- its own cookies keeps an identical User-Agent/Accept-* fingerprint, so
-- this passes for the exact scenario this feature exists to catch
-- (attacker clears cookies, comes right back on the same IP/browser).
-- A mismatch merely gets logged for investigation -- deliberately not used
-- to block/deny the IP-based recovery, since two distinct low-value users
-- sharing one honeypot session (false negative) is far cheaper than an
-- attacker escaping detection by spoofing headers to dodge a fingerprint
-- check (false positive). IP is the authoritative signal; fingerprinting
-- is enrichment only, used here strictly as a secondary corroboration
-- signal, not a primary identity mechanism.
function _M.fingerprint_matches(session_data, user_agent)
    if not session_data or not session_data.metadata then
        return true
    end
    local stored_fp = session_data.metadata.browser_fingerprint
    local current_fp = _M.generate_browser_fingerprint(user_agent)
    if not stored_fp or not current_fp then
        return true
    end
    return stored_fp == current_fp
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

        -- So a later cookie-clear from this same IP can recover this exact
        -- session instead of starting over at threat_score=0 -- see the
        -- "IP -> session_id binding" comment above.
        _M.bind_ip_to_session(ip_address, session_id)

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

        -- Refresh the IP->session TTL alongside the session's own, so the
        -- binding stays alive exactly as long as the session does rather
        -- than expiring independently on its own fixed schedule from
        -- creation time.
        if session_data.ip_address then
            _M.bind_ip_to_session(session_data.ip_address, session_id)
        end

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

-- Get or create session for current request
function _M.get_or_create_session()
    local session_id = ngx.var.cookie_PHPSESSID or ngx.var.cookie_HONEYPOT_SESSION
    local session_data
    
    if session_id then
        session_data = _M.get_session(session_id)
    end
    
    if not session_data then
        -- Create new session
        session_data = _M.create_session(
            ngx.var.remote_addr,
            ngx.var.http_user_agent,
            "production"
        )
        
        -- Set session cookie
        local cookie_value = session_data.id .. "; Path=/; HttpOnly; SameSite=Lax"
        if ngx.var.scheme == "https" then
            cookie_value = cookie_value .. "; Secure"
        end
        
        ngx.header["Set-Cookie"] = _G.config.session.cookie_name .. "=" .. cookie_value
        ngx.log(ngx.INFO, "[SESSION] 🍪 Setting session cookie for new session: ", session_data.id)
    else
        ngx.log(ngx.INFO, "[SESSION] 🔄 Using existing session: ", session_data.id, 
                " | Request #", session_data.request_count or 0, " | Threat Score: ", session_data.threat_score or 0)
    end
    
    return session_data
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