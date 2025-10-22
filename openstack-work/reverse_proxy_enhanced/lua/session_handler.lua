-- session_handler.lua - Session management module for Nginx Lua
-- Handles session creation, retrieval, updates, and routing decisions

local cjson = require "cjson"
local resty_sha1 = require "resty.sha1"
local str = require "resty.string"

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

-- Create a new session
function _M.create_session(ip_address, user_agent, initial_route)
    local session_id = _M.generate_session_id()
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
        
        ngx.log(ngx.INFO, "Created new session: ", session_id, " for IP: ", ip_address)
    else
        ngx.log(ngx.ERR, "Failed to store session in Redis: ", err)
    end
    
    return session_data
end

-- Update existing session data
function _M.update_session(session_id, updates)
    local session_data = _M.get_session(session_id)
    if not session_data then
        ngx.log(ngx.WARN, "Attempted to update non-existent session: ", session_id)
        return false
    end
    
    -- Apply updates
    for key, value in pairs(updates) do
        session_data[key] = value
    end
    
    -- Update timestamps
    session_data.last_activity = ngx.time()
    session_data.expires = ngx.time() + _G.config.session.max_idle_time
    session_data.request_count = (session_data.request_count or 0) + 1
    
    -- Store updated session
    local red, err = _G.redis_pool.get_connection()
    if red then
        local session_json = cjson.encode(session_data)
        red:setex("session:" .. session_id, _G.config.session.max_idle_time, session_json)
        _G.redis_pool.close_connection(red)
        
        -- Update local cache
        local sessions_dict = ngx.shared.sessions
        sessions_dict:set("session:" .. session_id, session_json, 300)
        
        return true
    else
        ngx.log(ngx.ERR, "Failed to update session in Redis: ", err)
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

-- Check if session should be routed to honeypot
function _M.should_route_to_honeypot(session_data)
    if not session_data then
        return false
    end
    
    -- Already bound to honeypot
    if session_data.honeypot_bound then
        return true
    end
    
    -- Check threat score threshold
    if session_data.threat_score >= _G.config.threat.honeypot_threshold then
        return true
    end
    
    -- Check if IP is in whitelist
    if _G.utils.is_ip_whitelisted(session_data.ip_address) then
        return false
    end
    
    -- Check for too many suspicious activities
    if session_data.suspicious_activities and #session_data.suspicious_activities >= 3 then
        return true
    end
    
    -- Check for rapid requests (potential automated tool)
    if session_data.request_count and session_data.created_at then
        local session_duration = ngx.time() - session_data.created_at
        if session_duration > 0 and (session_data.request_count / session_duration) > 10 then
            return true
        end
    end
    
    return false
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
    end
    
    return session_data
end

-- Analyze session for anomalies
function _M.analyze_session_anomalies(session_data)
    local anomalies = {}
    
    if not session_data then
        return anomalies
    end
    
    -- Check for IP changes
    if session_data.ip_address ~= ngx.var.remote_addr then
        table.insert(anomalies, "ip_change")
    end
    
    -- Check for user agent changes
    local current_ua = ngx.var.http_user_agent or ""
    if session_data.user_agent ~= current_ua then
        table.insert(anomalies, "user_agent_change")
    end
    
    -- Check for suspicious user agents
    local ua_lower = string.lower(current_ua)
    local threat_intel = ngx.shared.threat_intel
    local malicious_agents_json = threat_intel:get("malicious_agents")
    if malicious_agents_json then
        local malicious_agents = cjson.decode(malicious_agents_json)
        for _, agent in ipairs(malicious_agents) do
            if string.find(ua_lower, string.lower(agent)) then
                table.insert(anomalies, "malicious_user_agent")
                break
            end
        end
    end
    
    -- Check for rapid requests
    if session_data.request_count and session_data.last_activity then
        local time_diff = ngx.time() - session_data.last_activity
        if time_diff < 1 and session_data.request_count > 5 then
            table.insert(anomalies, "rapid_requests")
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