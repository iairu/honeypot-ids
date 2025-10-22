-- admin_handler.lua - Admin access handling module for Nginx Lua
-- Handles WordPress admin panel access and authentication monitoring

local cjson = require "cjson"
local resty_sha1 = require "resty.sha1"
local str = require "resty.string"

local _M = {}

-- Process admin access requests
function _M.process_admin_request(remote_ip, uri)
    local admin_info = {
        ip = remote_ip,
        uri = uri,
        timestamp = ngx.time(),
        user_agent = ngx.var.http_user_agent or "",
        method = ngx.var.request_method or "GET"
    }
    
    -- Check if IP is whitelisted for admin access
    if _G.utils.is_ip_whitelisted(remote_ip) then
        _M.log_admin_access(admin_info, "allowed", "whitelisted_ip")
        return
    end
    
    -- Check for brute force attempts
    local brute_force_score = _M.check_brute_force_attempts(remote_ip)
    if brute_force_score > 50 then
        _M.log_admin_access(admin_info, "blocked", "brute_force_detected")
        _M.increment_threat_score(remote_ip, 30)
        return
    end
    
    -- Analyze admin request patterns
    local pattern_analysis = _M.analyze_admin_patterns(uri, admin_info.user_agent)
    if pattern_analysis.suspicious then
        _M.log_admin_access(admin_info, "suspicious", pattern_analysis.reason)
        _M.increment_threat_score(remote_ip, pattern_analysis.score)
    end
    
    -- Track admin attempts
    _M.track_admin_attempt(remote_ip, uri)
    
    -- Log legitimate admin access
    _M.log_admin_access(admin_info, "monitored", "legitimate_access")
end

-- Check for brute force login attempts
function _M.check_brute_force_attempts(ip)
    local rate_limit_dict = ngx.shared.rate_limit
    local current_time = ngx.time()
    local window_size = 300  -- 5 minutes
    local attempt_key = "admin_attempts:" .. ip
    
    local attempts_json = rate_limit_dict:get(attempt_key)
    local attempts_data
    
    if attempts_json then
        attempts_data = cjson.decode(attempts_json)
        
        -- Clean old attempts outside window
        local filtered_attempts = {}
        for _, attempt in ipairs(attempts_data.attempts or {}) do
            if current_time - attempt.timestamp <= window_size then
                table.insert(filtered_attempts, attempt)
            end
        end
        attempts_data.attempts = filtered_attempts
        attempts_data.count = #filtered_attempts
    else
        attempts_data = {
            count = 0,
            attempts = {},
            first_attempt = current_time
        }
    end
    
    -- Calculate brute force score
    local score = 0
    if attempts_data.count >= 10 then
        score = 80  -- High score for many attempts
    elseif attempts_data.count >= 5 then
        score = 50  -- Medium score for moderate attempts
    elseif attempts_data.count >= 3 then
        score = 25  -- Low score for few attempts
    end
    
    -- Check for rapid succession attempts
    if attempts_data.count >= 3 then
        local time_span = current_time - attempts_data.first_attempt
        if time_span < 60 then  -- 3+ attempts in less than 1 minute
            score = score + 30
        end
    end
    
    return score
end

-- Analyze admin access patterns for suspicious behavior
function _M.analyze_admin_patterns(uri, user_agent)
    local analysis = {
        suspicious = false,
        reason = "clean",
        score = 0
    }
    
    local uri_lower = string.lower(uri or "")
    local ua_lower = string.lower(user_agent or "")
    
    -- Check for direct admin file access (bypassing login)
    local direct_access_patterns = {
        "/wp%-admin/admin%-ajax%.php",
        "/wp%-admin/admin%-post%.php",
        "/wp%-admin/users%.php",
        "/wp%-admin/user%-new%.php",
        "/wp%-admin/options%.php"
    }
    
    for _, pattern in ipairs(direct_access_patterns) do
        if string.find(uri_lower, pattern) then
            analysis.suspicious = true
            analysis.reason = "direct_admin_file_access"
            analysis.score = 20
            break
        end
    end
    
    -- Check for admin enumeration attempts
    if string.find(uri_lower, "wp%-json/wp/v2/users") then
        analysis.suspicious = true
        analysis.reason = "user_enumeration"
        analysis.score = 25
    end
    
    -- Check for plugin/theme enumeration
    if string.find(uri_lower, "wp%-content/plugins") and string.find(uri_lower, "readme%.txt") then
        analysis.suspicious = true
        analysis.reason = "plugin_enumeration"
        analysis.score = 15
    end
    
    -- Check for automated tool signatures in admin context
    local automation_patterns = {
        "wpscan", "wp%-cli", "curl", "wget", "python", "scanner"
    }
    
    for _, pattern in ipairs(automation_patterns) do
        if string.find(ua_lower, pattern) then
            analysis.suspicious = true
            analysis.reason = "automated_admin_tool"
            analysis.score = 35
            break
        end
    end
    
    -- Check for suspicious admin parameters
    local suspicious_params = {
        "action=upload%-plugin",
        "action=activate",
        "action=delete",
        "action=edit%-theme%-plugin%-file",
        "file=%.%./"
    }
    
    for _, param in ipairs(suspicious_params) do
        if string.find(uri_lower, param) then
            analysis.suspicious = true
            analysis.reason = "suspicious_admin_action"
            analysis.score = analysis.score + 20
        end
    end
    
    return analysis
end

-- Track admin access attempts for pattern analysis
function _M.track_admin_attempt(ip, uri)
    local rate_limit_dict = ngx.shared.rate_limit
    local current_time = ngx.time()
    local attempt_key = "admin_attempts:" .. ip
    
    local attempts_json = rate_limit_dict:get(attempt_key)
    local attempts_data
    
    if attempts_json then
        attempts_data = cjson.decode(attempts_json)
    else
        attempts_data = {
            count = 0,
            attempts = {},
            first_attempt = current_time
        }
    end
    
    -- Add new attempt
    table.insert(attempts_data.attempts, {
        timestamp = current_time,
        uri = uri,
        method = ngx.var.request_method,
        user_agent = ngx.var.http_user_agent or ""
    })
    
    attempts_data.count = attempts_data.count + 1
    attempts_data.last_attempt = current_time
    
    -- Store updated data (expire in 30 minutes)
    rate_limit_dict:set(attempt_key, cjson.encode(attempts_data), 1800)
end

-- Increment threat score for IP based on admin activity
function _M.increment_threat_score(ip, additional_score)
    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR, "Failed to connect to Redis for threat score update: ", err)
        return
    end
    
    local threat_data = red:get('threat_ips') or '{}'
    local threats = cjson.decode(threat_data)
    
    if not threats[ip] then
        threats[ip] = {
            score = 0,
            reason = "clean",
            updated = ngx.time()
        }
    end
    
    threats[ip].score = math.min(threats[ip].score + additional_score, 100)
    threats[ip].admin_activity = (threats[ip].admin_activity or 0) + 1
    threats[ip].updated = ngx.time()
    threats[ip].reason = "suspicious_admin_activity"
    
    red:set('threat_ips', cjson.encode(threats))
    _G.redis_pool.close_connection(red)
end

-- Log admin access events
function _M.log_admin_access(admin_info, status, reason)
    local log_entry = {
        timestamp = ngx.time(),
        iso_timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        event_type = "admin_access",
        status = status,
        reason = reason,
        ip = admin_info.ip,
        uri = admin_info.uri,
        method = admin_info.method,
        user_agent = admin_info.user_agent,
        server_name = ngx.var.server_name or "unknown"
    }
    
    -- Log to Nginx error log
    local log_level = (status == "blocked" or status == "suspicious") and ngx.ERR or ngx.INFO
    ngx.log(log_level, "ADMIN_ACCESS: ", cjson.encode(log_entry))
    
    -- Store in Redis for analytics
    local red, err = _G.redis_pool.get_connection()
    if red then
        red:lpush("admin_access_logs", cjson.encode(log_entry))
        red:ltrim("admin_access_logs", 0, 999)  -- Keep last 1000 entries
        _G.redis_pool.close_connection(red)
    end
end

-- Check if current request is a login attempt
function _M.is_login_attempt(uri, method)
    if method ~= "POST" then
        return false
    end
    
    local login_endpoints = {
        "wp%-login%.php",
        "wp%-admin/admin%-ajax%.php",
        "xmlrpc%.php"
    }
    
    local uri_lower = string.lower(uri or "")
    for _, endpoint in ipairs(login_endpoints) do
        if string.find(uri_lower, endpoint) then
            return true
        end
    end
    
    return false
end

-- Analyze login POST data for credential stuffing
function _M.analyze_login_data()
    if ngx.var.request_method ~= "POST" then
        return { suspicious = false, score = 0 }
    end
    
    -- Read POST body
    ngx.req.read_body()
    local post_data = ngx.req.get_body_data()
    
    if not post_data then
        return { suspicious = false, score = 0 }
    end
    
    local analysis = {
        suspicious = false,
        score = 0,
        patterns = {}
    }
    
    local post_lower = string.lower(post_data)
    
    -- Check for common credential stuffing patterns
    local stuffing_patterns = {
        { pattern = "admin", score = 5, name = "common_username" },
        { pattern = "password", score = 5, name = "common_password" },
        { pattern = "123456", score = 10, name = "weak_password" },
        { pattern = "qwerty", score = 10, name = "keyboard_pattern" },
        { pattern = "test", score = 8, name = "test_credentials" }
    }
    
    for _, check in ipairs(stuffing_patterns) do
        if string.find(post_lower, check.pattern) then
            analysis.score = analysis.score + check.score
            table.insert(analysis.patterns, check.name)
        end
    end
    
    -- Check for automated login attempts (rapid-fire characteristics)
    if string.len(post_data) < 50 then  -- Very short POST data
        analysis.score = analysis.score + 10
        table.insert(analysis.patterns, "short_post_data")
    end
    
    if analysis.score >= 15 then
        analysis.suspicious = true
    end
    
    return analysis
end

-- Generate admin access report
function _M.generate_admin_report(ip)
    local red, err = _G.redis_pool.get_connection()
    if not red then
        return { error = "Redis connection failed" }
    end
    
    local logs = red:lrange("admin_access_logs", 0, 99)  -- Last 100 entries
    _G.redis_pool.close_connection(red)
    
    local ip_logs = {}
    local total_attempts = 0
    local blocked_attempts = 0
    local suspicious_attempts = 0
    
    for _, log_json in ipairs(logs) do
        local log_entry = cjson.decode(log_json)
        if log_entry.ip == ip then
            table.insert(ip_logs, log_entry)
            total_attempts = total_attempts + 1
            
            if log_entry.status == "blocked" then
                blocked_attempts = blocked_attempts + 1
            elseif log_entry.status == "suspicious" then
                suspicious_attempts = suspicious_attempts + 1
            end
        end
    end
    
    return {
        ip = ip,
        total_attempts = total_attempts,
        blocked_attempts = blocked_attempts,
        suspicious_attempts = suspicious_attempts,
        success_rate = total_attempts > 0 and ((total_attempts - blocked_attempts) / total_attempts * 100) or 0,
        recent_logs = ip_logs
    }
end

-- Block admin access based on threat score
function _M.should_block_admin_access(ip)
    local red, err = _G.redis_pool.get_connection()
    if not red then
        return false
    end
    
    local threat_data = red:get('threat_ips') or '{}'
    local threats = cjson.decode(threat_data)
    _G.redis_pool.close_connection(red)
    
    if threats[ip] and threats[ip].score >= 70 then
        return true
    end
    
    -- Check recent admin attempt frequency
    local brute_force_score = _M.check_brute_force_attempts(ip)
    return brute_force_score >= 80
end

return _M