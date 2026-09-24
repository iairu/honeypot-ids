-- admin_handler.lua - Admin access handling module for Nginx Lua
-- Handles WordPress admin panel access and authentication monitoring
--
-- Adapter half of the pure/adapter split with admin_rules.lua: this file
-- does all the Redis/shared-dict I/O, request-body/args reading, and
-- ngx.log calls; admin_rules.lua holds the actual decision logic (zero
-- ngx.*/_G.* dependency, plain-`lua`-interpreter testable).

local cjson = require "cjson"
local resty_sha1 = require "resty.sha1"
local str = require "resty.string"
local admin_rules = require "admin_rules"

local _M = {}

-- Check if admin-ajax.php call is legitimate (not suspicious).
-- Thin adapter over admin_rules.is_suspicious_ajax_action() -- reads the
-- POST body/GET action (I/O), delegates the actual pattern matching, then
-- logs which specific pattern matched (the pure function returns it for
-- exactly this purpose).
function _M.is_legitimate_ajax_call(uri, method)
    local uri_lower = string.lower(uri or "")

    -- Only check if this is admin-ajax.php
    if not string.find(uri_lower, "admin%-ajax%.php") then
        return false
    end

    local post_data = nil
    if method == "POST" then
        ngx.req.read_body()
        post_data = ngx.req.get_body_data()
    end

    local args = ngx.req.get_uri_args()
    local get_action = args and args.action or nil

    local suspicious, matched, source = admin_rules.is_suspicious_ajax_action(post_data, get_action)
    if suspicious then
        if source == "post" then
            ngx.log(ngx.WARN, "[ADMIN] 🚨 Suspicious action in admin-ajax.php: ", matched)
        else
            ngx.log(ngx.WARN, "[ADMIN] 🚨 Suspicious GET action in admin-ajax.php: ", matched)
        end
        return false  -- This is suspicious
    end

    -- If we get here, it's a legitimate admin-ajax.php call
    return true
end

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
        ngx.log(ngx.INFO, "[ADMIN] ✅ Whitelisted IP accessing admin area | IP: ", remote_ip, " | URI: ", uri)
        _M.log_admin_access(admin_info, "allowed", "whitelisted_ip")
        return
    end

    ngx.log(ngx.INFO, "[ADMIN] 🔐 Admin area access attempt | IP: ", remote_ip, " | URI: ", uri, " | Method: ", admin_info.method)

    -- Check if this is a legitimate admin-ajax.php call (WordPress AJAX handler)
    local is_legitimate_ajax = _M.is_legitimate_ajax_call(uri, admin_info.method)

    if is_legitimate_ajax then
        ngx.log(ngx.INFO, "[ADMIN] ✅ Legitimate admin-ajax.php call | IP: ", remote_ip)
        _M.log_admin_access(admin_info, "monitored", "legitimate_ajax")
        return
    end

    -- Check for brute force attempts (only for actual login endpoints)
    local is_login = _M.is_login_attempt(uri, admin_info.method)
    if is_login then
        local brute_force_score = _M.check_brute_force_attempts(remote_ip)
        if brute_force_score > 50 then
            ngx.log(ngx.WARN, "[ADMIN] 🚨 BRUTE FORCE DETECTED | IP: ", remote_ip, " | Score: ", brute_force_score, " | URI: ", uri)
            _M.log_admin_access(admin_info, "blocked", "brute_force_detected")
            _M.increment_threat_score(remote_ip, 30)
            return
        elseif brute_force_score > 0 then
            ngx.log(ngx.WARN, "[ADMIN] ⚠️  Multiple admin attempts detected | IP: ", remote_ip, " | Score: ", brute_force_score)
        end

        -- Track login attempts
        _M.track_admin_attempt(remote_ip, uri)
    end

    -- Analyze admin request patterns
    local pattern_analysis = _M.analyze_admin_patterns(uri, admin_info.user_agent, admin_info.method)
    if pattern_analysis.suspicious then
        ngx.log(ngx.WARN, "[ADMIN] 🔍 Suspicious admin pattern detected | IP: ", remote_ip,
                " | Reason: ", pattern_analysis.reason, " | Score: +", pattern_analysis.score)
        _M.log_admin_access(admin_info, "suspicious", pattern_analysis.reason)
        _M.increment_threat_score(remote_ip, pattern_analysis.score)
    else
        ngx.log(ngx.INFO, "[ADMIN] ✅ Admin access pattern appears legitimate | IP: ", remote_ip)
        _M.log_admin_access(admin_info, "monitored", "legitimate_access")
    end
end

-- Check for brute force login attempts
-- Thin adapter over admin_rules.score_brute_force_attempts() -- reads the
-- attempt-tracking record from the shared dict (I/O), delegates the actual
-- window-filtering/scoring, then logs at the tier the pure function's
-- score maps back to (kept here rather than in the pure function, since
-- deriving "which tier fired" from the final score alone -- e.g. 55 could
-- be tier-25-plus-rapid-bonus or some other combination -- would be
-- ambiguous; the adapter re-checks the same count thresholds purely for
-- log-message selection, not for the actual scoring decision).
function _M.check_brute_force_attempts(ip)
    local rate_limit_dict = ngx.shared.rate_limit
    local current_time = ngx.time()
    local window_size = 300  -- 5 minutes
    local attempt_key = "admin_attempts:" .. ip

    local attempts_json = rate_limit_dict:get(attempt_key)
    local attempts, first_attempt

    if attempts_json then
        local attempts_data = cjson.decode(attempts_json)
        attempts = attempts_data.attempts
        first_attempt = attempts_data.first_attempt
    else
        attempts = {}
        first_attempt = current_time
    end

    local score, filtered = admin_rules.score_brute_force_attempts(attempts, first_attempt, current_time, window_size)

    if #filtered >= 10 then
        ngx.log(ngx.WARN, "[ADMIN] 🚨 High brute force score | IP: ", ip, " | Attempts: ", #filtered, " | Score: ", score)
    elseif #filtered >= 5 then
        ngx.log(ngx.WARN, "[ADMIN] ⚠️  Moderate brute force score | IP: ", ip, " | Attempts: ", #filtered, " | Score: ", score)
    elseif #filtered >= 3 then
        ngx.log(ngx.INFO, "[ADMIN] ⚡ Low brute force score | IP: ", ip, " | Attempts: ", #filtered, " | Score: ", score)
    end

    return score
end

-- Analyze admin access patterns for suspicious behavior
-- Thin adapter over admin_rules.analyze_admin_patterns() -- fetches the
-- query string (I/O) and delegates the actual pattern matching/scoring.
-- No logging here: process_admin_request() (the only caller) already logs
-- a summary line for any suspicious result. The original had per-pattern
-- log lines inside this function too, which is lost in this extraction --
-- an accepted trade-off (the "reason" field was already last-write-wins in
-- the multi-match case, so those extra lines were partial detail, not the
-- full picture, even before this change) in exchange for the actual
-- decision logic being pure and unit-tested.
function _M.analyze_admin_patterns(uri, user_agent, method)
    return admin_rules.analyze_admin_patterns(uri, user_agent, ngx.var.query_string, method)
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
    -- Update Redis for persistence
    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.ERR, "Failed to connect to Redis for threat score update: ", err)
        -- Continue to update shared memory even if Redis fails
    end
    
    local threats = {}
    local old_score = 0

    if red then
        local threat_data = red:get('threat_ips')
        if threat_data then
            threat_data = tostring(threat_data)
            local ok, decoded = pcall(cjson.decode, threat_data)
            if ok and decoded then
                threats = decoded
            end
        end

        if not threats[ip] then
            threats[ip] = {
                raw_score = 0,
                reason = "clean",
                updated = ngx.time()
            }
        end

        old_score = threats[ip].raw_score
        threats[ip].raw_score = math.min(threats[ip].raw_score + additional_score, 100)
        threats[ip].admin_activity = (threats[ip].admin_activity or 0) + 1
        threats[ip].offenses = (threats[ip].offenses or 0) + 1  -- decay escalation (decay_policy.lua)
        threats[ip].updated = ngx.time()
        threats[ip].reason = "suspicious_admin_activity"

        red:set('threat_ips', cjson.encode(threats))
        _G.redis_pool.close_connection(red)
    end
    
    -- Also update shared memory for immediate effect in threat_analyzer
    local threat_intel = ngx.shared.threat_intel
    if threat_intel then
        local shared_threats_json = threat_intel:get("threat_ips")
        local shared_threats = {}
        if shared_threats_json then
            local ok, decoded = pcall(cjson.decode, tostring(shared_threats_json))
            if ok and decoded then
                shared_threats = decoded
            end
        end
        
        if not shared_threats[ip] then
            shared_threats[ip] = {
                raw_score = 0,
                reason = "clean",
                updated = ngx.time()
            }
        end

        old_score = shared_threats[ip].raw_score
        shared_threats[ip].raw_score = math.min(shared_threats[ip].raw_score + additional_score, 100)
        shared_threats[ip].admin_activity = (shared_threats[ip].admin_activity or 0) + 1
        shared_threats[ip].offenses = (shared_threats[ip].offenses or 0) + 1  -- decay escalation (decay_policy.lua)
        shared_threats[ip].updated = ngx.time()
        shared_threats[ip].reason = "suspicious_admin_activity"

        threat_intel:set("threat_ips", cjson.encode(shared_threats))
    end

    ngx.log(ngx.WARN, "[ADMIN] 📈 Threat score increased | IP: ", ip, " | Old: ", old_score,
            " | New: ", (threats[ip] and threats[ip].raw_score or (shared_threats and shared_threats[ip] and shared_threats[ip].raw_score or 0)),
            " | Added: +", additional_score)
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
    
    -- Log to Nginx error log with emoji indicators
    local status_emoji = {
        blocked = "🚫",
        suspicious = "⚠️",
        allowed = "✅",
        monitored = "👀"
    }
    local emoji = status_emoji[status] or "📝"
    local log_level = (status == "blocked" or status == "suspicious") and ngx.WARN or ngx.INFO
    ngx.log(log_level, "[ADMIN ACCESS] ", emoji, " Status: ", status, " | Reason: ", reason, 
            " | IP: ", admin_info.ip, " | URI: ", admin_info.uri)
    
    -- Store in Redis for analytics
    local red, err = _G.redis_pool.get_connection()
    if red then
        red:lpush("admin_access_logs", cjson.encode(log_entry))
        red:ltrim("admin_access_logs", 0, 999)  -- Keep last 1000 entries
        _G.redis_pool.close_connection(red)
    end
end

-- Check if current request is a login attempt
-- Thin wrapper over admin_rules.is_login_attempt() -- already pure/no-I/O,
-- kept here as a re-export so existing callers don't need to change.
function _M.is_login_attempt(uri, method)
    return admin_rules.is_login_attempt(uri, method)
end

-- Analyze login POST data for credential stuffing.
-- Thin adapter over admin_rules.score_login_credential_stuffing() -- reads
-- the POST body (I/O) and delegates the actual scoring.
function _M.analyze_login_data()
    if ngx.var.request_method ~= "POST" then
        return { suspicious = false, score = 0 }
    end

    ngx.req.read_body()
    local post_data = ngx.req.get_body_data()

    return admin_rules.score_login_credential_stuffing(post_data)
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
    
    -- red:get() returns the ngx.null userdata sentinel for a missing key,
    -- not Lua nil -- "or '{}'" alone doesn't catch that since ngx.null is
    -- truthy, so cjson.decode() would crash with "string expected, got
    -- userdata" on a key that's never been set (e.g. right after a fresh
    -- deploy or a Redis flush). See threat_analyzer.lua/router.lua etc. for
    -- the established `x and x ~= ngx.null` idiom used elsewhere in this
    -- codebase; fixed here to match.
    local threat_data = red:get('threat_ips')
    if not threat_data or threat_data == ngx.null then
        threat_data = '{}'
    end
    local threats = cjson.decode(threat_data)
    _G.redis_pool.close_connection(red)
    
    if threats[ip] and threats[ip].raw_score >= 70 then
        return true
    end
    
    -- Check recent admin attempt frequency
    local brute_force_score = _M.check_brute_force_attempts(ip)
    return brute_force_score >= 80
end

return _M