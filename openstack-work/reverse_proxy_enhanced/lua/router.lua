-- router.lua - Routing decision module for Nginx Lua
-- Makes intelligent routing decisions between production and honeypot instances

local cjson = require "cjson"

local _M = {}

-- Main routing decision function
function _M.decide_route(session_data, threat_result, remote_ip)
    local routing_decision = {
        target = "production",
        upstream = "production_backend",
        update_session = false,
        session_data = {}
    }
    
    -- Check if request is for static assets - always route to production
    if _M.is_static_asset(ngx.var.request_uri) then
        routing_decision.target = "production"
        routing_decision.upstream = "production_backend"
        return routing_decision
    end
    
    -- Initialize session if not exists
    if not session_data then
        local session_handler = require "session_handler"
        session_data = session_handler.create_session(remote_ip, ngx.var.http_user_agent, "production")
        routing_decision.update_session = true
        routing_decision.session_data = session_data
    end
    
    -- Check if already bound to honeypot
    if session_data.honeypot_bound then
        routing_decision.target = "honeypot"
        routing_decision.upstream = "honeypot_backend"
        return routing_decision
    end
    
    -- Check threat score threshold
    if threat_result.score >= _G.config.threat.honeypot_threshold then
        routing_decision.target = "honeypot"
        routing_decision.upstream = "honeypot_backend"
        routing_decision.update_session = true
        routing_decision.session_data = {
            honeypot_bound = true,
            route_preference = "honeypot",
            threat_score = threat_result.score,
            honeypot_reason = "high_threat_score"
        }
        
        _G.utils.log_security_event("routing_to_honeypot", {
            reason = "high_threat_score",
            score = threat_result.score,
            ip = remote_ip,
            session_id = session_data.id
        })
        
        return routing_decision
    end
    
    -- Check for CVE pattern matches (immediate honeypot routing)
    if threat_result.cve_matched and #threat_result.cve_matched > 0 then
        routing_decision.target = "honeypot"
        routing_decision.upstream = "honeypot_backend"
        routing_decision.update_session = true
        routing_decision.session_data = {
            honeypot_bound = true,
            route_preference = "honeypot",
            threat_score = threat_result.score,
            honeypot_reason = "cve_pattern_match",
            matched_cves = threat_result.cve_matched
        }
        
        _G.utils.log_security_event("routing_to_honeypot", {
            reason = "cve_pattern_match",
            cves = threat_result.cve_matched,
            ip = remote_ip,
            session_id = session_data.id
        })
        
        return routing_decision
    end
    
    -- Check for vulnerable plugin access
    local uri = ngx.var.request_uri or ""
    if _M.is_vulnerable_plugin_access(uri) then
        routing_decision.target = "honeypot"
        routing_decision.upstream = "honeypot_backend"
        routing_decision.update_session = true
        routing_decision.session_data = {
            honeypot_bound = true,
            route_preference = "honeypot",
            threat_score = math.max(threat_result.score, 60),
            honeypot_reason = "vulnerable_plugin_access"
        }
        
        _G.utils.log_security_event("routing_to_honeypot", {
            reason = "vulnerable_plugin_access",
            uri = uri,
            ip = remote_ip,
            session_id = session_data.id
        })
        
        return routing_decision
    end
    
    -- Check IP reputation
    if threat_result.ip_reputation > 50 then
        routing_decision.target = "honeypot"
        routing_decision.upstream = "honeypot_backend"
        routing_decision.update_session = true
        routing_decision.session_data = {
            honeypot_bound = true,
            route_preference = "honeypot",
            threat_score = threat_result.score,
            honeypot_reason = "bad_ip_reputation"
        }
        
        return routing_decision
    end
    
    -- Check for admin area access from non-whitelisted IPs
    if _M.is_admin_access(uri) and not _G.utils.is_ip_whitelisted(remote_ip) then
        -- Gradual escalation: first warning, then honeypot
        local admin_attempts = session_data.admin_attempts or 0
        if admin_attempts >= 2 then
            routing_decision.target = "honeypot"
            routing_decision.upstream = "honeypot_backend"
            routing_decision.update_session = true
            routing_decision.session_data = {
                honeypot_bound = true,
                route_preference = "honeypot",
                threat_score = math.max(threat_result.score, 40),
                honeypot_reason = "multiple_admin_attempts"
            }
        else
            -- Increment admin attempts but stay on production
            routing_decision.update_session = true
            routing_decision.session_data = {
                admin_attempts = admin_attempts + 1,
                threat_score = math.max(session_data.threat_score or 0, threat_result.score)
            }
        end
        
        return routing_decision
    end
    
    -- Check for suspicious activities accumulation (increased threshold from 3 to 5)
    if session_data.suspicious_activities and #session_data.suspicious_activities >= 5 then
        routing_decision.target = "honeypot"
        routing_decision.upstream = "honeypot_backend"
        routing_decision.update_session = true
        routing_decision.session_data = {
            honeypot_bound = true,
            route_preference = "honeypot",
            threat_score = threat_result.score,
            honeypot_reason = "accumulated_suspicious_activities"
        }
        
        return routing_decision
    end
    
    -- Check for rapid automated requests
    if _M.is_rapid_automation(session_data, threat_result) then
        routing_decision.target = "honeypot"
        routing_decision.upstream = "honeypot_backend"
        routing_decision.update_session = true
        routing_decision.session_data = {
            honeypot_bound = true,
            route_preference = "honeypot",
            threat_score = math.max(threat_result.score, 45),
            honeypot_reason = "rapid_automation_detected"
        }
        
        return routing_decision
    end
    
    -- Check for file upload attacks
    if _M.is_suspicious_upload() then
        routing_decision.target = "honeypot"
        routing_decision.upstream = "honeypot_backend"
        routing_decision.update_session = true
        routing_decision.session_data = {
            honeypot_bound = true,
            route_preference = "honeypot",
            threat_score = math.max(threat_result.score, 50),
            honeypot_reason = "suspicious_file_upload"
        }
        
        return routing_decision
    end
    
    -- Probabilistic routing for moderate threat scores
    if threat_result.score >= 25 and threat_result.score < _G.config.threat.honeypot_threshold then
        local probability = (threat_result.score - 25) / (_G.config.threat.honeypot_threshold - 25)
        if math.random() < probability then
            routing_decision.target = "honeypot"
            routing_decision.upstream = "honeypot_backend"
            routing_decision.update_session = true
            routing_decision.session_data = {
                honeypot_bound = true,
                route_preference = "honeypot",
                threat_score = threat_result.score,
                honeypot_reason = "probabilistic_routing"
            }
            
            return routing_decision
        end
    end
    
    -- Update session with current threat information if staying on production
    if threat_result.suspicious or threat_result.score > 10 then
        routing_decision.update_session = true
        routing_decision.session_data = {
            threat_score = math.max(session_data.threat_score or 0, threat_result.score),
            last_threat_time = ngx.time()
        }
        
        -- Add suspicious activity to log
        if not session_data.suspicious_activities then
            session_data.suspicious_activities = {}
        end
        
        if threat_result.suspicious then
            table.insert(session_data.suspicious_activities, {
                timestamp = ngx.time(),
                uri = ngx.var.request_uri,
                threat_score = threat_result.score,
                patterns = threat_result.patterns_matched
            })
            
            routing_decision.session_data.suspicious_activities = session_data.suspicious_activities
        end
    end
    
    -- Default to production
    return routing_decision
end

-- Check if request is for static assets (CSS, JS, images, fonts)
function _M.is_static_asset(uri)
    if not uri then
        return false
    end
    
    local uri_lower = string.lower(uri)
    
    -- Check against static asset patterns
    if _G.config.threat.static_asset_patterns then
        for _, pattern in ipairs(_G.config.threat.static_asset_patterns) do
            if string.find(uri_lower, pattern) then
                return true
            end
        end
    end
    
    return false
end

-- Check if the request is accessing vulnerable plugins
function _M.is_vulnerable_plugin_access(uri)
    if not uri then
        return false
    end
    
    local uri_lower = string.lower(uri)
    
    -- Don't flag static assets from plugins as vulnerable
    if _M.is_static_asset(uri) then
        return false
    end
    
    for _, plugin in ipairs(_G.config.vulnerability.plugins) do
        if string.find(uri_lower, "/wp%-content/plugins/" .. plugin .. "/") then
            return true
        end
    end
    
    return false
end

-- Check if the request is accessing admin areas
function _M.is_admin_access(uri)
    if not uri then
        return false
    end
    
    local uri_lower = string.lower(uri)
    
    local admin_patterns = {
        "/wp%-admin/",
        "/wp%-login%.php",
        "/admin/",
        "/administrator/",
        "/wp%-config%.php"
    }
    
    for _, pattern in ipairs(admin_patterns) do
        if string.find(uri_lower, pattern) then
            return true
        end
    end
    
    return false
end

-- Check for rapid automation patterns
function _M.is_rapid_automation(session_data, threat_result)
    if not session_data then
        return false
    end
    
    local current_time = ngx.time()
    
    -- Check request frequency (increased threshold from 5 to 20 to avoid false positives)
    if session_data.created_at and session_data.request_count then
        local session_duration = current_time - session_data.created_at
        if session_duration > 0 then
            local requests_per_second = session_data.request_count / session_duration
            if requests_per_second > 20 then
                return true
            end
        end
    end
    
    -- Check for automation tool signatures
    if threat_result.details then
        for _, detail in ipairs(threat_result.details) do
            if string.find(detail, "automation_detected") then
                return true
            end
        end
    end
    
    -- Check timing patterns (increased threshold from 10 to 50 to avoid false positives)
    if session_data.last_activity then
        local time_diff = current_time - session_data.last_activity
        if time_diff < 1 and session_data.request_count and session_data.request_count > 50 then
            return true
        end
    end
    
    return false
end

-- Check for suspicious file uploads
function _M.is_suspicious_upload()
    local method = ngx.var.request_method
    if method ~= "POST" then
        return false
    end
    
    local uri = ngx.var.request_uri or ""
    local content_type = ngx.var.content_type or ""
    
    -- Check for file upload endpoints
    if string.find(string.lower(uri), "upload") or 
       string.find(string.lower(content_type), "multipart/form%-data") then
        
        -- Check for suspicious file upload parameters
        local args = ngx.var.args or ""
        local suspicious_upload_patterns = {
            "%.php",
            "%.jsp",
            "%.asp",
            "%.exe",
            "%.sh",
            "%.bat",
            "%.cmd"
        }
        
        for _, pattern in ipairs(suspicious_upload_patterns) do
            if string.find(string.lower(args), pattern) then
                return true
            end
        end
        
        -- Check for known vulnerable upload actions
        if string.find(args, "dnd_codedropz_upload") or
           string.find(args, "mwb_wgm_preview_mail") or
           string.find(args, "pc_added_uploaded_image") then
            return true
        end
    end
    
    return false
end

-- Apply routing decision and set appropriate variables
function _M.apply_routing_decision(decision)
    ngx.var.route_decision = decision.target
    ngx.var.backend_upstream = decision.upstream
    
    if decision.target == "honeypot" then
        ngx.var.suspicious_activity = "true"
        
        -- Add custom headers for honeypot identification
        ngx.header["X-Honeypot-Route"] = "true"
        ngx.header["X-Route-Reason"] = decision.session_data.honeypot_reason or "unknown"
    end
    
    return decision
end

-- Check for geographic anomalies (if GeoIP data is available)
function _M.check_geographic_anomalies(session_data, current_ip)
    -- This would require GeoIP integration
    -- For now, just check for rapid IP changes
    if session_data and session_data.ip_address and session_data.ip_address ~= current_ip then
        return {
            anomaly_detected = true,
            anomaly_type = "ip_change",
            score_increase = 15
        }
    end
    
    return {
        anomaly_detected = false,
        score_increase = 0
    }
end

-- Behavioral analysis for routing decisions
function _M.analyze_behavior_patterns(session_data)
    if not session_data then
        return { score = 0, patterns = {} }
    end
    
    local behavior_score = 0
    local patterns = {}
    
    -- Analyze request patterns
    if session_data.request_count then
        -- Too many requests in short time
        if session_data.created_at then
            local session_age = ngx.time() - session_data.created_at
            if session_age > 0 and session_data.request_count / session_age > 3 then
                behavior_score = behavior_score + 20
                table.insert(patterns, "high_request_frequency")
            end
        end
        
        -- Single request to admin area (potential targeted attack)
        if session_data.request_count == 1 and _M.is_admin_access(ngx.var.request_uri) then
            behavior_score = behavior_score + 15
            table.insert(patterns, "direct_admin_access")
        end
    end
    
    -- Analyze navigation patterns
    if session_data.suspicious_activities then
        local recent_activities = 0
        local current_time = ngx.time()
        
        for _, activity in ipairs(session_data.suspicious_activities) do
            if current_time - activity.timestamp < 300 then -- Last 5 minutes
                recent_activities = recent_activities + 1
            end
        end
        
        if recent_activities >= 3 then
            behavior_score = behavior_score + 25
            table.insert(patterns, "multiple_recent_suspicious_activities")
        end
    end
    
    return {
        score = behavior_score,
        patterns = patterns
    }
end

return _M