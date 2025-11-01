-- threat_analyzer.lua - Threat analysis module for Nginx Lua
-- Analyzes incoming requests for suspicious patterns and threat indicators

local cjson = require "cjson"
local resty_sha1 = require "resty.sha1"
local str = require "resty.string"

local _M = {}

-- Analyze incoming request for threats
function _M.analyze_request(uri, headers, remote_ip)
    local threat_result = {
        score = 0,
        suspicious = false,
        patterns_matched = {},
        cve_matched = {},
        ip_reputation = 0,
        details = {}
    }
    
    ngx.log(ngx.INFO, "[THREAT ANALYZER] Starting analysis for: ", uri or "unknown", " | IP: ", remote_ip)
    
    -- Check if request is for static assets - skip threat analysis
    if _M.is_static_asset(uri) then
        ngx.log(ngx.INFO, "[THREAT ANALYZER] ✅ Static asset - threat analysis skipped")
        return threat_result  -- Return zero score for static assets
    end
    
    -- Analyze URI for suspicious patterns
    local uri_score = _M.analyze_uri_patterns(uri)
    threat_result.score = threat_result.score + uri_score.score
    
    if uri_score.score > 0 then
        ngx.log(ngx.WARN, "[THREAT ANALYZER] 🔍 URI patterns matched (+", uri_score.score, ") | Patterns: ", 
                table.concat(uri_score.patterns or {}, ", "))
    end
    
    if uri_score.patterns then
        for _, pattern in ipairs(uri_score.patterns) do
            table.insert(threat_result.patterns_matched, pattern)
        end
    end
    
    -- Analyze headers for threats
    local header_score = _M.analyze_headers(headers)
    threat_result.score = threat_result.score + header_score.score
    
    if header_score.suspicious_headers then
        for _, header in ipairs(header_score.suspicious_headers) do
            table.insert(threat_result.details, "suspicious_header: " .. header)
        end
        if header_score.score > 0 then
            ngx.log(ngx.WARN, "[THREAT ANALYZER] 🔍 Suspicious headers (+", header_score.score, ") | Details: ", 
                    table.concat(header_score.suspicious_headers, ", "))
        end
    end
    
    -- Check CVE-specific patterns
    local cve_score = _M.analyze_cve_patterns(uri, headers)
    threat_result.score = threat_result.score + cve_score.score
    
    if cve_score.cves then
        for _, cve in ipairs(cve_score.cves) do
            table.insert(threat_result.cve_matched, cve)
        end
        if #cve_score.cves > 0 then
            ngx.log(ngx.ERR, "[THREAT ANALYZER] 🎯 CVE PATTERNS DETECTED (+", cve_score.score, ") | CVEs: ", 
                    table.concat(cve_score.cves, ", "))
        end
    end
    
    -- Check IP reputation
    local ip_rep = _M.check_ip_reputation(remote_ip)
    threat_result.ip_reputation = ip_rep.score
    threat_result.score = threat_result.score + ip_rep.score
    
    if ip_rep.reason then
        table.insert(threat_result.details, "ip_reputation: " .. ip_rep.reason)
        if ip_rep.score > 0 then
            ngx.log(ngx.WARN, "[THREAT ANALYZER] 🚫 Bad IP reputation (+", ip_rep.score, ") | Reason: ", ip_rep.reason)
        elseif ip_rep.score < 0 then
            ngx.log(ngx.INFO, "[THREAT ANALYZER] ✅ Whitelisted IP (", ip_rep.score, ") | Reason: ", ip_rep.reason)
        end
    end
    
    -- Analyze request method and parameters
    local method_score = _M.analyze_request_method()
    threat_result.score = threat_result.score + method_score.score
    
    if method_score.score > 0 then
        ngx.log(ngx.WARN, "[THREAT ANALYZER] 🔍 Suspicious request method (+", method_score.score, ")")
    end
    
    -- Check for automated tools
    local automation_score = _M.detect_automation(headers, uri)
    threat_result.score = threat_result.score + automation_score.score
    
    if automation_score.detected then
        table.insert(threat_result.details, "automation_detected: " .. automation_score.tool)
        ngx.log(ngx.WARN, "[THREAT ANALYZER] 🤖 Automation detected (+", automation_score.score, ") | Tool: ", 
                automation_score.tool or "unknown")
    end
    
    -- Determine if request is suspicious
    threat_result.suspicious = threat_result.score >= _G.config.threat.honeypot_threshold
    
    -- Log final threat score
    if threat_result.score >= _G.config.threat.honeypot_threshold then
        ngx.log(ngx.ERR, "[THREAT ANALYZER] 🚨 FINAL SCORE: ", threat_result.score, 
                "/", _G.config.threat.honeypot_threshold, " (SUSPICIOUS) | IP: ", remote_ip, 
                " | Patterns: ", #threat_result.patterns_matched, " | CVEs: ", #threat_result.cve_matched)
    elseif threat_result.score > 20 then
        ngx.log(ngx.WARN, "[THREAT ANALYZER] ⚠️  FINAL SCORE: ", threat_result.score, 
                "/", _G.config.threat.honeypot_threshold, " (elevated but below threshold) | IP: ", remote_ip)
    else
        ngx.log(ngx.INFO, "[THREAT ANALYZER] ✅ FINAL SCORE: ", threat_result.score, 
                "/", _G.config.threat.honeypot_threshold, " (clean) | IP: ", remote_ip)
    end
    
    -- Log high-threat requests
    if threat_result.score > 70 then
        _G.utils.log_security_event("high_threat_request", {
            ip = remote_ip,
            uri = uri,
            score = threat_result.score,
            patterns = threat_result.patterns_matched,
            cves = threat_result.cve_matched
        })
    end
    
    return threat_result
end

-- Analyze URI for suspicious patterns
function _M.analyze_uri_patterns(uri)
    local result = {
        score = 0,
        patterns = {}
    }
    
    if not uri then
        return result
    end
    
    local uri_lower = string.lower(uri)
    
    -- Check against suspicious patterns
    for _, pattern in ipairs(_G.config.threat.suspicious_patterns) do
        if string.find(uri_lower, pattern) then
            result.score = result.score + 15
            table.insert(result.patterns, pattern)
        end
    end
    
    -- Additional specific checks
    local specific_checks = {
        -- Directory traversal
        {pattern = "%.%./", score = 20, name = "directory_traversal"},
        {pattern = "%%2e%%2e/", score = 20, name = "encoded_directory_traversal"},
        
        -- SQL injection patterns
        {pattern = "union.*select", score = 25, name = "sql_union"},
        {pattern = "or.*1.*=.*1", score = 20, name = "sql_or_condition"},
        {pattern = "'.*or.*'", score = 20, name = "sql_quote_or"},
        {pattern = "select.*from", score = 15, name = "sql_select"},
        {pattern = "drop.*table", score = 30, name = "sql_drop"},
        {pattern = "insert.*into", score = 20, name = "sql_insert"},
        
        -- XSS patterns
        {pattern = "<script", score = 25, name = "xss_script"},
        {pattern = "javascript:", score = 20, name = "xss_javascript"},
        {pattern = "onerror=", score = 20, name = "xss_onerror"},
        {pattern = "onload=", score = 15, name = "xss_onload"},
        {pattern = "alert%s*%(", score = 15, name = "xss_alert"},
        
        -- Command injection
        {pattern = ";.*cat", score = 25, name = "cmd_cat"},
        {pattern = ";.*ls", score = 20, name = "cmd_ls"},
        {pattern = "|.*nc", score = 30, name = "cmd_netcat"},
        {pattern = "&&.*curl", score = 25, name = "cmd_curl"},
        {pattern = "`.*`", score = 20, name = "cmd_backticks"},
        
        -- File inclusion
        {pattern = "php://", score = 25, name = "php_wrapper"},
        {pattern = "file://", score = 20, name = "file_wrapper"},
        {pattern = "data://", score = 20, name = "data_wrapper"},
        
        -- WordPress specific attacks
        {pattern = "/wp%-config%.php", score = 30, name = "wp_config_access"},
        {pattern = "/wp%-admin/install%.php", score = 25, name = "wp_install_access"},
        {pattern = "wp%-admin.*user%-new%.php", score = 20, name = "wp_user_creation"},
        {pattern = "xmlrpc%.php", score = 15, name = "wp_xmlrpc"},
        
        -- Common scanning patterns
        {pattern = "/admin", score = 5, name = "admin_scan"},
        {pattern = "/administrator", score = 5, name = "administrator_scan"},
        {pattern = "/phpmyadmin", score = 10, name = "phpmyadmin_scan"},
        {pattern = "/backup", score = 10, name = "backup_scan"},
        {pattern = "/%.env", score = 20, name = "env_file_scan"}
    }
    
    for _, check in ipairs(specific_checks) do
        if string.find(uri_lower, check.pattern) then
            result.score = result.score + check.score
            table.insert(result.patterns, check.name)
        end
    end
    
    -- Check for encoded characters (potential evasion)
    if string.find(uri, "%%[0-9a-fA-F][0-9a-fA-F]") then
        result.score = result.score + 10
        table.insert(result.patterns, "url_encoding_detected")
    end
    
    -- Check for excessive parameters (potential parameter pollution)
    local param_count = 0
    for _ in string.gmatch(uri, "[&?]") do
        param_count = param_count + 1
    end
    
    if param_count > 20 then
        result.score = result.score + 15
        table.insert(result.patterns, "excessive_parameters")
    end
    
    return result
end

-- Analyze request headers for threats
function _M.analyze_headers(headers)
    local result = {
        score = 0,
        suspicious_headers = {}
    }
    
    if not headers then
        return result
    end
    
    -- Check User-Agent
    local user_agent = headers["User-Agent"] or headers["user-agent"] or ""
    local ua_lower = string.lower(user_agent)
    
    -- Known malicious user agents
    local malicious_uas = {
        "sqlmap", "nmap", "masscan", "zap", "nikto", "dirb", "gobuster",
        "wpscan", "whatweb", "nuclei", "burpsuite", "havij", "pangolin"
    }
    
    for _, ua in ipairs(malicious_uas) do
        if string.find(ua_lower, ua) then
            result.score = result.score + 50
            table.insert(result.suspicious_headers, "malicious_user_agent: " .. ua)
            break
        end
    end
    
    -- Empty or missing user agent
    if user_agent == "" or not user_agent then
        result.score = result.score + 10
        table.insert(result.suspicious_headers, "missing_user_agent")
    end
    
    -- Check for CVE-specific headers
    if headers["X-WCPAY-PLATFORM-CHECKOUT-USER"] then
        result.score = result.score + 50
        table.insert(result.suspicious_headers, "cve_2023_28121_header")
    end
    
    -- Suspicious accept headers (removed - many legitimate browsers send */* for certain requests)
    
    -- Missing referer on POST requests (reduced score from 10 to 5)
    if ngx.var.request_method == "POST" then
        local referer = headers["Referer"] or headers["referer"]
        if not referer then
            result.score = result.score + 5
            table.insert(result.suspicious_headers, "missing_referer_on_post")
        end
    end
    
    -- Suspicious authorization attempts
    local auth = headers["Authorization"] or headers["authorization"]
    if auth then
        if string.find(string.lower(auth), "basic") then
            result.score = result.score + 5
            table.insert(result.suspicious_headers, "basic_auth_attempt")
        end
    end
    
    return result
end

-- Analyze for CVE-specific patterns
function _M.analyze_cve_patterns(uri, headers)
    local result = {
        score = 0,
        cves = {}
    }
    
    if not uri then
        return result
    end
    
    local uri_lower = string.lower(uri)
    local query_params = ngx.var.args or ""
    
    -- Check each CVE pattern
    for cve, pattern in pairs(_G.config.vulnerability.cve_patterns) do
        local found = false
        
        -- Check in URI
        if string.find(uri_lower, string.lower(pattern)) then
            found = true
        end
        
        -- Check in query parameters
        if query_params and string.find(string.lower(query_params), string.lower(pattern)) then
            found = true
        end
        
        -- Check in headers for header-based CVEs
        if headers then
            for header_name, header_value in pairs(headers) do
                if string.find(string.lower(header_name), string.lower(pattern)) or
                   string.find(string.lower(header_value or ""), string.lower(pattern)) then
                    found = true
                    break
                end
            end
        end
        
        if found then
            result.score = result.score + 40  -- High score for CVE matches
            table.insert(result.cves, cve)
            
            -- Log CVE detection
            _G.utils.log_security_event("cve_pattern_detected", {
                cve = cve,
                pattern = pattern,
                uri = uri,
                ip = ngx.var.remote_addr
            })
        end
    end
    
    return result
end

-- Check IP reputation
function _M.check_ip_reputation(ip)
    local result = {
        score = 0,
        reason = nil
    }
    
    if not ip then
        return result
    end
    
    -- Check if IP is whitelisted
    if _G.utils.is_ip_whitelisted(ip) then
        result.score = -20  -- Negative score for whitelisted IPs
        result.reason = "whitelisted"
        ngx.log(ngx.INFO, "[THREAT ANALYZER] ✅ IP is whitelisted: ", ip)
        return result
    end
    
    -- Check threat intelligence data
    local threat_intel = ngx.shared.threat_intel
    local threat_ips_json = threat_intel:get("threat_ips")
    
    if threat_ips_json then
        local threat_ips = cjson.decode(threat_ips_json)
        if threat_ips[ip] then
            result.score = threat_ips[ip].score or 50
            result.reason = threat_ips[ip].reason or "known_threat"
            ngx.log(ngx.ERR, "[THREAT ANALYZER] 🚨 Known threat IP detected: ", ip, " | Reason: ", result.reason)
        end
    end
    
    -- Check rate limiting data for rapid requests
    local rate_limit_dict = ngx.shared.rate_limit
    local rate_key = "ip:" .. ip
    local rate_data_json = rate_limit_dict:get(rate_key)
    
    if rate_data_json then
        local rate_data = cjson.decode(rate_data_json)
        if rate_data.requests and rate_data.window_start then
            local requests_per_second = rate_data.requests / (ngx.time() - rate_data.window_start + 1)
            if requests_per_second > 10 then
                result.score = result.score + 20
                result.reason = (result.reason and result.reason .. ", " or "") .. "high_request_rate"
            end
        end
    end
    
    return result
end

-- Analyze request method for suspicious activity
function _M.analyze_request_method()
    local result = {
        score = 0
    }
    
    local method = ngx.var.request_method
    
    -- Uncommon methods might be scanning
    if method == "OPTIONS" or method == "TRACE" or method == "CONNECT" then
        result.score = result.score + 10
    end
    
    -- Check for method override attempts
    local method_override = ngx.var.http_x_http_method_override
    if method_override then
        result.score = result.score + 15
    end
    
    return result
end

-- Detect automation tools
function _M.detect_automation(headers, uri)
    local result = {
        score = 0,
        detected = false,
        tool = nil
    }
    
    local user_agent = headers["User-Agent"] or headers["user-agent"] or ""
    local ua_lower = string.lower(user_agent)
    
    -- Known automation tool signatures
    local automation_tools = {
        {pattern = "curl", name = "curl", score = 5},
        {pattern = "wget", name = "wget", score = 5},
        {pattern = "python%-requests", name = "python-requests", score = 10},
        {pattern = "go%-http%-client", name = "go-http-client", score = 10},
        {pattern = "apache%-httpclient", name = "apache-httpclient", score = 10},
        {pattern = "okhttp", name = "okhttp", score = 10},
        {pattern = "bot", name = "generic-bot", score = 15},
        {pattern = "crawler", name = "crawler", score = 10},
        {pattern = "scanner", name = "scanner", score = 20}
    }
    
    for _, tool in ipairs(automation_tools) do
        if string.find(ua_lower, tool.pattern) then
            result.score = result.score + tool.score
            result.detected = true
            result.tool = tool.name
            break
        end
    end
    
    -- Check for automation patterns in request timing
    local sessions_dict = ngx.shared.sessions
    local timing_key = "timing:" .. (ngx.var.remote_addr or "unknown")
    local last_request = sessions_dict:get(timing_key)
    
    if last_request then
        local time_diff = ngx.time() - tonumber(last_request)
        if time_diff < 1 then  -- Less than 1 second between requests
            result.score = result.score + 15
            result.detected = true
            result.tool = (result.tool or "unknown") .. "-rapid-requests"
        end
    end
    
    sessions_dict:set(timing_key, ngx.time(), 10)  -- Keep for 10 seconds
    
    return result
end

-- Rate limit analysis
function _M.analyze_rate_limiting(ip)
    local rate_limit_dict = ngx.shared.rate_limit
    local current_time = ngx.time()
    local window_size = 60  -- 1 minute window
    local rate_key = "ip:" .. ip
    
    local rate_data_json = rate_limit_dict:get(rate_key)
    local rate_data
    
    if rate_data_json then
        rate_data = cjson.decode(rate_data_json)
        
        -- Reset window if expired
        if current_time - rate_data.window_start > window_size then
            rate_data = {
                requests = 1,
                window_start = current_time,
                last_request = current_time
            }
        else
            rate_data.requests = rate_data.requests + 1
            rate_data.last_request = current_time
        end
    else
        rate_data = {
            requests = 1,
            window_start = current_time,
            last_request = current_time
        }
    end
    
    -- Store updated data
    rate_limit_dict:set(rate_key, cjson.encode(rate_data), window_size)
    
    return rate_data
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

return _M