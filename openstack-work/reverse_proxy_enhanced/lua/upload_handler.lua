-- upload_handler.lua - File upload security analysis module for Nginx Lua
-- Handles detection and analysis of suspicious file uploads and POST requests

local cjson = require "cjson"
local resty_sha1 = require "resty.sha1"
local str = require "resty.string"
local upload_rules = require "upload_rules"

local _M = {}

-- Analyze upload requests for suspicious activity
function _M.analyze_upload(headers, args)
    local analysis = {
        is_suspicious = false,
        threat_score = 0,
        risk_factors = {},
        upload_type = "unknown"
    }
    
    ngx.log(ngx.INFO, "[UPLOAD] 📤 Analyzing potential upload request | IP: ", ngx.var.remote_addr, " | URI: ", ngx.var.request_uri)
    
    -- Check if this is actually a file upload
    local content_type = headers["Content-Type"] or headers["content-type"] or ""
    if not _M.is_file_upload(content_type, args) then
        ngx.log(ngx.INFO, "[UPLOAD] ℹ️  Not a file upload request")
        return analysis
    end
    
    ngx.log(ngx.INFO, "[UPLOAD] 📎 File upload detected | Content-Type: ", content_type:sub(1, 50))
    analysis.upload_type = "file_upload"
    
    -- Analyze content type for suspicious patterns
    local ct_analysis = _M.analyze_content_type(content_type)
    analysis.threat_score = analysis.threat_score + ct_analysis.score
    if ct_analysis.suspicious then
        table.insert(analysis.risk_factors, ct_analysis.reason)
        ngx.log(ngx.WARN, "[UPLOAD] ⚠️  Suspicious content type (+", ct_analysis.score, ") | Reason: ", ct_analysis.reason)
    end
    
    -- Analyze upload parameters
    local param_analysis = _M.analyze_upload_parameters(args or "")
    analysis.threat_score = analysis.threat_score + param_analysis.score
    for _, factor in ipairs(param_analysis.risk_factors) do
        table.insert(analysis.risk_factors, factor)
        ngx.log(ngx.WARN, "[UPLOAD] ⚠️  Suspicious parameter (+", param_analysis.score, ") | Factor: ", factor)
    end
    
    -- Check for known vulnerable upload endpoints
    local endpoint_analysis = _M.analyze_upload_endpoint(ngx.var.request_uri or "")
    analysis.threat_score = analysis.threat_score + endpoint_analysis.score
    for _, factor in ipairs(endpoint_analysis.risk_factors) do
        table.insert(analysis.risk_factors, factor)
        ngx.log(ngx.ERR, "[UPLOAD] 🎯 Vulnerable endpoint detected (+", endpoint_analysis.score, ") | Factor: ", factor)
    end
    
    -- Analyze user agent for automation tools
    local ua_analysis = _M.analyze_upload_user_agent(headers["User-Agent"] or headers["user-agent"] or "")
    analysis.threat_score = analysis.threat_score + ua_analysis.score
    for _, factor in ipairs(ua_analysis.risk_factors) do
        table.insert(analysis.risk_factors, factor)
        ngx.log(ngx.WARN, "[UPLOAD] 🤖 Automated tool detected (+", ua_analysis.score, ") | Factor: ", factor)
    end
    
    -- Check for file upload bypass techniques
    local bypass_analysis = _M.analyze_upload_bypass_techniques(content_type, args or "")
    analysis.threat_score = analysis.threat_score + bypass_analysis.score
    for _, factor in ipairs(bypass_analysis.risk_factors) do
        table.insert(analysis.risk_factors, factor)
        ngx.log(ngx.ERR, "[UPLOAD] 🚨 Upload bypass technique detected (+", bypass_analysis.score, ") | Factor: ", factor)
    end
    
    -- Determine if upload is suspicious
    analysis.is_suspicious = analysis.threat_score >= 30 or #analysis.risk_factors >= 2
    
    -- Log final analysis
    if analysis.is_suspicious then
        ngx.log(ngx.ERR, "[UPLOAD] 🚨 SUSPICIOUS UPLOAD DETECTED | Score: ", analysis.threat_score, 
                " | Risk Factors: ", #analysis.risk_factors, " | Factors: ", table.concat(analysis.risk_factors, ", "))
        _M.log_suspicious_upload(analysis, headers, args)
    else
        ngx.log(ngx.INFO, "[UPLOAD] ✅ Upload appears clean | Score: ", analysis.threat_score, 
                " | Risk Factors: ", #analysis.risk_factors)
    end
    
    return analysis.is_suspicious
end

-- Thin delegating wrappers over upload_rules.lua's pure functions -- see
-- that file's header comment. analyze_upload() above is the adapter that
-- orchestrates these plus the ngx.log/Redis I/O.

function _M.is_file_upload(content_type, args)
    return upload_rules.is_file_upload(content_type, args)
end

function _M.analyze_content_type(content_type)
    return upload_rules.analyze_content_type(content_type)
end

function _M.analyze_upload_parameters(args)
    return upload_rules.analyze_upload_parameters(args)
end

function _M.analyze_upload_endpoint(uri)
    return upload_rules.analyze_upload_endpoint(uri)
end

function _M.analyze_upload_user_agent(user_agent)
    return upload_rules.analyze_upload_user_agent(user_agent)
end

function _M.analyze_upload_bypass_techniques(content_type, args)
    return upload_rules.analyze_upload_bypass_techniques(content_type, args)
end

-- Log suspicious upload attempts
function _M.log_suspicious_upload(analysis, headers, args)
    local log_entry = {
        timestamp = ngx.time(),
        iso_timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        event_type = "suspicious_upload",
        ip = ngx.var.remote_addr,
        uri = ngx.var.request_uri,
        method = ngx.var.request_method,
        user_agent = headers["User-Agent"] or headers["user-agent"] or "",
        content_type = headers["Content-Type"] or headers["content-type"] or "",
        threat_score = analysis.threat_score,
        risk_factors = analysis.risk_factors,
        upload_type = analysis.upload_type,
        args = args or "",
        server_name = ngx.var.server_name or "unknown"
    }
    
    -- Log to Nginx error log
    ngx.log(ngx.WARN, "SUSPICIOUS_UPLOAD: ", cjson.encode(log_entry))
    
    -- Store in Redis for analysis
    local red, err = _G.redis_pool.get_connection()
    if red then
        red:lpush("suspicious_uploads", cjson.encode(log_entry))
        red:ltrim("suspicious_uploads", 0, 999)  -- Keep last 1000 entries
        _G.redis_pool.close_connection(red)
    end
    
    -- Update IP threat score
    _M.update_ip_threat_for_upload(ngx.var.remote_addr, analysis.threat_score)
end

-- Update IP threat score based on upload activity
function _M.update_ip_threat_for_upload(ip, upload_threat_score)
    local red, err = _G.redis_pool.get_connection()
    if not red then
        return
    end
    
    -- red:get() returns the ngx.null userdata sentinel for a missing key,
    -- not Lua nil -- "or '{}'" doesn't catch that (ngx.null is truthy), so
    -- cjson.decode() crashed with "string expected, got userdata" on a
    -- fresh/flushed Redis. Confirmed live: this crash aborted the request
    -- (500) right after analyze_upload() had already correctly detected a
    -- malicious upload, so the honeypot reroute never happened either.
    local threat_data = red:get('threat_ips')
    if not threat_data or threat_data == ngx.null then
        threat_data = '{}'
    end
    local threats = cjson.decode(threat_data)
    
    if not threats[ip] then
        threats[ip] = {
            score = 0,
            reason = "clean",
            updated = ngx.time()
        }
    end
    
    -- Add upload-specific threat score
    local additional_score = math.floor(upload_threat_score / 2)  -- Scale down for IP reputation
    threats[ip].score = math.min(threats[ip].score + additional_score, 100)
    threats[ip].reason = "suspicious_upload_activity"
    threats[ip].updated = ngx.time()
    threats[ip].upload_attempts = (threats[ip].upload_attempts or 0) + 1
    
    red:set('threat_ips', cjson.encode(threats))
    _G.redis_pool.close_connection(red)
end

-- Generate upload security report
function _M.generate_upload_report(ip)
    local red, err = _G.redis_pool.get_connection()
    if not red then
        return { error = "Redis connection failed" }
    end
    
    local uploads = red:lrange("suspicious_uploads", 0, 999)
    _G.redis_pool.close_connection(red)
    
    local report = {
        ip = ip,
        total_suspicious_uploads = 0,
        upload_types = {},
        risk_factors = {},
        threat_timeline = {},
        highest_threat_score = 0
    }
    
    for _, upload_json in ipairs(uploads) do
        local upload = cjson.decode(upload_json)
        if upload.ip == ip then
            report.total_suspicious_uploads = report.total_suspicious_uploads + 1
            
            -- Track upload types
            report.upload_types[upload.upload_type] = 
                (report.upload_types[upload.upload_type] or 0) + 1
            
            -- Track risk factors
            for _, factor in ipairs(upload.risk_factors or {}) do
                report.risk_factors[factor] = (report.risk_factors[factor] or 0) + 1
            end
            
            -- Track highest threat score
            if upload.threat_score > report.highest_threat_score then
                report.highest_threat_score = upload.threat_score
            end
            
            -- Add to timeline (last 10 entries)
            if #report.threat_timeline < 10 then
                table.insert(report.threat_timeline, {
                    timestamp = upload.timestamp,
                    threat_score = upload.threat_score,
                    uri = upload.uri,
                    risk_factors = upload.risk_factors
                })
            end
        end
    end
    
    return report
end

-- Check if upload should be blocked
function _M.should_block_upload(analysis)
    return upload_rules.should_block_upload(analysis)
end

return _M