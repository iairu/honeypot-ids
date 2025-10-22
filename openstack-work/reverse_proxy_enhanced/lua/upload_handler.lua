-- upload_handler.lua - File upload security analysis module for Nginx Lua
-- Handles detection and analysis of suspicious file uploads and POST requests

local cjson = require "cjson"
local resty_sha1 = require "resty.sha1"
local str = require "resty.string"

local _M = {}

-- Analyze upload requests for suspicious activity
function _M.analyze_upload(headers, args)
    local analysis = {
        is_suspicious = false,
        threat_score = 0,
        risk_factors = {},
        upload_type = "unknown"
    }
    
    -- Check if this is actually a file upload
    local content_type = headers["Content-Type"] or headers["content-type"] or ""
    if not _M.is_file_upload(content_type, args) then
        return analysis
    end
    
    analysis.upload_type = "file_upload"
    
    -- Analyze content type for suspicious patterns
    local ct_analysis = _M.analyze_content_type(content_type)
    analysis.threat_score = analysis.threat_score + ct_analysis.score
    if ct_analysis.suspicious then
        table.insert(analysis.risk_factors, ct_analysis.reason)
    end
    
    -- Analyze upload parameters
    local param_analysis = _M.analyze_upload_parameters(args or "")
    analysis.threat_score = analysis.threat_score + param_analysis.score
    for _, factor in ipairs(param_analysis.risk_factors) do
        table.insert(analysis.risk_factors, factor)
    end
    
    -- Check for known vulnerable upload endpoints
    local endpoint_analysis = _M.analyze_upload_endpoint(ngx.var.request_uri or "")
    analysis.threat_score = analysis.threat_score + endpoint_analysis.score
    for _, factor in ipairs(endpoint_analysis.risk_factors) do
        table.insert(analysis.risk_factors, factor)
    end
    
    -- Analyze user agent for automation tools
    local ua_analysis = _M.analyze_upload_user_agent(headers["User-Agent"] or headers["user-agent"] or "")
    analysis.threat_score = analysis.threat_score + ua_analysis.score
    for _, factor in ipairs(ua_analysis.risk_factors) do
        table.insert(analysis.risk_factors, factor)
    end
    
    -- Check for file upload bypass techniques
    local bypass_analysis = _M.analyze_upload_bypass_techniques(content_type, args or "")
    analysis.threat_score = analysis.threat_score + bypass_analysis.score
    for _, factor in ipairs(bypass_analysis.risk_factors) do
        table.insert(analysis.risk_factors, factor)
    end
    
    -- Determine if upload is suspicious
    analysis.is_suspicious = analysis.threat_score >= 30 or #analysis.risk_factors >= 2
    
    -- Log suspicious uploads
    if analysis.is_suspicious then
        _M.log_suspicious_upload(analysis, headers, args)
    end
    
    return analysis.is_suspicious
end

-- Check if request is a file upload
function _M.is_file_upload(content_type, args)
    -- Check content type
    if string.find(string.lower(content_type), "multipart/form%-data") then
        return true
    end
    
    -- Check for upload-related parameters
    local args_lower = string.lower(args or "")
    local upload_indicators = {
        "upload", "file", "attachment", "document", "image", "media"
    }
    
    for _, indicator in ipairs(upload_indicators) do
        if string.find(args_lower, indicator) then
            return true
        end
    end
    
    return false
end

-- Analyze content type header for suspicious patterns
function _M.analyze_content_type(content_type)
    local analysis = {
        suspicious = false,
        score = 0,
        reason = "clean"
    }
    
    if not content_type or content_type == "" then
        analysis.suspicious = true
        analysis.score = 10
        analysis.reason = "missing_content_type"
        return analysis
    end
    
    local ct_lower = string.lower(content_type)
    
    -- Check for content type spoofing
    local suspicious_combinations = {
        { pattern = "image/.*php", score = 40, reason = "php_disguised_as_image" },
        { pattern = "text/.*executable", score = 35, reason = "executable_disguised_as_text" },
        { pattern = "application/.*script", score = 30, reason = "script_content_type" },
        { pattern = "image/.*script", score = 35, reason = "script_disguised_as_image" }
    }
    
    for _, check in ipairs(suspicious_combinations) do
        if string.match(ct_lower, check.pattern) then
            analysis.suspicious = true
            analysis.score = check.score
            analysis.reason = check.reason
            return analysis
        end
    end
    
    -- Check for unusual content types for web uploads
    local unusual_types = {
        "application/x%-executable",
        "application/x%-msdos%-program",
        "application/x%-msdownload",
        "application/x%-winexe",
        "application/x%-java%-archive"
    }
    
    for _, type_pattern in ipairs(unusual_types) do
        if string.find(ct_lower, type_pattern) then
            analysis.suspicious = true
            analysis.score = 25
            analysis.reason = "unusual_executable_type"
            break
        end
    end
    
    return analysis
end

-- Analyze upload parameters for malicious patterns
function _M.analyze_upload_parameters(args)
    local analysis = {
        score = 0,
        risk_factors = {}
    }
    
    if not args or args == "" then
        return analysis
    end
    
    local args_lower = string.lower(args)
    
    -- Check for suspicious file extensions in parameters
    local dangerous_extensions = {
        { ext = "%.php", score = 40, factor = "php_extension" },
        { ext = "%.asp", score = 35, factor = "asp_extension" },
        { ext = "%.jsp", score = 35, factor = "jsp_extension" },
        { ext = "%.exe", score = 45, factor = "executable_extension" },
        { ext = "%.bat", score = 40, factor = "batch_file" },
        { ext = "%.sh", score = 40, factor = "shell_script" },
        { ext = "%.py", score = 25, factor = "python_script" },
        { ext = "%.pl", score = 25, factor = "perl_script" },
        { ext = "%.rb", score = 25, factor = "ruby_script" }
    }
    
    for _, ext_check in ipairs(dangerous_extensions) do
        if string.find(args_lower, ext_check.ext) then
            analysis.score = analysis.score + ext_check.score
            table.insert(analysis.risk_factors, ext_check.factor)
        end
    end
    
    -- Check for upload bypass techniques in parameters
    local bypass_patterns = {
        { pattern = "%.php%.", score = 35, factor = "double_extension_bypass" },
        { pattern = "%.php%%00", score = 40, factor = "null_byte_injection" },
        { pattern = "%.php%%20", score = 30, factor = "space_bypass" },
        { pattern = "%.phtml", score = 35, factor = "phtml_variant" },
        { pattern = "%.php3", score = 35, factor = "php3_variant" },
        { pattern = "%.php4", score = 35, factor = "php4_variant" },
        { pattern = "%.php5", score = 35, factor = "php5_variant" }
    }
    
    for _, bypass in ipairs(bypass_patterns) do
        if string.find(args_lower, bypass.pattern) then
            analysis.score = analysis.score + bypass.score
            table.insert(analysis.risk_factors, bypass.factor)
        end
    end
    
    -- Check for directory traversal in file paths
    local traversal_patterns = {
        "%.%.%/", "%2e%2e%2f", "%.%./", "%2e%2e/"
    }
    
    for _, pattern in ipairs(traversal_patterns) do
        if string.find(args_lower, pattern) then
            analysis.score = analysis.score + 30
            table.insert(analysis.risk_factors, "directory_traversal")
            break
        end
    end
    
    -- Check for suspicious upload destinations
    local suspicious_destinations = {
        { pattern = "/wp%-admin/", score = 20, factor = "admin_directory_upload" },
        { pattern = "/wp%-content/themes/", score = 25, factor = "theme_directory_upload" },
        { pattern = "/wp%-includes/", score = 30, factor = "includes_directory_upload" },
        { pattern = "/cgi%-bin/", score = 35, factor = "cgi_directory_upload" }
    }
    
    for _, dest in ipairs(suspicious_destinations) do
        if string.find(args_lower, dest.pattern) then
            analysis.score = analysis.score + dest.score
            table.insert(analysis.risk_factors, dest.factor)
        end
    end
    
    return analysis
end

-- Analyze upload endpoint for known vulnerabilities
function _M.analyze_upload_endpoint(uri)
    local analysis = {
        score = 0,
        risk_factors = {}
    }
    
    if not uri then
        return analysis
    end
    
    local uri_lower = string.lower(uri)
    
    -- Known vulnerable upload endpoints
    local vulnerable_endpoints = {
        -- CVE-2025-4403: Drag and Drop file upload
        { pattern = "dnd_codedropz_upload", score = 50, factor = "cve_2025_4403_endpoint" },
        
        -- CVE-2025-47577 & CVE-2024-8425: Gift Voucher upload
        { pattern = "mwb_wgm_preview_mail", score = 50, factor = "cve_2025_47577_endpoint" },
        
        -- CVE-2025-10142: PagSeguro file upload
        { pattern = "pc_added_uploaded_image", score = 45, factor = "cve_2025_10142_endpoint" },
        
        -- Generic WordPress admin-ajax vulnerabilities
        { pattern = "wp%-admin/admin%-ajax%.php", score = 20, factor = "admin_ajax_upload" },
        
        -- Theme/Plugin file editors
        { pattern = "theme%-editor%.php", score = 40, factor = "theme_editor_access" },
        { pattern = "plugin%-editor%.php", score = 40, factor = "plugin_editor_access" },
        
        -- File managers
        { pattern = "file%-manager", score = 30, factor = "file_manager_access" },
        { pattern = "filemanager", score = 30, factor = "file_manager_variant" },
        
        -- Backup/restore endpoints
        { pattern = "backup", score = 25, factor = "backup_endpoint" },
        { pattern = "restore", score = 25, factor = "restore_endpoint" },
        
        -- Media upload endpoints
        { pattern = "media%-upload", score = 15, factor = "media_upload_endpoint" },
        { pattern = "upload%.php", score = 25, factor = "generic_upload_script" }
    }
    
    for _, endpoint in ipairs(vulnerable_endpoints) do
        if string.find(uri_lower, endpoint.pattern) then
            analysis.score = analysis.score + endpoint.score
            table.insert(analysis.risk_factors, endpoint.factor)
        end
    end
    
    return analysis
end

-- Analyze user agent for upload automation tools
function _M.analyze_upload_user_agent(user_agent)
    local analysis = {
        score = 0,
        risk_factors = {}
    }
    
    if not user_agent or user_agent == "" then
        analysis.score = 15
        table.insert(analysis.risk_factors, "missing_user_agent")
        return analysis
    end
    
    local ua_lower = string.lower(user_agent)
    
    -- Known upload automation tools
    local automation_tools = {
        { pattern = "curl", score = 20, factor = "curl_upload" },
        { pattern = "wget", score = 20, factor = "wget_upload" },
        { pattern = "python%-requests", score = 25, factor = "python_requests" },
        { pattern = "postman", score = 15, factor = "postman_client" },
        { pattern = "burpsuite", score = 35, factor = "burp_suite" },
        { pattern = "sqlmap", score = 40, factor = "sqlmap_tool" },
        { pattern = "metasploit", score = 45, factor = "metasploit_framework" },
        { pattern = "exploit", score = 40, factor = "exploit_tool" },
        { pattern = "payload", score = 35, factor = "payload_delivery" },
        { pattern = "scanner", score = 30, factor = "vulnerability_scanner" }
    }
    
    for _, tool in ipairs(automation_tools) do
        if string.find(ua_lower, tool.pattern) then
            analysis.score = analysis.score + tool.score
            table.insert(analysis.risk_factors, tool.factor)
        end
    end
    
    -- Check for suspicious user agent patterns
    if string.len(user_agent) < 10 then
        analysis.score = analysis.score + 20
        table.insert(analysis.risk_factors, "suspiciously_short_ua")
    end
    
    if not string.find(ua_lower, "mozilla") and not string.find(ua_lower, "webkit") and
       not string.find(ua_lower, "chrome") and not string.find(ua_lower, "firefox") and
       not string.find(ua_lower, "safari") then
        analysis.score = analysis.score + 15
        table.insert(analysis.risk_factors, "non_browser_ua")
    end
    
    return analysis
end

-- Analyze upload bypass techniques
function _M.analyze_upload_bypass_techniques(content_type, args)
    local analysis = {
        score = 0,
        risk_factors = {}
    }
    
    local ct_lower = string.lower(content_type or "")
    local args_lower = string.lower(args or "")
    
    -- Content-Type bypass techniques
    if string.find(ct_lower, "multipart/form%-data") then
        -- Check for boundary manipulation
        if not string.find(ct_lower, "boundary=") then
            analysis.score = analysis.score + 20
            table.insert(analysis.risk_factors, "missing_boundary")
        end
        
        -- Check for unusual boundary values
        local boundary_match = string.match(ct_lower, "boundary=([^;%s]+)")
        if boundary_match then
            if string.len(boundary_match) > 50 then
                analysis.score = analysis.score + 15
                table.insert(analysis.risk_factors, "unusual_boundary_length")
            end
            
            if string.find(boundary_match, "%.%.") or string.find(boundary_match, "%%00") then
                analysis.score = analysis.score + 25
                table.insert(analysis.risk_factors, "malicious_boundary_pattern")
            end
        end
    end
    
    -- Parameter manipulation techniques
    local bypass_techniques = {
        -- File extension bypasses
        { pattern = "%.php%.", score = 35, factor = "double_extension" },
        { pattern = "%.php%%00", score = 40, factor = "null_byte_injection" },
        { pattern = "%.php%%20", score = 30, factor = "trailing_space" },
        { pattern = "%.php%s+", score = 25, factor = "trailing_whitespace" },
        { pattern = "%.pHp", score = 20, factor = "case_variation" },
        { pattern = "%.PhP", score = 20, factor = "case_variation" },
        
        -- MIME type bypasses
        { pattern = "image/gif.*php", score = 40, factor = "gif_php_polyglot" },
        { pattern = "image/jpeg.*php", score = 40, factor = "jpeg_php_polyglot" },
        { pattern = "image/png.*php", score = 40, factor = "png_php_polyglot" },
        
        -- Path manipulation
        { pattern = "%.%./", score = 30, factor = "path_traversal" },
        { pattern = "%%2e%%2e/", score = 35, factor = "encoded_path_traversal" },
        { pattern = "/%.%./", score = 25, factor = "absolute_path_traversal" },
        
        -- Special characters
        { pattern = "%%00", score = 30, factor = "null_byte" },
        { pattern = "%%0a", score = 20, factor = "line_feed_injection" },
        { pattern = "%%0d", score = 20, factor = "carriage_return_injection" },
        
        -- Upload parameter manipulation
        { pattern = "filename.*%.php", score = 25, factor = "php_filename" },
        { pattern = "name.*%.php", score = 25, factor = "php_field_name" },
        { pattern = "type.*script", score = 30, factor = "script_type_override" }
    }
    
    for _, technique in ipairs(bypass_techniques) do
        if string.find(args_lower, technique.pattern) or string.find(ct_lower, technique.pattern) then
            analysis.score = analysis.score + technique.score
            table.insert(analysis.risk_factors, technique.factor)
        end
    end
    
    return analysis
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
    
    local threat_data = red:get('threat_ips') or '{}'
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
    -- Block uploads with very high threat scores
    if analysis.threat_score >= 70 then
        return true, "high_threat_score"
    end
    
    -- Block uploads with multiple high-risk factors
    local critical_factors = {
        "php_extension", "executable_extension", "cve_2025_4403_endpoint",
        "cve_2025_47577_endpoint", "metasploit_framework", "exploit_tool"
    }
    
    local critical_count = 0
    for _, factor in ipairs(analysis.risk_factors) do
        for _, critical in ipairs(critical_factors) do
            if factor == critical then
                critical_count = critical_count + 1
                break
            end
        end
    end
    
    if critical_count >= 2 then
        return true, "multiple_critical_factors"
    end
    
    -- Block based on specific dangerous combinations
    local has_executable = false
    local has_bypass = false
    local has_cve_endpoint = false
    
    for _, factor in ipairs(analysis.risk_factors) do
        if string.find(factor, "extension") and 
           (string.find(factor, "php") or string.find(factor, "executable")) then
            has_executable = true
        elseif string.find(factor, "bypass") or string.find(factor, "injection") then
            has_bypass = true
        elseif string.find(factor, "cve_") then
            has_cve_endpoint = true
        end
    end
    
    if (has_executable and has_bypass) or (has_executable and has_cve_endpoint) then
        return true, "dangerous_combination"
    end
    
    return false, "allowed"
end

return _M