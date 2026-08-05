-- upload_rules.lua - Pure file-upload threat analysis used by upload_handler.lua
--
-- Same split rationale as threat_rules.lua/router_rules.lua/vulnerability_rules.lua:
-- no ngx.* dependency, plain-`lua`-interpreter testable (see
-- tests/test_upload_rules.lua). upload_handler.lua is the thin adapter --
-- it does the ngx.log calls and Redis I/O (suspicious-upload storage, IP
-- threat-score updates) and is wired live from nginx.conf's
-- /wp-admin/admin-ajax.php upload-handling location block.
--
-- Unlike the other _rules.lua modules, almost everything in the original
-- upload_handler.lua was already pure at the individual-function level --
-- this module is close to a straight move, not a rewrite.

local _M = {}

-- ---------------------------------------------------------------------------
-- is_file_upload(content_type, args)
-- ---------------------------------------------------------------------------
function _M.is_file_upload(content_type, args)
    if string.find(string.lower(content_type or ""), "multipart/form%-data") then
        return true
    end

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

-- ---------------------------------------------------------------------------
-- analyze_content_type(content_type)
-- ---------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------
-- analyze_upload_parameters(args)
-- ---------------------------------------------------------------------------
function _M.analyze_upload_parameters(args)
    local analysis = {
        score = 0,
        risk_factors = {}
    }

    if not args or args == "" then
        return analysis
    end

    local args_lower = string.lower(args)

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

    -- Directory traversal in file paths. The %2e%2e-style entries are
    -- literal URL-encoded substrings, not Lua patterns -- matched with
    -- plain=true. Previously passed straight to string.find() as patterns,
    -- "%2e%2e%2f"/"%2e%2e/" crashed outright with "invalid capture index"
    -- (Lua reads %2 as a backreference to a non-existent capture group),
    -- which meant *any* POST to /wp-admin/admin-ajax.php with a non-empty,
    -- upload-looking query string 500'd instead of being analysed --
    -- confirmed live via a real curl request before this fix. See
    -- tests/test_upload_rules.lua.
    local traversal_patterns = {
        { pattern = "%.%.%/",   plain = false },
        { pattern = "%2e%2e%2f", plain = true },
        { pattern = "%.%./",    plain = false },
        { pattern = "%2e%2e/",  plain = true }
    }

    for _, tp in ipairs(traversal_patterns) do
        if string.find(args_lower, tp.pattern, 1, tp.plain) then
            analysis.score = analysis.score + 30
            table.insert(analysis.risk_factors, "directory_traversal")
            break
        end
    end

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

-- ---------------------------------------------------------------------------
-- analyze_upload_endpoint(uri)
-- ---------------------------------------------------------------------------
function _M.analyze_upload_endpoint(uri)
    local analysis = {
        score = 0,
        risk_factors = {}
    }

    if not uri then
        return analysis
    end

    local uri_lower = string.lower(uri)

    local vulnerable_endpoints = {
        { pattern = "dnd_codedropz_upload", score = 50, factor = "cve_2025_4403_endpoint" },
        { pattern = "mwb_wgm_preview_mail", score = 50, factor = "cve_2025_47577_endpoint" },
        { pattern = "pc_added_uploaded_image", score = 45, factor = "cve_2025_10142_endpoint" },
        { pattern = "wp%-admin/admin%-ajax%.php", score = 20, factor = "admin_ajax_upload" },
        { pattern = "theme%-editor%.php", score = 40, factor = "theme_editor_access" },
        { pattern = "plugin%-editor%.php", score = 40, factor = "plugin_editor_access" },
        { pattern = "file%-manager", score = 30, factor = "file_manager_access" },
        { pattern = "filemanager", score = 30, factor = "file_manager_variant" },
        { pattern = "backup", score = 25, factor = "backup_endpoint" },
        { pattern = "restore", score = 25, factor = "restore_endpoint" },
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

-- ---------------------------------------------------------------------------
-- analyze_upload_user_agent(user_agent)
-- ---------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------
-- analyze_upload_bypass_techniques(content_type, args)
-- ---------------------------------------------------------------------------
function _M.analyze_upload_bypass_techniques(content_type, args)
    local analysis = {
        score = 0,
        risk_factors = {}
    }

    local ct_lower = string.lower(content_type or "")
    local args_lower = string.lower(args or "")

    if string.find(ct_lower, "multipart/form%-data") then
        if not string.find(ct_lower, "boundary=") then
            analysis.score = analysis.score + 20
            table.insert(analysis.risk_factors, "missing_boundary")
        end

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

    local bypass_techniques = {
        { pattern = "%.php%.", score = 35, factor = "double_extension" },
        { pattern = "%.php%%00", score = 40, factor = "null_byte_injection" },
        { pattern = "%.php%%20", score = 30, factor = "trailing_space" },
        { pattern = "%.php%s+", score = 25, factor = "trailing_whitespace" },
        { pattern = "%.pHp", score = 20, factor = "case_variation" },
        { pattern = "%.PhP", score = 20, factor = "case_variation" },

        { pattern = "image/gif.*php", score = 40, factor = "gif_php_polyglot" },
        { pattern = "image/jpeg.*php", score = 40, factor = "jpeg_php_polyglot" },
        { pattern = "image/png.*php", score = 40, factor = "png_php_polyglot" },

        { pattern = "%.%./", score = 30, factor = "path_traversal" },
        { pattern = "%%2e%%2e/", score = 35, factor = "encoded_path_traversal" },
        { pattern = "/%.%./", score = 25, factor = "absolute_path_traversal" },

        { pattern = "%%00", score = 30, factor = "null_byte" },
        { pattern = "%%0a", score = 20, factor = "line_feed_injection" },
        { pattern = "%%0d", score = 20, factor = "carriage_return_injection" },

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

-- ---------------------------------------------------------------------------
-- should_block_upload(analysis)
--
-- @param analysis  table  { threat_score, risk_factors[] } (e.g. the merged
--                          result upload_handler.analyze_upload() builds).
-- @return boolean, string  should_block, reason
-- ---------------------------------------------------------------------------
function _M.should_block_upload(analysis)
    if analysis.threat_score >= 70 then
        return true, "high_threat_score"
    end

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
