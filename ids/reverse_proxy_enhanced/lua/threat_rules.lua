-- threat_rules.lua - Pure scoring rules used by threat_analyzer.lua
--
-- PURPOSE:
--   Holds the actual pattern-matching / scoring logic that used to live
--   directly inside threat_analyzer.lua's functions, factored out so it has
--   no ngx.* dependency and no reliance on _G.config/_G.utils being set up.
--   Every function here takes plain Lua values (strings, tables) as
--   arguments and returns plain Lua tables -- nothing here reads a request
--   header off ngx.req, touches a shared dict, or writes a log line.
--   threat_analyzer.lua is the adapter: it pulls config out of _G.config,
--   pulls request context out of ngx.var/ngx.req, calls into this module for
--   the actual scoring decision, and does all the I/O (ngx.log,
--   log_security_event, Redis/shared-dict reads for IP reputation and
--   automation timing).
--
--   This mirrors prompt_injection_filter.lua's existing "no ngx.* dependency
--   by design" convention so the same kind of plain-`lua`-interpreter unit
--   tests are possible here -- see tests/test_threat_rules.lua.
--
-- WHY THIS SPLIT: a pure core is testable without spinning up OpenResty, and
-- makes it obvious at a glance which functions can silently depend on
-- request-scoped globals (ngx.var.*) and which can't -- several bugs found
-- earlier in this codebase (e.g. sophistication_analyzer's lost UA field)
-- came from exactly that kind of implicit, easy-to-miss dependency.

local pattern_utils = require "lua_pattern_utils"

local _M = {}

-- Re-exported for backward compatibility with anything already calling
-- threat_rules.url_decode() directly (e.g. existing tests); the actual
-- implementation now lives in lua_pattern_utils.lua, shared with
-- router_rules.lua/vulnerability_rules.lua/upload_rules.lua instead of each
-- keeping its own copy.
local url_decode = pattern_utils.url_decode
_M.url_decode = url_decode

-- Re-exported for the same reason: threat_analyzer.lua's install.php
-- not-yet-installed fast path needs the exact same matcher router_rules.lua
-- uses, so the two can never quietly disagree (see lua_pattern_utils.lua's
-- own comment on this function).
_M.is_install_wizard_uri = pattern_utils.is_install_wizard_uri

-- ---------------------------------------------------------------------------
-- is_static_asset(uri, static_asset_patterns)
--
-- Query-string-stripping kept in sync with router_rules.is_static_asset
-- (the two used to disagree here -- router.lua's stripped "?query" before
-- matching, this one didn't, so "style.css?v=123" was classified as static
-- by one and not the other).
--
-- @param uri                     string       Raw request URI.
-- @param static_asset_patterns   table|nil    List of Lua patterns (from
--                                              _G.config.threat.static_asset_patterns).
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.is_static_asset(uri, static_asset_patterns)
    if not uri then
        return false
    end

    local uri_lower = string.lower(uri)
    local uri_path = uri_lower:match("^([^?]+)") or uri_lower

    if static_asset_patterns then
        for _, pattern in ipairs(static_asset_patterns) do
            if string.find(uri_path, pattern) then
                return true
            end
        end
    end

    return false
end

-- ---------------------------------------------------------------------------
-- analyze_uri_patterns(uri, suspicious_patterns)
--
-- Scores the raw request URI string against two layers of patterns: the
-- caller-supplied generic list (Layer 1, e.g. _G.config.threat.suspicious_patterns)
-- and a fixed, finer-grained table with individual scores and OWASP WSTG
-- mappings (Layer 2, unchanged from the original threat_analyzer.lua).
--
-- @param uri                  string
-- @param suspicious_patterns  table|nil  List of Lua patterns.
-- @param max_score            number|nil Clamp the returned score to this
--                             (the caller passes _G.config.threat.max_threat_score).
--                             The overall request score is capped at that max
--                             anyway, so a single URI signal contributing more
--                             than the max (e.g. author_enum 80 + several
--                             generic hits => "+110") is meaningless and just
--                             misleads a log/report reader -- clamp it so the
--                             "+N" never exceeds the score it can actually add.
-- @return table  { score, patterns[] }
-- ---------------------------------------------------------------------------
function _M.analyze_uri_patterns(uri, suspicious_patterns, max_score)
    local result = {
        score = 0,
        patterns = {}
    }

    if not uri then
        return result
    end

    local uri_lower = string.lower(uri)
    local uri_decoded = url_decode(uri)
    local uri_lower_decoded = string.lower(uri_decoded)

    -- Layer 1: generic suspicious patterns supplied by the caller.
    if suspicious_patterns then
        for _, pattern in ipairs(suspicious_patterns) do
            if string.find(uri_lower_decoded, pattern) or string.find(uri_lower, pattern) then
                result.score = result.score + 15
                table.insert(result.patterns, pattern)
            end
        end
    end

    -- Layer 2: finer-grained checks with per-pattern scores and OWASP mapping.
    -- Scores reflect severity: path traversal/RCE > SQLi > XSS > recon probes.
    local specific_checks = {
        -- WSTG-INPV-01: Path Traversal
        {pattern = "%.%./",    score = 20, name = "directory_traversal"},
        {pattern = "%%2e%%2e/", score = 20, name = "encoded_directory_traversal"},

        -- WSTG-INPV-05: SQL Injection
        {pattern = "union.*select", score = 25, name = "sql_union"},
        {pattern = "or.*1.*=.*1",   score = 20, name = "sql_or_condition"},
        {pattern = "'.*or.*'",       score = 20, name = "sql_quote_or"},
        {pattern = "select.*from",   score = 15, name = "sql_select"},
        {pattern = "drop.*table",    score = 30, name = "sql_drop"},
        {pattern = "insert.*into",   score = 20, name = "sql_insert"},

        -- WSTG-INPV-02: Reflected / Stored XSS
        {pattern = "<script",    score = 25, name = "xss_script"},
        {pattern = "javascript:", score = 20, name = "xss_javascript"},
        {pattern = "onerror=",   score = 20, name = "xss_onerror"},
        {pattern = "onload=",    score = 15, name = "xss_onload"},
        {pattern = "alert%s*%(", score = 15, name = "xss_alert"},

        -- WSTG-INPV-12: Command Injection
        {pattern = ";.*cat",    score = 25, name = "cmd_cat"},
        {pattern = ";.*ls",     score = 20, name = "cmd_ls"},
        {pattern = "|.*nc",     score = 30, name = "cmd_netcat"},
        {pattern = "&&.*curl",  score = 25, name = "cmd_curl"},
        {pattern = "`.*`",      score = 20, name = "cmd_backticks"},

        -- WSTG-INPV-11: Local/Remote File Inclusion
        {pattern = "php://",  score = 25, name = "php_wrapper"},
        {pattern = "file://", score = 20, name = "file_wrapper"},
        {pattern = "data://", score = 20, name = "data_wrapper"},

        -- WSTG-CONF-05 / WordPress-specific: Sensitive file and endpoint access.
        {pattern = "/wp%-config%.php",        score = 30, name = "wp_config_access"},
        {pattern = "/wp%-admin/install%.php",  score = 25, name = "wp_install_access"},
        {pattern = "wp%-admin.*user%-new%.php", score = 20, name = "wp_user_creation"},
        {pattern = "xmlrpc%.php",              score = 15, name = "wp_xmlrpc"},
        {pattern = "wp%-config%.php%.bak", score = 80, name = "wp_config_bak"},
        {pattern = "wp%-config%-",         score = 30, name = "wp_config_variant"},
        {pattern = "%.bak$",               score = 20, name = "bak_file"},
        {pattern = "%.old$",               score = 20, name = "old_file"},
        {pattern = "backup%.zip",          score = 25, name = "backup_zip"},
        {pattern = "wp%-backup",           score = 25, name = "wp_backup"},
        {pattern = "phpinfo%.php",         score = 30, name = "phpinfo_file"},
        {pattern = "%.htaccess",           score = 25, name = "htaccess_file"},
        {pattern = "install%.php",         score = 30, name = "install_php"},
        {pattern = "etc/passwd",           score = 30, name = "etc_passwd"},
        {pattern = "%%3[cC]script",        score = 25, name = "enc_script"},
        {pattern = "system%.listMethods",  score = 25, name = "xmlrpc_methods"},
        {pattern = "multicall",            score = 25, name = "xmlrpc_multicall"},
        {pattern = "admin%-post%.php",     score = 20, name = "admin_post"},
        {pattern = "author=%d+",           score = 80, name = "author_enum"},

        -- WSTG-INFO-02 / WSTG-INFO-03: Reconnaissance probes.
        {pattern = "/admin",        score =  5, name = "admin_scan"},
        {pattern = "/administrator", score =  5, name = "administrator_scan"},
        {pattern = "/phpmyadmin",   score = 10, name = "phpmyadmin_scan"},
        {pattern = "/backup",       score = 10, name = "backup_scan"},
        {pattern = "/%.env",        score = 20, name = "env_file_scan"},

        -- WSTG-IDNT: WordPress user enumeration via REST API
        {pattern = "/wp%-json/wp/v2/users", score = 25, name = "wp_user_enumeration"},
        {pattern = "rest_route=.*/wp/v2/users", score = 25, name = "wp_user_enumeration_rest"}
    }

    for _, check in ipairs(specific_checks) do
        if string.find(uri_lower_decoded, check.pattern) or string.find(uri_lower, check.pattern) then
            result.score = result.score + check.score
            table.insert(result.patterns, check.name)
        end
    end

    -- WSTG-INPV-05 / WSTG-INPV-02: URL encoding evasion detection.
    if string.find(uri, "%%[0-9a-fA-F][0-9a-fA-F]") then
        result.score = result.score + 10
        table.insert(result.patterns, "url_encoding_detected")
    end

    -- WSTG-INPV-04: HTTP Parameter Pollution.
    local param_count = 0
    for _ in string.gmatch(uri, "[&?]") do
        param_count = param_count + 1
    end

    if param_count > 20 then
        result.score = result.score + 15
        table.insert(result.patterns, "excessive_parameters")
    end

    -- Clamp to the max score this signal can actually contribute (see @param
    -- max_score). Purely corrects the reported "+N" -- the request total is
    -- min(sum, max_threat_score) regardless, so this never changes routing.
    if max_score and result.score > max_score then
        result.score = max_score
    end

    return result
end

-- ---------------------------------------------------------------------------
-- analyze_headers(headers, request_method)
--
-- @param headers         table       Request headers (e.g. ngx.req.get_headers()).
-- @param request_method  string|nil  HTTP method of the current request.
-- @return table  { score, suspicious_headers[] }
-- ---------------------------------------------------------------------------
function _M.analyze_headers(headers, request_method)
    local result = {
        score = 0,
        suspicious_headers = {}
    }

    if not headers then
        return result
    end

    -- WSTG-INFO-02: Security tool fingerprinting via User-Agent.
    local user_agent = headers["User-Agent"] or headers["user-agent"] or ""
    local ua_lower = string.lower(user_agent)

    local malicious_uas = {
        "sqlmap", "nmap", "masscan", "zap", "acunetix", "nikto", "dirb",
        "gobuster", "wpscan", "whatweb", "nuclei", "burpsuite", "havij", "pangolin"
    }

    for _, ua in ipairs(malicious_uas) do
        if string.find(ua_lower, ua) then
            result.score = result.score + 50
            table.insert(result.suspicious_headers, "malicious_user_agent: " .. ua)
            break
        end
    end

    -- Missing User-Agent: legitimate browsers always send one.
    if user_agent == "" or not user_agent then
        result.score = result.score + 10
        table.insert(result.suspicious_headers, "missing_user_agent")
    end

    -- WSTG-AUTHZ: CVE-2023-28121 exploit header (WooCommerce Payments).
    if headers["X-WCPAY-PLATFORM-CHECKOUT-USER"] then
        result.score = result.score + 50
        table.insert(result.suspicious_headers, "cve_2023_28121_header")
    end

    -- WSTG-ATHN-04: Missing Referer on POST requests.
    if request_method == "POST" then
        local referer = headers["Referer"] or headers["referer"]
        if not referer then
            result.score = result.score + 5
            table.insert(result.suspicious_headers, "missing_referer_on_post")
        end
    end

    -- WSTG-ATHN-01: HTTP Basic Authentication probe.
    local auth = headers["Authorization"] or headers["authorization"]
    if auth then
        if string.find(string.lower(auth), "basic") then
            result.score = result.score + 5
            table.insert(result.suspicious_headers, "basic_auth_attempt")
        end
    end

    return result
end

-- ---------------------------------------------------------------------------
-- analyze_cve_patterns(uri, headers, query_params, cve_patterns)
--
-- Checks the request URI, query string, and all headers against a CVE
-- pattern dictionary. Pure: does NOT log -- the caller (threat_analyzer.lua)
-- logs a cve_pattern_detected security event for each match, since logging
-- is I/O.
--
-- @param uri            string
-- @param headers        table|nil
-- @param query_params   string|nil   e.g. ngx.var.args
-- @param cve_patterns   table        Map of CVE ID -> Lua pattern (from
--                                    _G.config.vulnerability.cve_patterns).
-- @return table  { score, cves[] }
-- ---------------------------------------------------------------------------
function _M.analyze_cve_patterns(uri, headers, query_params, cve_patterns, max_score)
    local result = {
        score = 0,
        cves = {}
    }

    if not uri or not cve_patterns then
        return result
    end

    local uri_lower = string.lower(uri)
    query_params = query_params or ""

    for cve, pattern in pairs(cve_patterns) do
        local found = false
        local pattern_lower = string.lower(pattern)

        if string.find(uri_lower, pattern_lower) then
            found = true
        end

        if not found and query_params ~= "" and string.find(string.lower(query_params), pattern_lower) then
            found = true
        end

        if not found and headers then
            for header_name, header_value in pairs(headers) do
                if string.find(string.lower(header_name), pattern_lower) or
                   string.find(string.lower(header_value or ""), pattern_lower) then
                    found = true
                    break
                end
            end
        end

        if found then
            result.score = result.score + 40
            table.insert(result.cves, cve)
        end
    end

    -- Clamp to the max score this signal can actually add (the request total
    -- is capped at max_threat_score anyway) so a multi-CVE match no longer
    -- reports a meaningless "+120" the score can never reach. cves[] is left
    -- intact -- the count of distinct CVEs is still reported truthfully.
    if max_score and result.score > max_score then
        result.score = max_score
    end

    return result
end

-- ---------------------------------------------------------------------------
-- analyze_request_method(method, method_override_header)
--
-- @param method                   string|nil  e.g. ngx.var.request_method
-- @param method_override_header  string|nil  e.g. ngx.var.http_x_http_method_override
-- @return table  { score }
-- ---------------------------------------------------------------------------
function _M.analyze_request_method(method, method_override_header)
    local result = { score = 0 }

    if method == "OPTIONS" or method == "TRACE" or method == "CONNECT" then
        result.score = result.score + 10
    end

    if method_override_header then
        result.score = result.score + 15
    end

    return result
end

-- ---------------------------------------------------------------------------
-- score_automation_user_agent(user_agent)
--
-- Pure User-Agent-string half of the original detect_automation(): matches
-- known automation-tool fingerprints. The other half (rapid-request timing,
-- which needs the shared `sessions` dict) stays in threat_analyzer.lua's
-- detect_automation() as I/O.
--
-- @param user_agent  string|nil
-- @return table  { score, detected, tool }
-- ---------------------------------------------------------------------------
function _M.score_automation_user_agent(user_agent)
    local result = {
        score = 0,
        detected = false,
        tool = nil
    }

    local ua_lower = string.lower(user_agent or "")

    local automation_tools = {
        {pattern = "curl", name = "curl", score = 5},
        {pattern = "wget", name = "wget", score = 5},
        {pattern = "python%-requests", name = "python-requests", score = 10},
        {pattern = "go%-http%-client", name = "go-http-client", score = 10},
        {pattern = "apache%-httpclient", name = "apache-httpclient", score = 10},
        {pattern = "okhttp", name = "okhttp", score = 10},
        {pattern = "bot", name = "generic-bot", score = 15},
        {pattern = "crawler", name = "crawler", score = 10},
        {pattern = "scanner", name = "scanner", score = 20},
        {pattern = "wpscan", name = "wpscan", score = 30}
    }

    for _, tool in ipairs(automation_tools) do
        if string.find(ua_lower, tool.pattern) then
            result.score = result.score + tool.score
            result.detected = true
            result.tool = tool.name
            break
        end
    end

    return result
end

return _M
