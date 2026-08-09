-- threat_analyzer.lua - Threat analysis module for Nginx Lua
--
-- PURPOSE:
--   Scores every inbound HTTP request using a weighted rule set that maps to
--   OWASP Web Security Testing Guide (WSTG) v4.2 categories and specific
--   WordPress/WooCommerce CVEs.  The numeric score returned drives the routing
--   decision in router.lua: requests that exceed the honeypot_threshold are
--   redirected to an isolated honeypot pool instance instead of reaching the
--   production WordPress site.
--
-- OWASP WSTG CATEGORY COVERAGE:
--   WSTG-INFO  – Information gathering (version fingerprinting, user enum)
--   WSTG-CONF  – Configuration issues (backup files, sensitive paths)
--   WSTG-IDNT  – Identity management (user enumeration via wp-json)
--   WSTG-ATHN  – Authentication testing (brute-force, credential bypass)
--   WSTG-AUTHZ – Authorization testing (privilege escalation, BAC)
--   WSTG-SESS  – Session management (session fixation, cookie theft)
--   WSTG-INPV  – Input validation (SQLi, XSS, CMDi, file inclusion, LFI)
--
-- SCORING SUMMARY:
--   Static asset requests          →   0 (always skipped)
--   Matching a suspicious pattern  → +15 base, +5..+30 for specific checks
--   Matching a CVE pattern         → +40 per CVE matched
--   Malicious user-agent string    → +50
--   Bad IP reputation              → +variable (from threat_intel dict)
--   Missing user-agent             → +10
--   CVE-specific header present    → +50
--   Automated tool signature       → +30
--   Honeypot threshold (default)   →  80 (configurable in init.lua)
--
-- DEPENDENCIES:
--   cjson        – JSON encoding for security event logging
--   resty.sha1   – SHA-1 for browser fingerprinting helper
--   resty.string – hex encoding for SHA-1 digests
--   _G.config    – global config table initialised in init.lua
--   _G.utils     – global utility functions initialised in init.lua

local cjson = require "cjson"
local resty_sha1 = require "resty.sha1"
local str = require "resty.string"

local _M = {}

-- ---------------------------------------------------------------------------
-- analyze_request(uri, headers, remote_ip)
--
-- Entry point called once per non-static request from nginx.conf
-- access_by_lua_block.  Runs every sub-analyser in sequence, accumulates
-- their scores into a single threat_result table, and sets the .suspicious
-- flag when the total reaches or exceeds honeypot_threshold.
--
-- @param uri        string   Raw request URI including query string.
-- @param headers    table    Request headers table from ngx.req.get_headers().
-- @param remote_ip  string   Client IP address (ngx.var.remote_addr).
-- @return           table    threat_result with fields:
--                              .score           – integer threat score (0..100)
--                              .suspicious      – boolean threshold exceeded
--                              .patterns_matched – list of matched pattern names
--                              .cve_matched      – list of matched CVE IDs
--                              .ip_reputation    – integer reputation score
--                              .details          – list of human-readable notes
-- ---------------------------------------------------------------------------
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
    
    -- Static assets (CSS, JS, images, fonts) carry no attack surface.
    -- Skipping them avoids inflating the threat score on normal page loads
    -- and keeps the hot path fast (no regex evaluation needed).
    if _M.is_static_asset(uri) then
        ngx.log(ngx.INFO, "[THREAT ANALYZER] ✅ Static asset - threat analysis skipped")
        return threat_result  -- Return zero score for static assets
    end
    
    -- Stage 1: URI pattern analysis (WSTG-INPV, WSTG-CONF, WSTG-INFO)
    -- Checks the raw URI path and query string against known attack signatures.
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
    
    -- Stage 2: Header analysis (WSTG-ATHN, WSTG-AUTHZ, CVE-specific headers)
    -- Inspects HTTP headers for tool signatures, missing mandatory headers,
    -- and headers that are specifically associated with known CVE exploits
    -- (e.g. X-WCPAY-PLATFORM-CHECKOUT-USER for CVE-2023-28121).
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
    
    -- Stage 3: CVE pattern matching (WSTG-AUTHZ, WSTG-INPV)
    -- Compares URI and header values against regex/string patterns defined in
    -- _G.config.vulnerability.cve_patterns (init.lua).  A single CVE match
    -- adds +40 to the score, which alone is enough to push moderate-scoring
    -- requests over the honeypot threshold.
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
    
    -- Stage 4: IP reputation check
    -- Looks up the client IP in the threat_intel shared dict populated by
    -- init_worker.lua (parse_suricata_logs) and init.lua (static seed data).
    -- Known-good IPs (Tailscale, STUBA ranges) receive a negative score that
    -- can absorb minor false-positive signals from other stages.
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
    
    -- Stage 5: Request method analysis (WSTG-INPV)
    -- Flags unusual HTTP methods (PUT, DELETE, PATCH, OPTIONS on non-API
    -- endpoints) that are not expected from a standard WooCommerce storefront.
    local method_score = _M.analyze_request_method()
    threat_result.score = threat_result.score + method_score.score
    
    if method_score.score > 0 then
        ngx.log(ngx.WARN, "[THREAT ANALYZER] 🔍 Suspicious request method (+", method_score.score, ")")
    end
    
    -- Stage 6: Automation detection (WSTG-INFO, WSTG-ATHN)
    -- Identifies well-known security scanning tools (sqlmap, wpscan, nikto,
    -- gobuster, etc.) by their User-Agent strings and absence of a Referer on
    -- POST requests.  Automated tool detection immediately routes to honeypot
    -- so that scan data is captured in isolation.
    local automation_score = _M.detect_automation(headers, uri)
    threat_result.score = threat_result.score + automation_score.score
    
    if automation_score.detected then
        table.insert(threat_result.details, "automation_detected: " .. automation_score.tool)
        ngx.log(ngx.WARN, "[THREAT ANALYZER] 🤖 Automation detected (+", automation_score.score, ") | Tool: ", 
                automation_score.tool or "unknown")
    end
    
    -- Final determination: flag as suspicious when accumulated score meets
    -- or exceeds the threshold defined in _G.config.threat.honeypot_threshold.
    -- router.lua will act on this flag to assign a pool and redirect.
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

-- ---------------------------------------------------------------------------
-- analyze_uri_patterns(uri)
--
-- Scores the raw request URI string against two layers of patterns:
--
--   Layer 1 – _G.config.threat.suspicious_patterns (init.lua)
--             General attack signatures from WSTG-INPV: directory traversal,
--             SQL injection fragments, XSS tags, dangerous PHP functions.
--             Each match adds +15.
--
--   Layer 2 – Inline specific_checks table below
--             Finer-grained patterns with individual scores reflecting their
--             relative severity and OWASP WSTG mapping.
--
-- OWASP WSTG mappings per check (noted in comments):
--   WSTG-INPV-01  – Directory traversal  (../, encoded variants)
--   WSTG-INPV-05  – SQL injection        (UNION SELECT, OR conditions, etc.)
--   WSTG-INPV-02  – XSS                  (<script>, javascript:, event handlers)
--   WSTG-INPV-12  – Command injection    (;cat, |nc, backticks)
--   WSTG-INPV-11  – File inclusion       (php://, file://, data://)
--   WSTG-CONF-05  – Sensitive file access (wp-config.php, .env, admin install)
--   WSTG-INFO-*   – Scanning probes      (/admin, /phpmyadmin, /backup)
-- ---------------------------------------------------------------------------
function _M.analyze_uri_patterns(uri)
    local result = {
        score = 0,
        patterns = {}
    }
    
    if not uri then
        return result
    end
    
    local uri_lower = string.lower(uri)
    
    -- Layer 1: generic suspicious patterns defined in init.lua config.
    -- These cover the broadest attack categories from OWASP WSTG-INPV.
    for _, pattern in ipairs(_G.config.threat.suspicious_patterns) do
        if string.find(uri_lower, pattern) then
            result.score = result.score + 15
            table.insert(result.patterns, pattern)
        end
    end
    
    -- Layer 2: finer-grained checks with per-pattern scores and OWASP mapping.
    -- Scores reflect severity: path traversal/RCE > SQLi > XSS > recon probes.
    local specific_checks = {
        -- WSTG-INPV-01: Path Traversal
        -- Detect both plain and URL-encoded "../" sequences used to escape the
        -- document root and read arbitrary files (e.g. /etc/passwd, wp-config.php).
        {pattern = "%.%./",    score = 20, name = "directory_traversal"},
        {pattern = "%%2e%%2e/", score = 20, name = "encoded_directory_traversal"},
        
        -- WSTG-INPV-05: SQL Injection
        -- Classic injection techniques: UNION-based extraction, boolean conditions,
        -- tautologies, schema enumeration, and DDL commands.
        {pattern = "union.*select", score = 25, name = "sql_union"},
        {pattern = "or.*1.*=.*1",   score = 20, name = "sql_or_condition"},
        {pattern = "'.*or.*'",       score = 20, name = "sql_quote_or"},
        {pattern = "select.*from",   score = 15, name = "sql_select"},
        {pattern = "drop.*table",    score = 30, name = "sql_drop"},
        {pattern = "insert.*into",   score = 20, name = "sql_insert"},
        
        -- WSTG-INPV-02: Reflected / Stored XSS
        -- Inline script injection, JavaScript protocol handler, and DOM event
        -- handler attributes that execute arbitrary JS in the victim's browser.
        {pattern = "<script",    score = 25, name = "xss_script"},
        {pattern = "javascript:", score = 20, name = "xss_javascript"},
        {pattern = "onerror=",   score = 20, name = "xss_onerror"},
        {pattern = "onload=",    score = 15, name = "xss_onload"},
        {pattern = "alert%s*%(", score = 15, name = "xss_alert"},
        
        -- WSTG-INPV-12: Command Injection
        -- Shell metacharacters used to chain OS commands to a vulnerable parameter.
        -- Netcat pipe (+30) scored highest as it typically signals a reverse shell.
        {pattern = ";.*cat",    score = 25, name = "cmd_cat"},
        {pattern = ";.*ls",     score = 20, name = "cmd_ls"},
        {pattern = "|.*nc",     score = 30, name = "cmd_netcat"},
        {pattern = "&&.*curl",  score = 25, name = "cmd_curl"},
        {pattern = "`.*`",      score = 20, name = "cmd_backticks"},
        
        -- WSTG-INPV-11: Local/Remote File Inclusion
        -- PHP stream wrappers (php://, file://, data://) used to include and
        -- execute arbitrary file content via vulnerable include() calls.
        {pattern = "php://",  score = 25, name = "php_wrapper"},
        {pattern = "file://", score = 20, name = "file_wrapper"},
        {pattern = "data://", score = 20, name = "data_wrapper"},
        
        -- WSTG-CONF-05 / WordPress-specific: Sensitive file and endpoint access.
        -- wp-config.php contains DB credentials; install.php resets the site;
        -- user-new.php triggers a user-creation form; xmlrpc.php is a brute-force
        -- and DDoS amplification vector.
        {pattern = "/wp%-config%.php",        score = 30, name = "wp_config_access"},
        {pattern = "/wp%-admin/install%.php",  score = 25, name = "wp_install_access"},
        {pattern = "wp%-admin.*user%-new%.php", score = 20, name = "wp_user_creation"},
        {pattern = "xmlrpc%.php",              score = 15, name = "wp_xmlrpc"},
        
        -- WSTG-INFO-02 / WSTG-INFO-03: Reconnaissance probes.
        -- Low-score signals; they are relevant as part of a cumulative pattern
        -- (e.g. a session that probes /admin and then injects SQL is more likely
        -- malicious than one that only checks /admin once).
        {pattern = "/admin",        score =  5, name = "admin_scan"},
        {pattern = "/administrator", score =  5, name = "administrator_scan"},
        {pattern = "/phpmyadmin",   score = 10, name = "phpmyadmin_scan"},
        {pattern = "/backup",       score = 10, name = "backup_scan"},
        -- WSTG-CONF-01: .env file exposure reveals secrets and DB credentials.
        {pattern = "/%.env",        score = 20, name = "env_file_scan"},
        
        -- WSTG-IDNT: WordPress user enumeration via REST API
        -- Supports both /wp-json/wp/v2/users and ?rest_route=/wp/v2/users patterns
        {pattern = "/wp%-json/wp/v2/users", score = 25, name = "wp_user_enumeration"},
        {pattern = "rest_route=.*/wp/v2/users", score = 25, name = "wp_user_enumeration_rest"}
    }
    
    for _, check in ipairs(specific_checks) do
        if string.find(uri_lower, check.pattern) then
            result.score = result.score + check.score
            table.insert(result.patterns, check.name)
        end
    end
    
    -- WSTG-INPV-05 / WSTG-INPV-02: URL encoding evasion detection.
    -- Percent-encoded characters in URIs can bypass naive string-match filters.
    -- Their presence does not confirm an attack on its own, but combined with
    -- other signals it raises the cumulative score.
    if string.find(uri, "%%[0-9a-fA-F][0-9a-fA-F]") then
        result.score = result.score + 10
        table.insert(result.patterns, "url_encoding_detected")
    end
    
    -- WSTG-INPV-04: HTTP Parameter Pollution.
    -- An unusual number of query-string delimiters suggests an attempt to
    -- confuse server-side parameter parsers or overwhelm WAF inspection windows.
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

-- ---------------------------------------------------------------------------
-- analyze_headers(headers)
--
-- Inspects request headers for attack tool fingerprints, missing browser
-- context headers, and CVE-specific exploit headers.
--
-- OWASP WSTG coverage:
--   WSTG-INFO-02  – Tool identification via User-Agent strings
--   WSTG-ATHN-04  – Brute-force signals (missing Referer on POST, Basic Auth)
--   WSTG-AUTHZ-*  – CVE-specific header injection (CVE-2023-28121)
--
-- @param headers  table  ngx.req.get_headers() result.
-- @return         table  { score, suspicious_headers[] }
-- ---------------------------------------------------------------------------
function _M.analyze_headers(headers)
    local result = {
        score = 0,
        suspicious_headers = {}
    }
    
    if not headers then
        return result
    end
    
    -- WSTG-INFO-02: Security tool fingerprinting via User-Agent.
    -- Known scanners and exploitation frameworks advertise themselves in their
    -- User-Agent string.  A match here scores +50, immediately pushing most
    -- requests over the honeypot threshold on its own.
    local user_agent = headers["User-Agent"] or headers["user-agent"] or ""
    local ua_lower = string.lower(user_agent)

    -- Ordered by prevalence in web-application attack traffic.
    local malicious_uas = {
        "sqlmap",    -- SQL injection automation (WSTG-INPV-05)
        "nmap",      -- Network/service scanner  (WSTG-INFO-01)
        "masscan",   -- Mass port scanner
        "zap",       -- OWASP Zed Attack Proxy   (all WSTG-INPV categories)
        "nikto",     -- Web vulnerability scanner (WSTG-CONF, WSTG-INFO)
        "dirb",      -- Directory brute-forcer    (WSTG-INFO-02)
        "gobuster",  -- Directory/DNS brute-forcer
        "wpscan",    -- WordPress-specific scanner (WSTG-INFO, CVEs)
        "whatweb",   -- Technology fingerprinter  (WSTG-INFO-02)
        "nuclei",    -- Template-based exploit scanner
        "burpsuite", -- Web app penetration-testing proxy
        "havij",     -- Automated SQL injection tool
        "pangolin"   -- SQL injection tool
    }

    for _, ua in ipairs(malicious_uas) do
        if string.find(ua_lower, ua) then
            result.score = result.score + 50
            table.insert(result.suspicious_headers, "malicious_user_agent: " .. ua)
            break  -- one match is sufficient; avoid double-counting
        end
    end

    -- Missing User-Agent: legitimate browsers always send one.  Absence suggests
    -- a custom script or tool that does not bother to impersonate a browser.
    if user_agent == "" or not user_agent then
        result.score = result.score + 10
        table.insert(result.suspicious_headers, "missing_user_agent")
    end

    -- WSTG-AUTHZ: CVE-2023-28121 exploit header.
    -- The WooCommerce Payments plugin (≤5.6.1) trusts the value of this header
    -- to authenticate requests as any WordPress user, including administrator.
    -- Its mere presence in a request is a definitive exploit signal.
    if headers["X-WCPAY-PLATFORM-CHECKOUT-USER"] then
        result.score = result.score + 50
        table.insert(result.suspicious_headers, "cve_2023_28121_header")
    end

    -- WSTG-ATHN-04: Missing Referer on POST requests.
    -- Legitimate browser form submissions always include a Referer that matches
    -- the site domain.  Its absence on POST is a weak signal (CLI tools, API
    -- clients) but contributes to the cumulative score.
    -- Score deliberately kept low (+5) to avoid false-positives on REST clients.
    if ngx.var.request_method == "POST" then
        local referer = headers["Referer"] or headers["referer"]
        if not referer then
            result.score = result.score + 5
            table.insert(result.suspicious_headers, "missing_referer_on_post")
        end
    end

    -- WSTG-ATHN-01: HTTP Basic Authentication probe.
    -- WooCommerce REST API supports Basic Auth for machine-to-machine access,
    -- but Basic Auth from an unexpected client is a credential-stuffing signal.
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
-- analyze_cve_patterns(uri, headers)
--
-- Checks the request URI, query string, and all headers against the CVE
-- pattern dictionary defined in _G.config.vulnerability.cve_patterns (init.lua).
-- Each pattern is tied to a specific CVE and matched case-insensitively.
--
-- A single CVE match scores +40.  Most requests that hit a CVE pattern will
-- already have a non-zero URI/header score, so the combined total readily
-- crosses the honeypot_threshold (80) without further signals.
--
-- Covered CVEs and their WSTG category:
--   CVE-2023-28121  WooCommerce Payments unauthorized admin – WSTG-AUTHZ
--   CVE-2023-2986   Abandoned Cart hardcoded key            – WSTG-AUTHZ
--   CVE-2025-4403   DnD file upload type bypass             – WSTG-INPV-10
--   CVE-2025-2266   CWMP unauthenticated options update     – WSTG-AUTHZ
--   CVE-2025-47577  Gift Voucher file-upload RCE            – WSTG-INPV-10
--   CVE-2024-8425   Gift Voucher alternate vector           – WSTG-INPV-10
--   CVE-2024-2387   AFI SQL injection via URL param         – WSTG-INPV-05
--   CVE-2025-10142  PagSeguro file path traversal           – WSTG-INPV-01
--   CVE-2024-50508  WP File Upload path traversal           – WSTG-INPV-01
-- ---------------------------------------------------------------------------

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