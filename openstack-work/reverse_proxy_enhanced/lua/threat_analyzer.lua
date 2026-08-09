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
-- ARCHITECTURE:
--   This file is the *adapter*: it pulls config out of _G.config, pulls
--   request context out of ngx.var/ngx.req, does all I/O (ngx.log, Redis /
--   shared-dict reads, log_security_event), and orchestrates the stages
--   below in sequence. The actual pattern-matching/scoring decisions are
--   pure functions in threat_rules.lua (no ngx.* dependency, unit-testable
--   with a plain `lua` interpreter -- see tests/test_threat_rules.lua).
--   Splitting it this way is what let threat_rules.lua get real unit test
--   coverage without needing OpenResty running.
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
--   High per-IP request rate       → +20 (rate_limit shared dict, >10 req/s)
--   Missing user-agent             → +10
--   CVE-specific header present    → +50
--   Automated tool signature       → +5..+30
--   Prompt-injection pattern hit   → +(prompt_injection_filter risk_score / 2)
--   Honeypot threshold (default)   →  80 (configurable in init.lua)
--
-- DEPENDENCIES:
--   cjson                    – JSON encoding for security event logging
--   threat_rules             – pure scoring rules (see above)
--   abuseipdb_client         – on-demand IP reputation lookups (Stage 4)
--   prompt_injection_filter  – forward-looking LLM-abuse pattern probe (Stage 7)
--   _G.config    – global config table initialised in init.lua
--   _G.utils     – global utility functions initialised in init.lua

local cjson = require "cjson"
local threat_rules = require "threat_rules"
local suricata_rules = require "suricata_rules"
local wp_install_state = require "wp_install_state"

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
--                              .ip_reputation_reason – string|nil, why (e.g.
--                                "suricata: CVE-2023-28121 ..." when a
--                                Suricata alert is what flagged this IP --
--                                see init_worker.lua's parse_suricata_logs);
--                                nil when ip_reputation is 0/unset.
--                              .details          – list of human-readable notes
-- ---------------------------------------------------------------------------
function _M.analyze_request(uri, headers, remote_ip)
    local threat_result = {
        score = 0,
        suspicious = false,
        patterns_matched = {},
        cve_matched = {},
        ip_reputation = 0,
        ip_reputation_reason = nil,
        details = {}
    }

    ngx.log(ngx.INFO, "[THREAT ANALYZER] Starting analysis for: ", uri or "unknown", " | IP: ", remote_ip)

    -- Static assets (CSS, JS, images, fonts) carry no attack surface.
    if _M.is_static_asset(uri) then
        ngx.log(ngx.INFO, "[THREAT ANALYZER] ✅ Static asset - threat analysis skipped")
        return threat_result
    end

    -- WordPress installer fast path: install.php is only ever this
    -- aggressively scored (see the wp_install_access/install_php checks in
    -- Stage 1 below) because a legitimately-installed site has no reason for
    -- anyone to hit it. Before production has completed its first-run setup
    -- wizard, hitting it IS the legitimate flow -- see wp_install_state.lua's
    -- header comment for how "not installed yet" is determined and why
    -- checking production's state alone is sufficient for honeypot pools too.
    if threat_rules.is_install_wizard_uri(uri) and not wp_install_state.is_installed("production_backend") then
        ngx.log(ngx.INFO, "[THREAT ANALYZER] ✅ WordPress not yet installed - install.php allowed, analysis skipped")
        return threat_result
    end

    -- Stage 1: URI pattern analysis (WSTG-INPV, WSTG-CONF, WSTG-INFO)
    --
    -- admin-ajax.php is scanned on its query string only, not its full
    -- path. Its fixed path ("/wp-admin/admin-ajax.php") itself trips the
    -- generic "/admin" and "/wp-admin/" reconnaissance-probe patterns on
    -- every single request regardless of content, since this is
    -- WordPress's public AJAX gateway that legitimate frontend JS hits
    -- constantly (WooCommerce cart updates, coupon apply, ...) -- not a
    -- probed/discovered admin path. Confirmed live this pipeline previously
    -- never ran for admin-ajax.php at all (see Stage 6b below), so this
    -- false-positive path was latent until that bypass was fixed.
    -- SQLi/XSS/traversal/CVE-action-name signals still fire normally since
    -- those live in the query string, and Stage 3/Stage 6b give this
    -- endpoint its own dedicated, appropriately-scoped analysis.
    local uri_for_pattern_scan = uri
    if uri and uri:find("admin%-ajax%.php") then
        uri_for_pattern_scan = "/" .. (ngx.var.args or "")
    end
    local uri_score = _M.analyze_uri_patterns(uri_for_pattern_scan)
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
    local cve_score = _M.analyze_cve_patterns(uri, headers)
    threat_result.score = threat_result.score + cve_score.score

    if cve_score.cves then
        for _, cve in ipairs(cve_score.cves) do
            table.insert(threat_result.cve_matched, cve)
            -- Logging is I/O, so it stays here rather than in the pure
            -- threat_rules.analyze_cve_patterns().
            _G.utils.log_security_event("cve_pattern_detected", {
                cve = cve,
                uri = uri,
                ip = remote_ip
            })
        end
        if #cve_score.cves > 0 then
            ngx.log(ngx.ERR, "[THREAT ANALYZER] 🎯 CVE PATTERNS DETECTED (+", cve_score.score, ") | CVEs: ",
                    table.concat(cve_score.cves, ", "))
        end
    end

    -- Stage 4: IP reputation check
    local ip_rep = _M.check_ip_reputation(remote_ip)
    threat_result.ip_reputation = ip_rep.score
    threat_result.ip_reputation_reason = ip_rep.reason
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
    local method_score = _M.analyze_request_method()
    threat_result.score = threat_result.score + method_score.score

    if method_score.score > 0 then
        ngx.log(ngx.WARN, "[THREAT ANALYZER] 🔍 Suspicious request method (+", method_score.score, ")")
    end

    -- Stage 6: Automation detection (WSTG-INFO, WSTG-ATHN)
    local automation_score = _M.detect_automation(headers, uri)
    threat_result.score = threat_result.score + automation_score.score

    if automation_score.detected then
        table.insert(threat_result.details, "automation_detected: " .. automation_score.tool)
        ngx.log(ngx.WARN, "[THREAT ANALYZER] 🤖 Automation detected (+", automation_score.score, ") | Tool: ",
                automation_score.tool or "unknown")
    end

    -- Stage 6b: WordPress AJAX upload-specific analysis (WSTG-INPV-10).
    -- Scoped to POST /wp-admin/admin-ajax.php, mirroring upload_handler.lua's
    -- original intent. This used to run from its own dedicated nginx
    -- location with its own proxy_pass, entirely bypassing this pipeline
    -- and session_handler's accumulation -- a detection there never
    -- survived past the single request it fired on and never reached the
    -- dashboard's displayed score. Folding it in here fixes both: it now
    -- accumulates like every other signal, and benefits from
    -- upload_rules.lua's endpoint check no longer blanket-flagging every
    -- admin-ajax.php request regardless of actual signal (see that file's
    -- comment -- confirmed live this misfired on a plain product-page visit).
    if ngx.var.request_method == "POST" and uri and uri:find("admin%-ajax%.php") then
        local upload_handler = require "upload_handler"
        local upload_analysis = upload_handler.analyze_upload(headers, ngx.var.args)
        threat_result.score = threat_result.score + upload_analysis.threat_score

        if upload_analysis.threat_score > 0 then
            table.insert(threat_result.details, "upload_analysis: " .. table.concat(upload_analysis.risk_factors, ","))
            ngx.log(ngx.WARN, "[THREAT ANALYZER] 📤 Upload analysis (+", upload_analysis.threat_score,
                    ") | Factors: ", table.concat(upload_analysis.risk_factors, ", "))
        end
    end

    -- Stage 7: Prompt-injection pattern probe (forward-looking LLM-abuse
    -- signal; see prompt_injection_filter.lua header comment).
    local prompt_injection_filter = require "prompt_injection_filter"
    local injection_result = prompt_injection_filter.detect(_G.utils.url_decode(uri))
    if injection_result.risk_score > 0 then
        local injection_score = math.floor(injection_result.risk_score / 2)
        threat_result.score = threat_result.score + injection_score
        table.insert(threat_result.details, "prompt_injection_probe: risk_score=" .. injection_result.risk_score)
        for _, m in ipairs(injection_result.matched) do
            table.insert(threat_result.patterns_matched, "prompt_injection:" .. m.category)
        end
        ngx.log(ngx.WARN, "[THREAT ANALYZER] 🧪 Prompt-injection pattern detected (+", injection_score,
                ") | Filter risk_score: ", injection_result.risk_score, " | URI: ", uri)
    end

    -- Final determination: flag as suspicious when accumulated score meets
    -- or exceeds the threshold defined in _G.config.threat.honeypot_threshold.
    threat_result.suspicious = threat_result.score >= _G.config.threat.honeypot_threshold

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

-- Thin delegating wrappers: pull the relevant slice of _G.config / ngx.var
-- and hand off to the pure rules in threat_rules.lua. Kept on _M (rather
-- than inlined into analyze_request) since nothing else in the codebase
-- calls them directly, but the public shape is preserved in case that
-- changes, and it keeps analyze_request's stage list readable.

function _M.analyze_uri_patterns(uri)
    return threat_rules.analyze_uri_patterns(uri, _G.config.threat.suspicious_patterns)
end

function _M.analyze_headers(headers)
    return threat_rules.analyze_headers(headers, ngx.var.request_method)
end

function _M.analyze_cve_patterns(uri, headers)
    return threat_rules.analyze_cve_patterns(uri, headers, ngx.var.args, _G.config.vulnerability.cve_patterns)
end

function _M.analyze_request_method()
    return threat_rules.analyze_request_method(ngx.var.request_method, ngx.var.http_x_http_method_override)
end

function _M.is_static_asset(uri)
    return threat_rules.is_static_asset(uri, _G.config.threat.static_asset_patterns)
end

-- ---------------------------------------------------------------------------
-- check_ip_reputation(ip)
--
-- Inherently I/O: reads the threat_intel and rate_limit shared dicts,
-- kicks off an async AbuseIPDB check. Not moved to threat_rules.lua since
-- there's no meaningful pure core left once the Redis/shared-dict reads are
-- taken out -- the "is this IP whitelisted" check itself is a single
-- _G.utils call, not scoring logic.
-- ---------------------------------------------------------------------------
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
        result.score = -20
        result.reason = "whitelisted"
        ngx.log(ngx.INFO, "[THREAT ANALYZER] ✅ IP is whitelisted: ", ip)
        return result
    end

    -- Check threat intelligence data
    local threat_intel = ngx.shared.threat_intel
    local threat_ips_json = threat_intel:get("threat_ips")

    local known_ip = false
    if threat_ips_json then
        local threat_ips = cjson.decode(threat_ips_json)
        if threat_ips[ip] then
            known_ip = true
            -- Decayed, not the raw stored value: a stale alert (or a
            -- one-off false positive, e.g. an AbuseIPDB blacklist entry
            -- that's since been resolved) would otherwise permanently
            -- poison this IP's reputation contribution with no way to age
            -- out short of manually clearing Redis -- confirmed live this
            -- was happening repeatedly. (A DIFFERENT class of false
            -- positive -- Suricata's network_mode:host visibility
            -- misattributing an alert to a container's own internal
            -- address rather than the real client -- is filtered out
            -- before it ever reaches threat_ips at all; see
            -- suricata_rules.lua's module docstring and
            -- init_worker.lua's parse_suricata_logs().)
            -- score_decay_half_life_seconds is the same knob session-level
            -- scoring decays against (router_rules.decayed_score(),
            -- router.lua) -- one shared "how long does suspicion linger"
            -- setting for both.
            result.score = suricata_rules.decayed_score(
                threat_ips[ip], ngx.time(), _G.config.threat.score_decay_half_life_seconds)
            result.reason = threat_ips[ip].reason or "known_threat"
            ngx.log(ngx.ERR, "[THREAT ANALYZER] 🚨 Known threat IP detected: ", ip, " | Reason: ", result.reason,
                    " | Stored raw_score: ", threat_ips[ip].raw_score or 0, " | Decayed score: ",
                    string.format("%.1f", result.score))
        end
    end

    -- No local reputation data yet for this IP: kick off an async AbuseIPDB
    -- on-demand check (abuseipdb_client.check_ip_async) so future requests
    -- from this IP benefit from the lookup. Fire-and-forget: never blocks
    -- the current request and is a no-op if the integration is disabled.
    if not known_ip then
        local ok, abuseipdb_client = pcall(require, "abuseipdb_client")
        if ok then
            abuseipdb_client.check_ip_async(ip)
        end
    end

    -- Per-IP request-rate check. update_rate_limit() below both increments
    -- and reads the counter for this IP in the same call -- previously this
    -- read the rate_limit shared dict without anything ever writing to it
    -- (the only writer, analyze_rate_limiting(), was defined but never
    -- called from anywhere in the request path), so this signal was
    -- permanently dead. Fixed by having check_ip_reputation call the
    -- writer itself instead of a stale read-only snapshot.
    local rate_data = _M.update_rate_limit(ip)
    if rate_data.requests and rate_data.window_start then
        local requests_per_second = rate_data.requests / (ngx.time() - rate_data.window_start + 1)
        if requests_per_second > 10 then
            result.score = result.score + 20
            result.reason = (result.reason and result.reason .. ", " or "") .. "high_request_rate"
        end
    end

    return result
end

-- ---------------------------------------------------------------------------
-- update_rate_limit(ip)
--
-- Increments (or starts) the current 60s request-count window for `ip` in
-- the rate_limit shared dict and returns the resulting window data. I/O
-- (shared dict read+write), so it stays here rather than in threat_rules.lua.
-- ---------------------------------------------------------------------------
function _M.update_rate_limit(ip)
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

    rate_limit_dict:set(rate_key, cjson.encode(rate_data), window_size)

    return rate_data
end

-- ---------------------------------------------------------------------------
-- detect_automation(headers, uri)
--
-- User-Agent fingerprint matching is pure (threat_rules.score_automation_user_agent);
-- the rapid-request timing check needs the `sessions` shared dict, so it
-- stays here as I/O and its result is merged with the pure score.
-- ---------------------------------------------------------------------------
function _M.detect_automation(headers, uri)
    local user_agent = headers["User-Agent"] or headers["user-agent"] or ""
    local result = threat_rules.score_automation_user_agent(user_agent)

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

return _M
