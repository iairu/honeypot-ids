-- router.lua - Routing decision module for Nginx Lua
--
-- PURPOSE:
--   Makes the final routing decision for every inbound HTTP request: either
--   forward to the production WordPress instance (production_backend) or
--   divert to an isolated honeypot pool instance (honeypot_backend_N).
--
-- DECISION PIPELINE (evaluated in order; first match wins):
--   1. Static asset  → always production (CSS/JS/images, no attack surface)
--   2. Session already honeypot_bound → sticky honeypot (same pool via Redis)
--   3. Threat score ≥ honeypot_threshold → honeypot (high threat, WSTG-INPV)
--   4. CVE pattern matched → honeypot (exploit attempt detected)
--   5. Vulnerable plugin URI → honeypot (direct plugin endpoint access)
--   6. Bad IP reputation → honeypot (known malicious IP from threat_intel)
--   7. Multiple admin-access attempts (≥3) → honeypot (WSTG-ATHN-04)
--   8. Accumulated suspicious activities (≥5) → honeypot
--   9. Rapid automation detected → honeypot (WSTG-INFO-02)
--  10. Suspicious file upload → honeypot (WSTG-INPV-10)
--  11. Default → production
--
-- POOLING INTEGRATION:
--   When a request is routed to the honeypot, pool_router.lua is consulted to
--   determine which specific pool instance (honeypot_eshop_1/2/3) the attacking
--   IP should be sent to.  Once assigned, the IP always hits the same pool so
--   the attacker sees a consistent fake environment.  The assigned pool number is
--   also stored in the session under session_data.honeypot_pool so that
--   session-bound re-routing (session already honeypot_bound) can use the same pool
--   without an extra Redis lookup.
--
-- KEY DATA FLOWS:
--   nginx.conf access_by_lua_block
--     → threat_analyzer.analyze_request()   (scoring)
--     → session_handler.get_session()        (state lookup)
--     → router.decide_route()               (THIS MODULE)
--       → pool_router.get_or_assign_pool()  (pool selection)
--     → session_handler.update_session()    (state persist)
--   nginx.conf sets $backend_upstream from routing_decision.upstream
--
-- BOTNET / SLOWDOWN:
--   The apply_routing_decision() function injects a Tarpit-style delay for
--   sessions flagged as automated scanners.  This wastes attacker resources
--   and extends the observation window without raising suspicion.
--
-- DEPENDENCIES:
--   pool_router    – pool assignment and health-aware selection
--   session_handler – session CRUD on Redis
--   _G.config      – global config (init.lua)
--   _G.utils       – utility helpers (init.lua)

local cjson = require "cjson"
local router_rules = require "router_rules"

local _M = {}

-- ---------------------------------------------------------------------------
-- Internal helper: route to honeypot and assign a pool instance for the IP.
--
-- Centralises the pool-assignment logic that was previously duplicated across
-- every honeypot routing branch.  Sets:
--   routing_decision.target   = "honeypot"
--   routing_decision.upstream = "honeypot_backend_N"  (where N is the pool number)
--   routing_decision.update_session = true
--   routing_decision.session_data   = supplied extra_session_data merged with
--                                     { honeypot_bound, route_preference,
--                                       honeypot_pool, honeypot_reason }
--
-- Also refreshes the Redis TTL for the IP's pool assignment so long-running
-- attack sessions are not evicted mid-way.
-- ---------------------------------------------------------------------------
local function assign_honeypot_pool(routing_decision, extra_session_data, remote_ip)
    -- Lazy-require to avoid circular dependency issues at module load time.
    local pool_router = require "pool_router"

    -- Determine which pool this IP belongs to (round-robin for new IPs,
    -- sticky for returning ones).  Falls back to pool 1 on Redis errors.
    local pool_num = pool_router.get_or_assign_pool(remote_ip)
    local upstream = pool_router.get_upstream_for_pool(pool_num)

    routing_decision.target   = "honeypot"
    routing_decision.upstream = upstream
    routing_decision.update_session = true

    -- Merge caller-supplied session fields with the pool assignment metadata
    -- on top of whatever routing_decision.session_data already holds --
    -- for a brand-new visitor whose very first request already trips this
    -- stage (the common case for CVE/exploit probes), that's the full
    -- record decide_route's session-bootstrap step just built via
    -- session_handler.create_session() (user_agent, ip_address, metadata,
    -- ...). Overwriting it outright here used to silently drop those fields
    -- before sophistication_analyzer ever saw them, blinding its
    -- User-Agent-based scripted-tool signal for exactly the sessions it's
    -- meant to classify.
    local sd = routing_decision.session_data or {}
    for k, v in pairs(extra_session_data or {}) do
        sd[k] = v
    end
    sd.honeypot_bound    = true
    sd.route_preference  = "honeypot"
    sd.honeypot_pool     = pool_num
    routing_decision.session_data = sd

    -- Keep the assignment alive in Redis while the attacker is still active.
    pool_router.refresh_assignment_ttl(remote_ip)

    -- Report to AbuseIPDB, but only for deterministic, high-confidence
    -- reasons (CVE match, vulnerable-plugin access, brute-force, confirmed
    -- automation, suspicious upload). abuseipdb_client.is_reportable_reason()
    -- filters out soft heuristic reasons (e.g. accumulated score) to keep
    -- report quality high. Fire-and-forget; never blocks routing.
    local abuseipdb_ok, abuseipdb_client = pcall(require, "abuseipdb_client")
    if abuseipdb_ok then
        abuseipdb_client.report_ip_async(remote_ip, sd.honeypot_reason, sd)
    end

    ngx.log(ngx.WARN,
        "[POOL] IP ", remote_ip,
        " assigned to honeypot pool ", pool_num,
        " (upstream=", upstream, ")",
        " reason=", sd.honeypot_reason or "unknown")

    return pool_num
end

-- ---------------------------------------------------------------------------
-- decide_route(session_data, threat_result, remote_ip)
--
-- Core routing function called from nginx.conf access_by_lua_block on every
-- non-static request.  Returns a routing_decision table which the caller uses
-- to set ngx.var.backend_upstream and update the session.
--
-- @param session_data  table|nil  Existing session (nil for brand-new visitors).
-- @param threat_result table      Output from threat_analyzer.analyze_request().
-- @param remote_ip     string     Client IP address (ngx.var.remote_addr).
-- @return              table      routing_decision:
--                                   .target          "production"|"honeypot"
--                                   .upstream        upstream block name
--                                   .update_session  boolean
--                                   .session_data    fields to merge into session
-- ---------------------------------------------------------------------------
function _M.decide_route(session_data, threat_result, remote_ip, session_id)
    local routing_decision = {
        target = "production",
        upstream = "production_backend",
        update_session = false,
        session_data = {}
    }
    
    -- Stage 1: Static asset fast-path.
    -- CSS, JS, images, and fonts carry no attack surface.  Bypassing all
    -- further checks keeps the per-request overhead near zero for the vast
    -- majority of page-load requests, which are dominated by static assets.
    if _M.is_static_asset(ngx.var.request_uri) then
        routing_decision.target = "production"
        routing_decision.upstream = "production_backend"
        ngx.log(ngx.INFO, "[ROUTING] Static asset detected: ", ngx.var.request_uri, " -> PRODUCTION")
        return routing_decision
    end
    
    -- Session bootstrap: create a fresh session record for first-time visitors.
    -- Subsequent requests reuse the existing session (looked up by cookie in
    -- nginx.conf before decide_route is called).  Session data persists in Redis
    -- with a 1-hour idle TTL and is also cached in the worker-local shared dict
    -- for five minutes to avoid Redis round-trips on every request.
    if not session_data then
        local session_handler = require "session_handler"
        -- Use provided session_id or generate new one
        session_data = session_handler.create_session(remote_ip, ngx.var.http_user_agent, "production", session_id)
        routing_decision.update_session = true
        routing_decision.session_data = session_data
        ngx.log(ngx.INFO, "[ROUTING] New session created for IP: ", remote_ip, " | Session ID: ", session_data.id)
    end
    
    -- Stage 2: Sticky honeypot routing.
    -- Once a session is marked honeypot_bound (by any routing stage on a prior
    -- request), all subsequent requests from the same session are locked to the
    -- same honeypot pool instance.  This preserves the attacker's illusion of
    -- a single persistent target: WordPress state changes they made in earlier
    -- requests (cookies, wp-login tokens, uploaded files) are still visible.
    if session_data.honeypot_bound then
        -- Re-evaluate: if current threat score is low, allow production access
        if threat_result.score < 30 then
            routing_decision.target = "production"
            routing_decision.upstream = "production_backend"
            ngx.log(ngx.INFO, "[ROUTING] Session bound but low threat - allowing production | Score: ", threat_result.score)
            return routing_decision
        end
        -- Re-use the pool number that was stored when the session was first
        -- flagged.  If the session pre-dates pooling (no honeypot_pool field)
        -- fall back to a fresh pool assignment so the IP is properly tracked.
        local pool_router = require "pool_router"
        local pool_num = session_data.honeypot_pool
        if not pool_num then
            pool_num = pool_router.get_or_assign_pool(remote_ip)
            -- Persist pool number back into session on next update_session call.
            routing_decision.update_session = true
            routing_decision.session_data   = { honeypot_pool = pool_num }
        end
        -- Always refresh the TTL so an active attack session is never evicted.
        pool_router.refresh_assignment_ttl(remote_ip)

        routing_decision.target   = "honeypot"
        routing_decision.upstream = pool_router.get_upstream_for_pool(pool_num)
        ngx.log(ngx.WARN, "[ROUTING] ⚠️  Session bound to HONEYPOT | Session: ", session_data.id or "unknown",
                " | Pool: ", pool_num,
                " | IP: ", remote_ip, " | Reason: ", session_data.honeypot_reason or "unknown",
                " | URI: ", ngx.var.request_uri)
        return routing_decision
    end
    
    -- Stage 3: Threat-score threshold (WSTG-INPV catch-all).
    -- The threat_analyzer accumulates scores across URI patterns, headers,
    -- CVE matches, and IP reputation.  If the total meets honeypot_threshold
    -- (default 80, set in init.lua), the request is diverted regardless of
    -- which specific patterns triggered the score.
    if threat_result.score >= _G.config.threat.honeypot_threshold then
        assign_honeypot_pool(routing_decision, {
            threat_score    = threat_result.score,
            honeypot_reason = "high_threat_score",
        }, remote_ip)

        ngx.log(ngx.WARN, "[ROUTING] 🚨 HIGH THREAT SCORE -> HONEYPOT | Score: ", threat_result.score,
                "/", _G.config.threat.honeypot_threshold, " | IP: ", remote_ip,
                " | URI: ", ngx.var.request_uri, " | Patterns: ", table.concat(threat_result.patterns_matched or {}, ", "))

        _G.utils.log_security_event("routing_to_honeypot", {
            reason    = "high_threat_score",
            score     = threat_result.score,
            ip        = remote_ip,
            pool      = routing_decision.session_data.honeypot_pool,
            session_id = session_data.id
        })

        return routing_decision
    end
    
    -- Stage 4: CVE-specific exploit patterns (immediate diversion).
    -- CVE matches in threat_analyzer.analyze_cve_patterns() score +40 each.
    -- Even a single CVE match on a low-baseline request can cross the 80-point
    -- threshold; this explicit stage ensures diversion even for requests where
    -- the overall score is below threshold but a CVE was still matched.
    -- Covered patterns are defined in _G.config.vulnerability.cve_patterns (init.lua).
    if threat_result.cve_matched and #threat_result.cve_matched > 0 then
        assign_honeypot_pool(routing_decision, {
            threat_score    = threat_result.score,
            honeypot_reason = "cve_pattern_match",
            matched_cves    = threat_result.cve_matched,
        }, remote_ip)

        ngx.log(ngx.WARN, "[ROUTING] 🎯 CVE EXPLOIT DETECTED -> HONEYPOT | CVEs: ",
                table.concat(threat_result.cve_matched, ", "), " | Score: ", threat_result.score,
                " | IP: ", remote_ip, " | URI: ", ngx.var.request_uri)

        _G.utils.log_security_event("routing_to_honeypot", {
            reason    = "cve_pattern_match",
            cves      = threat_result.cve_matched,
            ip        = remote_ip,
            pool      = routing_decision.session_data.honeypot_pool,
            session_id = session_data.id
        })

        return routing_decision
    end
    
    -- Stage 5: Vulnerable plugin endpoint access.
    -- Direct access to PHP files inside a known-vulnerable plugin directory
    -- (e.g. /wp-content/plugins/woocommerce-payments/*.php) is a strong signal
    -- even before any payload is sent.  Static assets (CSS/JS) inside these
    -- directories are excluded by is_vulnerable_plugin_access() to avoid
    -- false-positives on page loads that reference plugin stylesheets.
    local uri = ngx.var.request_uri or ""
    if _M.is_vulnerable_plugin_access(uri) then
        assign_honeypot_pool(routing_decision, {
            threat_score    = math.max(threat_result.score, 60),
            honeypot_reason = "vulnerable_plugin_access",
        }, remote_ip)

        ngx.log(ngx.WARN, "[ROUTING] 🔌 VULNERABLE PLUGIN ACCESS -> HONEYPOT | Score: ",
                math.max(threat_result.score, 60), " | IP: ", remote_ip, " | URI: ", uri)

        _G.utils.log_security_event("routing_to_honeypot", {
            reason    = "vulnerable_plugin_access",
            uri       = uri,
            ip        = remote_ip,
            pool      = routing_decision.session_data.honeypot_pool,
            session_id = session_data.id
        })

        return routing_decision
    end
    
    -- Stage 6: IP reputation gate.
    -- threat_intel shared dict is seeded at init time and updated every 30 s
    -- by the Suricata log parser in init_worker.lua.  IPs that appear in
    -- Suricata eve.json alerts accumulate a severity-graded score there
    -- (suricata_rules.severity_to_score); any IP scoring > 50 is diverted
    -- immediately regardless of the current request's content.
    if threat_result.ip_reputation > 50 then
        -- honeypot_reason stays one of the fixed category strings every
        -- other stage uses (matches abuseipdb_rules.REASON_CATEGORIES'
        -- whitelist, which does exact-string lookup) -- NOT the rich,
        -- per-signature text in threat_result.ip_reputation_reason (that
        -- already reaches Kibana via the WARN log line a few lines below
        -- and via threat_ips[ip].reason in Redis; it would never match the
        -- whitelist if used here directly). Distinguishing "flagged by
        -- Suricata" from "flagged by the AbuseIPDB blacklist feed" (both
        -- populate the same threat_ips structure) makes Suricata-confirmed
        -- attackers reportable for the first time -- "bad_ip_reputation"
        -- was never in the whitelist regardless of source.
        local reputation_reason = "bad_ip_reputation"
        if threat_result.ip_reputation_reason
            and threat_result.ip_reputation_reason:find("^suricata: ") then
            reputation_reason = "suricata_confirmed_alert"
        end

        assign_honeypot_pool(routing_decision, {
            threat_score    = threat_result.score,
            honeypot_reason = reputation_reason,
        }, remote_ip)

        ngx.log(ngx.WARN, "[ROUTING] 🚫 BAD IP REPUTATION -> HONEYPOT | IP Rep Score: ",
                threat_result.ip_reputation, " | Threat Score: ", threat_result.score,
                " | Reason: ", threat_result.ip_reputation_reason or "unknown",
                " | IP: ", remote_ip, " | URI: ", uri)

        return routing_decision
    end
    
    -- Stage 7: Repeated admin-area probing (WSTG-ATHN-04).
    -- A single admin-panel GET could be a legitimate admin; three consecutive
    -- attempts from a non-whitelisted IP indicate credential stuffing or
    -- reconnaissance.  The gradual escalation model (warn → honeypot) avoids
    -- false-positives on legitimate admins who mistype their password.
    if _M.is_admin_access(uri) and not _G.utils.is_ip_whitelisted(remote_ip) then
        -- Gradual escalation: first warning, then honeypot
        local admin_attempts = session_data.admin_attempts or 0
        if admin_attempts >= 2 then
            assign_honeypot_pool(routing_decision, {
                threat_score    = math.max(threat_result.score, 40),
                honeypot_reason = "multiple_admin_attempts",
            }, remote_ip)
            ngx.log(ngx.WARN, "[ROUTING] 🔐 MULTIPLE ADMIN ATTEMPTS -> HONEYPOT | Attempts: ",
                    admin_attempts + 1, " | Score: ", math.max(threat_result.score, 40),
                    " | IP: ", remote_ip, " | URI: ", uri)
        else
            -- Increment admin attempts but stay on production
            routing_decision.update_session = true
            routing_decision.session_data = {
                admin_attempts = admin_attempts + 1,
                threat_score = math.max(session_data.threat_score or 0, threat_result.score)
            }
            ngx.log(ngx.INFO, "[ROUTING] ⚠️  Admin access attempt #", admin_attempts + 1, 
                    " -> PRODUCTION (warning) | Score: ", threat_result.score, 
                    " | IP: ", remote_ip, " | URI: ", uri)
        end
        
        return routing_decision
    end
    
    -- Stage 8: Cumulative suspicious-activity threshold.
    -- Individual low-score signals (e.g. missing Referer, URL encoding, admin
    -- probe) are not individually conclusive.  When five such events accumulate
    -- within the same session window the pattern becomes statistically reliable
    -- enough to divert.  Threshold raised from 3 to 5 after tuning to reduce
    -- false-positive rate on aggressive but legitimate API clients.
    if session_data.suspicious_activities and #session_data.suspicious_activities >= 5 then
        assign_honeypot_pool(routing_decision, {
            threat_score    = threat_result.score,
            honeypot_reason = "accumulated_suspicious_activities",
        }, remote_ip)

        ngx.log(ngx.WARN, "[ROUTING] 📊 ACCUMULATED SUSPICIOUS ACTIVITIES -> HONEYPOT | Count: ",
                #session_data.suspicious_activities, " | Score: ", threat_result.score,
                " | IP: ", remote_ip, " | URI: ", uri)

        return routing_decision
    end
    
    -- Stage 9: Rapid-automation / botnet detection (WSTG-INFO-02).
    -- is_rapid_automation() checks request-per-second rate stored in the
    -- session and the detect_automation() result from threat_analyzer.
    -- Threshold is 20 req/s to avoid penalising legitimate single-page apps
    -- that prefetch multiple API endpoints on load.
    -- NOTE: Only route to honeypot if automation is detected AND the threat
    -- score is already elevated (>= 40). This prevents false positives on
    -- legitimate CLI tools like curl accessing the homepage.
    if _M.is_rapid_automation(session_data, threat_result) and threat_result.score >= 40 then
        assign_honeypot_pool(routing_decision, {
            threat_score    = math.max(threat_result.score, 45),
            honeypot_reason = "rapid_automation_detected",
        }, remote_ip)

        ngx.log(ngx.WARN, "[ROUTING] 🤖 RAPID AUTOMATION DETECTED -> HONEYPOT | Score: ",
                math.max(threat_result.score, 45), " | IP: ", remote_ip,
                " | Request Count: ", session_data.request_count or 0, " | URI: ", uri)

        return routing_decision
    end
    
    -- Stage 10: Suspicious file upload detection (WSTG-INPV-10).
    -- POST requests to upload endpoints carrying executable file extensions
    -- (php, jsp, asp, sh, bat) or matching known-vulnerable upload action
    -- parameters (dnd_codedropz_upload, mwb_wgm_preview_mail, etc.) are
    -- diverted before the file reaches the production filesystem.
    if _M.is_suspicious_upload() then
        assign_honeypot_pool(routing_decision, {
            threat_score    = math.max(threat_result.score, 50),
            honeypot_reason = "suspicious_file_upload",
        }, remote_ip)

        ngx.log(ngx.WARN, "[ROUTING] 📤 SUSPICIOUS FILE UPLOAD -> HONEYPOT | Score: ",
                math.max(threat_result.score, 50), " | IP: ", remote_ip, " | URI: ", uri)

        return routing_decision
    end
    
    -- Probabilistic routing for moderate threat scores (Commented out - change math.random for something else or remove)
    -- if threat_result.score >= 25 and threat_result.score < _G.config.threat.honeypot_threshold then
    --     local probability = (threat_result.score - 25) / (_G.config.threat.honeypot_threshold - 25)
    --     if math.random() < probability then
    --         routing_decision.target = "honeypot"
    --         routing_decision.upstream = "honeypot_backend"
    --         routing_decision.update_session = true
    --         routing_decision.session_data = {
    --             honeypot_bound = true,
    --             route_preference = "honeypot",
    --             threat_score = threat_result.score,
    --             honeypot_reason = "probabilistic_routing"
    --         }
    --         
    --         return routing_decision
    --     end
    -- end
    -- Removed probabilistic routing to prevent false positives on legitimate traffic
    
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
            
            ngx.log(ngx.INFO, "[ROUTING] ⚠️  Suspicious activity logged but staying on PRODUCTION | Score: ", 
                    threat_result.score, "/", _G.config.threat.honeypot_threshold, 
                    " | Suspicious count: ", #session_data.suspicious_activities + 1, "/5", 
                    " | IP: ", remote_ip, " | URI: ", uri)
        end
    end
    
    -- Default to production - log clean requests
    if threat_result.score == 0 then
        ngx.log(ngx.INFO, "[ROUTING] ✅ Clean request -> PRODUCTION | Score: 0 | IP: ", 
                remote_ip, " | URI: ", uri)
    elseif threat_result.score > 0 and threat_result.score < _G.config.threat.honeypot_threshold then
        ngx.log(ngx.INFO, "[ROUTING] ⚡ Low threat -> PRODUCTION | Score: ", threat_result.score, 
                "/", _G.config.threat.honeypot_threshold, " | IP: ", remote_ip, " | URI: ", uri)
    end
    
    return routing_decision
end

-- Thin delegating wrappers over router_rules.lua's pure predicates -- see
-- that file's header comment for why decide_route() itself stays here as
-- the adapter rather than being made pure too.

-- Check if request is for static assets (CSS, JS, images, fonts)
function _M.is_static_asset(uri)
    local is_static = router_rules.is_static_asset(uri, _G.config.threat.static_asset_patterns)
    if is_static then
        ngx.log(ngx.INFO, "Static asset matched: ", uri)
    end
    return is_static
end

-- Check if the request is accessing vulnerable plugins
function _M.is_vulnerable_plugin_access(uri)
    return router_rules.is_vulnerable_plugin_access(
        uri, _G.config.vulnerability.plugins, _G.config.threat.static_asset_patterns)
end

-- Check if the request is accessing admin areas
function _M.is_admin_access(uri)
    return router_rules.is_admin_access(uri)
end

-- Check for rapid automation patterns
function _M.is_rapid_automation(session_data, threat_result)
    return router_rules.is_rapid_automation(session_data, threat_result, ngx.time())
end

-- Check for suspicious file uploads
function _M.is_suspicious_upload()
    return router_rules.is_suspicious_upload(
        ngx.var.request_method, ngx.var.request_uri, ngx.var.content_type, ngx.var.args)
end

-- Apply routing decision and set appropriate variables
function _M.apply_routing_decision(decision)
    ngx.var.route_decision = decision.target
    ngx.var.backend_upstream = decision.upstream

    -- Pass routing decision to WordPress for SQL proxy routing
    ngx.req.set_header("X-DB-Target", decision.target)
    ngx.log(ngx.INFO, "[ROUTING] Setting X-DB-Target header: ", decision.target)

    -- Set X-Route-Target header for testing/validation, gated behind the
    -- same internal-test shared secret as nginx.conf's header_filter
    -- blocks (see BLIND_PENTEST_PROTOCOL.md §8.2) -- this function is
    -- currently unreferenced (dead code) but kept consistent with the live
    -- gating so it isn't a landmine if it's ever wired back in.
    local secret = _G.config.internal_test_secret
    if secret and secret ~= "" and ngx.var.http_x_internal_test_auth == secret then
        ngx.header["X-Route-Target"] = decision.target
    end

    if decision.target == "honeypot" then
        ngx.var.suspicious_activity = "true"

        -- Add custom headers for honeypot identification.
        -- X-Honeypot-Pool is intentionally NOT exposed to the client (set on the
        -- internal request object only); it is used by backend WordPress for logging.
        ngx.header["X-Honeypot-Route"] = "true"
        ngx.header["X-Route-Reason"]   = decision.session_data.honeypot_reason or "unknown"
        -- Pass pool number to backend for SQL-level tracking (stripped by nginx
        -- before forwarding to the upstream via proxy_pass).
        ngx.req.set_header("X-Honeypot-Pool", tostring(decision.session_data.honeypot_pool or "1"))
    end

    return decision
end

-- Check for geographic anomalies (if GeoIP data is available)
function _M.check_geographic_anomalies(session_data, current_ip)
    return router_rules.check_geographic_anomalies(session_data, current_ip)
end

-- Behavioral analysis for routing decisions
function _M.analyze_behavior_patterns(session_data)
    return router_rules.analyze_behavior_patterns(session_data, ngx.time(), ngx.var.request_uri)
end

-- ---------------------------------------------------------------------------
-- apply_botnet_slowdown(session_data, threat_result)
--
-- Implements a Tarpit-style response delay for sessions that are confirmed as
-- automated scanners or botnets.  The delay wastes attacker compute/time and
-- extends the observation window without raising suspicion (real servers
-- occasionally respond slowly under load).
--
-- STRATEGY:
--   - Confirmed scanner UA  → 1.5 s delay  (tool detected, polite but noticeable)
--   - Rapid automation      → 2.0 s delay  (burst detected, stronger slowdown)
--   - Honeypot-bound + high score → 3.0 s delay (actively being exploited)
--   - All other honeypot traffic  → 0.5 s delay (mild friction)
--
-- The delay is applied via ngx.sleep() which suspends the coroutine without
-- blocking the Nginx event loop, so other workers and connections continue
-- serving requests normally.  The function is a no-op for production-bound
-- requests or whitelisted IPs.
--
-- BOTNET IDENTIFICATION signals (item 9 in general checklist):
--   - session_data.honeypot_bound = true (any prior diversion trigger)
--   - threat_result.details containing "automation_detected"
--   - threat_result.score ≥ honeypot_threshold on a fresh session
--
-- @param session_data  table   Current session (may be nil for new visitors).
-- @param threat_result table   Output from threat_analyzer.analyze_request().
-- ---------------------------------------------------------------------------
function _M.apply_botnet_slowdown(session_data, threat_result)
    -- Never delay whitelisted IPs (admin, monitoring, trusted partners).
    if _G.utils.is_ip_whitelisted(ngx.var.remote_addr) then
        return
    end

    local delay = 0

    -- Determine delay tier based on confirmed signals.
    local is_automation = false
    if threat_result and threat_result.details then
        for _, detail in ipairs(threat_result.details) do
            if string.find(detail, "automation_detected") then
                is_automation = true
                break
            end
        end
    end

    if session_data and session_data.honeypot_bound then
        -- Already confirmed hostile session.
        if threat_result and threat_result.score >= 90 then
            delay = 3.0  -- Actively exploiting; maximum slowdown.
        else
            delay = 0.5  -- General honeypot traffic; mild friction.
        end
    elseif is_automation then
        if session_data and session_data.request_count and session_data.created_at then
            local age = ngx.time() - session_data.created_at
            local rps = age > 0 and (session_data.request_count / age) or 0
            if rps > 20 then
                delay = 2.0  -- Burst-rate scanner.
            else
                delay = 1.5  -- Confirmed scanner UA but moderate rate.
            end
        else
            delay = 1.5
        end
    elseif threat_result and threat_result.score >= _G.config.threat.honeypot_threshold then
        -- High-score fresh request that will be diverted on this pass.
        delay = 1.0
    end

    if delay > 0 then
        ngx.log(ngx.INFO,
            "[SLOWDOWN] Applying tarpit delay of ", delay, "s | IP: ", ngx.var.remote_addr,
            " | score=", (threat_result and threat_result.score or "n/a"),
            " | automation=", tostring(is_automation),
            " | honeypot_bound=", tostring(session_data and session_data.honeypot_bound or false))
        ngx.sleep(delay)
    end
end

return _M