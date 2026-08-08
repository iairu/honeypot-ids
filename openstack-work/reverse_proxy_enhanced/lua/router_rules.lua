-- router_rules.lua - Pure routing predicates used by router.lua
--
-- PURPOSE:
--   Holds the standalone "is this request/session suspicious in way X"
--   predicates that router.lua's decide_route() consults. Factored out with
--   the same intent as threat_rules.lua: no ngx.* dependency, no reliance on
--   _G.config/_G.utils, plain-`lua`-interpreter testable (see
--   tests/test_router_rules.lua).
--
--   decide_route() itself is NOT moved here. Its staged pipeline deeply
--   interleaves session mutation with Redis I/O (pool_router, AbuseIPDB
--   report-back via assign_honeypot_pool) at almost every stage -- forcing
--   that into a pure core would mean either faking a large I/O surface in
--   tests or fundamentally restructuring the routing algorithm, both of
--   which risk introducing a subtle bug in the single most safety-critical
--   function in this codebase (get honeypot/production separation wrong and
--   the entire deception layer is compromised). router.lua stays the
--   adapter for that function; only the self-contained predicate checks
--   below move here.
--
-- NOTE ON is_static_asset: this used to have two independently-maintained
-- copies (router.lua and threat_analyzer.lua) that disagreed on whether to
-- strip the query string before matching -- router.lua's stripped it,
-- threat_analyzer.lua's (now threat_rules.lua's) didn't, so a request like
-- "style.css?v=123" was classified as static by one and not the other.
-- This module's version (query-string-stripping, the more correct
-- behaviour) is now the single implementation router.lua uses; threat_rules
-- still has its own copy since the two modules must stay independently
-- requireable, but see threat_rules.lua's is_static_asset docstring, which
-- now cross-references this one.

local pattern_utils = require "lua_pattern_utils"

local _M = {}

-- escape_pattern: see lua_pattern_utils.lua for the implementation and the
-- is_vulnerable_plugin_access() hyphen-escaping bug this fixes. Re-exported
-- here for backward compatibility with anything already calling
-- router_rules.escape_pattern() directly.
local escape_pattern = pattern_utils.escape_pattern
_M.escape_pattern = escape_pattern

-- Re-exported for the same reason: decide_route()'s install.php
-- not-yet-installed fast path needs the exact same matcher
-- threat_analyzer.lua uses, so the two can never quietly disagree (see
-- lua_pattern_utils.lua's own comment on this function, and this file's
-- NOTE ON is_static_asset above for the exact bug class that already
-- happened once from independently-maintained copies).
_M.is_install_wizard_uri = pattern_utils.is_install_wizard_uri

-- ---------------------------------------------------------------------------
-- is_static_asset(uri, static_asset_patterns)
--
-- @param uri                     string|nil
-- @param static_asset_patterns   table|nil  List of Lua patterns (from
--                                            _G.config.threat.static_asset_patterns).
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.is_static_asset(uri, static_asset_patterns)
    if not uri then
        return false
    end

    local uri_lower = string.lower(uri)

    -- Strip query string for pattern matching (e.g. "style.css?v=123" should
    -- still match "%.css$").
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
-- is_vulnerable_plugin_access(uri, vulnerable_plugins, static_asset_patterns)
--
-- @param uri                     string|nil
-- @param vulnerable_plugins      table  List of plugin slugs (from
--                                       _G.config.vulnerability.plugins).
-- @param static_asset_patterns   table|nil
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.is_vulnerable_plugin_access(uri, vulnerable_plugins, static_asset_patterns)
    if not uri then
        return false
    end

    -- Don't flag static assets from plugins as vulnerable.
    if _M.is_static_asset(uri, static_asset_patterns) then
        return false
    end

    local uri_lower = string.lower(uri)

    for _, plugin in ipairs(vulnerable_plugins or {}) do
        if string.find(uri_lower, "/wp%-content/plugins/" .. escape_pattern(plugin) .. "/") then
            return true
        end
    end

    return false
end

-- ---------------------------------------------------------------------------
-- is_admin_access(uri)
--
-- Detects requests to the actual WordPress/generic admin PANEL -- pages
-- that only make sense for an authenticated admin or someone probing for
-- one (WSTG-ATHN-04's basis for router.lua's Stage 7 repeated-probing
-- escalation, and session_rules.lua's "direct_admin_access" first-request
-- signal).
--
-- Deliberately excludes admin-ajax.php even though it lives under
-- /wp-admin/: it's WordPress's public, unauthenticated AJAX gateway, hit
-- automatically by ordinary frontend JS on essentially every WooCommerce
-- page load (cart fragments, stock/price sync, "recently viewed", ...) --
-- not a signal that someone is trying to reach the admin panel. Confirmed
-- live this was escalating an entirely normal shopper straight to the
-- honeypot after their third product-page view, since each page load
-- fires its own admin-ajax.php call and Stage 7 escalates at the third
-- occurrence within a session. admin-ajax.php gets its own dedicated,
-- appropriately-scoped analysis elsewhere (threat_analyzer.lua's Stage 6b,
-- upload_handler.lua, the CVE action-name checks in Stage 3) -- it doesn't
-- need (and must not get) blanket treatment as "admin area access" here.
--
-- @param uri  string|nil
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.is_admin_access(uri)
    if not uri then
        return false
    end

    local uri_lower = string.lower(uri)

    if string.find(uri_lower, "/wp%-admin/admin%-ajax%.php") then
        return false
    end

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

-- ---------------------------------------------------------------------------
-- is_rapid_automation(session_data, threat_result, current_time)
--
-- @param session_data  table|nil
-- @param threat_result table|nil
-- @param current_time  number  e.g. ngx.time()
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.is_rapid_automation(session_data, threat_result, current_time)
    if not session_data then
        return false
    end

    -- Check request frequency.
    if session_data.created_at and session_data.request_count then
        local session_duration = current_time - session_data.created_at
        if session_duration > 0 then
            local requests_per_second = session_data.request_count / session_duration
            if requests_per_second > 20 then
                return true
            end
        end
    end

    -- Check for automation tool signatures.
    if threat_result and threat_result.details then
        for _, detail in ipairs(threat_result.details) do
            if string.find(detail, "automation_detected") then
                return true
            end
        end
    end

    -- Check timing patterns.
    if session_data.last_activity then
        local time_diff = current_time - session_data.last_activity
        if time_diff < 1 and session_data.request_count and session_data.request_count > 50 then
            return true
        end
    end

    return false
end

-- ---------------------------------------------------------------------------
-- decayed_score(session_data, current_time, half_life_seconds)
--
-- A honeypot-bound session's stored peak threat_score (session_data.
-- threat_score, set via math.max() elsewhere in router.lua so it only ever
-- ratchets UP on a new suspicious signal), exponentially decayed based on
-- how long it's been since the LAST suspicious signal
-- (session_data.last_threat_time, only touched when a signal actually
-- fires -- a genuinely clean request never moves it). Used by router.lua's
-- Stage 2 to decide whether a previously-flagged session has earned its
-- way back to production: a single clean request barely moves this (the
-- elapsed time since last_threat_time is ~0), but sustained clean behavior
-- over multiple half-lives brings it down.
--
-- Deliberately does NOT get called on every request to progressively
-- shrink the STORED value -- that would compound incorrectly across
-- repeated evaluations. The stored peak stays fixed; only this computed,
-- never-persisted view of it decays.
--
-- @param session_data      table|nil
-- @param current_time      number  e.g. ngx.time()
-- @param half_life_seconds number  e.g. _G.config.threat.score_decay_half_life_seconds
-- @return number  the decayed score (never negative, never above the stored peak)
-- ---------------------------------------------------------------------------
function _M.decayed_score(session_data, current_time, half_life_seconds)
    if not session_data then
        return 0
    end

    local peak = session_data.threat_score or 0
    if peak <= 0 then
        return 0
    end

    local anchor = session_data.last_threat_time or session_data.updated_at or session_data.created_at
    if not anchor or not half_life_seconds or half_life_seconds <= 0 then
        return peak
    end

    local elapsed = current_time - anchor
    if elapsed <= 0 then
        return peak
    end

    local half_lives_elapsed = elapsed / half_life_seconds
    return peak * (0.5 ^ half_lives_elapsed)
end

-- ---------------------------------------------------------------------------
-- is_suspicious_upload(method, uri, content_type, args)
--
-- @param method        string|nil  e.g. ngx.var.request_method
-- @param uri           string|nil  e.g. ngx.var.request_uri
-- @param content_type  string|nil  e.g. ngx.var.content_type
-- @param args          string|nil  e.g. ngx.var.args
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.is_suspicious_upload(method, uri, content_type, args)
    if method ~= "POST" then
        return false
    end

    uri = uri or ""
    content_type = content_type or ""
    args = args or ""

    if string.find(string.lower(uri), "upload") or
       string.find(string.lower(content_type), "multipart/form%-data") then

        local suspicious_upload_patterns = {
            "%.php", "%.jsp", "%.asp", "%.exe", "%.sh", "%.bat", "%.cmd"
        }

        for _, pattern in ipairs(suspicious_upload_patterns) do
            if string.find(string.lower(args), pattern) then
                return true
            end
        end

        if string.find(args, "dnd_codedropz_upload") or
           string.find(args, "mwb_wgm_preview_mail") or
           string.find(args, "pc_added_uploaded_image") then
            return true
        end
    end

    return false
end

-- ---------------------------------------------------------------------------
-- check_geographic_anomalies(session_data, current_ip)
--
-- @param session_data  table|nil
-- @param current_ip    string
-- @return table  { anomaly_detected, anomaly_type, score_increase }
-- ---------------------------------------------------------------------------
function _M.check_geographic_anomalies(session_data, current_ip)
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

-- ---------------------------------------------------------------------------
-- analyze_behavior_patterns(session_data, current_time, request_uri)
--
-- @param session_data  table|nil
-- @param current_time  number  e.g. ngx.time()
-- @param request_uri   string|nil  e.g. ngx.var.request_uri
-- @return table  { score, patterns[] }
-- ---------------------------------------------------------------------------
function _M.analyze_behavior_patterns(session_data, current_time, request_uri)
    if not session_data then
        return { score = 0, patterns = {} }
    end

    local behavior_score = 0
    local patterns = {}

    if session_data.request_count then
        if session_data.created_at then
            local session_age = current_time - session_data.created_at
            if session_age > 0 and session_data.request_count / session_age > 3 then
                behavior_score = behavior_score + 20
                table.insert(patterns, "high_request_frequency")
            end
        end

        if session_data.request_count == 1 and _M.is_admin_access(request_uri) then
            behavior_score = behavior_score + 15
            table.insert(patterns, "direct_admin_access")
        end
    end

    if session_data.suspicious_activities then
        local recent_activities = 0

        for _, activity in ipairs(session_data.suspicious_activities) do
            if current_time - activity.timestamp < 300 then
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
