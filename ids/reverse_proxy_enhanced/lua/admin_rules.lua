-- admin_rules.lua - Pure admin-access decision logic used by admin_handler.lua
--
-- Same split rationale as threat_rules.lua/router_rules.lua: no ngx.*
-- dependency, no reliance on _G.config/_G.utils, plain-`lua`-interpreter
-- testable (see tests/test_admin_rules.lua). admin_handler.lua is the
-- adapter -- it does all the Redis/shared-dict I/O, request-body reading,
-- and ngx.log calls, and passes this module already-fetched values.
--
-- architecture.canvas flagged admin_handler.lua as "I/O-dominated... lower
-- value than the four [pure/adapter splits] already done" -- true relative
-- to those, but there turned out to be five genuinely pure decision cores
-- once the ngx.req.*()/ngx.var.* reads were turned into parameters:
-- login-endpoint matching, admin-pattern scoring, suspicious-ajax-action
-- matching, brute-force scoring, and credential-stuffing scoring.

local _M = {}

-- ---------------------------------------------------------------------------
-- is_login_attempt(uri, method)
--
-- @param uri     string|nil
-- @param method  string|nil  e.g. ngx.var.request_method
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.is_login_attempt(uri, method)
    if method ~= "POST" then
        return false
    end

    -- Only actual login endpoints, not admin-ajax which handles general AJAX.
    local login_endpoints = { "wp%-login%.php", "xmlrpc%.php" }

    local uri_lower = string.lower(uri or "")
    for _, endpoint in ipairs(login_endpoints) do
        if string.find(uri_lower, endpoint) then
            return true
        end
    end

    return false
end

-- ---------------------------------------------------------------------------
-- analyze_admin_patterns(uri, user_agent, query_string, method)
--
-- Scores a request URI/UA/query-string for suspicious admin-area access
-- patterns: direct file access bypassing login, user/plugin enumeration,
-- automated-tool signatures, and suspicious action parameters.
--
-- @param uri            string|nil
-- @param user_agent     string|nil
-- @param query_string   string|nil  e.g. ngx.var.query_string
-- @param method          string|nil  (unused today, kept for API symmetry
--                                     with the adapter's call site and any
--                                     future method-specific rule)
-- @return table  { suspicious: boolean, reason: string, score: number }
-- ---------------------------------------------------------------------------
function _M.analyze_admin_patterns(uri, user_agent, query_string, method)
    local analysis = { suspicious = false, reason = "clean", score = 0 }

    local uri_lower = string.lower(uri or "")
    local args_lower = string.lower(query_string or "")
    local ua_lower = string.lower(user_agent or "")

    -- Direct admin file access (bypassing login). admin-ajax.php is handled
    -- separately (is_suspicious_ajax_action below) and not flagged here.
    local direct_access_patterns = {
        "/wp%-admin/admin%-post%.php",
        "/wp%-admin/users%.php",
        "/wp%-admin/user%-new%.php",
        "/wp%-admin/options%.php",
        "/wp%-admin/install%.php",
        "/wp%-admin/setup%-config%.php"
    }
    for _, pattern in ipairs(direct_access_patterns) do
        if string.find(uri_lower, pattern) then
            analysis.suspicious = true
            analysis.reason = "direct_admin_file_access"
            analysis.score = 20
            break
        end
    end

    -- User enumeration via WordPress REST API (/wp-json/wp/v2/users or
    -- ?rest_route=/wp/v2/users).
    if string.find(uri_lower, "wp%-json/wp/v2/users") or
       (string.find(args_lower, "rest_route=") and string.find(args_lower, "/wp/v2/users")) then
        analysis.suspicious = true
        analysis.reason = "user_enumeration"
        analysis.score = 25
    end

    -- Plugin/theme enumeration via readme.txt disclosure.
    if string.find(uri_lower, "wp%-content/plugins") and string.find(uri_lower, "readme%.txt") then
        analysis.suspicious = true
        analysis.reason = "plugin_enumeration"
        analysis.score = 15
    end

    -- Automated tool signatures in admin context.
    local automation_patterns = { "wpscan", "wp%-cli", "curl", "wget", "python", "scanner" }
    for _, pattern in ipairs(automation_patterns) do
        if string.find(ua_lower, pattern) then
            analysis.suspicious = true
            analysis.reason = "automated_admin_tool"
            analysis.score = 35
            break
        end
    end

    -- Suspicious admin action parameters (cumulative -- can stack with the
    -- checks above, matching the original scoring behavior).
    local suspicious_params = {
        "action=upload%-plugin", "action=activate", "action=delete",
        "action=edit%-theme%-plugin%-file", "file=%.%./"
    }
    for _, param in ipairs(suspicious_params) do
        if string.find(uri_lower, param) then
            analysis.suspicious = true
            analysis.reason = "suspicious_admin_action"
            analysis.score = analysis.score + 20
        end
    end

    return analysis
end

-- ---------------------------------------------------------------------------
-- is_suspicious_ajax_action(post_data, get_action)
--
-- Pure core of the old is_legitimate_ajax_call(): given the already-read
-- POST body (or nil) and the already-parsed `action` GET parameter (or
-- nil), decides whether this looks like a suspicious admin-ajax.php call.
-- Note the INVERTED sense vs. the old function name: this returns true for
-- SUSPICIOUS (matching the "is_X_bad" naming convention used by the other
-- *_rules.lua predicates), not true for legitimate.
--
-- @param post_data  string|nil  Raw POST body, or nil for non-POST/no body.
-- @param get_action string|nil  The `action` GET parameter value, if any.
-- @return boolean, string|nil, string|nil  is_suspicious, the specific
--                              pattern/action that matched (for logging),
--                              and its source ("post"|"get"), or nil, nil.
-- ---------------------------------------------------------------------------
function _M.is_suspicious_ajax_action(post_data, get_action)
    if post_data then
        local post_lower = string.lower(post_data)
        local suspicious_actions = {
            "action=upload%-plugin", "action=install%-plugin", "action=activate",
            "action=delete%-plugin", "action=edit%-theme%-plugin%-file",
            "action=update%-plugin", "action=update%-theme", "action=delete%-theme",
            "file=%.%./"
        }
        for _, action in ipairs(suspicious_actions) do
            if string.find(post_lower, action) then
                return true, action, "post"
            end
        end
    end

    if get_action then
        local action_lower = string.lower(get_action)
        local suspicious_get_actions = {
            "upload%-plugin", "install%-plugin", "delete%-plugin",
            "edit%-theme%-plugin%-file", "update%-plugin", "update%-theme"
        }
        for _, sus_action in ipairs(suspicious_get_actions) do
            if string.find(action_lower, sus_action) then
                return true, get_action, "get"
            end
        end
    end

    return false, nil, nil
end

-- ---------------------------------------------------------------------------
-- score_brute_force_attempts(attempts, first_attempt, current_time, window_size)
--
-- Pure core of the old check_brute_force_attempts(): given the raw list of
-- past attempt records (each with a .timestamp), filters to those within
-- the window and scores the result. Does NOT mutate its input.
--
-- `first_attempt` is intentionally a SEPARATE parameter, not derived from
-- the attempts list: it's the timestamp the attempt-tracking record was
-- first created (track_admin_attempt() sets it once and never updates it,
-- even as older individual attempts get filtered out of the window on
-- later calls), so the "rapid succession" bonus below measures time since
-- this IP's very first tracked attempt, not time since the oldest
-- still-in-window one. This is the original's actual behavior, preserved
-- exactly rather than "corrected" during extraction.
--
-- @param attempts       table|nil  List of { timestamp = number, ... }.
-- @param first_attempt  number|nil  Timestamp the attempt record was
--                                   created; e.g. attempts_data.first_attempt.
-- @param current_time   number     e.g. ngx.time()
-- @param window_size    number     Seconds; attempts older than this are
--                                  ignored. Caller passes 300 (5 min) today.
-- @return number, table  score, filtered_attempts (attempts within window)
-- ---------------------------------------------------------------------------
function _M.score_brute_force_attempts(attempts, first_attempt, current_time, window_size)
    local filtered = {}
    for _, attempt in ipairs(attempts or {}) do
        if current_time - attempt.timestamp <= window_size then
            table.insert(filtered, attempt)
        end
    end

    local count = #filtered
    local score = 0
    if count >= 10 then
        score = 80
    elseif count >= 5 then
        score = 50
    elseif count >= 3 then
        score = 25
    end

    -- Rapid succession bonus: 3+ attempts in-window, and the record's
    -- original first attempt was less than a minute ago.
    if count >= 3 and first_attempt then
        local time_span = current_time - first_attempt
        if time_span < 60 then
            score = score + 30
        end
    end

    return score, filtered
end

-- ---------------------------------------------------------------------------
-- score_login_credential_stuffing(post_data)
--
-- Pure core of the old analyze_login_data(): scores a login POST body for
-- common credential-stuffing patterns (weak/default credentials, unusually
-- short payloads consistent with scripted attempts).
--
-- @param post_data  string|nil  Raw POST body.
-- @return table  { suspicious: boolean, score: number, patterns: table }
-- ---------------------------------------------------------------------------
function _M.score_login_credential_stuffing(post_data)
    if not post_data then
        return { suspicious = false, score = 0, patterns = {} }
    end

    local analysis = { suspicious = false, score = 0, patterns = {} }
    local post_lower = string.lower(post_data)

    local stuffing_patterns = {
        { pattern = "admin",    score = 5,  name = "common_username" },
        { pattern = "password", score = 5,  name = "common_password" },
        { pattern = "123456",   score = 10, name = "weak_password" },
        { pattern = "qwerty",   score = 10, name = "keyboard_pattern" },
        { pattern = "test",     score = 8,  name = "test_credentials" }
    }
    for _, check in ipairs(stuffing_patterns) do
        if string.find(post_lower, check.pattern) then
            analysis.score = analysis.score + check.score
            table.insert(analysis.patterns, check.name)
        end
    end

    if string.len(post_data) < 50 then
        analysis.score = analysis.score + 10
        table.insert(analysis.patterns, "short_post_data")
    end

    if analysis.score >= 15 then
        analysis.suspicious = true
    end

    return analysis
end

return _M
