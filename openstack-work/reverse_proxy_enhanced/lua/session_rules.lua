-- session_rules.lua - Pure session-anomaly and routing predicates used by
-- session_handler.lua
--
-- Same split rationale as threat_rules.lua/router_rules.lua: no ngx.*
-- dependency, no reliance on _G.config/_G.utils, plain-`lua`-interpreter
-- testable (see tests/test_session_rules.lua). session_handler.lua is the
-- adapter -- it does all the Redis/shared-dict I/O and ngx.log calls, and
-- passes this module already-fetched values (current time, current IP/UA,
-- the decoded malicious-agents list, whitelist result) rather than letting
-- it reach into ngx.* or _G.* directly.
--
-- Extracted from session_handler.lua's analyze_session_anomalies() and
-- should_route_to_honeypot(), which architecture.canvas flagged as "pure
-- logic mixed into the write path" -- both were genuinely pure decision
-- cores once their ngx.*/_G.* reads were turned into parameters; the only
-- non-trivial change was moving the ngx.log() calls in
-- analyze_session_anomalies() out to the caller, since a pure function
-- can't log and still be plain-lua-interpreter testable.

local _M = {}

-- ---------------------------------------------------------------------------
-- analyze_session_anomalies(session_data, current_ip, current_ua, malicious_agents, current_time)
--
-- Detects anomalies for the current request against a session's recorded
-- state: IP address change, User-Agent change, a User-Agent matching the
-- known-malicious-agents list, or a burst of requests in under a second.
--
-- @param session_data       table|nil  Must have .ip_address, .user_agent,
--                                       .request_count, .last_activity if
--                                       those checks are to run.
-- @param current_ip          string|nil  e.g. ngx.var.remote_addr
-- @param current_ua           string|nil  e.g. ngx.var.http_user_agent
-- @param malicious_agents     table|nil   Already-decoded list of strings
--                                         (from the "malicious_agents" key
--                                         in ngx.shared.threat_intel).
-- @param current_time         number      e.g. ngx.time()
-- @return table  List of anomaly name strings: subset of
--                 {"ip_change", "user_agent_change", "malicious_user_agent",
--                  "rapid_requests"}. Never nil, may be empty.
-- ---------------------------------------------------------------------------
function _M.analyze_session_anomalies(session_data, current_ip, current_ua, malicious_agents, current_time)
    local anomalies = {}

    if not session_data then
        return anomalies
    end

    current_ua = current_ua or ""

    if session_data.ip_address ~= current_ip then
        table.insert(anomalies, "ip_change")
    end

    if session_data.user_agent ~= current_ua then
        table.insert(anomalies, "user_agent_change")
    end

    if malicious_agents then
        local ua_lower = string.lower(current_ua)
        for _, agent in ipairs(malicious_agents) do
            if string.find(ua_lower, string.lower(agent)) then
                table.insert(anomalies, "malicious_user_agent")
                break
            end
        end
    end

    if session_data.request_count and session_data.last_activity and current_time then
        local time_diff = current_time - session_data.last_activity
        if time_diff < 1 and session_data.request_count > 5 then
            table.insert(anomalies, "rapid_requests")
        end
    end

    return anomalies
end

-- ---------------------------------------------------------------------------
-- should_route_to_honeypot(session_data, honeypot_threshold, is_whitelisted, current_time)
--
-- @param session_data        table|nil  Must have .honeypot_bound,
--                                        .threat_score, .ip_address,
--                                        .suspicious_activities,
--                                        .request_count, .created_at.
-- @param honeypot_threshold  number     e.g. _G.config.threat.honeypot_threshold
-- @param is_whitelisted      boolean    Result of e.g.
--                                       _G.utils.is_ip_whitelisted(session_data.ip_address),
--                                       computed by the caller.
-- @param current_time        number     e.g. ngx.time()
-- @return boolean
-- ---------------------------------------------------------------------------
function _M.should_route_to_honeypot(session_data, honeypot_threshold, is_whitelisted, current_time)
    if not session_data then
        return false
    end

    if session_data.honeypot_bound then
        return true
    end

    if honeypot_threshold and session_data.threat_score and session_data.threat_score >= honeypot_threshold then
        return true
    end

    if is_whitelisted then
        return false
    end

    if session_data.suspicious_activities and #session_data.suspicious_activities >= 3 then
        return true
    end

    -- Rapid requests: more than 20 requests/second sustained over the
    -- session's lifetime (matches the threshold already used live -- raised
    -- once before to avoid false positives on legitimate page loads).
    if session_data.request_count and session_data.created_at and current_time then
        local session_duration = current_time - session_data.created_at
        if session_duration > 0 and (session_data.request_count / session_duration) > 20 then
            return true
        end
    end

    return false
end

return _M
