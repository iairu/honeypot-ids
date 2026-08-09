-- test_session_rules.lua - Standalone unit tests
--
-- Runs under a plain `lua` interpreter (no OpenResty/ngx required), since
-- session_rules.lua has no ngx.* or _G.* dependency by design.
--
-- Usage:
--   cd ids/reverse_proxy_enhanced/lua/tests
--   lua test_session_rules.lua

package.path = "../?.lua;" .. package.path
local rules = require "session_rules"

local passed, failed = 0, 0

local function check(name, condition)
    if condition then
        passed = passed + 1
        print("  [PASS] " .. name)
    else
        failed = failed + 1
        print("  [FAIL] " .. name)
    end
end

print("== analyze_session_anomalies() ==")
do
    local base = { ip_address = "1.2.3.4", user_agent = "curl/8.0" }

    check("nil session_data returns empty table",
          #rules.analyze_session_anomalies(nil, "1.2.3.4", "curl/8.0", nil, 1000) == 0)

    check("no changes -> no anomalies",
          #rules.analyze_session_anomalies(base, "1.2.3.4", "curl/8.0", nil, 1000) == 0)

    local anomalies = rules.analyze_session_anomalies(base, "9.9.9.9", "curl/8.0", nil, 1000)
    check("IP change detected", anomalies[1] == "ip_change")

    anomalies = rules.analyze_session_anomalies(base, "1.2.3.4", "Mozilla/5.0", nil, 1000)
    check("UA change detected", anomalies[1] == "user_agent_change")

    anomalies = rules.analyze_session_anomalies(
        base, "1.2.3.4", "sqlmap/1.0", { "sqlmap", "nikto" }, 1000)
    local found_malicious = false
    for _, a in ipairs(anomalies) do
        if a == "malicious_user_agent" then found_malicious = true end
    end
    check("malicious UA match is case-insensitive substring", found_malicious)
    -- sqlmap UA also differs from base's "curl/8.0" -> both anomalies fire
    check("UA change AND malicious UA both fire", #anomalies == 2)

    anomalies = rules.analyze_session_anomalies(
        base, "1.2.3.4", "clean-browser/1.0", { "sqlmap" }, 1000)
    found_malicious = false
    for _, a in ipairs(anomalies) do
        if a == "malicious_user_agent" then found_malicious = true end
    end
    check("clean UA against malicious list does not false-positive", not found_malicious)

    local rapid = { request_count = 6, last_activity = 1000 }
    anomalies = rules.analyze_session_anomalies(rapid, nil, nil, nil, 1000)
    found_malicious = false
    local found_rapid = false
    for _, a in ipairs(anomalies) do
        if a == "rapid_requests" then found_rapid = true end
    end
    check("rapid requests (6 reqs, <1s gap) detected", found_rapid)

    local not_rapid = { request_count = 5, last_activity = 999 }
    anomalies = rules.analyze_session_anomalies(not_rapid, nil, nil, nil, 1000)
    found_rapid = false
    for _, a in ipairs(anomalies) do
        if a == "rapid_requests" then found_rapid = true end
    end
    check("exactly 5 requests does not trip rapid_requests (> 5, not >=)", not found_rapid)

    local slow = { request_count = 6, last_activity = 990 }
    anomalies = rules.analyze_session_anomalies(slow, nil, nil, nil, 1000)
    found_rapid = false
    for _, a in ipairs(anomalies) do
        if a == "rapid_requests" then found_rapid = true end
    end
    check("6 requests over 10s gap does not trip rapid_requests", not found_rapid)
end

print("== should_route_to_honeypot() ==")
do
    check("nil session_data returns false",
          rules.should_route_to_honeypot(nil, 80, false, 1000) == false)

    check("already honeypot_bound short-circuits true",
          rules.should_route_to_honeypot({ honeypot_bound = true, threat_score = 0 }, 80, false, 1000) == true)

    check("threat_score >= threshold returns true",
          rules.should_route_to_honeypot({ threat_score = 80 }, 80, false, 1000) == true)

    check("threat_score just below threshold returns false",
          rules.should_route_to_honeypot({ threat_score = 79 }, 80, false, 1000) == false)

    -- Matches original session_handler.lua behavior exactly: the whitelist
    -- check sits AFTER the threat_score check, so it only exempts the
    -- softer heuristics below it (suspicious_activities count, rapid
    -- requests) -- it does NOT override an already-crossed threat_score
    -- threshold. Confirmed against the pre-extraction source before writing
    -- this test.
    check("threat_score >= threshold still wins even when whitelisted",
          rules.should_route_to_honeypot({ threat_score = 100 }, 80, true, 1000) == true)

    check("whitelisting DOES exempt the suspicious_activities heuristic",
          rules.should_route_to_honeypot(
              { threat_score = 0, suspicious_activities = { "a", "b", "c" } }, 80, true, 1000) == false)

    check(">= 3 suspicious activities returns true",
          rules.should_route_to_honeypot(
              { threat_score = 0, suspicious_activities = { "a", "b", "c" } }, 80, false, 1000) == true)

    check("2 suspicious activities does not trip",
          rules.should_route_to_honeypot(
              { threat_score = 0, suspicious_activities = { "a", "b" } }, 80, false, 1000) == false)

    -- 21 req/s over a 10s session (created_at=990, now=1000) exceeds the
    -- 20 req/s threshold.
    check("sustained >20 req/s returns true",
          rules.should_route_to_honeypot(
              { threat_score = 0, request_count = 210, created_at = 990 }, 80, false, 1000) == true)

    check("exactly 20 req/s does not trip (> not >=)",
          rules.should_route_to_honeypot(
              { threat_score = 0, request_count = 200, created_at = 990 }, 80, false, 1000) == false)

    check("zero session_duration guarded against divide-by-zero",
          rules.should_route_to_honeypot(
              { threat_score = 0, request_count = 5, created_at = 1000 }, 80, false, 1000) == false)
end

print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
