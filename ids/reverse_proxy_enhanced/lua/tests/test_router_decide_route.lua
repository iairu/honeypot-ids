-- test_router_decide_route.lua - Stage-by-stage tests for router.decide_route()
--
-- decide_route() is the one routing function that stays impure (it reads
-- ngx.var, _G.config/_G.utils, and calls pool_router/session_handler), so
-- this suite runs it against in-memory stubs of all of those instead of a
-- live nginx + Redis. Each test pins one pipeline stage: which target wins,
-- which honeypot_reason is recorded, and that earlier stages take priority.
--
-- Usage:
--   cd ids/reverse_proxy_enhanced/lua/tests
--   lua test_router_decide_route.lua

package.path = "../?.lua;" .. package.path

local NOW = 1700000000

-- ---------------------------------------------------------------------------
-- Stubs
-- ---------------------------------------------------------------------------
ngx = {
    INFO = 7, WARN = 5, ERR = 4,
    var = {},
    log = function() end,
    time = function() return NOW end,
}

_G.config = {
    threat = {
        honeypot_threshold = 80,
        max_threat_score = 100,
        score_decay_half_life_seconds = 0, -- off: scores below are exact
        static_asset_patterns = { "%.css$", "%.js$", "%.png$", "%.jpg$" },
    },
    vulnerability = { plugins = { "woocommerce-payments", "abandoned-cart-lite" } },
}

local whitelisted = {}
local security_events = {}
_G.utils = {
    is_ip_whitelisted = function(ip) return whitelisted[ip] == true end,
    log_security_event = function(kind, data)
        table.insert(security_events, { kind = kind, data = data })
    end,
}

local pool_calls
package.loaded["pool_router"] = {
    get_or_assign_pool = function(ip)
        pool_calls.assign = pool_calls.assign + 1
        return 2
    end,
    get_upstream_for_pool = function(n) return "honeypot_backend_" .. n end,
    refresh_assignment_ttl = function() pool_calls.refresh = pool_calls.refresh + 1 end,
}

local created_sessions
package.loaded["session_handler"] = {
    create_session = function(ip, ua, route, id)
        local s = { id = id or "new-session", ip = ip, user_agent = ua, created_at = NOW }
        table.insert(created_sessions, s)
        return s
    end,
}

local wp_installed = true
package.loaded["wp_install_state"] = {
    is_installed = function() return wp_installed end,
}

local abuse_reports
package.loaded["abuseipdb_client"] = {
    report_ip_async = function(ip, reason) table.insert(abuse_reports, { ip = ip, reason = reason }) end,
}

package.loaded["cjson"] = package.loaded["cjson"] or { encode = tostring, decode = function() return {} end }

local router = require "router"

-- ---------------------------------------------------------------------------
-- Harness
-- ---------------------------------------------------------------------------
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

local IP = "203.0.113.7"

-- Runs decide_route for one request. `req` sets ngx.var fields, `threat`
-- overrides the default clean threat_result, `session` is the stored session
-- (pass false for "no session yet").
local function route(req, threat, session)
    ngx.var = {
        request_uri = req.uri or "/",
        request_method = req.method or "GET",
        content_type = req.content_type,
        args = req.args,
        http_user_agent = "Mozilla/5.0",
    }
    local t = { score = 0, ip_reputation = 0, patterns_matched = {}, cve_matched = {}, details = {} }
    for k, v in pairs(threat or {}) do t[k] = v end
    if session == nil then session = { id = "s1", created_at = NOW - 60, request_count = 3 } end
    pool_calls = { assign = 0, refresh = 0 }
    created_sessions, abuse_reports, security_events = {}, {}, {}
    return router.decide_route(session or nil, t, IP, "s1"), t
end

local function reason(d) return d.session_data and d.session_data.honeypot_reason end

-- ---------------------------------------------------------------------------
print("Stage 1: static assets")
do
    local d = route({ uri = "/wp-content/themes/x/style.css" }, { score = 95 })
    check("static asset -> production even with high score", d.target == "production")
    check("static asset never touches pool_router", pool_calls.assign == 0)
end

print("Session creation")
do
    local d = route({ uri = "/shop/" }, nil, false)
    check("missing session is created", #created_sessions == 1)
    check("new session is persisted", d.update_session == true and d.session_data.id == "s1")
    check("clean first request -> production", d.target == "production")
end

print("Stage 1b: install wizard")
do
    wp_installed = false
    local d = route({ uri = "/wp-admin/install.php" }, { score = 95 })
    check("install.php on uninstalled WP -> production", d.target == "production")
    d = route({ uri = "/wp-admin/install.php" }, { score = 95 }, { id = "s1", honeypot_bound = true, honeypot_pool = 1 })
    check("install.php exemption does not apply to bound sessions", d.target == "honeypot")
    wp_installed = true
    d = route({ uri = "/wp-admin/install.php" }, { score = 95 })
    check("install.php on installed WP is scored normally", d.target == "honeypot")
end

print("Stage 2: sticky honeypot binding")
do
    local bound = { id = "s1", honeypot_bound = true, honeypot_pool = 3, threat_score = 90,
                    last_threat_time = NOW, honeypot_reason = "cve_pattern_match" }
    local d = route({ uri = "/shop/" }, nil, bound)
    check("bound session stays on its own pool", d.target == "honeypot" and d.upstream == "honeypot_backend_3")
    check("bound session keeps original reason", reason(d) == "cve_pattern_match")
    check("bound session refreshes pool TTL", pool_calls.refresh == 1 and pool_calls.assign == 0)

    local unpooled = { id = "s1", honeypot_bound = true, threat_score = 90, last_threat_time = NOW }
    d = route({ uri = "/shop/" }, nil, unpooled)
    check("bound session without pool gets one assigned", d.upstream == "honeypot_backend_2"
          and d.session_data.honeypot_pool == 2)

    local cooled = { id = "s1", honeypot_bound = true, honeypot_pool = 1, threat_score = 20, last_threat_time = NOW }
    d = route({ uri = "/shop/" }, nil, cooled)
    check("bound session whose score fell under 30 is released to production", d.target == "production")

    d = route({ uri = "/shop/" }, { score = 15 }, { id = "s1", honeypot_bound = true, honeypot_pool = 1,
                                                    threat_score = 50, last_threat_time = NOW, offenses = 2 })
    check("new signal on bound session accumulates score", d.session_data.threat_score == 65)
    check("new signal on bound session counts an offense", d.session_data.offenses == 3)
end

print("Stage 3: threat threshold")
do
    local d = route({ uri = "/?id=1'--" }, { score = 80, patterns_matched = { "sqli" } })
    check("score at threshold -> honeypot", d.target == "honeypot" and reason(d) == "high_threat_score")
    check("honeypot session is bound to the assigned pool",
          d.session_data.honeypot_bound == true and d.session_data.honeypot_pool == 2)
    check("diversion is reported to AbuseIPDB", #abuse_reports == 1 and abuse_reports[1].reason == "high_threat_score")
    check("diversion logs a security event", #security_events == 1 and security_events[1].kind == "routing_to_honeypot")

    d = route({ uri = "/" }, { score = 79 })
    check("score just under threshold -> production", d.target == "production")

    d = route({ uri = "/" }, { score = 50 }, { id = "s1", threat_score = 40, last_threat_time = NOW })
    check("fresh signal adds to stored score and crosses threshold", d.target == "honeypot")

    d = route({ uri = "/" }, { score = 5 }, { id = "s1", threat_score = 85, last_threat_time = NOW })
    check("stored score alone (no fresh signal) still diverts", d.target == "honeypot")
end

print("Stage 4: CVE match")
do
    local d = route({ uri = "/wp-json/wp/v2/users" }, { score = 20, cve_matched = { "CVE-2023-28121" } })
    check("CVE match below threshold -> honeypot", d.target == "honeypot" and reason(d) == "cve_pattern_match")
    check("matched CVEs are stored on the session", d.session_data.matched_cves[1] == "CVE-2023-28121")
end

print("Stage 5: vulnerable plugin path")
do
    local d = route({ uri = "/wp-content/plugins/woocommerce-payments/readme.txt" })
    check("hyphenated vulnerable plugin path -> honeypot",
          d.target == "honeypot" and reason(d) == "vulnerable_plugin_access")
    check("plugin access floors score at 60", d.session_data.threat_score == 60)
    d = route({ uri = "/wp-content/plugins/woocommerce-payments/assets/app.js" })
    check("static asset inside a vulnerable plugin -> production", d.target == "production")
end

print("Stage 6: IP reputation")
do
    local d = route({ uri = "/" }, { ip_reputation = 60 })
    check("bad reputation -> honeypot", d.target == "honeypot" and reason(d) == "bad_ip_reputation")
    d = route({ uri = "/" }, { ip_reputation = 60, ip_reputation_reason = "suricata: ET SCAN" })
    check("Suricata-sourced reputation keeps its own reason", reason(d) == "suricata_confirmed_alert")
    d = route({ uri = "/" }, { ip_reputation = 50 })
    check("reputation of exactly 50 is not enough", d.target == "production")
end

print("Stage 7: repeated admin access")
do
    local d = route({ uri = "/wp-admin/" }, nil, { id = "s1", admin_attempts = 0 })
    check("first admin hit -> production", d.target == "production")
    check("first admin hit is counted", d.session_data.admin_attempts == 1)
    d = route({ uri = "/wp-admin/" }, nil, { id = "s1", admin_attempts = 2 })
    check("third admin hit -> honeypot", d.target == "honeypot" and reason(d) == "multiple_admin_attempts")
    whitelisted[IP] = true
    d = route({ uri = "/wp-admin/" }, nil, { id = "s1", admin_attempts = 5 })
    check("whitelisted IP is never diverted for admin access", d.target == "production")
    whitelisted[IP] = nil
end

print("Stage 8: accumulated suspicious activity")
do
    local s = { id = "s1", suspicious_activities = { {}, {}, {}, {}, {} } }
    local d = route({ uri = "/shop/" }, nil, s)
    check("five logged suspicious activities -> honeypot",
          d.target == "honeypot" and reason(d) == "accumulated_suspicious_activities")

    s = { id = "s1" }
    d = route({ uri = "/?q=<b>" }, { score = 20, suspicious = true, patterns_matched = { "xss" } }, s)
    check("suspicious request under threshold stays on production", d.target == "production")
    check("suspicious request is appended to the session log",
          #d.session_data.suspicious_activities == 1 and d.session_data.suspicious_activities[1].threat_score == 20)
end

print("Stage 9: rapid automation")
do
    local s = { id = "s1", created_at = NOW - 1, request_count = 50 }
    local d = route({ uri = "/shop/" }, { score = 40 }, s)
    check("50 req/s with score 40 -> honeypot", d.target == "honeypot" and reason(d) == "rapid_automation_detected")
    d = route({ uri = "/shop/" }, { score = 30 }, { id = "s1", created_at = NOW - 1, request_count = 50 })
    check("automation alone under score 40 -> production", d.target == "production")
end

print("Stage 10: suspicious upload")
do
    local d = route({ uri = "/upload", method = "POST", args = "file=shell.php" })
    check("POST upload of .php -> honeypot", d.target == "honeypot" and reason(d) == "suspicious_file_upload")
    d = route({ uri = "/upload", method = "GET", args = "file=shell.php" })
    check("GET with the same args -> production", d.target == "production")
end

print("Stage ordering")
do
    local d = route({ uri = "/wp-content/plugins/woocommerce-payments/x.php" },
                    { score = 90, cve_matched = { "CVE-2023-28121" }, ip_reputation = 80 })
    check("threshold beats CVE, plugin and reputation", reason(d) == "high_threat_score")
    d = route({ uri = "/wp-content/plugins/woocommerce-payments/x.php" },
              { score = 10, cve_matched = { "CVE-2023-28121" }, ip_reputation = 80 })
    check("CVE beats plugin path and reputation", reason(d) == "cve_pattern_match")
end

print("Default")
do
    local d = route({ uri = "/product/hoodie/" })
    check("clean request -> production", d.target == "production" and d.upstream == "production_backend")
    check("clean request does not write the session", d.update_session == false)
    check("clean request never assigns a pool", pool_calls.assign == 0)
end

print()
print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
