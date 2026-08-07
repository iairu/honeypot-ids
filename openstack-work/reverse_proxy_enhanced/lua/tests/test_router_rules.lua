-- test_router_rules.lua - Standalone unit tests
--
-- Runs under a plain `lua` interpreter (no OpenResty/ngx required), since
-- router_rules.lua has no ngx.* or _G.* dependency by design.
--
-- Usage:
--   cd openstack-work/reverse_proxy_enhanced/lua/tests
--   lua test_router_rules.lua

package.path = "../?.lua;" .. package.path
local rules = require "router_rules"

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

local STATIC_PATTERNS = { "%.css$", "%.js$", "%.png$" }
-- Plain literal plugin slugs, matching what _G.config.vulnerability.plugins
-- actually contains (init.lua) -- is_vulnerable_plugin_access() escapes Lua
-- pattern magic characters (including "-") internally, so these must NOT be
-- pre-escaped here.
local VULNERABLE_PLUGINS = { "woocommerce-payments", "abandoned-cart-lite" }

print("== is_static_asset() ==")
do
    check("css file matches", rules.is_static_asset("/theme/style.css", STATIC_PATTERNS) == true)
    check("css file with query string still matches",
          rules.is_static_asset("/theme/style.css?v=123", STATIC_PATTERNS) == true)
    check("php file does not match", rules.is_static_asset("/index.php", STATIC_PATTERNS) == false)
    check("nil uri returns false", rules.is_static_asset(nil, STATIC_PATTERNS) == false)
end

print("== is_vulnerable_plugin_access() ==")
do
    local hit = rules.is_vulnerable_plugin_access(
        "/wp-content/plugins/woocommerce-payments/api.php", VULNERABLE_PLUGINS, STATIC_PATTERNS)
    check("vulnerable plugin PHP access detected", hit == true)

    local static_excluded = rules.is_vulnerable_plugin_access(
        "/wp-content/plugins/woocommerce-payments/style.css", VULNERABLE_PLUGINS, STATIC_PATTERNS)
    check("static asset inside vulnerable plugin dir excluded", static_excluded == false)

    local other_plugin = rules.is_vulnerable_plugin_access(
        "/wp-content/plugins/some-other-plugin/api.php", VULNERABLE_PLUGINS, STATIC_PATTERNS)
    check("non-listed plugin not flagged", other_plugin == false)

    check("nil uri returns false", rules.is_vulnerable_plugin_access(nil, VULNERABLE_PLUGINS, STATIC_PATTERNS) == false)
end

print("== is_admin_access() ==")
do
    check("wp-admin matches", rules.is_admin_access("/wp-admin/") == true)
    check("wp-login matches", rules.is_admin_access("/wp-login.php") == true)
    check("shop page does not match", rules.is_admin_access("/shop/") == false)
    check("nil uri returns false", rules.is_admin_access(nil) == false)
end

print("== is_rapid_automation() ==")
do
    local now = 1000000
    local fast_session = { created_at = now - 2, request_count = 100 }
    check("high requests-per-second detected", rules.is_rapid_automation(fast_session, {}, now) == true)

    local slow_session = { created_at = now - 100, request_count = 5 }
    check("low requests-per-second not detected", rules.is_rapid_automation(slow_session, {}, now) == false)

    local tool_session = { created_at = now - 100, request_count = 1 }
    local threat_with_automation = { details = { "automation_detected: curl" } }
    check("automation_detected detail triggers true",
          rules.is_rapid_automation(tool_session, threat_with_automation, now) == true)

    check("nil session_data returns false", rules.is_rapid_automation(nil, {}, now) == false)
end

print("== is_suspicious_upload() ==")
do
    check("GET is never suspicious", rules.is_suspicious_upload("GET", "/upload", "multipart/form-data", "") == false)

    local php_upload = rules.is_suspicious_upload("POST", "/upload-handler", "multipart/form-data", "file=shell.php")
    check("PHP file in upload args detected", php_upload == true)

    local clean_upload = rules.is_suspicious_upload("POST", "/upload-handler", "multipart/form-data", "file=photo.jpg")
    check("clean image upload not flagged", clean_upload == false)

    local known_vuln_action = rules.is_suspicious_upload("POST", "/wp-admin/admin-ajax.php", "multipart/form-data",
                                                           "action=dnd_codedropz_upload")
    check("known vulnerable upload action detected", known_vuln_action == true)

    local non_upload_post = rules.is_suspicious_upload("POST", "/wp-login.php", "application/x-www-form-urlencoded",
                                                         "log=admin&pwd=x")
    check("non-upload POST not flagged", non_upload_post == false)
end

print("== check_geographic_anomalies() ==")
do
    local changed = rules.check_geographic_anomalies({ ip_address = "1.2.3.4" }, "5.6.7.8")
    check("IP change detected", changed.anomaly_detected == true)
    check("score_increase is 15", changed.score_increase == 15)

    local same = rules.check_geographic_anomalies({ ip_address = "1.2.3.4" }, "1.2.3.4")
    check("same IP no anomaly", same.anomaly_detected == false)

    local nil_session = rules.check_geographic_anomalies(nil, "1.2.3.4")
    check("nil session no anomaly", nil_session.anomaly_detected == false)
end

print("== analyze_behavior_patterns() ==")
do
    local now = 1000000
    local high_freq = { request_count = 100, created_at = now - 10 }
    local r1 = rules.analyze_behavior_patterns(high_freq, now, "/shop/")
    check("high request frequency scores > 0", r1.score > 0)

    local direct_admin = { request_count = 1 }
    local r2 = rules.analyze_behavior_patterns(direct_admin, now, "/wp-admin/")
    check("single request to admin area scores > 0", r2.score > 0)

    local clean = { request_count = 2, created_at = now - 100 }
    local r3 = rules.analyze_behavior_patterns(clean, now, "/shop/")
    check("normal browsing scores zero", r3.score == 0)

    local nil_session = rules.analyze_behavior_patterns(nil, now, "/shop/")
    check("nil session_data returns zero score", nil_session.score == 0)
end

print("== decayed_score() ==")
do
    local now = 1000000
    local HALF_LIFE = 300

    local fresh = { threat_score = 90, last_threat_time = now }
    check("no time elapsed -> no decay", rules.decayed_score(fresh, now, HALF_LIFE) == 90)

    -- The specific bug this function exists to fix: a session flagged
    -- moments ago (e.g. by a CVE match) must NOT be back near-zero after
    -- one immediate follow-up request -- confirmed live this was
    -- previously possible by checking only the fresh per-request score.
    local one_second_later = rules.decayed_score(fresh, now + 1, HALF_LIFE)
    check("1s elapsed -> still clearly above the 30 release threshold", one_second_later > 89)

    local one_half_life = rules.decayed_score(fresh, now + HALF_LIFE, HALF_LIFE)
    check("one half-life elapsed -> decayed to ~half", math.abs(one_half_life - 45) < 0.01)

    local two_half_lives = rules.decayed_score(fresh, now + 2 * HALF_LIFE, HALF_LIFE)
    check("two half-lives elapsed -> below the 30 release threshold", two_half_lives < 30)

    local zero_score = rules.decayed_score({ threat_score = 0, last_threat_time = now }, now + 10000, HALF_LIFE)
    check("zero stored score stays zero", zero_score == 0)

    local no_anchor = rules.decayed_score({ threat_score = 90 }, now + 10000, HALF_LIFE)
    check("missing last_threat_time -> no decay (treated as still-fresh)", no_anchor == 90)

    check("nil session_data returns zero", rules.decayed_score(nil, now, HALF_LIFE) == 0)
    check("nil half_life returns undecayed peak",
          rules.decayed_score(fresh, now + 10000, nil) == 90)
end

print()
print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
