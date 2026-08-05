-- test_admin_rules.lua - Standalone unit tests
--
-- Usage:
--   cd openstack-work/reverse_proxy_enhanced/lua/tests
--   lua test_admin_rules.lua

package.path = "../?.lua;" .. package.path
local rules = require "admin_rules"

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

print("== is_login_attempt() ==")
do
    check("POST to wp-login.php is a login attempt",
          rules.is_login_attempt("/wp-login.php", "POST") == true)
    check("POST to xmlrpc.php is a login attempt",
          rules.is_login_attempt("/xmlrpc.php", "POST") == true)
    check("GET to wp-login.php is not (only POST counts)",
          rules.is_login_attempt("/wp-login.php", "GET") == false)
    check("POST to unrelated URI is not a login attempt",
          rules.is_login_attempt("/wp-admin/admin-ajax.php", "POST") == false)
    check("nil uri does not crash", rules.is_login_attempt(nil, "POST") == false)
end

print("== analyze_admin_patterns() ==")
do
    local clean = rules.analyze_admin_patterns("/wp-admin/", "Mozilla/5.0", "", "GET")
    check("clean request is not suspicious", clean.suspicious == false and clean.reason == "clean")

    local direct = rules.analyze_admin_patterns("/wp-admin/users.php", "Mozilla/5.0", "", "GET")
    check("direct admin file access detected", direct.suspicious == true and direct.reason == "direct_admin_file_access")
    check("direct admin file access scores 20", direct.score == 20)

    local enum1 = rules.analyze_admin_patterns("/wp-json/wp/v2/users", "Mozilla/5.0", "", "GET")
    check("REST API user enumeration detected", enum1.reason == "user_enumeration")

    local enum2 = rules.analyze_admin_patterns("/", "Mozilla/5.0", "rest_route=/wp/v2/users", "GET")
    check("?rest_route= user enumeration detected", enum2.reason == "user_enumeration")

    local plugin_enum = rules.analyze_admin_patterns(
        "/wp-content/plugins/woocommerce/readme.txt", "Mozilla/5.0", "", "GET")
    check("plugin readme.txt enumeration detected", plugin_enum.reason == "plugin_enumeration")

    local bot = rules.analyze_admin_patterns("/wp-admin/", "wpscan/3.8", "", "GET")
    check("wpscan UA detected as automated tool", bot.reason == "automated_admin_tool")
    check("automated tool scores 35", bot.score == 35)

    local stacked = rules.analyze_admin_patterns(
        "/wp-admin/users.php?action=delete", "Mozilla/5.0", "", "GET")
    check("direct-access + suspicious-param scores stack (20+20=40)", stacked.score == 40)
end

print("== is_suspicious_ajax_action() ==")
do
    local ok, matched, source = rules.is_suspicious_ajax_action(nil, nil)
    check("no post data, no get action -> not suspicious", ok == false and matched == nil and source == nil)

    ok, matched, source = rules.is_suspicious_ajax_action("action=upload-plugin&file=evil.php", nil)
    check("suspicious POST action detected", ok == true)
    check("matched pattern returned for logging", matched == "action=upload%-plugin")
    check("source reported as post", source == "post")

    ok = rules.is_suspicious_ajax_action("action=heartbeat&data=1", nil)
    check("benign POST action (heartbeat) not flagged", ok == false)

    ok, matched, source = rules.is_suspicious_ajax_action(nil, "delete-plugin")
    check("suspicious GET action detected", ok == true and matched == "delete-plugin")
    check("source reported as get", source == "get")

    ok = rules.is_suspicious_ajax_action(nil, "heartbeat")
    check("benign GET action not flagged", ok == false)

    ok = rules.is_suspicious_ajax_action("file=../../etc/passwd", nil)
    check("directory traversal in POST body detected", ok == true)
end

print("== score_brute_force_attempts() ==")
do
    local score, filtered = rules.score_brute_force_attempts({}, 1000, 1000, 300)
    check("no attempts scores 0", score == 0 and #filtered == 0)

    local two = { { timestamp = 990 }, { timestamp = 995 } }
    score = rules.score_brute_force_attempts(two, 990, 1000, 300)
    check("2 attempts within window scores 0 (below 3-attempt floor)", score == 0)

    local three_fast = { { timestamp = 970 }, { timestamp = 980 }, { timestamp = 990 } }
    -- first_attempt (970) is 30s before current_time (1000) -> < 60s -> rapid bonus applies
    score = rules.score_brute_force_attempts(three_fast, 970, 1000, 300)
    check("3 attempts, record started <60s ago, scores 25 (base) + 30 (rapid) = 55", score == 55)

    local five = {}
    for i = 1, 5 do five[i] = { timestamp = 1000 - i * 20 } end -- all within last 100s (in-window)
    -- first_attempt is old (record created 500s ago) -> rapid bonus does NOT apply,
    -- even though the individual attempts themselves are recent -- this is the
    -- exact "first_attempt is the record's original creation time, not
    -- recomputed from the filtered set" behavior being preserved.
    score = rules.score_brute_force_attempts(five, 500, 1000, 300)
    check("5 in-window attempts but old record creation time scores 50 (medium tier only, no rapid bonus)", score == 50)

    local ten = {}
    for i = 1, 10 do ten[i] = { timestamp = 1000 - i * 5 } end -- all within last 50s
    score = rules.score_brute_force_attempts(ten, 970, 1000, 300)
    check("10 attempts, record started <60s ago, scores 80 (high) + 30 (rapid) = 110", score == 110)

    local outside_window = { { timestamp = 100 } } -- 900s ago, window is 300s
    local _, filtered2 = rules.score_brute_force_attempts(outside_window, 100, 1000, 300)
    check("attempts outside window are filtered out", #filtered2 == 0)

    check("nil attempts list doesn't crash", rules.score_brute_force_attempts(nil, 1000, 1000, 300) == 0)
    check("nil first_attempt doesn't crash (rapid bonus just skipped)",
          rules.score_brute_force_attempts(three_fast, nil, 1000, 300) == 25)
end

print("== score_login_credential_stuffing() ==")
do
    local none = rules.score_login_credential_stuffing(nil)
    check("nil post_data is not suspicious", none.suspicious == false and none.score == 0)

    local clean = rules.score_login_credential_stuffing(
        "log=realistic_username_123&pwd=Tr0ub4dor%26Zebra9!Correct")
    check("long, non-default-looking credentials not suspicious", clean.suspicious == false)

    local weak = rules.score_login_credential_stuffing("log=admin&pwd=123456")
    check("admin/123456 flagged suspicious", weak.suspicious == true)
    check("admin/123456 scores at least 20 (5 admin + 5 password-word + 10 weak)",
          weak.score >= 20)

    local short = rules.score_login_credential_stuffing("a=1")
    check("very short POST data flagged suspicious (short_post_data alone = 10, below 15 threshold)",
          short.suspicious == false and short.score == 10)

    local qwerty = rules.score_login_credential_stuffing("log=root&pwd=qwerty")
    local found_kb_pattern = false
    for _, p in ipairs(qwerty.patterns) do
        if p == "keyboard_pattern" then found_kb_pattern = true end
    end
    check("qwerty detected as keyboard_pattern", found_kb_pattern)
end

print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
