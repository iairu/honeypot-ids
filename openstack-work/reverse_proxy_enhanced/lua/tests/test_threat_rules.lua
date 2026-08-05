-- test_threat_rules.lua - Standalone unit tests
--
-- Runs under a plain `lua` interpreter (no OpenResty/ngx required), since
-- threat_rules.lua has no ngx.* or _G.* dependency by design.
--
-- Usage:
--   cd openstack-work/reverse_proxy_enhanced/lua/tests
--   lua test_threat_rules.lua

package.path = "../?.lua;" .. package.path
local rules = require "threat_rules"

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

local STATIC_PATTERNS = { "%.css$", "%.js$", "%.png$", "%.jpg$" }
local SUSPICIOUS_PATTERNS = { "eval%(", "base64_decode" }
local CVE_PATTERNS = {
    ["CVE-2023-28121"] = "X%-WCPAY%-PLATFORM%-CHECKOUT%-USER",
    ["CVE-2024-2387"]  = "afi_search"
}

print("== is_static_asset() ==")
do
    check("css file matches", rules.is_static_asset("/wp-content/theme.css", STATIC_PATTERNS) == true)
    check("php file does not match", rules.is_static_asset("/index.php", STATIC_PATTERNS) == false)
    check("nil uri returns false", rules.is_static_asset(nil, STATIC_PATTERNS) == false)
    check("css file with query string still matches",
          rules.is_static_asset("/style.css?v=123", STATIC_PATTERNS) == true)
end

print("== analyze_uri_patterns() ==")
do
    local clean = rules.analyze_uri_patterns("/shop/product/red-shirt", SUSPICIOUS_PATTERNS)
    check("clean uri scores zero", clean.score == 0)

    local traversal = rules.analyze_uri_patterns("/../../etc/passwd", SUSPICIOUS_PATTERNS)
    check("directory traversal scores > 0", traversal.score > 0)
    local found_traversal = false
    for _, p in ipairs(traversal.patterns) do
        if p == "directory_traversal" or p == "etc_passwd" then found_traversal = true end
    end
    check("directory traversal pattern named", found_traversal)

    local sqli = rules.analyze_uri_patterns("/?id=1 UNION SELECT user,pass FROM wp_users", SUSPICIOUS_PATTERNS)
    check("sql union scores > 0", sqli.score > 0)

    local author_enum = rules.analyze_uri_patterns("/?author=1", SUSPICIOUS_PATTERNS)
    check("author enumeration scores high", author_enum.score >= 80)

    local layer1 = rules.analyze_uri_patterns("/?x=eval(1)", SUSPICIOUS_PATTERNS)
    check("caller-supplied suspicious_patterns contribute score", layer1.score >= 15)

    local nil_uri = rules.analyze_uri_patterns(nil, SUSPICIOUS_PATTERNS)
    check("nil uri returns zero score", nil_uri.score == 0)
end

print("== analyze_headers() ==")
do
    local clean = rules.analyze_headers({ ["User-Agent"] = "Mozilla/5.0 (Macintosh)" }, "GET")
    check("clean browser UA scores zero", clean.score == 0)

    local scanner = rules.analyze_headers({ ["User-Agent"] = "sqlmap/1.7" }, "GET")
    check("known scanner UA scores 50", scanner.score == 50)

    local missing_ua = rules.analyze_headers({}, "GET")
    check("missing UA scores 10", missing_ua.score == 10)

    local cve_header = rules.analyze_headers(
        { ["User-Agent"] = "Mozilla/5.0", ["X-WCPAY-PLATFORM-CHECKOUT-USER"] = "1" }, "GET")
    check("CVE-2023-28121 header scores 50", cve_header.score == 50)

    local post_no_referer = rules.analyze_headers({ ["User-Agent"] = "Mozilla/5.0" }, "POST")
    check("POST without Referer scores > 0", post_no_referer.score > 0)

    local post_with_referer = rules.analyze_headers(
        { ["User-Agent"] = "Mozilla/5.0", ["Referer"] = "https://example.com" }, "POST")
    check("POST with Referer does not add missing_referer score",
          post_with_referer.score < post_no_referer.score)

    local basic_auth = rules.analyze_headers({ ["Authorization"] = "Basic dXNlcjpwYXNz" }, "GET")
    check("basic auth attempt scores > 0", basic_auth.score > 0)

    local nil_headers = rules.analyze_headers(nil, "GET")
    check("nil headers returns zero score", nil_headers.score == 0)
end

print("== analyze_cve_patterns() ==")
do
    local match = rules.analyze_cve_patterns("/wp-json/wc/v3/orders", { ["X-WCPAY-PLATFORM-CHECKOUT-USER"] = "1" },
                                              nil, CVE_PATTERNS)
    check("header-based CVE match scores 40", match.score == 40)
    check("matched CVE listed", match.cves[1] == "CVE-2023-28121")

    local no_match = rules.analyze_cve_patterns("/shop/", {}, nil, CVE_PATTERNS)
    check("no CVE match scores zero", no_match.score == 0)

    local query_match = rules.analyze_cve_patterns("/", {}, "action=afi_search&q=1", CVE_PATTERNS)
    check("query-param CVE match scores 40", query_match.score == 40)

    local nil_uri = rules.analyze_cve_patterns(nil, {}, nil, CVE_PATTERNS)
    check("nil uri returns zero score", nil_uri.score == 0)
end

print("== analyze_request_method() ==")
do
    local get = rules.analyze_request_method("GET", nil)
    check("GET scores zero", get.score == 0)

    local options = rules.analyze_request_method("OPTIONS", nil)
    check("OPTIONS scores 10", options.score == 10)

    local trace = rules.analyze_request_method("TRACE", nil)
    check("TRACE scores 10", trace.score == 10)

    local override = rules.analyze_request_method("GET", "PUT")
    check("method override header scores 15", override.score == 15)

    local both = rules.analyze_request_method("OPTIONS", "PUT")
    check("both signals stack to 25", both.score == 25)
end

print("== score_automation_user_agent() ==")
do
    local curl = rules.score_automation_user_agent("curl/8.21.0")
    check("curl UA detected", curl.detected == true)
    check("curl UA scores 5", curl.score == 5)

    local wpscan = rules.score_automation_user_agent("WPScan v3.8.0")
    check("wpscan UA scores 30", wpscan.score == 30)

    local browser = rules.score_automation_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
    check("browser UA not detected as automation", browser.detected == false)

    local empty = rules.score_automation_user_agent(nil)
    check("nil UA not detected, zero score", empty.detected == false and empty.score == 0)
end

print("== url_decode() ==")
do
    check("percent-decodes", rules.url_decode("%2e%2e%2f") == "../")
    check("plus becomes space", rules.url_decode("hello+world") == "hello world")
    check("nil returns empty string", rules.url_decode(nil) == "")
end

print()
print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
