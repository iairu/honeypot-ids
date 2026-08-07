-- test_upload_rules.lua - Standalone unit tests
--
-- Runs under a plain `lua` interpreter (no OpenResty/ngx required), since
-- upload_rules.lua has no ngx.* dependency by design.
--
-- Usage:
--   cd openstack-work/reverse_proxy_enhanced/lua/tests
--   lua test_upload_rules.lua

package.path = "../?.lua;" .. package.path
local rules = require "upload_rules"

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

print("== is_file_upload() ==")
do
    check("multipart content-type detected", rules.is_file_upload("multipart/form-data; boundary=x", "") == true)
    check("upload keyword in args detected", rules.is_file_upload("", "action=upload&x=1") == true)
    check("clean GET request not a file upload", rules.is_file_upload("", "page=2") == false)
end

print("== analyze_content_type() ==")
do
    local missing = rules.analyze_content_type("")
    check("missing content-type flagged", missing.suspicious == true and missing.reason == "missing_content_type")

    local spoofed = rules.analyze_content_type("image/gif; php")
    check("php disguised as image flagged", spoofed.suspicious == true and spoofed.reason == "php_disguised_as_image")

    local clean = rules.analyze_content_type("multipart/form-data; boundary=abc")
    check("clean multipart content-type not flagged", clean.suspicious == false)

    local unusual = rules.analyze_content_type("application/x-msdownload")
    check("unusual executable type flagged", unusual.suspicious == true)
end

print("== analyze_upload_parameters() (regression test for the crash bug) ==")
do
    -- This exact input previously crashed with "invalid capture index %2"
    -- via the unescaped %2e%2e%2f / %2e%2e/ entries in traversal_patterns --
    -- confirmed live: a real POST to /wp-admin/admin-ajax.php with this
    -- query string 500'd before the fix.
    local ok, result = pcall(rules.analyze_upload_parameters, "action=upload&file=test.jpg")
    check("does not crash on a realistic upload request", ok == true)
    if ok then
        check("clean filename scores zero", result.score == 0)
    end

    local php_ext = rules.analyze_upload_parameters("file=shell.php")
    check("php extension detected", php_ext.score > 0)
    local found_php = false
    for _, f in ipairs(php_ext.risk_factors) do
        if f == "php_extension" then found_php = true end
    end
    check("php_extension risk factor recorded", found_php)

    local traversal_plain = rules.analyze_upload_parameters("file=../../etc/passwd")
    check("plain directory traversal detected", traversal_plain.score > 0)

    local traversal_encoded = rules.analyze_upload_parameters("file=%2e%2e%2fetc%2fpasswd")
    local ok2, _ = pcall(function() return traversal_encoded end)
    check("encoded traversal input does not crash", ok2 == true)
    check("encoded directory traversal detected", traversal_encoded.score > 0)

    local empty = rules.analyze_upload_parameters("")
    check("empty args scores zero", empty.score == 0)

    local nil_args = rules.analyze_upload_parameters(nil)
    check("nil args scores zero", nil_args.score == 0)
end

print("== analyze_upload_endpoint() ==")
do
    local cve_endpoint = rules.analyze_upload_endpoint("/wp-admin/admin-ajax.php?action=dnd_codedropz_upload")
    check("CVE-2025-4403 endpoint detected", cve_endpoint.score >= 50)

    local clean = rules.analyze_upload_endpoint("/shop/checkout/")
    check("clean endpoint scores zero", clean.score == 0)

    check("nil uri returns zero score", rules.analyze_upload_endpoint(nil).score == 0)

    -- Regression test: a plain admin-ajax.php hit with no known-vulnerable
    -- action name must score zero. This used to score +20 unconditionally
    -- (the "admin_ajax_upload" blanket rule) -- confirmed live it fired on
    -- a normal WooCommerce product-page visit, since every admin-ajax.php
    -- request matches the URI by definition, real signal or not.
    local plain_ajax = rules.analyze_upload_endpoint("/wp-admin/admin-ajax.php")
    check("plain admin-ajax.php with no known-vulnerable action scores zero", plain_ajax.score == 0)
    check("plain admin-ajax.php with no known-vulnerable action has no risk factors",
          #plain_ajax.risk_factors == 0)
end

print("== analyze_upload_user_agent() ==")
do
    local missing = rules.analyze_upload_user_agent("")
    check("missing UA scores 15", missing.score == 15)

    local curl = rules.analyze_upload_user_agent("curl/8.21.0")
    check("curl UA scores > 0", curl.score > 0)

    local metasploit = rules.analyze_upload_user_agent("Mozilla/5.0 metasploit")
    check("metasploit UA scores highest tool weight", metasploit.score >= 45)

    local browser = rules.analyze_upload_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
    check("real browser UA scores zero", browser.score == 0)
end

print("== analyze_upload_bypass_techniques() ==")
do
    local missing_boundary = rules.analyze_upload_bypass_techniques("multipart/form-data", "")
    check("multipart without boundary flagged", missing_boundary.score > 0)

    local clean_multipart = rules.analyze_upload_bypass_techniques("multipart/form-data; boundary=abc123", "")
    check("multipart with normal boundary not flagged for that alone", clean_multipart.score == 0)

    local polyglot = rules.analyze_upload_bypass_techniques("image/gif; php code", "")
    check("gif/php polyglot detected", polyglot.score > 0)

    local null_byte = rules.analyze_upload_bypass_techniques("", "file=shell.php%00.gif")
    check("null byte injection detected", null_byte.score > 0)
end

print("== should_block_upload() ==")
do
    local high_score = rules.should_block_upload({ threat_score = 80, risk_factors = {} })
    check("high threat score blocks", (rules.should_block_upload({ threat_score = 80, risk_factors = {} })) == true)

    local low_score = rules.should_block_upload({ threat_score = 5, risk_factors = {} })
    check("low threat score with no factors allowed", low_score == false)

    local critical, reason = rules.should_block_upload({
        threat_score = 20,
        risk_factors = { "php_extension", "metasploit_framework" }
    })
    check("multiple critical factors blocks", critical == true)
    check("reason is multiple_critical_factors", reason == "multiple_critical_factors")

    local combo = rules.should_block_upload({
        threat_score = 20,
        risk_factors = { "php_extension", "double_extension_bypass" }
    })
    check("executable + bypass combination blocks", combo == true)
end

print()
print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
