-- test_lua_pattern_utils.lua - Standalone unit tests
--
-- Runs under a plain `lua` interpreter (no OpenResty/ngx required), since
-- lua_pattern_utils.lua has no ngx.* dependency by design.
--
-- Usage:
--   cd ids/reverse_proxy_enhanced/lua/tests
--   lua test_lua_pattern_utils.lua

package.path = "../?.lua;" .. package.path
local utils = require "lua_pattern_utils"

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

print("== url_decode() ==")
do
    check("percent-decodes", utils.url_decode("%2e%2e%2f") == "../")
    check("plus becomes space", utils.url_decode("hello+world") == "hello world")
    check("nil returns empty string", utils.url_decode(nil) == "")
    check("plain text unchanged", utils.url_decode("shop") == "shop")
end

print("== escape_pattern() ==")
do
    local escaped = utils.escape_pattern("woocommerce-payments")
    check("hyphen escaped", string.find(escaped, "%%%-") ~= nil)

    local ok, found = pcall(string.find, "/wp-content/plugins/woocommerce-payments/api.php",
                             "/wp%-content/plugins/" .. escaped .. "/")
    check("escaped slug matches the real literal string", ok == true and found ~= nil)

    local unescaped_would_fail = string.find(
        "/wp-content/plugins/woocommerce-payments/api.php",
        "/wp%-content/plugins/" .. "woocommerce-payments" .. "/")
    check("regression: un-escaped concatenation is the bug this prevents", unescaped_would_fail == nil)

    check("no magic chars in a plain slug stays unchanged", utils.escape_pattern("cwmp") == "cwmp")

    local dot_escaped = utils.escape_pattern("a.b")
    check("dot escaped", dot_escaped == "a%.b")
end

print("== is_install_wizard_uri() ==")
do
    check("matches bare install.php", utils.is_install_wizard_uri("/wp-admin/install.php") == true)
    check("matches with query string", utils.is_install_wizard_uri("/wp-admin/install.php?step=1") == true)
    check("case-insensitive", utils.is_install_wizard_uri("/WP-ADMIN/INSTALL.PHP?step=2") == true)
    check("nil returns false", utils.is_install_wizard_uri(nil) == false)
    check("unrelated uri returns false", utils.is_install_wizard_uri("/wp-admin/") == false)
    check("does not match a substring probe (regression)",
          utils.is_install_wizard_uri("/wp-content/uploads/wp-config-install.php.bak") == false)
    check("does not match install.php outside wp-admin",
          utils.is_install_wizard_uri("/install.php") == false)
end

print()
print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
