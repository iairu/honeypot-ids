-- lua_pattern_utils.lua - Shared pure string/pattern helpers
--
-- Small, stable helpers used by every *_rules.lua pure module
-- (threat_rules.lua, router_rules.lua, vulnerability_rules.lua,
-- upload_rules.lua). Previously each of those modules kept its own
-- verbatim copy of url_decode() and/or escape_pattern() -- both were
-- explicitly flagged at the time as "promote to a shared module if this
-- ever grows" (see threat_rules.lua's original comment); this is that
-- promotion, done once the duplication reached three independent copies of
-- escape_pattern() rather than speculatively up front.
--
-- No ngx.* dependency: plain-`lua`-interpreter testable, same as every
-- other *_rules.lua module (see tests/test_lua_pattern_utils.lua).

local _M = {}

-- ---------------------------------------------------------------------------
-- url_decode(str)
--
-- Percent-decodes a URL-encoded string and turns "+" into a space. Mirrors
-- _G.utils.url_decode (init.lua) -- kept as a separate pure copy here
-- rather than requiring init.lua, since init.lua sets up _G.config/_G.utils
-- as a side effect and pulling it in would reintroduce an ngx.*-adjacent
-- dependency into what's meant to be a plain-Lua-testable module.
-- ---------------------------------------------------------------------------
function _M.url_decode(str)
    if not str then return "" end
    str = string.gsub(str, "%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    str = string.gsub(str, "+", " ")
    return str
end

-- ---------------------------------------------------------------------------
-- escape_pattern(s)
--
-- Escapes Lua pattern magic characters ( ) . % + - * ? [ ] ^ $ so a plain
-- literal string (e.g. a plugin slug like "woocommerce-payments") can be
-- safely concatenated into a string.find()/string.match() pattern.
--
-- This exists because of a real, confirmed bug: concatenating an
-- un-escaped plugin slug straight into a pattern (e.g.
-- "/wp%-content/plugins/" .. plugin .. "/") silently broke the match for
-- every hyphenated slug, since Lua reads the "-" in "woocommerce-payments"
-- as its lazy-repetition magic character rather than a literal hyphen.
-- Confirmed via tests/test_vulnerability_rules.lua and
-- tests/test_router_rules.lua, where is_vulnerable_plugin_request()/
-- is_vulnerable_plugin_access() never matched any plugin except the one
-- slug without a hyphen ("cwmp") until this was applied.
-- ---------------------------------------------------------------------------
function _M.escape_pattern(s)
    return (s:gsub("[%(%)%.%%%+%-%*%?%[%]%^%$]", "%%%1"))
end

-- ---------------------------------------------------------------------------
-- is_install_wizard_uri(uri)
--
-- True only for WordPress's actual installer endpoint, /wp-admin/install.php
-- (query string ignored, e.g. "?step=1"). Shared by threat_rules.lua (skips
-- scoring) and router_rules.lua (skips honeypot diversion) so a WordPress
-- instance that hasn't been installed yet can still be set up through the
-- browser -- see wp_install_state.lua for how "not installed yet" itself is
-- determined. Deliberately an exact path match, not a substring match like
-- threat_rules.lua's "install%.php" scoring pattern: that broader pattern is
-- meant to catch things like "wp-config-install.php.bak" probes, which this
-- helper must NOT bypass.
-- ---------------------------------------------------------------------------
function _M.is_install_wizard_uri(uri)
    if not uri then
        return false
    end

    local uri_lower = string.lower(uri)
    local uri_path = uri_lower:match("^([^?]+)") or uri_lower

    return uri_path == "/wp-admin/install.php"
end

return _M
