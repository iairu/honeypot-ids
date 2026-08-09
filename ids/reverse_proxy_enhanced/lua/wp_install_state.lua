-- wp_install_state.lua - Tracks whether WordPress has completed its
-- first-run install wizard, so install.php can be treated as legitimate
-- traffic instead of an attack until it has.
--
-- PURPOSE:
--   threat_analyzer.lua/router.lua score and divert /wp-admin/install.php
--   very aggressively (see threat_rules.lua's wp_install_access/install_php
--   checks) -- correct once a site is actually running (it's also one of
--   the dashboard's exploit presets, dashboard/core/exploits.py), but wrong
--   during the legitimate first-run setup wizard, which is exactly what a
--   fresh/never-installed WordPress instance needs install.php for.
--
-- DETECTION:
--   Nginx has no MySQL driver, so this doesn't inspect the database
--   directly. WordPress's own wp-admin/install.php prints the literal
--   string "You appear to have already installed WordPress" (from
--   is_blog_installed(), see wp-admin/install.php) when the site IS already
--   installed, and renders the real setup form otherwise. A lightweight
--   periodic GET to that same endpoint (see init_worker.lua's timer) is
--   therefore a reliable, version-independent signal -- no different in
--   spirit from health_check.lua's own periodic backend probing, which this
--   module deliberately mirrors the shape of.
--
-- SCOPE:
--   Only production_backend is probed/consulted. Honeypot pool databases
--   are raw copies of production_database_data (see docker-compose.yml's
--   init_setup/honeypot_db_migration), so they share production's install
--   state by construction -- there is no need to resolve a pool assignment
--   before the routing pipeline can ask this question.
--
-- FAIL-SAFE DEFAULT:
--   is_installed() defaults to true (installed) whenever state is
--   missing/unknown/stale. That keeps today's strict scoring/routing
--   behavior as the default -- a probe outage must never silently open up
--   an exploit path, only a CONFIRMED "not installed yet" response does.

local http = require "resty.http"

local _M = {}

-- Shared dictionary for cached install state -- reuses threat_intel, the
-- same cross-worker dict health_check.lua and pool_router.lua already read
-- health/threat data from, rather than declaring a new lua_shared_dict.
local install_state = ngx.shared.threat_intel

local INSTALLED_MARKER = "already installed"

-- ---------------------------------------------------------------------------
-- refresh(backend_name, backend_url)
--
-- GETs backend_url .. "/wp-admin/install.php" and caches whether the
-- response body contains WordPress's own "already installed" message.
-- On any request error (backend down, timeout, ...) the previous cached
-- value is left untouched -- a transient failure must not flip a site from
-- "installed" (strict) to "not installed" (permissive) or vice versa.
--
-- @param backend_name  string  e.g. "production_backend" (used as the cache key)
-- @param backend_url   string  e.g. "http://production_eshop"
-- ---------------------------------------------------------------------------
function _M.refresh(backend_name, backend_url)
    local httpc = http.new()
    httpc:set_timeouts(5000, 5000, 5000)

    local res, err = httpc:request_uri(backend_url .. "/wp-admin/install.php", {
        method = "GET",
        keepalive_timeout = 60000,
        keepalive_pool = 100
    })

    if not res then
        ngx.log(ngx.WARN, "[WP_INSTALL_STATE] Probe failed for ", backend_name, ": ", err,
                " -- keeping previous cached state")
        return
    end

    local body = res.body or ""
    local installed = string.find(string.lower(body), INSTALLED_MARKER, 1, true) ~= nil

    install_state:set("wp_installed:" .. backend_name, installed and "1" or "0")

    if not installed then
        ngx.log(ngx.INFO, "[WP_INSTALL_STATE] ", backend_name,
                " has NOT completed WordPress setup yet -- install.php will be allowed through")
    end
end

-- ---------------------------------------------------------------------------
-- is_installed(backend_name)
--
-- @return boolean  true (installed/unknown) unless a refresh() has
--                   explicitly confirmed the site is not yet installed.
-- ---------------------------------------------------------------------------
function _M.is_installed(backend_name)
    local cached = install_state:get("wp_installed:" .. backend_name)
    if cached == "0" then
        return false
    end
    return true
end

return _M
