-- abuseipdb_client.lua - AbuseIPDB threat-intelligence client
--
-- PURPOSE:
--   Integrates the free-tier AbuseIPDB API (https://www.abuseipdb.com) as a
--   third threat-intelligence source alongside the Suricata fast.log parser
--   (init_worker.lua) and the static seed data (init.lua).  Three integration
--   points, all documented in .env.example:
--
--     1. Bulk blacklist feed  – fetch_blacklist(), called periodically from
--        init_worker.lua (worker 0 only).  Pulls the /blacklist endpoint and
--        merges high-confidence IPs into the threat_intel shared dict that
--        threat_analyzer.check_ip_reputation() already reads.
--     2. On-demand reputation – check_ip_async(ip), called from
--        threat_analyzer.check_ip_reputation() the first time an unrecognised
--        IP is seen.  Never blocks the current request: the HTTP round-trip
--        runs in a zero-delay ngx.timer so the result is only available for
--        *subsequent* requests from that IP, keeping the hot path latency
--        budget intact.
--     3. Confirmed-attacker report-back – report_ip_async(ip, reason), called
--        from router.lua's assign_honeypot_pool() for high-confidence routing
--        reasons only (CVE match, vulnerable-plugin access, brute-force,
--        confirmed automation, suspicious upload).  Also fire-and-forget via
--        ngx.timer.
--
-- DESIGN NOTES:
--   - All network I/O happens inside ngx.timer.at(0, ...) callbacks so this
--     module never adds latency to the request currently being processed.
--   - A missing or placeholder ABUSEIPDB_API_KEY disables every function
--     here (is_enabled() returns false); callers are expected to check it
--     or simply call the async wrappers, which no-op safely when disabled.
--   - fetch_blacklist() additionally requires config.abuseipdb.
--     blacklist_enabled (is_blacklist_enabled()), off by default -- the
--     bulk pull is the single biggest quota consumer of the three
--     integrations here, and is cached in Redis (see fetch_blacklist()'s
--     own comment) so a fresh-enough cache is reused across restarts
--     instead of triggering a real API call every time.
--   - The daily on-demand check quota (ABUSEIPDB_DAILY_CHECK_LIMIT) is
--     tracked in the threat_intel shared dict so it is shared across all
--     Nginx worker processes, not just the worker that happens to run it.
--   - Report-back deduplicates per IP for 24h so a sustained attack session
--     generates one report, not one per request.
--
-- DEPENDENCIES:
--   resty.http  – optional; module degrades to a no-op if unavailable.
--   cjson       – JSON encode/decode for API responses and threat_intel blobs.
--   _G.config.abuseipdb – api_key / confidence_minimum / daily_check_limit.

local cjson = require "cjson"
local abuseipdb_rules = require "abuseipdb_rules"

local http_ok, http = pcall(require, "resty.http")

local _M = {}

local API_BASE = "https://api.abuseipdb.com/api/v2"

-- Placeholder value shipped in .env.example; treated as "not configured".
local PLACEHOLDER_KEY = "change_this_abuseipdb_api_key"

--- Whether the AbuseIPDB integration has a usable API key configured.
--- @return boolean
function _M.is_enabled()
    local key = _G.config and _G.config.abuseipdb and _G.config.abuseipdb.api_key
    return http_ok and key ~= nil and key ~= "" and key ~= PLACEHOLDER_KEY
end

--- Whether the bulk /blacklist pull specifically is enabled -- a separate
--- opt-in from is_enabled(), off by default (see init.lua's
--- config.abuseipdb.blacklist_enabled comment for why: it's the biggest
--- quota consumer of the three integrations, and free-tier accounts can
--- have a real daily cap as low as single digits). On-demand check/
--- report-back only ever consult is_enabled(), not this.
--- @return boolean
function _M.is_blacklist_enabled()
    return _M.is_enabled() and _G.config.abuseipdb.blacklist_enabled == true
end

-- ---------------------------------------------------------------------------
-- Internal: merge a table of {ip -> {score, reason}} into the threat_intel
-- shared dict's "threat_ips" blob, taking the max score when an IP already
-- has an entry (e.g. from a Suricata alert) so we never downgrade an
-- existing higher-confidence signal.
-- ---------------------------------------------------------------------------
local function merge_threat_ips(updates)
    local threat_intel = ngx.shared.threat_intel
    if not threat_intel then return end

    local current_json = threat_intel:get("threat_ips")
    local threat_ips = current_json and cjson.decode(current_json) or {}

    for ip, entry in pairs(updates) do
        local existing = threat_ips[ip]
        if not existing or (entry.score or 0) > (existing.score or 0) then
            threat_ips[ip] = entry
        end
    end

    threat_intel:set("threat_ips", cjson.encode(threat_ips))
end

-- ---------------------------------------------------------------------------
-- Internal: daily on-demand check quota, shared across workers via
-- threat_intel.  Resets automatically when the UTC date rolls over.
-- ---------------------------------------------------------------------------
local function quota_available()
    local threat_intel = ngx.shared.threat_intel
    if not threat_intel then return false end

    local today = os.date("!%Y-%m-%d")
    local stored_date = threat_intel:get("abuseipdb_quota_date")

    if stored_date ~= today then
        threat_intel:set("abuseipdb_quota_date", today)
        threat_intel:set("abuseipdb_quota_count", 0)
        return true
    end

    local count = threat_intel:get("abuseipdb_quota_count") or 0
    local limit = _G.config.abuseipdb.daily_check_limit
    return count < limit
end

local function increment_quota()
    local threat_intel = ngx.shared.threat_intel
    if threat_intel then
        local ok, new_count = pcall(function()
            return threat_intel:incr("abuseipdb_quota_count", 1, 0)
        end)
        if not ok then
            threat_intel:set("abuseipdb_quota_count", 1)
        end
    end
end

-- ---------------------------------------------------------------------------
-- Redis-backed cache for the bulk blacklist pull -- survives worker/
-- container restarts, unlike merge_threat_ips()'s target (the in-memory
-- threat_intel shared dict, which starts empty on every restart). Without
-- this, EVERY restart of reverse_proxy re-triggered a fresh /blacklist call
-- 15s after startup (see init_worker.lua's scheduling) regardless of how
-- recently the last one ran -- confirmed this alone can burn through a
-- free-tier account's real daily quota (as low as single digits on some
-- accounts) within a handful of dev-session restarts, long before the
-- periodic timer.every() interval would have fired again on its own.
-- ---------------------------------------------------------------------------
local BLACKLIST_CACHE_KEY = "abuseipdb_blacklist_cache"

local function load_cached_blacklist()
    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.WARN, "[ABUSEIPDB] Redis unavailable for blacklist cache read: ", err)
        return nil
    end
    local cached_json = red:get(BLACKLIST_CACHE_KEY)
    _G.redis_pool.close_connection(red)

    if not cached_json or cached_json == ngx.null then
        return nil
    end
    local ok, decoded = pcall(cjson.decode, cached_json)
    if not ok or not decoded.fetched_at or not decoded.data then
        return nil
    end
    return decoded
end

local function save_cached_blacklist(updates)
    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.WARN, "[ABUSEIPDB] Redis unavailable for blacklist cache write: ", err)
        return
    end
    local payload = cjson.encode({ fetched_at = ngx.time(), data = updates })
    -- Expire well after the next scheduled refresh would naturally occur,
    -- so a stale key can never quietly outlive its own freshness check.
    local ttl = (_G.config.abuseipdb.blacklist_refresh_hours or 24) * 3600 * 3
    red:setex(BLACKLIST_CACHE_KEY, ttl, payload)
    _G.redis_pool.close_connection(red)
end

-- ---------------------------------------------------------------------------
-- fetch_blacklist()
--
-- Pulls the AbuseIPDB /blacklist endpoint (IPs at or above
-- config.abuseipdb.confidence_minimum) and merges them into threat_intel --
-- but only if config.abuseipdb.blacklist_enabled is on AND the Redis-backed
-- cache is older than config.abuseipdb.blacklist_refresh_hours (or missing).
-- A fresh-enough cache is re-merged into threat_intel with no API call at
-- all -- this is what actually protects a small daily quota, not just the
-- long timer.every() interval init_worker.lua schedules this on.
--
-- Blocking call (on an actual cache miss): must only be invoked from inside
-- an ngx.timer callback, never from the request-processing (access_by_lua)
-- phase.
-- ---------------------------------------------------------------------------
function _M.fetch_blacklist()
    if not _M.is_blacklist_enabled() then
        return
    end

    local refresh_seconds = (_G.config.abuseipdb.blacklist_refresh_hours or 24) * 3600
    local cached = load_cached_blacklist()
    if cached and (ngx.time() - cached.fetched_at) < refresh_seconds then
        merge_threat_ips(cached.data)
        ngx.log(ngx.INFO, "[ABUSEIPDB] Blacklist served from cache (age=",
                ngx.time() - cached.fetched_at, "s, refresh interval=", refresh_seconds,
                "s) -- no API call made")
        return
    end

    local httpc = http.new()
    httpc:set_timeout(10000)

    local res, err = httpc:request_uri(API_BASE .. "/blacklist", {
        method = "GET",
        query = {
            confidenceMinimum = tostring(_G.config.abuseipdb.confidence_minimum),
            limit = "10000"
        },
        headers = {
            ["Key"] = _G.config.abuseipdb.api_key,
            ["Accept"] = "application/json"
        },
        ssl_verify = true
    })

    if not res then
        ngx.log(ngx.WARN, "[ABUSEIPDB] Blacklist fetch failed: ", err or "unknown error")
        return
    end

    if res.status ~= 200 then
        ngx.log(ngx.WARN, "[ABUSEIPDB] Blacklist fetch returned HTTP ", res.status, ": ", (res.body or ""):sub(1, 200))
        return
    end

    local ok, decoded = pcall(cjson.decode, res.body)
    if not ok or not decoded.data then
        ngx.log(ngx.WARN, "[ABUSEIPDB] Blacklist response could not be parsed")
        return
    end

    local updates = {}
    for _, entry in ipairs(decoded.data) do
        if entry.ipAddress then
            updates[entry.ipAddress] = {
                score = entry.abuseConfidenceScore or _G.config.abuseipdb.confidence_minimum,
                reason = "abuseipdb_blacklist",
                updated = ngx.time()
            }
        end
    end

    merge_threat_ips(updates)
    save_cached_blacklist(updates)
    ngx.log(ngx.INFO, "[ABUSEIPDB] Blacklist feed merged ", #decoded.data, " IPs (confidenceMinimum=",
            _G.config.abuseipdb.confidence_minimum, ") -- refreshed from API, cached for ",
            _G.config.abuseipdb.blacklist_refresh_hours, "h")
end

-- ---------------------------------------------------------------------------
-- check_ip_async(ip)
--
-- Schedules a zero-delay background timer that queries the AbuseIPDB
-- /check endpoint for a single IP and writes the result into threat_intel.
-- Safe to call from the request-processing phase: returns immediately and
-- never affects the current request's routing decision, only future ones.
--
-- Respects the daily quota and de-duplicates: an IP that was checked in the
-- last hour is not re-queried.
-- ---------------------------------------------------------------------------
function _M.check_ip_async(ip)
    if not _M.is_enabled() or not ip then
        return
    end

    local threat_intel = ngx.shared.threat_intel
    if not threat_intel then return end

    local dedup_key = "abuseipdb_checked:" .. ip
    if threat_intel:get(dedup_key) then
        return  -- checked recently, avoid burning quota on repeat visitors
    end

    local ok, err = ngx.timer.at(0, function(premature)
        if premature then return end

        if not quota_available() then
            ngx.log(ngx.DEBUG, "[ABUSEIPDB] Daily on-demand check quota exhausted, skipping ", ip)
            return
        end

        -- Mark as checked immediately so concurrent requests from the same
        -- IP don't race to schedule duplicate timers before this one completes.
        threat_intel:set(dedup_key, true, 3600)

        local httpc = http.new()
        httpc:set_timeout(5000)

        local res, req_err = httpc:request_uri(API_BASE .. "/check", {
            method = "GET",
            query = { ipAddress = ip, maxAgeInDays = "90" },
            headers = {
                ["Key"] = _G.config.abuseipdb.api_key,
                ["Accept"] = "application/json"
            },
            ssl_verify = true
        })

        increment_quota()

        if not res then
            ngx.log(ngx.WARN, "[ABUSEIPDB] Check failed for ", ip, ": ", req_err or "unknown error")
            return
        end

        if res.status ~= 200 then
            ngx.log(ngx.WARN, "[ABUSEIPDB] Check for ", ip, " returned HTTP ", res.status)
            return
        end

        local decode_ok, decoded = pcall(cjson.decode, res.body)
        if not decode_ok or not decoded.data then
            ngx.log(ngx.WARN, "[ABUSEIPDB] Check response for ", ip, " could not be parsed")
            return
        end

        local confidence = decoded.data.abuseConfidenceScore or 0
        if confidence > 0 then
            merge_threat_ips({
                [ip] = {
                    score = confidence,
                    reason = "abuseipdb_check",
                    updated = ngx.time()
                }
            })
            ngx.log(ngx.INFO, "[ABUSEIPDB] On-demand check: ", ip, " confidence=", confidence)
        end
    end)

    if not ok then
        ngx.log(ngx.ERR, "[ABUSEIPDB] Failed to schedule check for ", ip, ": ", err)
    end
end

-- REASON_CATEGORIES / is_reportable_reason moved to abuseipdb_rules.lua
-- (pure reason->category-ID whitelist + lookup, architecture.canvas's
-- lowest-priority refactor candidate -- extracted for consistency with the
-- rest of this session's pure/adapter splits, see tests/test_abuseipdb_rules.lua).
-- Re-exported here for backward compatibility with anything already calling
-- abuseipdb_client.is_reportable_reason() directly.
_M.is_reportable_reason = abuseipdb_rules.is_reportable_reason

-- ---------------------------------------------------------------------------
-- report_ip_async(ip, reason, details)
--
-- Schedules a zero-delay background timer that reports a confirmed attacker
-- IP to AbuseIPDB via POST /report. Only called by router.lua for reasons
-- present in REASON_CATEGORIES (deterministic exploit/brute-force/upload
-- signals) to keep report quality high and avoid polluting the public feed
-- with soft heuristic matches.
--
-- De-duplicates per IP for 24h.
--
-- @param ip       string  Attacker IP address.
-- @param reason    string  router.lua honeypot_reason (must be reportable).
-- @param details   table|nil  Optional extra context folded into the comment.
-- ---------------------------------------------------------------------------
function _M.report_ip_async(ip, reason, details)
    if not _M.is_enabled() or not ip or not _M.is_reportable_reason(reason) then
        return
    end

    local threat_intel = ngx.shared.threat_intel
    if not threat_intel then return end

    local dedup_key = "abuseipdb_reported:" .. ip
    if threat_intel:get(dedup_key) then
        return
    end
    threat_intel:set(dedup_key, true, 86400)

    local categories = abuseipdb_rules.get_categories(reason)
    local comment = abuseipdb_rules.build_report_comment(reason, details)

    local ok, err = ngx.timer.at(0, function(premature)
        if premature then return end

        local httpc = http.new()
        httpc:set_timeout(5000)

        local cat_strings = {}
        for _, c in ipairs(categories) do
            table.insert(cat_strings, tostring(c))
        end

        local res, req_err = httpc:request_uri(API_BASE .. "/report", {
            method = "POST",
            body = "ip=" .. ngx.escape_uri(ip) ..
                   "&categories=" .. table.concat(cat_strings, ",") ..
                   "&comment=" .. ngx.escape_uri(comment),
            headers = {
                ["Key"] = _G.config.abuseipdb.api_key,
                ["Accept"] = "application/json",
                ["Content-Type"] = "application/x-www-form-urlencoded"
            },
            ssl_verify = true
        })

        if not res then
            ngx.log(ngx.WARN, "[ABUSEIPDB] Report-back failed for ", ip, ": ", req_err or "unknown error")
            return
        end

        if res.status == 200 then
            ngx.log(ngx.INFO, "[ABUSEIPDB] Reported ", ip, " (reason=", reason, ", categories=",
                    table.concat(cat_strings, ","), ")")
        else
            ngx.log(ngx.WARN, "[ABUSEIPDB] Report-back for ", ip, " returned HTTP ", res.status, ": ",
                    (res.body or ""):sub(1, 200))
        end
    end)

    if not ok then
        ngx.log(ngx.ERR, "[ABUSEIPDB] Failed to schedule report for ", ip, ": ", err)
    end
end

return _M
