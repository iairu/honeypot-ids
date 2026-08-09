-- abuseipdb_rules.lua - Pure report-eligibility logic used by
-- abuseipdb_client.lua
--
-- Same split rationale as threat_rules.lua/router_rules.lua: no ngx.*
-- dependency, no reliance on _G.config/_G.utils, plain-`lua`-interpreter
-- testable (see tests/test_abuseipdb_rules.lua). abuseipdb_client.lua is
-- the adapter -- it does all the HTTP/timer/shared-dict I/O.
--
-- Lowest-priority candidate on architecture.canvas ("the value is marginal
-- given how small it already is") -- extracted anyway since it's a genuine,
-- self-contained pure core (a deterministic reason->category-ID whitelist
-- and the report-comment text it builds from it), same shape as every
-- other split done this session, just smaller.

local _M = {}

-- Maps a router.lua honeypot_reason to AbuseIPDB report category IDs.
-- Category reference: https://www.abuseipdb.com/categories
--
-- Exposed as module data (not just consumed internally) so callers/tests
-- can inspect the whitelist directly without re-deriving it.
_M.REASON_CATEGORIES = {
    cve_pattern_match               = { 15, 21 },  -- Hacking, Web App Attack
    vulnerable_plugin_access        = { 15, 21 },
    multiple_admin_attempts         = { 18 },       -- Brute-Force
    rapid_automation_detected       = { 19 },       -- Bad Web Bot
    suspicious_file_upload          = { 21 },       -- Web App Attack
    -- An IP that crossed router.lua Stage 6's IP-reputation threshold
    -- because Suricata fired on it (not the AbuseIPDB blacklist feed --
    -- see router.lua's honeypot_reason selection there) is just as
    -- deterministic a signal as cve_pattern_match/vulnerable_plugin_access
    -- above, so it's reportable too. Previously "bad_ip_reputation" (the
    -- reason string used for every IP-reputation hit regardless of source)
    -- was never in this whitelist, so Suricata-confirmed attackers were
    -- never actually reported to AbuseIPDB despite Suricata correctly
    -- detecting them.
    suricata_confirmed_alert        = { 15, 21 },
}

--- Whether a given routing reason is confident enough to justify reporting
--- the IP to AbuseIPDB (deterministic signal, not an aggregate heuristic).
--- @param reason string  routing_decision.session_data.honeypot_reason
--- @return boolean
function _M.is_reportable_reason(reason)
    return _M.REASON_CATEGORIES[reason] ~= nil
end

--- The AbuseIPDB category ID list for a given reason.
--- @param reason string
--- @return table|nil  List of integer category IDs, or nil if not reportable.
function _M.get_categories(reason)
    return _M.REASON_CATEGORIES[reason]
end

--- Build the free-text comment sent with an AbuseIPDB report.
--- @param reason   string
--- @param details  table|nil  Optional context; only .matched_cves is used.
--- @return string
function _M.build_report_comment(reason, details)
    local comment = "Honeypot detection: " .. reason
    if details and details.matched_cves and #details.matched_cves > 0 then
        comment = comment .. " (CVEs: " .. table.concat(details.matched_cves, ", ") .. ")"
    end
    return comment
end

return _M
