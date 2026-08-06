-- suricata_rules.lua - Pure eve.json alert parsing/scoring used by
-- init_worker.lua's Suricata log ingestion.
--
-- PURPOSE:
--   Suricata alerts feed threat_intel.threat_ips (read by
--   threat_analyzer.check_ip_reputation, gating router.lua's Stage 6 "IP
--   reputation" honeypot diversion). This module holds the pure, testable
--   pieces of that pipeline: parsing one eve.json line into an alert record
--   (or nil for the non-alert event types eve.json interleaves -- flow,
--   netflow, http, dns, tls, ...), and turning an alert into a threat-score
--   delta and a human-readable reason string.
--
-- WHY eve.json, NOT fast.log:
--   The previous version of this pipeline regex-parsed fast.log with a
--   pattern that had 8 capture groups destructured into 7 local variables
--   (timestamp, priority, classification, src_ip, src_port, dst_ip,
--   dst_port) -- Lua silently drops the last matched value when there are
--   more captures than destination variables, so every field from
--   `priority` onward was shifted by one position. `src_ip` actually
--   received the classification TEXT (e.g. "Attempted Denial of Service"),
--   never a real IP address. Confirmed live against a real fast.log line
--   before this fix: threat_ips ended up keyed by that string, not the
--   attacker's IP, so Suricata alerts never actually reached the IP
--   reputation gate for the real attacker. eve.json is structured JSON --
--   src_ip, alert.signature, alert.severity, alert.category are named
--   fields, not positionally inferred, so this entire bug class can't
--   recur.
--
-- KNOWN CAVEAT -- src_ip attribution for same-host (loopback) testing:
--   Suricata runs with network_mode: host and interface "any" (see
--   docker-compose.yml's suricata_ids service), so it sees every hop of a
--   request, not just the client->nginx leg. Verified live: curling
--   127.0.0.1 from the docker host itself, nginx's own access log shows
--   client 172.21.0.1 (the docker bridge gateway) for a request, while
--   Suricata's eve.json alert for the SAME request reports src_ip as a
--   different internal address (e.g. 172.21.0.6/.9 -- whichever
--   container-to-container hop the matching content actually traversed).
--   The two never correlate in this same-host test setup, so a
--   Suricata-flagged score currently accumulates against an address
--   router.lua's remote_ip never actually sees, and Stage 6 never fires
--   from it locally. For genuine external attacker traffic (the real
--   target use case -- see ARCHITECTURE.md's two-host deployment) this is
--   expected to work correctly: Docker's DNAT-based port publishing
--   preserves the source IP on the client->host leg, so Suricata should
--   capture the real external IP there, matching what nginx logs as
--   remote_addr -- but that has NOT been verified against genuine
--   external traffic (not available in this dev environment). Flagged
--   here rather than silently assumed fixed.
--
-- SEVERITY -> SCORE:
--   Suricata's own severity field (lower number = more severe, standard
--   Suricata/Snort convention: 1=high, 2=medium, 3=low) grades the score
--   bump instead of the previous flat +20-per-alert regardless of what
--   fired. A single confirmed CVE-exploit-attempt rule (priority 1 in
--   local.rules) now moves an IP most of the way to Stage 6's >50
--   honeypot-diversion threshold on its own; a low-priority scan/recon
--   signature contributes much less, so noisy background scanning doesn't
--   force honeypot diversion as readily as a real exploit attempt does.

-- No cjson dependency here, deliberately -- matches this codebase's
-- pool_router_rules.lua/pool_router.lua split: the impure glue file
-- (init_worker.lua) does the cjson.decode (it already requires cjson for
-- everything else it touches) and hands this module the decoded table, so
-- this module stays plain-`lua`-interpreter testable without needing a
-- cjson shim in the test environment.

local _M = {}

-- Score added to an IP's running total per alert, keyed by Suricata's
-- severity field. Anything not 1 or 2 (including missing/malformed) falls
-- through to the severity-3/unknown bucket.
local SEVERITY_SCORE = {
    [1] = 50,
    [2] = 25,
}
local DEFAULT_SEVERITY_SCORE = 10

-- Ceiling matching threat_analyzer.check_ip_reputation's known_threat scale
-- (0-100) -- a single severity-1 alert plus one prior alert of any severity
-- is already enough to cross Stage 6's >50 gate, by design.
local MAX_SCORE = 100

--- Cheap pre-check: does this raw eve.json line look like an "alert" event?
--- eve.json interleaves alert/flow/netflow/http/dns/tls/... event types in
--- one file, and flow/netflow accounting events vastly outnumber alerts in
--- practice -- this lets the caller skip a full JSON decode (and the
--- allocation that comes with it) for the large majority of lines. A
--- plain substring check, not a JSON parse, so it can't itself throw on a
--- malformed/partial line (e.g. one still being written).
---
--- @param  line  string|nil  One raw line from eve.json.
--- @return boolean
function _M.is_alert_line(line)
    return line ~= nil and line:find('"event_type":"alert"', 1, true) ~= nil
end

--- Extract an alert record from an already-decoded eve.json event object.
--- Decoding (cjson.decode) is the caller's job -- see the module docstring
--- for why that split exists. Returns nil for anything that isn't a
--- well-formed alert event (wrong event_type, missing alert/src_ip/
--- signature) rather than raising, since a malformed line should be
--- skipped, not crash the 30s ingestion timer.
---
--- @param  decoded  table  Result of cjson.decode() on one eve.json line.
--- @return table|nil  { timestamp, src_ip, src_port, dest_ip, dest_port,
---                       signature, signature_id, category, severity }
function _M.extract_alert(decoded)
    if type(decoded) ~= "table" or decoded.event_type ~= "alert" then
        return nil
    end

    local alert = decoded.alert
    if type(alert) ~= "table" or not decoded.src_ip or not alert.signature then
        return nil
    end

    return {
        timestamp    = decoded.timestamp,
        src_ip       = decoded.src_ip,
        src_port     = decoded.src_port,
        dest_ip      = decoded.dest_ip,
        dest_port    = decoded.dest_port,
        signature    = alert.signature,
        signature_id = alert.signature_id,
        category     = alert.category,
        severity     = tonumber(alert.severity),
    }
end

--- Score delta for one alert, graded by Suricata's severity field.
---
--- @param  severity  number|nil  Suricata's alert.severity (1=high..3=low).
--- @return integer
function _M.severity_to_score(severity)
    return SEVERITY_SCORE[severity] or DEFAULT_SEVERITY_SCORE
end

--- Apply an alert's score delta to a previous running score, capped at
--- MAX_SCORE. Never decreases -- alerts only ever raise suspicion here;
--- decay/expiry (if ever added) is a separate concern.
---
--- @param  previous_score  number|nil
--- @param  severity        number|nil
--- @return integer
function _M.next_score(previous_score, severity)
    local delta = _M.severity_to_score(severity)
    return math.min((previous_score or 0) + delta, MAX_SCORE)
end

--- Human-readable reason string for threat_ips[ip].reason, surfaced all the
--- way to router.lua's Stage 6 honeypot_reason and from there into
--- AbuseIPDB report-back and session logs -- so "why was this IP diverted"
--- says the actual matched signature (e.g. "suricata: CVE-2023-28121
--- WooCommerce Payments Unauthorized Admin Access Attempt") instead of a
--- generic "bad_ip_reputation".
---
--- @param  alert  table  A record returned by parse_eve_alert_line().
--- @return string
function _M.build_reason(alert)
    return "suricata: " .. tostring(alert.signature)
end

return _M
