-- shared_ip_rules.lua - Keep one attacker's IP reputation off their NAT neighbours
--
-- PURPOSE:
--   Many users can share one public address (carrier-grade NAT on mobile
--   networks, ISP CGNAT, offices, universities). Everything the proxy learns
--   from a client's own behaviour is kept on that client's SESSION
--   (session_identity_rules.lua): its score, admin/brute-force counters,
--   request rate and timing. What remains per address is outside reputation
--   only the address can carry -- Suricata alerts (Suricata sees packets, not
--   sessions) and AbuseIPDB. This module limits how much that per-address
--   reputation can do to a session that did nothing itself:
--
--   1. It is capped (ip_reputation_cap, below the honeypot threshold), so
--      address reputation alone can never divert a session; it only adds
--      weight to a session's own signals.
--   2. When the address is visibly shared -- at least shared_ip_sessions
--      distinct sessions active on it within shared_ip_window seconds -- it
--      contributes nothing. One attacker behind a CGNAT then cannot push
--      anyone else's score up; the attacker is still caught by their own
--      session's signals (CVE patterns, scanners, brute force, ...).
--
--   A negative contribution (the operator's IP whitelist) passes through
--   unchanged.
--
-- Pure module: no ngx.* dependency (see tests/test_shared_ip_rules.lua).

local _M = {}

--- Record that `actor` (a session id) was seen on an address at `now`, and
--- drop actors not seen within `window` seconds.
---
--- @param  state   table|nil  { [actor] = last_seen } for one address.
--- @param  actor   string|nil Session id (nil: only prune).
--- @param  now     number
--- @param  window  number     Seconds an actor counts as active.
--- @return table   The updated state.
--- @return number  How many distinct actors are active on the address.
function _M.track(state, actor, now, window)
    local out, count = {}, 0
    for a, seen in pairs(type(state) == "table" and state or {}) do
        if type(seen) == "number" and now - seen <= window then
            out[a] = seen
        end
    end
    if actor then
        out[actor] = now
    end
    for _ in pairs(out) do
        count = count + 1
    end
    return out, count
end

--- Whether an address with `count` active sessions is shared.
function _M.is_shared(count, min_sessions)
    return (count or 0) >= (min_sessions or 3)
end

--- How much an address's reputation adds to one session's request score.
---
--- @param  score   number   The address's (already decayed) reputation score.
--- @param  shared  boolean  is_shared() for the address.
--- @param  cap     number   ip_reputation_cap.
--- @return number  The contribution.
--- @return string|nil  "shared_ip" or "capped" when it was reduced.
function _M.contribution(score, shared, cap)
    score = tonumber(score) or 0
    if score <= 0 then
        return score, nil
    end
    if shared then
        return 0, "shared_ip"
    end
    if cap and score > cap then
        return cap, "capped"
    end
    return score, nil
end

return _M
