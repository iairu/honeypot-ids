-- decay_policy.lua
--
-- Escalation policy shared by the two threat-score decay paths:
--   * router_rules.decayed_score()   -- per-SESSION suspicion decay (the
--     "can this session earn its way back to production" re-check).
--   * suricata_rules.decayed_score() -- per-IP reputation (threat_ips) decay.
--
-- Both used to be a flat exponential: score = peak * 0.5^(elapsed/half_life),
-- with ONE fixed half-life for everyone. That let a confirmed attacker who
-- had already landed real exploits fade back to a clean score at exactly the
-- same rate as a single stray probe -- so alternating "run exploit" / "wait"
-- could keep re-earning production access indefinitely.
--
-- This module scales the decay by how much abuse the source has actually
-- committed, tracked as an `offenses` counter (bumped once per recorded
-- attack signal by the handlers/session code -- NOT capped, unlike the 0..100
-- score, so it keeps climbing long after the score has pinned at 100):
--
--   * Each offense multiplies the half-life by (1 + decay_offense_slowdown),
--     so a repeat offender's score fades progressively more slowly.
--   * Past permaflag_offenses offenses, OR once the stored peak has ever
--     reached permaflag_score (a single high-threat exploit that maxes the
--     score), decay stops entirely: the source is treated as a confirmed
--     attacker and stays flagged (a "permaflag"). This is the ceiling the
--     "high threat exploit = max decay" requirement asks for.
--
-- Pure: no ngx / _G access, all knobs passed in, so it is unit-testable and
-- both callers feed it the same config from _G.config.threat.
local _M = {}

--- Multiplier applied to the base half-life for a source with `offenses`
--- recorded attacks. 0 offenses (or slowdown disabled) => 1 (base rate).
--- Grows linearly so decay slows smoothly with each additional offense.
--- @param offenses number|nil
--- @param slowdown number|nil  e.g. _G.config.threat.decay_offense_slowdown
--- @return number  >= 1
function _M.half_life_multiplier(offenses, slowdown)
    offenses = tonumber(offenses) or 0
    slowdown = tonumber(slowdown) or 0
    if offenses <= 0 or slowdown <= 0 then
        return 1
    end
    return 1 + slowdown * offenses
end

--- Whether a source should never decay (confirmed attacker / permaflag).
--- @param peak              number|nil  the stored peak score (0..100)
--- @param offenses          number|nil
--- @param permaflag_score   number|nil  peak at/above this => permaflag (nil disables)
--- @param permaflag_offenses number|nil offenses at/above this => permaflag (nil disables)
--- @return boolean
function _M.is_permaflagged(peak, offenses, permaflag_score, permaflag_offenses)
    if permaflag_score and peak and peak >= permaflag_score then
        return true
    end
    if permaflag_offenses and (tonumber(offenses) or 0) >= permaflag_offenses then
        return true
    end
    return false
end

--- Full escalation-aware decay. Returns the effective (decayed) score.
--- Mirrors the guard order the two callers used before this module existed
--- (peak<=0 -> 0; missing/zero half-life or non-positive elapsed -> peak),
--- then applies permaflag and the offense-scaled half-life.
--- @param peak            number|nil
--- @param elapsed         number|nil  seconds since the decay anchor
--- @param base_half_life  number|nil  _G.config.threat.score_decay_half_life_seconds
--- @param offenses        number|nil
--- @param cfg             table|nil   { decay_offense_slowdown, permaflag_score, permaflag_offenses }
--- @return number
function _M.decay(peak, elapsed, base_half_life, offenses, cfg)
    peak = tonumber(peak) or 0
    if peak <= 0 then
        return 0
    end
    if not base_half_life or base_half_life <= 0 or not elapsed or elapsed <= 0 then
        return peak
    end
    cfg = cfg or {}
    offenses = tonumber(offenses) or 0
    if _M.is_permaflagged(peak, offenses, cfg.permaflag_score, cfg.permaflag_offenses) then
        return peak
    end
    local eff_half_life = base_half_life * _M.half_life_multiplier(offenses, cfg.decay_offense_slowdown)
    return peak * (0.5 ^ (elapsed / eff_half_life))
end

return _M
