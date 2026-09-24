#!/usr/bin/env lua
-- test_decay_policy.lua -- unit tests for the escalation-aware decay policy
-- (lua/decay_policy.lua). Runs under a plain `lua` interpreter.

package.path = "../?.lua;" .. package.path
local dp = require "decay_policy"

local passed, failed = 0, 0
local function check(name, cond)
    if cond then
        passed = passed + 1
        print("  [PASS] " .. name)
    else
        failed = failed + 1
        print("  [FAIL] " .. name)
    end
end
local function approx(a, b) return math.abs(a - b) < 0.01 end

local HL = 300

print("== half_life_multiplier() ==")
check("0 offenses -> 1x", dp.half_life_multiplier(0, 0.75) == 1)
check("nil offenses -> 1x", dp.half_life_multiplier(nil, 0.75) == 1)
check("slowdown 0 -> 1x regardless", dp.half_life_multiplier(9, 0) == 1)
check("1 offense @0.75 -> 1.75x", approx(dp.half_life_multiplier(1, 0.75), 1.75))
check("4 offenses @0.75 -> 4x", approx(dp.half_life_multiplier(4, 0.75), 4.0))

print("== is_permaflagged() ==")
check("maxed score permaflags", dp.is_permaflagged(100, 0, 100, 5) == true)
check("below max score, few offenses -> no permaflag", dp.is_permaflagged(60, 2, 100, 5) == false)
check("enough offenses permaflags even below max", dp.is_permaflagged(60, 5, 100, 5) == true)
check("nil thresholds disable permaflag", dp.is_permaflagged(100, 99, nil, nil) == false)

print("== decay() base behaviour (no escalation cfg) ==")
check("peak<=0 -> 0", dp.decay(0, 100, HL, 0, {}) == 0)
check("elapsed<=0 -> peak", dp.decay(90, 0, HL, 0, {}) == 90)
check("nil half_life -> peak", dp.decay(90, 100, nil, 0, {}) == 90)
check("one half-life halves it (no offenses)", approx(dp.decay(100, HL, HL, 0, {}), 50))

print("== decay() escalation ==")
local cfg = { decay_offense_slowdown = 0.75, permaflag_offenses = 5, permaflag_score = 100 }
-- 1 offense -> half-life 1.75x longer, so at t=HL only ~0.5^(1/1.75) remains.
check("1 offense decays slower than base",
      dp.decay(80, HL, HL, 1, cfg) > dp.decay(80, HL, HL, 0, cfg))
check("1 offense @ t=HL ~ 80*0.5^(1/1.75)",
      approx(dp.decay(80, HL, HL, 1, cfg), 80 * (0.5 ^ (1 / 1.75))))
check("maxed score never decays (permaflag)", dp.decay(100, 10 * HL, HL, 1, cfg) == 100)
check("5 offenses never decays (permaflag) even at score 60",
      dp.decay(60, 10 * HL, HL, 5, cfg) == 60)
check("more offenses -> higher remaining score at same elapsed",
      dp.decay(70, HL, HL, 3, cfg) > dp.decay(70, HL, HL, 1, cfg))

print("")
print(passed .. " passed, " .. failed .. " failed")
os.exit(failed == 0 and 0 or 1)
