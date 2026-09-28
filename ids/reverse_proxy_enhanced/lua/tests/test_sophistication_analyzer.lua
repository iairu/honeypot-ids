-- test_sophistication_analyzer.lua - Standalone unit tests
--
-- sophistication_analyzer.lua is pure apart from one ngx.time() call, so a
-- one-function ngx stub is enough to run it under a plain `lua` interpreter.
--
-- Usage:
--   cd ids/reverse_proxy_enhanced/lua/tests
--   lua test_sophistication_analyzer.lua

package.path = "../?.lua;" .. package.path

local NOW = 1700000000
ngx = { time = function() return NOW end }

local analyzer = require "sophistication_analyzer"

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

local function has_signal(result, prefix)
    for _, s in ipairs(result.signals) do
        if string.sub(s, 1, #prefix) == prefix then return true end
    end
    return false
end

local BROWSER_HEADERS = {
    ["accept-language"] = "en-US", ["accept-encoding"] = "gzip",
    ["sec-fetch-dest"] = "document", ["sec-fetch-mode"] = "navigate",
    ["sec-fetch-site"] = "none", ["upgrade-insecure-requests"] = "1"
}
local CHROME_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

print("classify_session: degenerate input")
do
    local r = analyzer.classify_session(nil, nil, nil)
    check("nil everything -> unknown, no crash", r.classification == "unknown")
    check("nil everything -> zero confidence", r.confidence == 0)
    check("missing UA is still recorded as a signal", has_signal(r, "missing_user_agent"))
end

print("classify_session: user-agent fingerprints")
do
    local r = analyzer.classify_session({ user_agent = "curl/8.4.0" }, nil, {})
    check("curl with bare headers -> scripted", r.classification == "scripted")
    check("curl signal recorded", has_signal(r, "scripted_tool_ua:curl"))

    -- Regression: fragments were matched as Lua patterns, where "-" is a
    -- lazy-repeat operator, so no hyphenated fragment ever matched.
    r = analyzer.classify_session({ user_agent = "Go-http-client/1.1" }, nil, {})
    check("Go-http-client -> scripted (hyphenated fragment)", r.classification == "scripted")
    r = analyzer.classify_session({ user_agent = "libwww-perl/6.72" }, nil, {})
    check("libwww-perl -> scripted (hyphenated fragment)", has_signal(r, "scripted_tool_ua:libwww-perl"))
    r = analyzer.classify_session({ user_agent = "python-requests/2.31.0" }, nil, {})
    check("python-requests -> ai_assisted (hyphenated fragment)", r.classification == "ai_assisted")
    r = analyzer.classify_session({ user_agent = "node-fetch/1.0" }, nil, {})
    check("node-fetch -> ai_assisted signal", has_signal(r, "ai_agent_client_ua:node-fetch"))

    r = analyzer.classify_session({ user_agent = CHROME_UA }, nil, BROWSER_HEADERS)
    check("real browser with full headers -> manual", r.classification == "manual")
    check("browser_ua and full_browser_headers both recorded",
          has_signal(r, "browser_ua") and has_signal(r, "full_browser_headers"))
end

print("classify_session: timing")
do
    -- Three prior gaps are enough for timing to kick in (MIN_SAMPLES_FOR_TIMING).
    local r = analyzer.classify_session({ timing_samples = { 0.1, 0.2, 0.1 } }, nil, nil)
    check("sub-second pacing noted", has_signal(r, "sub_second_pacing"))

    r = analyzer.classify_session({ timing_samples = { 2, 2.1, 2 } }, nil, nil)
    check("near-constant multi-second interval -> regular_interval", has_signal(r, "regular_interval"))

    r = analyzer.classify_session({ timing_samples = { 2, 3.5, 2 } }, nil, nil)
    check("steady 2-4s pacing -> llm_loop_pacing", has_signal(r, "llm_loop_pacing"))

    r = analyzer.classify_session({ timing_samples = { 1, 12, 3 } }, nil, nil)
    check("erratic pacing -> irregular_pacing", has_signal(r, "irregular_pacing"))

    r = analyzer.classify_session({ timing_samples = { 1, 2 } }, nil, nil)
    check("fewer than 3 samples -> no timing signal",
          not has_signal(r, "sub_second") and not has_signal(r, "regular")
          and not has_signal(r, "llm_loop") and not has_signal(r, "irregular"))

    r = analyzer.classify_session({ last_activity = NOW - 4 }, nil, nil)
    check("current gap appended to samples", #r.timing_samples == 1 and r.timing_samples[1] == 4)

    r = analyzer.classify_session({ last_activity = NOW - 600 }, nil, nil)
    check("idle gap over 5 minutes ignored", #r.timing_samples == 0)

    local many = {}
    for i = 1, 15 do many[i] = i end
    local input = { timing_samples = many, last_activity = NOW - 1 }
    r = analyzer.classify_session(input, nil, nil)
    check("samples capped at 15, oldest dropped",
          #r.timing_samples == 15 and r.timing_samples[1] == 2 and r.timing_samples[15] == 1)
    check("caller's session_data not mutated", #input.timing_samples == 15 and input.timing_samples[1] == 1)
end

print("classify_session: payload precision")
do
    local spray = { patterns_matched = { 1, 2, 3, 4, 5, 6 }, cve_matched = {} }
    local r = analyzer.classify_session({}, spray, nil)
    check("six+ patterns -> pattern_spray", has_signal(r, "pattern_spray(count=6)"))

    local surgical = { patterns_matched = { 1 }, cve_matched = { "CVE-2023-28121" } }
    r = analyzer.classify_session({}, surgical, nil)
    check("single CVE with little noise -> surgical_cve_match", has_signal(r, "surgical_cve_match"))
end

print("classify_session: decision rule")
do
    -- Browser UA + full headers (manual 35) vs sub-second pacing (scripted
    -- 30): top score clears 20 but the margin is under 10 -> unknown.
    local r = analyzer.classify_session(
        { user_agent = CHROME_UA, timing_samples = { 0.1, 0.1, 0.2 } }, nil, BROWSER_HEADERS)
    check("close call between buckets -> unknown", r.classification == "unknown")
    check("scores still reported for close call", r.scores.manual == 35 and r.scores.scripted == 30)

    -- Regression: signals were empty on sessions under 3 requests because
    -- ipairs stopped at the leading nil timing note.
    r = analyzer.classify_session({ user_agent = "curl/8" }, nil, {})
    check("short session still lists every signal", #r.signals == 2)

    check("confidence is rounded to two decimals",
          r.confidence == math.floor(r.confidence * 100 + 0.5) / 100)
end

print()
print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
