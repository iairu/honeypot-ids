-- sophistication_analyzer.lua - Attacker sophistication classifier
--
-- PURPOSE:
--   Heuristically classifies the traffic in a session as originating from a
--   scripted/automated tool, a manual human operator, or an AI-assisted
--   agent (e.g. LLM-driven pentesting frameworks such as PentAGI, AutoGPT-
--   style tool loops, or an LLM copilot used interactively by a human).
--
--   This is intentionally NOT a machine-learning classifier. Consistent
--   with the rest of the threat-scoring pipeline (see threat_analyzer.lua
--   and COUNTERARGUMENTS.md Q7 on the deliberate choice of explainable
--   rule-based detection over black-box ML), it is a deterministic, fully
--   inspectable weighted rule set over signals that are cheap to compute
--   from data already collected during routing: inter-request timing,
--   headers, User-Agent, and the CVE/pattern precision already produced by
--   threat_analyzer.analyze_request(). Every contributing signal is
--   returned in the `signals` list so the classification is auditable in
--   session/ELK logs, not just a bare label.
--
-- SIGNALS (each documented at its scoring function below):
--   1. Inter-request timing regularity (coefficient of variation)
--   2. Browser-fingerprint header completeness
--   3. User-Agent category (known scanner tool / known AI-agent HTTP
--      client / real browser)
--   4. Payload precision (few, surgical CVE hits vs. broad pattern spray)
--
-- OUTPUT of classify_session(): {
--   classification  "scripted" | "ai_assisted" | "manual" | "unknown"
--   confidence      0..1 (share of total signal weight held by the winner)
--   scores          { scripted, ai_assisted, manual } raw weighted totals
--   signals         list of human-readable notes, one per contributing signal
--   timing_samples  updated rolling inter-arrival sample list; the caller
--                   persists this back onto session_data.timing_samples
-- }
--
-- CALLER CONTRACT:
--   Called from nginx.conf's access_by_lua_block, after threat_analyzer and
--   router have both run, so the current request's threat_result and the
--   routing decision are available. Pure computation, no I/O — safe to run
--   on every non-static request without a meaningful latency impact.

local _M = {}

local MIN_SAMPLES_FOR_TIMING = 3
local MAX_TIMING_SAMPLES = 15

-- Known automated tool / scanner UA fragments. Kept as a separate list from
-- threat_analyzer's malicious_uas so this module can be tuned independently;
-- overlap between the two lists is intentional and expected.
local SCRIPTED_UA_FRAGMENTS = {
    "sqlmap", "nmap", "masscan", "zap", "acunetix", "nikto", "dirb",
    "gobuster", "wpscan", "whatweb", "nuclei", "burpsuite", "havij",
    "pangolin", "curl", "wget", "python-urllib", "libwww-perl", "go-http-client"
}

-- Known AI-agent / LLM-tooling HTTP client fingerprints. These frameworks
-- typically drive requests through generic HTTP libraries (python-requests,
-- httpx, node-fetch, axios) rather than a real browser, but with request
-- pacing and payload precision that differs from both hand-rolled scripts
-- and human browsing (see the timing and precision signals below).
local AI_AGENT_UA_FRAGMENTS = {
    "python-requests", "httpx", "node-fetch", "axios", "aiohttp",
    "langchain", "autogen", "crewai", "autogpt", "pentagi",
    "openai", "anthropic", "litellm", "ollama"
}

-- Headers a real browser sends automatically that hand-written HTTP clients
-- (curl, python-requests, most agent frameworks) typically omit unless
-- deliberately spoofed.
local BROWSER_FINGERPRINT_HEADERS = {
    "accept-language", "accept-encoding", "sec-fetch-dest", "sec-fetch-mode",
    "sec-fetch-site", "upgrade-insecure-requests"
}

local function mean(values)
    if #values == 0 then return 0 end
    local sum = 0
    for _, v in ipairs(values) do sum = sum + v end
    return sum / #values
end

local function stdev(values, avg)
    if #values < 2 then return 0 end
    local sum_sq = 0
    for _, v in ipairs(values) do
        sum_sq = sum_sq + (v - avg) ^ 2
    end
    return math.sqrt(sum_sq / (#values - 1))
end

--- Append the current inter-request gap to the session's rolling timing
--- sample list (bounded to MAX_TIMING_SAMPLES) and return the new list.
--- Does not mutate session_data; the caller persists the result.
local function update_timing_samples(session_data)
    local samples = {}
    if session_data.timing_samples then
        for _, v in ipairs(session_data.timing_samples) do
            table.insert(samples, v)
        end
    end

    if session_data.last_activity then
        local gap = ngx.time() - session_data.last_activity
        -- Ignore idle gaps over 5 minutes: these represent a new burst of
        -- activity after a pause, not a meaningful pacing sample.
        if gap >= 0 and gap < 300 then
            table.insert(samples, gap)
            if #samples > MAX_TIMING_SAMPLES then
                table.remove(samples, 1)
            end
        end
    end

    return samples
end

--- Score inter-request timing regularity into the three category buckets.
--- @param samples  table  list of inter-request gaps in seconds.
--- @return table, string|nil  score deltas, human-readable note.
local function score_timing(samples)
    local scores = { scripted = 0, ai_assisted = 0, manual = 0 }
    if #samples < MIN_SAMPLES_FOR_TIMING then
        return scores, nil
    end

    local avg = mean(samples)
    local sd = stdev(samples, avg)
    local cv = avg > 0 and (sd / avg) or 0

    local note
    if avg < 0.5 then
        -- Sub-second pacing regardless of variance: only achievable by a
        -- script issuing requests programmatically back-to-back.
        scores.scripted = scores.scripted + 30
        note = string.format("sub_second_pacing(avg=%.2fs)", avg)
    elseif cv < 0.25 then
        -- Very regular pacing at human-implausible precision (bots fire on
        -- a fixed timer or sleep() interval).
        scores.scripted = scores.scripted + 25
        note = string.format("regular_interval(avg=%.2fs,cv=%.2f)", avg, cv)
    elseif avg >= 1.0 and avg <= 6.0 and cv < 0.6 then
        -- Moderately consistent multi-second pacing matches the
        -- observe->reason->act loop latency of an LLM-driven agent
        -- (inference + tool-call round trip): steadier than unassisted
        -- human think-time, but slower and less rigid than a fixed-interval
        -- script.
        scores.ai_assisted = scores.ai_assisted + 25
        note = string.format("llm_loop_pacing(avg=%.2fs,cv=%.2f)", avg, cv)
    else
        -- High variance, human think-time: irregular pauses while reading
        -- responses, switching tools, or typing.
        scores.manual = scores.manual + 25
        note = string.format("irregular_pacing(avg=%.2fs,cv=%.2f)", avg, cv)
    end

    return scores, note
end

--- Score the request's User-Agent string into the three category buckets.
local function score_user_agent(user_agent)
    local scores = { scripted = 0, ai_assisted = 0, manual = 0 }
    local ua_lower = string.lower(user_agent or "")

    if ua_lower == "" then
        scores.scripted = scores.scripted + 15
        return scores, "missing_user_agent"
    end

    for _, fragment in ipairs(SCRIPTED_UA_FRAGMENTS) do
        if string.find(ua_lower, fragment) then
            scores.scripted = scores.scripted + 35
            return scores, "scripted_tool_ua:" .. fragment
        end
    end

    for _, fragment in ipairs(AI_AGENT_UA_FRAGMENTS) do
        if string.find(ua_lower, fragment) then
            scores.ai_assisted = scores.ai_assisted + 35
            return scores, "ai_agent_client_ua:" .. fragment
        end
    end

    if string.find(ua_lower, "mozilla") and
       (string.find(ua_lower, "chrome") or string.find(ua_lower, "firefox") or
        string.find(ua_lower, "safari") or string.find(ua_lower, "edg")) then
        scores.manual = scores.manual + 15
        return scores, "browser_ua"
    end

    return scores, nil
end

--- Score presence of browser-only fingerprint headers.
local function score_headers(headers)
    local scores = { scripted = 0, ai_assisted = 0, manual = 0 }
    if not headers then return scores, nil end

    local present = 0
    for _, h in ipairs(BROWSER_FINGERPRINT_HEADERS) do
        if headers[h] then
            present = present + 1
        end
    end

    local ratio = present / #BROWSER_FINGERPRINT_HEADERS
    local note
    if ratio >= 0.8 then
        scores.manual = scores.manual + 20
        note = "full_browser_headers"
    elseif ratio <= 0.15 then
        -- Absence alone doesn't distinguish scripted from ai_assisted (both
        -- typically use bare HTTP clients); weight is split evenly here and
        -- the UA/timing signals do the actual disambiguation.
        scores.scripted = scores.scripted + 8
        scores.ai_assisted = scores.ai_assisted + 8
        note = "no_browser_headers"
    end

    return scores, note
end

--- Score payload precision using the current request's threat_result. A
--- request that racks up many distinct low-value pattern hits (spray-and-
--- pray) reads as scripted; a request that hits few, precise, high-value
--- signals (a CVE-specific match with minimal noise) reads as targeted,
--- deliberate exploitation, more typical of a manual operator or an AI
--- agent executing a specific, reasoned plan.
local function score_precision(threat_result)
    local scores = { scripted = 0, ai_assisted = 0, manual = 0 }
    if not threat_result then return scores, nil end

    local pattern_count = threat_result.patterns_matched and #threat_result.patterns_matched or 0
    local cve_count = threat_result.cve_matched and #threat_result.cve_matched or 0

    local note
    if pattern_count >= 6 then
        -- Many generic patterns firing on one request: typical of a scanner
        -- throwing every payload variant at once.
        scores.scripted = scores.scripted + 20
        note = "pattern_spray(count=" .. pattern_count .. ")"
    elseif cve_count > 0 and pattern_count <= 2 then
        -- A precise CVE match with almost no collateral pattern noise: the
        -- request was crafted to hit exactly one known vulnerability.
        scores.ai_assisted = scores.ai_assisted + 10
        scores.manual = scores.manual + 10
        note = "surgical_cve_match(cves=" .. cve_count .. ")"
    end

    return scores, note
end

-- ---------------------------------------------------------------------------
-- classify_session(session_data, threat_result, headers)
--
-- @param session_data  table  Current session (must have at least
--                              .user_agent and .last_activity to produce
--                              useful signals; degrades gracefully without).
-- @param threat_result table  Output of threat_analyzer.analyze_request()
--                              for the current request.
-- @param headers       table  ngx.req.get_headers() result for the current
--                              request (caller-supplied to avoid a second
--                              fetch of the same table).
-- @return table  See module header for the output shape.
-- ---------------------------------------------------------------------------
function _M.classify_session(session_data, threat_result, headers)
    session_data = session_data or {}

    local totals = { scripted = 0, ai_assisted = 0, manual = 0 }
    local signals = {}

    local timing_samples = update_timing_samples(session_data)
    local timing_scores, timing_note = score_timing(timing_samples)
    local ua_scores, ua_note = score_user_agent(session_data.user_agent or "")
    local header_scores, header_note = score_headers(headers)
    local precision_scores, precision_note = score_precision(threat_result)

    for _, part in ipairs({ timing_scores, ua_scores, header_scores, precision_scores }) do
        totals.scripted = totals.scripted + part.scripted
        totals.ai_assisted = totals.ai_assisted + part.ai_assisted
        totals.manual = totals.manual + part.manual
    end

    for _, note in ipairs({ timing_note, ua_note, header_note, precision_note }) do
        if note then table.insert(signals, note) end
    end

    -- Pick the highest-scoring bucket, but require both a minimum absolute
    -- score and a minimum margin over the runner-up before committing to a
    -- classification. Below that bar, report "unknown" rather than a
    -- low-confidence guess — an academically honest failure mode for the
    -- thesis dataset, and consistent with the rest of the pipeline's
    -- preference for explainable, conservative thresholds over forced
    -- decisions (see threat_analyzer.lua's honeypot_threshold rationale).
    local ranked = {
        { key = "scripted", score = totals.scripted },
        { key = "ai_assisted", score = totals.ai_assisted },
        { key = "manual", score = totals.manual }
    }
    table.sort(ranked, function(a, b) return a.score > b.score end)

    local top, second = ranked[1], ranked[2]
    local classification = "unknown"
    local confidence = 0

    if top.score >= 20 and (top.score - second.score) >= 10 then
        classification = top.key
        local total_score = totals.scripted + totals.ai_assisted + totals.manual
        confidence = total_score > 0 and (top.score / total_score) or 0
    end

    return {
        classification = classification,
        confidence = math.floor(confidence * 100 + 0.5) / 100,
        scores = totals,
        signals = signals,
        timing_samples = timing_samples
    }
end

return _M
