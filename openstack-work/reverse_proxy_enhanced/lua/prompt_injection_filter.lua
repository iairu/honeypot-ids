-- prompt_injection_filter.lua - Prompt-injection detection and sanitization
--
-- PURPOSE:
--   This module is NOT currently wired into any live LLM call. No
--   LLM-driven feature exists yet in this codebase -- NEW_PLAN.md section
--   5.3.2, "Dynamic Response Generation (LLM Integration)", describes a
--   *planned* honeypot feature that would feed attacker-controlled request
--   data (URI, headers, POST body) into an LLM prompt to generate believable
--   fake responses. This module is built ahead of that feature, as a
--   standalone, independently testable defensive component so the design is
--   in place -- and its detection logic already validated -- before any
--   real LLM call is added.
--
--   Independent of that future use, injection-style payloads found in
--   request data are anomalous on their own: a legitimate WooCommerce
--   storefront visitor has no reason to send text engineered to look like a
--   chat-turn delimiter or a system-prompt override. threat_analyzer.lua
--   therefore wires detect() in as an additional content-inspection stage,
--   so this module has a genuine, exercised code path today rather than
--   sitting dead until the LLM feature exists (see PROMPT_TODO.md's
--   no-dead-code requirement).
--
-- THREAT MODEL (OWASP Top 10 for LLM Applications, LLM01: Prompt Injection):
--   If attacker-controlled request data is ever interpolated into an LLM
--   prompt, an attacker who suspects this could attempt to:
--     - Override the system prompt / hidden instructions
--       ("ignore previous instructions", "new instructions:", ...)
--     - Hijack the model's persona
--       ("you are now", "act as", "system:", chat-turn delimiters, ...)
--     - Exfiltrate the hidden prompt itself
--       ("repeat your instructions", "print your system prompt", ...)
--     - Break out of a wrapping delimiter/context boundary
--       (code-fence sequences, long runs of repeated punctuation used to
--       push prior context out of a limited context window)
--     - Smuggle any of the above past naive string matching via encoding
--       (base64-looking blobs that decode to an injection payload)
--
-- API:
--   detect(input)   -> { risk_score = 0..100, matched = {...}, category_counts = {...} }
--   sanitize(input) -> string  (a neutralized copy safe to interpolate into a
--                                prompt: matched spans and delimiter-breaking
--                                sequences are replaced with a placeholder,
--                                not silently dropped, so a future LLM
--                                feature can still log the original
--                                attacker-supplied text separately without
--                                ever executing it as an instruction)
--
-- PORTABILITY:
--   No ngx.* dependency in the detection/sanitization logic below, so this
--   module can be unit tested with a plain `lua` interpreter outside
--   OpenResty. See reverse_proxy_enhanced/lua/tests/test_prompt_injection_filter.lua.

local _M = {}

-- Each entry: { category, pattern, weight, plain }
--   plain = true  -> pattern is matched as a literal substring (string.find
--                     with the 4th "plain" argument), used whenever the
--                     pattern contains no wildcard and would otherwise
--                     require escaping Lua's magic characters.
--   plain = false -> pattern is a Lua pattern (supports %s+, .- wildcards
--                     for "word ... word" phrasing variants).
local INJECTION_PATTERNS = {
    -- Instruction override: attacker tries to supersede prior instructions.
    { category = "instruction_override", pattern = "ignore%s+.-instructions", weight = 40, plain = false },
    { category = "instruction_override", pattern = "ignore%s+.-prompt",       weight = 35, plain = false },
    { category = "instruction_override", pattern = "disregard%s+.-above",     weight = 35, plain = false },
    { category = "instruction_override", pattern = "forget%s+.-instructions", weight = 35, plain = false },
    { category = "instruction_override", pattern = "override%s+.-instructions", weight = 35, plain = false },
    { category = "instruction_override", pattern = "new instructions",       weight = 30, plain = true },

    -- Role/persona hijack: attacker tries to redefine the model's identity
    -- or inject a fake chat turn to make the model believe new instructions
    -- came from a trusted role.
    { category = "role_hijack", pattern = "you are now",     weight = 30, plain = true },
    { category = "role_hijack", pattern = "pretend to be",   weight = 25, plain = true },
    { category = "role_hijack", pattern = "act as",          weight = 15, plain = true },
    { category = "role_hijack", pattern = "system:",         weight = 25, plain = true },
    { category = "role_hijack", pattern = "assistant:",      weight = 20, plain = true },
    { category = "role_hijack", pattern = "[system]",        weight = 25, plain = true },
    { category = "role_hijack", pattern = "<|im_start|>",    weight = 30, plain = true },
    { category = "role_hijack", pattern = "<|im_end|>",      weight = 30, plain = true },

    -- Prompt/system exfiltration: attacker tries to make the model reveal
    -- its hidden instructions, which would also reveal the honeypot's
    -- deception strategy.
    { category = "prompt_exfiltration", pattern = "repeat%s+.-instructions", weight = 30, plain = false },
    { category = "prompt_exfiltration", pattern = "print%s+.-system prompt", weight = 35, plain = false },
    { category = "prompt_exfiltration", pattern = "reveal%s+.-prompt",       weight = 35, plain = false },
    { category = "prompt_exfiltration", pattern = "what were you told",      weight = 25, plain = true },
    { category = "prompt_exfiltration", pattern = "output everything above", weight = 25, plain = true },

    -- Context/delimiter breaking: attacker tries to escape a wrapping
    -- delimiter used to fence off untrusted input within the prompt.
    { category = "context_break", pattern = "```",  weight = 10, plain = true },
    { category = "context_break", pattern = "%-%-%-+%s*end", weight = 20, plain = false },
}

-- Runs of 4 or more repeated punctuation characters are a common technique
-- for pushing prior prompt context out of a model's attention / context
-- window ("fence flooding"). Detected via explicit run-length scanning
-- rather than a Lua pattern backreference: PUC-Rio Lua patterns do not
-- support a repetition quantifier (+, *) applied to a %1 backreference, so
-- "(%#)%1%1%1+" silently fails to match runs longer than its fixed length.
local PUNCTUATION_FLOOD_CHARSET = "#-=*~_"
local PUNCTUATION_FLOOD_MIN_RUN = 4

--- @return boolean  true if `text` contains a run of >= PUNCTUATION_FLOOD_MIN_RUN
---                   identical characters from PUNCTUATION_FLOOD_CHARSET.
local function has_punctuation_flood(text)
    local run_char, run_len = nil, 0
    for i = 1, #text do
        local c = text:sub(i, i)
        if PUNCTUATION_FLOOD_CHARSET:find(c, 1, true) then
            run_len = (c == run_char) and (run_len + 1) or 1
            run_char = c
            if run_len >= PUNCTUATION_FLOOD_MIN_RUN then
                return true
            end
        else
            run_char, run_len = nil, 0
        end
    end
    return false
end

--- Collapse runs of PUNCTUATION_FLOOD_MIN_RUN+ identical punctuation
--- characters down to 3, preserving short legitimate uses (e.g. "---" as a
--- markdown rule) while breaking flood sequences.
local function collapse_punctuation_flood(text)
    local out = {}
    local run_char, run_len = nil, 0
    for i = 1, #text do
        local c = text:sub(i, i)
        if PUNCTUATION_FLOOD_CHARSET:find(c, 1, true) then
            run_len = (c == run_char) and (run_len + 1) or 1
            run_char = c
            if run_len <= 3 then
                table.insert(out, c)
            end
        else
            run_char, run_len = nil, 0
            table.insert(out, c)
        end
    end
    return table.concat(out)
end

-- Minimum length for a token to be considered for base64-decode inspection.
-- Short base64-looking substrings (e.g. random query params) are far more
-- likely to be benign than a smuggled instruction payload.
local MIN_BASE64_TOKEN_LENGTH = 40

local B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64_LOOKUP = {}
for i = 1, #B64_CHARS do
    B64_LOOKUP[B64_CHARS:sub(i, i)] = i - 1
end

--- Minimal pure-Lua base64 decoder (no ngx.decode_base64 dependency, so this
--- module works identically inside OpenResty and under a plain `lua`
--- interpreter for unit testing).
--- @param data string  base64-encoded text (padding optional).
--- @return string|nil  decoded bytes, or nil if the input is not valid base64.
local function base64_decode(data)
    data = data:gsub("[^" .. B64_CHARS .. "=]", "")
    if #data == 0 then return nil end

    local ok, result = pcall(function()
        local bytes = {}
        local buffer, bits = 0, 0
        for i = 1, #data do
            local c = data:sub(i, i)
            if c ~= "=" then
                local val = B64_LOOKUP[c]
                if not val then error("invalid base64 character") end
                buffer = buffer * 64 + val
                bits = bits + 6
                if bits >= 8 then
                    bits = bits - 8
                    local byte = math.floor(buffer / (2 ^ bits)) % 256
                    -- Discard the bits just consumed so the accumulator
                    -- holds only the unconsumed remainder; without this the
                    -- buffer grows unboundedly and corrupts every byte
                    -- after the first.
                    buffer = buffer % (2 ^ bits)
                    table.insert(bytes, string.char(byte))
                end
            end
        end
        return table.concat(bytes)
    end)

    if ok then return result end
    return nil
end

--- Scan a single string against INJECTION_PATTERNS and the
--- repeated-punctuation structural check.
--- @param text string  already-lowercased input.
--- @return table  list of { category, note } matches.
local function scan_text(text)
    local matches = {}

    for _, entry in ipairs(INJECTION_PATTERNS) do
        local found
        if entry.plain then
            found = string.find(text, entry.pattern, 1, true)
        else
            found = string.find(text, entry.pattern)
        end
        if found then
            table.insert(matches, { category = entry.category, note = entry.pattern, weight = entry.weight })
        end
    end

    if has_punctuation_flood(text) then
        table.insert(matches, { category = "context_break", note = "repeated_punctuation_flood", weight = 15 })
    end

    return matches
end

-- ---------------------------------------------------------------------------
-- detect(input)
--
-- @param input string  Untrusted, attacker-controlled text (e.g. a decoded
--                       request URI, a query parameter, or a form field).
-- @return table  {
--   risk_score      integer 0..100, sum of matched pattern weights (capped)
--   matched         list of { category, note, weight }
--   category_counts table  category name -> number of matches
-- }
-- ---------------------------------------------------------------------------
function _M.detect(input)
    local result = { risk_score = 0, matched = {}, category_counts = {} }
    if not input or input == "" then
        return result
    end

    local text_lower = string.lower(input)
    local matches = scan_text(text_lower)

    -- Inspect any sufficiently long base64-looking token for an encoded
    -- injection payload, so naive string matching on the raw input can't be
    -- bypassed by base64-wrapping the same phrases.
    for token in string.gmatch(input, "[A-Za-z0-9+/]+=?=?") do
        if #token >= MIN_BASE64_TOKEN_LENGTH then
            local decoded = base64_decode(token)
            if decoded then
                local decoded_matches = scan_text(string.lower(decoded))
                for _, m in ipairs(decoded_matches) do
                    table.insert(matches, {
                        category = "encoded_payload",
                        note = m.category .. ":" .. m.note .. " (base64-decoded)",
                        weight = m.weight
                    })
                end
            end
        end
    end

    for _, m in ipairs(matches) do
        table.insert(result.matched, m)
        result.risk_score = result.risk_score + m.weight
        result.category_counts[m.category] = (result.category_counts[m.category] or 0) + 1
    end

    result.risk_score = math.min(result.risk_score, 100)
    return result
end

-- ---------------------------------------------------------------------------
-- sanitize(input)
--
-- Produces a neutralized copy of `input` that is safe to interpolate into a
-- prompt: matched instruction/role/exfiltration phrases and delimiter-
-- breaking sequences are replaced with a visible placeholder rather than
-- silently stripped, so a future LLM feature can still log what the
-- attacker attempted without ever having it interpreted as an instruction.
--
-- @param input string
-- @return string
-- ---------------------------------------------------------------------------
function _M.sanitize(input)
    if not input or input == "" then
        return input
    end

    local sanitized = input

    for _, entry in ipairs(INJECTION_PATTERNS) do
        local lua_pattern = entry.plain and entry.pattern:gsub("[%(%)%.%%%+%-%*%?%[%]%^%$]", "%%%1") or entry.pattern
        -- Case-insensitive replace: build an alternation-free approach by
        -- operating on a lowercase copy to find spans, then blank them out
        -- in the original string at the same byte offsets.
        local lower = string.lower(sanitized)
        local search_from = 1
        while true do
            local s, e = string.find(lower, lua_pattern, search_from)
            if not s then break end
            sanitized = sanitized:sub(1, s - 1) .. "[FILTERED:" .. entry.category .. "]" .. sanitized:sub(e + 1)
            lower = string.lower(sanitized)
            search_from = s + 1
        end
    end

    -- Collapse delimiter-flooding runs (4+ repeated punctuation) to 3
    -- characters so they can no longer push prior context out of a
    -- bounded window, while still preserving legitimate short emphasis
    -- (e.g. "---" as a markdown rule).
    sanitized = collapse_punctuation_flood(sanitized)

    -- Redact long base64-looking tokens that decode to an injection payload.
    sanitized = sanitized:gsub("[A-Za-z0-9+/]+=?=?", function(token)
        if #token >= MIN_BASE64_TOKEN_LENGTH then
            local decoded = base64_decode(token)
            if decoded and #scan_text(string.lower(decoded)) > 0 then
                return "[FILTERED:encoded_payload]"
            end
        end
        return token
    end)

    return sanitized
end

return _M
