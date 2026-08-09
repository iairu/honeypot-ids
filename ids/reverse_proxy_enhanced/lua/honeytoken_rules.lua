-- honeytoken_rules.lua - Pure token-matching core used by
-- honeytoken_handler.lua
--
-- Same split rationale as threat_rules.lua/router_rules.lua: no ngx.*
-- dependency, no reliance on _G.config/_G.utils, plain-`lua`-interpreter
-- testable (see tests/test_honeytoken_rules.lua). honeytoken_handler.lua
-- is the adapter -- it builds the token catalogue (derived from a
-- deployment-specific salt via resty.sha1, itself an ngx.* dependency
-- indirectly through OpenResty's crypto bindings), reads the actual
-- request corpus (headers/URI/body -- I/O), and does the Redis
-- record-keeping and ngx.log/ELK calls.
--
-- architecture.canvas flagged honeytoken_handler.lua + admin_handler.lua as
-- "I/O-dominated... lower value than the four [pure/adapter splits]
-- already done," and explicitly said not to merge the two files (separate,
-- non-overlapping responsibilities). This extracts the one genuinely pure
-- piece of honeytoken_handler.lua: given a built corpus string and a
-- token_id->token_entry lookup table, which token (if any) appears in it.

local _M = {}

-- ---------------------------------------------------------------------------
-- find_token_in_corpus(corpus, token_value_map)
--
-- Scans `corpus` for the first known token value present in it (plain
-- substring match, no Lua patterns -- token values are opaque hex/base62
-- strings, not patterns to interpret).
--
-- @param corpus            string|nil  Concatenated request text to scan
--                                       (headers, URI, POST body, etc.).
-- @param token_value_map   table|nil   Map of token_value -> token_entry,
--                                      e.g. { [token.value] = token, ... }.
-- @return table|nil, string|nil  The matched token_entry and the token
--                                 value that matched, or nil, nil if none
--                                 found. Iteration order over the map is
--                                 not guaranteed (Lua `pairs()` semantics);
--                                 if a corpus could somehow contain two
--                                 different token values at once, which one
--                                 is returned is undefined -- matches the
--                                 original's `break`-on-first-match-found
--                                 behavior, which had the same property.
-- ---------------------------------------------------------------------------
function _M.find_token_in_corpus(corpus, token_value_map)
    if not corpus or not token_value_map then
        return nil, nil
    end

    for value, token in pairs(token_value_map) do
        if string.find(corpus, value, 1, true) then
            return token, value
        end
    end

    return nil, nil
end

return _M
