-- test_honeytoken_rules.lua - Standalone unit tests
--
-- Usage:
--   cd ids/reverse_proxy_enhanced/lua/tests
--   lua test_honeytoken_rules.lua

package.path = "../?.lua;" .. package.path
local rules = require "honeytoken_rules"

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

local TOKEN_MAP = {
    ["ck_abc123"] = { id = "HT-APIKEY-CK", type = "wc_consumer_key" },
    ["cs_def456"] = { id = "HT-APIKEY-CS", type = "wc_consumer_secret" },
    ["AKIAsecretvalue"] = { id = "HT-S3AKID", type = "aws_access_key_id" },
}

print("== find_token_in_corpus() ==")
do
    local token, value = rules.find_token_in_corpus("Bearer ck_abc123 extra text", TOKEN_MAP)
    check("token found in corpus", token ~= nil and token.id == "HT-APIKEY-CK")
    check("matched value returned", value == "ck_abc123")

    token, value = rules.find_token_in_corpus("nothing suspicious here", TOKEN_MAP)
    check("no match returns nil, nil", token == nil and value == nil)

    token, value = rules.find_token_in_corpus(nil, TOKEN_MAP)
    check("nil corpus returns nil, nil", token == nil and value == nil)

    token, value = rules.find_token_in_corpus("ck_abc123", nil)
    check("nil token_value_map returns nil, nil", token == nil and value == nil)

    token = rules.find_token_in_corpus("", TOKEN_MAP)
    check("empty corpus finds nothing", token == nil)

    -- Plain substring match, not a Lua pattern -- confirm magic characters
    -- in the corpus don't break matching or cause false positives.
    token, value = rules.find_token_in_corpus("prefix%.*+ AKIAsecretvalue suffix", TOKEN_MAP)
    check("plain substring match works even with Lua magic chars nearby",
          token ~= nil and token.id == "HT-S3AKID")

    -- A token value that itself contains Lua magic characters must still
    -- match literally (plain=true), not be interpreted as a pattern.
    local magic_map = { ["a.b*c"] = { id = "HT-TEST" } }
    token = rules.find_token_in_corpus("xxa.b*cxx", magic_map)
    check("token value with magic chars matches literally", token ~= nil and token.id == "HT-TEST")
    token = rules.find_token_in_corpus("xxaXbYcxx", magic_map)
    check("token value with magic chars does NOT match as a pattern would (aXbYc)", token == nil)
end

print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
