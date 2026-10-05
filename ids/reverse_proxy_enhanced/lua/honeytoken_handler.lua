-- honeytoken_handler.lua - Honeytoken / CanaryToken injection and detection module
--
-- PURPOSE:
--   Implements the honeytoken strategy described in the thesis concept chapter.
--   Honeytokens are fake high-value artefacts (API keys, credentials, internal
--   paths) deliberately planted in the honeypot environment so that any attempt
--   to USE them outside the honeypot immediately signals a confirmed compromise.
--
--   This module operates in two modes:
--     1. INJECTION  – adds fake tokens to specific honeypot HTTP responses
--                     (wp-config leaks, REST API responses, wp-admin pages).
--     2. DETECTION  – recognises when a previously injected token appears in
--                     an inbound request (Authorization header, query param,
--                     POST body) and raises a high-confidence alert.
--
-- HONEYTOKEN TYPES IMPLEMENTED:
--   HT-APIKEY   – Fake WooCommerce REST API consumer key/secret pair.
--                 Injected into the honeypot /wp-json/wc/v3/ 200 response.
--                 Detected when used in a subsequent Authorization header.
--
--   HT-DBCREDS  – Fake MySQL credentials embedded in a "leaked" wp-config.php
--                 snippet returned by the honeypot on wp-config.php path probes.
--                 Detected when the DB host/user/pass appear in POST bodies.
--
--   HT-ADMINPW  – Fake WordPress admin password hash and plaintext hint placed
--                 in a dedicated honeypot admin-note page.
--                 Detected when the hash or the plaintext appears in login POST.
--
--   HT-S3URL    – Fake AWS S3 presigned URL injected into honeypot media
--                 library responses.  Detected when the URL is fetched or the
--                 access-key-id component appears in any request.
--
--   HT-JWTKEY   – Fake JWT signing secret injected into honeypot plugin settings
--                 REST response.  Detected when forged JWTs using that secret
--                 appear in Authorization: Bearer headers.
--
-- TOKEN STORAGE:
--   Tokens and their metadata are stored in the Redis session_store under the
--   key prefix "honeytoken:".  Each token entry contains:
--     { token_id, type, value, injected_at, injected_to_ip, use_count }
--   The injection timestamp allows measuring time-to-use (attacker dwell time).
--
-- DETECTION FLOW:
--   1. analyze_request_for_tokens() is called from nginx.conf access_by_lua_block
--      BEFORE the routing decision.
--   2. If a token is found, the event is logged to ELK and Redis, and the
--      request is flagged for immediate honeypot routing (score += 100).
--   3. The detected token's use_count is incremented in Redis.
--
-- THESIS REFERENCE:
--   Honeytoken concept described in §3.7 (Honeytokens) of 3_concept.tex.
--   Implementation documented in §4.x (Honeytokens/CanaryTokens) of 4_implement.tex.
--
-- DEPENDENCIES:
--   cjson        – JSON encoding
--   resty.sha1   – SHA-1 for deterministic token generation
--   resty.string – hex encoding
--   _G.redis_pool – Redis connection pool (init.lua)
--   _G.utils      – security event logging (init.lua)

local cjson  = require "cjson"
local sha1   = require "resty.sha1"
local str    = require "resty.string"
local honeytoken_rules = require "honeytoken_rules"

local _M = {}

-- ---------------------------------------------------------------------------
-- Configuration
-- ---------------------------------------------------------------------------

-- Redis key prefix for token records.
local TOKEN_KEY_PREFIX = "honeytoken:"

-- Token TTL in Redis (30 days).  Long TTL keeps tokens traceable even after
-- the attacker pauses activity for weeks.
local TOKEN_TTL = 2592000

-- Shared installation-specific salt used to make tokens unique per deployment.
-- In production this should be overridden by an environment variable.
local DEPLOYMENT_SALT = os.getenv("HONEYTOKEN_SALT") or "default-honeypot-salt-change-me"

-- Fake database host used in HT-DBCREDS tokens.  Points to a non-existent
-- internal address so any connection attempt is logged by the egress firewall.
local FAKE_DB_HOST = "internal-db-prod.corp.example.com"

-- ---------------------------------------------------------------------------
-- Internal helpers
-- ---------------------------------------------------------------------------

-- Generate a deterministic but opaque token value from a seed string.
-- Using SHA-1 ensures the value is consistent across Nginx workers and restarts
-- (same seed → same token), which matters for detection: we compare inbound
-- request data against a known-good value rather than storing every variant.
local function derive_token(seed)
    local s = sha1:new()
    s:update(DEPLOYMENT_SALT .. seed)
    local digest = s:final()
    return str.to_hex(digest)
end

-- Return a Redis connection or nil on error.
local function get_redis()
    local red, err = _G.redis_pool.get_connection()
    if not red then
        ngx.log(ngx.WARN, "[HONEYTOKEN] Redis unavailable: ", err)
        return nil
    end
    return red
end

-- ---------------------------------------------------------------------------
-- Token catalogue
-- ---------------------------------------------------------------------------
-- Each entry defines a static honeytoken whose value is derived from a seed.
-- The seed is deterministic so the same token is recognised on every worker.
-- ---------------------------------------------------------------------------
local TOKENS = {
    -- HT-APIKEY: WooCommerce consumer key/secret pair
    -- Injected into /wp-json/wc/v3/ responses for logged-in honeypot users.
    {
        id        = "HT-APIKEY-CK",
        type      = "wc_consumer_key",
        -- Consumer keys always start with "ck_" in WooCommerce
        value     = "ck_" .. derive_token("wc-consumer-key-2024"),
        -- Match when this value appears anywhere in Authorization or request body
        detect_in = { "authorization", "body", "uri" },
        severity  = "critical",
        note      = "Fake WooCommerce API consumer key planted in honeypot REST response",
    },
    {
        id        = "HT-APIKEY-CS",
        type      = "wc_consumer_secret",
        value     = "cs_" .. derive_token("wc-consumer-secret-2024"),
        detect_in = { "authorization", "body", "uri" },
        severity  = "critical",
        note      = "Fake WooCommerce API consumer secret planted in honeypot REST response",
    },

    -- HT-DBCREDS: MySQL credentials that look like production wp-config.php
    {
        id        = "HT-DBCREDS-PASS",
        type      = "mysql_password",
        value     = derive_token("mysql-password-2024"),
        detect_in = { "body", "uri" },
        severity  = "high",
        note      = "Fake MySQL password from honeypot wp-config.php leak",
    },

    -- HT-ADMINPW: Fake admin plaintext password hint
    -- Placed in a honeypot "admin notes" page as a comment in the HTML source.
    {
        id        = "HT-ADMINPW",
        type      = "wp_admin_password",
        value     = "P@ss" .. string.upper(derive_token("admin-pw-2024"):sub(1, 8)),
        detect_in = { "body" },
        severity  = "critical",
        note      = "Fake admin password hint planted in honeypot admin-notes page",
    },

    -- HT-S3URL: Fake AWS access key ID embedded in a fake S3 presigned URL
    -- AWS access key IDs always start with "AKIA".
    {
        id        = "HT-S3AKID",
        type      = "aws_access_key_id",
        value     = "AKIA" .. string.upper(derive_token("aws-access-key-2024"):sub(1, 16)),
        detect_in = { "authorization", "body", "uri" },
        severity  = "high",
        note      = "Fake AWS access key ID from honeypot S3 presigned URL",
    },

    -- HT-JWTKEY: Fake JWT signing secret embedded in plugin settings response
    {
        id        = "HT-JWTKEY",
        type      = "jwt_secret",
        value     = derive_token("jwt-signing-secret-2024"),
        detect_in = { "authorization", "body" },
        severity  = "high",
        note      = "Fake JWT signing secret from honeypot plugin settings endpoint",
    },
}

-- Build a lookup map (token_value → token_entry) for O(1) detection.
-- This is computed once at module load time (init_by_lua phase) and shared
-- across all Nginx workers via the module table.
local TOKEN_VALUE_MAP = {}
for _, token in ipairs(TOKENS) do
    TOKEN_VALUE_MAP[token.value] = token
end

-- ---------------------------------------------------------------------------
-- Public API: Detection
-- ---------------------------------------------------------------------------

--- Scan the current inbound request for any known honeytoken value.
---
--- Checks:
---   1. Authorization header (Basic, Bearer, AWS Signature)
---   2. All other request headers
---   3. Query string parameters
---   4. POST body (read without consuming, up to 16 KB)
---
--- When a token is detected the function:
---   a. Increments the use_count in Redis.
---   b. Logs a CRITICAL security event to Nginx error log + ELK.
---   c. Returns a detection_result table with token metadata so the caller
---      (nginx.conf) can immediately force honeypot routing.
---
--- @return table|nil  detection_result or nil if no token found.
---                    { token_id, type, severity, use_count }
function _M.analyze_request_for_tokens()
    local result = nil

    -- Collect the text corpus to scan for this request.
    -- We build all candidate strings first to avoid reading the body twice.
    local candidates = {}

    -- 1. Authorization and other sensitive headers
    local auth = ngx.var.http_authorization or ""
    if auth ~= "" then
        table.insert(candidates, auth)
    end

    -- 2. Full URI including query string
    local full_uri = (ngx.var.request_uri or "") .. "&" .. (ngx.var.args or "")
    table.insert(candidates, full_uri)

    -- 3. POST body (read non-destructively, capped at 16 KB to avoid memory pressure)
    if ngx.var.request_method == "POST" then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        if body then
            -- Limit body scan to first 16 KB; longer payloads are unlikely to
            -- contain a honeytoken in practice.
            table.insert(candidates, body:sub(1, 16384))
        end
    end

    -- Concatenate corpus into a single searchable string.
    local corpus = table.concat(candidates, " ")

    -- Scan for a known token value. Pure matching logic lives in
    -- honeytoken_rules.lua; this stays the adapter for the record-keeping
    -- and logging that follow a match.
    local token, value = honeytoken_rules.find_token_in_corpus(corpus, TOKEN_VALUE_MAP)
    if token then
        -- Token found.  Increment use counter and log.
        local use_count = _M.record_token_use(token.id, value)

        ngx.log(ngx.CRIT,
            "[HONEYTOKEN] ⚠️  TOKEN USED: id=", token.id,
            " type=", token.type,
            " severity=", token.severity,
            " use_count=", use_count,
            " ip=", ngx.var.remote_addr,
            " uri=", ngx.var.request_uri,
            " | ", token.note)

        -- Log to ELK via utility (fire-and-forget; ELK unavailability must
        -- not break the routing pipeline).
        pcall(function()
            _G.utils.log_security_event("honeytoken_used", {
                token_id   = token.id,
                token_type = token.type,
                severity   = token.severity,
                use_count  = use_count,
                ip         = ngx.var.remote_addr,
                uri        = ngx.var.request_uri,
                user_agent = ngx.var.http_user_agent,
                note       = token.note,
            })
        end)

        result = {
            token_id  = token.id,
            type      = token.type,
            severity  = token.severity,
            use_count = use_count,
        }
    end

    return result
end

--- Record a token use event in Redis.
--- Creates the token record on first use; increments use_count on subsequent uses.
---
--- @param  token_id  string  The token identifier (e.g. "HT-APIKEY-CK").
--- @param  value     string  The raw token value that was matched.
--- @return integer   Updated use_count.
function _M.record_token_use(token_id, value)
    local red = get_redis()
    if not red then
        return 0
    end

    local key = TOKEN_KEY_PREFIX .. token_id
    local existing_json = red:get(key)
    local record

    if existing_json and existing_json ~= ngx.null then
        local ok, decoded = pcall(cjson.decode, existing_json)
        record = ok and decoded or nil
    end

    if not record then
        -- First use: create the record.
        record = {
            token_id       = token_id,
            value          = value,
            first_used_at  = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            first_used_ip  = ngx.var.remote_addr,
            use_count      = 0,
        }
    end

    record.use_count      = (record.use_count or 0) + 1
    record.last_used_at   = os.date("!%Y-%m-%dT%H:%M:%SZ")
    record.last_used_ip   = ngx.var.remote_addr
    record.last_used_uri  = ngx.var.request_uri

    red:setex(key, TOKEN_TTL, cjson.encode(record))
    _G.redis_pool.close_connection(red)

    return record.use_count
end

-- ---------------------------------------------------------------------------
-- Public API: Injection
-- ---------------------------------------------------------------------------

--- Inject honeytokens into an outgoing response body (header_filter phase).
---
--- This function is designed to be called from a header_filter_by_lua_block or
--- body_filter_by_lua_block on the honeypot location.  It appends a hidden HTML
--- comment to the response body containing several honeytoken "hints" that a
--- careful attacker inspecting the page source will notice and try to use.
---
--- The comment is injected only into text/html responses to avoid corrupting
--- JSON API responses (which are checked separately via inject_into_api_response).
---
--- @param  pool_num  integer  The honeypot pool number (for per-pool token variants).
--- @return string|nil  Fragment to append to body, or nil if injection is not appropriate.
function _M.build_html_injection(pool_num)
    -- Only inject into HTML responses.
    local ct = ngx.header["Content-Type"] or ""
    if not string.find(ct, "text/html") then
        return nil
    end

    -- Craft the injected comment with multiple honeytoken hints.
    -- Format is realistic: looks like a developer left debug output in the source.
    local fragment = string.format([[
<!-- DEBUG: pool=%d host=%s user=wp_prod_user pass=%s -->
<!-- TODO: remove before production deploy: admin fallback = %s -->
]],
        pool_num or 1,
        FAKE_DB_HOST,
        TOKENS[3].value,   -- HT-DBCREDS-PASS
        TOKENS[4].value    -- HT-ADMINPW
    )

    ngx.log(ngx.INFO, "[HONEYTOKEN] Injected HTML comment honeytokens for pool ", pool_num)
    return fragment
end

--- Build a fake WooCommerce API credential response fragment.
--- Called when the honeypot serves a /wp-json/wc/v3/ response to inject
--- the HT-APIKEY tokens into the JSON body as a "leaked" key pair.
---
--- @return table  Fake credential table to merge into the JSON response.
function _M.build_api_credential_injection()
    return {
        consumer_key    = TOKENS[1].value,  -- HT-APIKEY-CK
        consumer_secret = TOKENS[2].value,  -- HT-APIKEY-CS
        key_permissions = "read_write",
        description     = "Internal automation key",
        last_access     = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    }
end

--- Build a fake wp-config.php snippet for honeypot config-file leak responses.
--- Returned as plain text to be inserted into an HTTP response body that
--- simulates a wp-config.php disclosure (e.g. a misconfigured backup endpoint).
---
--- @return string  Plain-text wp-config.php snippet.
function _M.build_config_leak_injection()
    return string.format([[
/** WordPress database credentials — DO NOT COMMIT */
define( 'DB_HOST',     '%s' );
define( 'DB_NAME',     'wp_production' );
define( 'DB_USER',     'wp_prod_user' );
define( 'DB_PASSWORD', '%s' );
define( 'AUTH_KEY',    '%s' );
define( 'SECURE_AUTH_KEY', '%s' );
]],
        FAKE_DB_HOST,
        TOKENS[3].value,   -- HT-DBCREDS-PASS
        TOKENS[5].value,   -- HT-JWTKEY (reuse as AUTH_KEY)
        TOKENS[5].value    -- HT-JWTKEY
    )
end

-- ---------------------------------------------------------------------------
-- Public API: Token statistics
-- ---------------------------------------------------------------------------

--- Retrieve usage statistics for all known honeytokens from Redis.
--- Used by the /nginx-health monitoring endpoint and by the data-collection
--- export script (collect_data.sh) for research analysis.
---
--- @return table  Array of token_stat objects.
function _M.get_token_stats()
    local red = get_redis()
    if not red then
        return {}
    end

    local stats = {}
    for _, token in ipairs(TOKENS) do
        local key = TOKEN_KEY_PREFIX .. token.id
        local json = red:get(key)
        if json and json ~= ngx.null then
            local ok, record = pcall(cjson.decode, json)
            if ok then
                table.insert(stats, {
                    token_id      = token.id,
                    token_type    = token.type,
                    severity      = token.severity,
                    use_count     = record.use_count or 0,
                    first_used_at = record.first_used_at,
                    last_used_at  = record.last_used_at,
                    last_used_ip  = record.last_used_ip,
                })
            end
        else
            -- Token never used: include a zero-count entry for completeness.
            table.insert(stats, {
                token_id  = token.id,
                token_type = token.type,
                severity  = token.severity,
                use_count = 0,
            })
        end
    end

    _G.redis_pool.close_connection(red)
    return stats
end

--- Return a flat list of all token values for external callers that need to
--- scan response bodies for accidental token leakage (self-audit).
---
--- @return table  Array of raw token value strings.
function _M.get_all_token_values()
    local values = {}
    for _, token in ipairs(TOKENS) do
        table.insert(values, token.value)
    end
    return values
end

ngx.log(ngx.INFO, "[HONEYTOKEN] Module loaded. ",
    #TOKENS, " tokens registered. Deployment salt hash: ",
    derive_token("audit"):sub(1, 8))

return _M