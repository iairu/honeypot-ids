-- init.lua - Nginx Lua initialization module
--
-- PURPOSE:
--   Runs once in the Nginx master process (init_by_lua_file phase) before any
--   worker is spawned.  Sets up the global configuration table (_G.config),
--   utility functions (_G.utils), the Redis connection-pool helpers
--   (_G.redis_pool), and pre-populates the Lua shared dictionaries with
--   seed threat-intelligence data.
--
-- GLOBALS EXPORTED:
--   _G.config       – Nested table with all tunable parameters (see below).
--   _G.utils        – Stateless utility functions (IP whitelist check, UUID
--                     generation, threat-score calculation, event logging).
--   _G.redis_pool   – get_connection() / close_connection() wrappers that
--                     maintain a per-worker keepalive pool to the Redis
--                     session_store service.
--
-- SHARED DICTIONARIES (declared in nginx.conf lua_shared_dict directives):
--   sessions        – Worker-local cache of session JSON blobs (10 MB).
--                     Reduces Redis round-trips on hot paths.
--   threat_intel    – Threat-intelligence data: malicious IPs, malicious
--                     user-agents, and backend health-check results (10 MB).
--   rate_limit      – Per-IP request-rate counters for botnet detection (10 MB).
--   honeypot_routes – Per-IP pool assignments cached locally for 5 min (1 MB).
--
-- CONFIGURATION GUIDE:
--   All values can be overridden at deploy time via environment variables
--   injected through docker-compose.yml.  The password fields specifically
--   MUST be set via env vars; never hardcode secrets in this file.

local cjson = require "cjson"
local redis = require "resty.redis"

-- ---------------------------------------------------------------------------
-- _G.config – Central configuration table
--
-- All sub-tables and their fields are documented inline below.
-- Callers reference values as e.g. _G.config.threat.honeypot_threshold.
-- ---------------------------------------------------------------------------
_G.config = {

    -- -----------------------------------------------------------------------
    -- redis: Connection parameters for the session_store Redis container.
    --
    --   host       – Docker service name; resolved by Docker's embedded DNS.
    --   port       – Default Redis port (no TLS; traffic stays on Docker
    --                bridge networks, never leaves the host).
    --   password   – Read from REDIS_PASSWORD env var injected by docker-compose.
    --                Fallback value is for local development only; MUST be
    --                changed in any internet-facing deployment.
    --   timeout    – Socket I/O timeout in milliseconds.  1 s is generous;
    --                Redis on the same host typically responds in < 1 ms.
    --   pool_size  – Max keepalive connections per Nginx worker to Redis.
    --                100 connections × N workers; tune based on worker count.
    --   backlog    – Nginx connection backlog size (nil = use system default).
    -- -----------------------------------------------------------------------
    redis = {
        host = "session_store",
        port = 6379,
        password = os.getenv("REDIS_PASSWORD") or "session_redis_password",  -- Fallback for backwards compatibility
        timeout = 1000,
        pool_size = 100,
        backlog = nil
    },

    -- -----------------------------------------------------------------------
    -- session: HTTP session management parameters.
    --
    --   cookie_name        – Name of the session-tracking cookie set by Nginx.
    --                        Deliberately resembles a standard PHP session cookie
    --                        to avoid raising suspicion in browser DevTools.
    --   max_idle_time      – Session TTL in seconds after the last request.
    --                        3600 s (1 hour) matches typical WooCommerce checkout
    --                        session durations so honeypot sessions feel realistic.
    --   cleanup_interval   – How often (seconds) the background session-cleanup
    --                        timer in init_worker.lua runs to evict expired
    --                        entries from the local shared dict.
    -- -----------------------------------------------------------------------
    session = {
        cookie_name = "HONEYPOT_SESSION",
        max_idle_time = 3600,
        cleanup_interval = 300
    },

    -- -----------------------------------------------------------------------
    -- threat: Threat-scoring and routing parameters.
    --
    --   ip_whitelist       – CIDR ranges or exact IPs that receive a negative
    --                        reputation score (−20) and are never diverted to
    --                        the honeypot.  Should include the operator's admin
    --                        IP, Tailscale tunnel range, and the university/lab
    --                        network used for testing.
    --   max_threat_score   – Hard cap on the accumulated score (100).  Prevents
    --                        a single extremely high-scoring request from
    --                        distorting per-session rolling averages.
    --   honeypot_threshold – Minimum total score that triggers honeypot routing.
    --                        Raised from 50 to 80 after tuning to eliminate
    --                        false-positives on aggressive but legitimate REST
    --                        API clients (WooCommerce mobile app, Stripe webhooks).
    --   score_decay_half_life_seconds – How long a honeypot-bound session's
    --                        stored peak threat_score takes to decay to half
    --                        its value once no new suspicious signal has
    --                        occurred (router.lua Stage 2's "allow production
    --                        again" re-check, router_rules.decayed_score()).
    --                        Added after confirming live that the un-stick
    --                        check previously used only the CURRENT request's
    --                        own score -- a single clean request (e.g. just
    --                        loading "/") fully reset a session that had JUST
    --                        triggered a CVE match moments earlier, letting an
    --                        attacker freely alternate "run exploit" / "visit
    --                        homepage" to re-run every exploit against
    --                        production from a clean slate every time. 300s (5
    --                        min) means a session can't be un-stuck by one
    --                        click, but a genuinely-reformed/false-positived
    --                        session isn't bound forever either.
    -- -----------------------------------------------------------------------
    threat = {
        ip_whitelist = {
            "127.0.0.1/32",
            "100.64.0.0/10",    -- Tailscale
            "10.0.0.0/8",       -- Private networks
        },
        max_threat_score = 100,
        honeypot_threshold = 80,  -- Raised from 50 to prevent false positives
        score_decay_half_life_seconds = tonumber(os.getenv("SCORE_DECAY_HALF_LIFE_SECONDS")) or 300,
        static_asset_patterns = {
            "robots%.txt",
            "sitemap%.xml",
            "%.css",
            "%.js",
            "%.jpg",
            "%.jpeg",
            "%.png",
            "%.gif",
            "%.svg",
            "%.woff",
            "%.woff2",
            "%.ttf",
            "%.eot",
            "%.otf",
            "%.ico",
            "%.webp",
            "%.webm",
            "%.mp4",
            "%.mp3",
            "%.pdf",
            "%.zip",
            "%.tar",
            "%.gz",
            "%.map",
            "/fonts/",
            "/images/",
            "/assets/",
            "/wp%-content/themes/",
            "/wp%-content/plugins/.*%.css",
            "/wp%-content/plugins/.*%.js",
            "/wp%-includes/css/",
            "/wp%-includes/js/",
            "/wp%-includes/fonts/"
        },
        -- suspicious_patterns: Generic OWASP WSTG-INPV attack signatures.
        -- Each pattern is a Lua string pattern (not PCRE) tested against the
        -- lower-cased request URI.  A match adds +15 to the threat score.
        -- More specific checks with individual scores live in threat_analyzer.lua.
        suspicious_patterns = {
            -- WSTG-INPV-01: Directory traversal
            "%.%.%/",                    -- ../ traversal
            "%.%.%\\",                  -- ..\\ traversal (Windows)
            
            -- WSTG-INPV-05: SQL Injection
            "union.*select",            -- UNION-based SQLi
            "or.*1.*=.*1",              -- OR 1=1 SQLi
            "select.*from",             -- SELECT FROM SQLi
            "drop.*table",              -- DROP TABLE SQLi
            "insert.*into",             -- INSERT INTO SQLi
            "sleep",                    -- SLEEP time-based SQLi
            "benchmark",                -- BENCHMARK time-based SQLi
            
            -- WSTG-INPV-02: XSS
            "<script",                  -- Script tag injection
            "javascript:",              -- JavaScript protocol
            "onerror=",                 -- onerror handler
            "onload=",                  -- onload handler
            "alert",                    -- alert call
            
            -- WSTG-INPV-12: Command Injection
            ";cat",                     -- Command chaining with cat
            ";ls",                      -- Command chaining with ls
            "|nc",                      -- Netcat pipe
            "&&curl",                   -- Curl chaining
            
            -- WSTG-INPV-11: File Inclusion
            "php://",                   -- PHP stream wrapper
            "file://",                  -- File protocol
            "data://",                  -- Data protocol
            
            -- WSTG-CONF: Sensitive file access
            "wp-config.php",            -- WordPress config
            "wp-config-",               -- wp-config.php.bak, wp-config.php.old
            ".env",                     -- Environment file
            ".bak",                     -- Backup files
            ".old",                     -- Old files
            ".backup",                  -- Backup extension
            ".sql",                     -- SQL dump files
            ".tar",                     -- Tar archives
            ".gz",                      -- Gzip files
            ".zip",                     -- Zip archives
            "backup",                   -- Backup keyword in path
            "readme.html",              -- WordPress readme
            "install.php",              -- Install script
            "setup-config.php",         -- WordPress setup
            ".htaccess",                -- Apache config
            ".htpasswd",                -- Apache passwords
            "phpinfo",                  -- PHP info pages
            "crossdomain.xml",          -- Flash policy
            
            -- WSTG-INFO: Reconnaissance probes
            "/admin",                   -- Admin path
            "/administrator",           -- Administrator path
            "/phpmyadmin",              -- phpMyAdmin
            "/wp-admin/",               -- WordPress admin
            "/wp-login",                -- WordPress login
            "/wp-includes/",            -- WordPress includes
            "/wp-content/",             -- WordPress content
            "xmlrpc.php",               -- XML-RPC endpoint
            
            -- WSTG-IDNT: User enumeration
            "author=",                  -- Author enumeration
            "/wp-json/wp/v2/users",     -- REST API users
            "rest_route=",              -- REST route
            
            -- WSTG-AUTHZ: Privilege escalation
            "wcal_action=checkout_link", -- CVE-2023-2986
            "integration_id",           -- CVE-2024-2387
            "cwmpUpdateOptions",        -- CVE-2025-2266
            "mwb_wgm_preview_mail",     -- CVE-2025-47577
            "dnd-wc-upload-file",       -- CVE-2025-4403
            "pc_added_uploaded_image",  -- CVE-2025-10142
            "file[path]",               -- CVE-2024-50508
            
            -- WSTG-INPV: Other injection
            "cmd=",                     -- Command parameter
            "template=",                -- Template injection
            "page=",                    -- Page inclusion
            "file=",                    -- File inclusion
            "redirect=",                -- Redirect injection
            "redirect_to=",             -- WordPress redirect
            
            -- WSTG-INPV-15: HTTP Splitting
            "%%0d%%0a",                   -- CRLF injection
            
            -- WSTG-AUTHZ: IDOR patterns
            "user_id=",                 -- User ID parameter
            "customer_id=",             -- Customer ID
            "order_id=",                -- Order ID
            "post_id=",                 -- Post ID
            "context=edit",             -- WordPress edit context
            
            -- WSTG-ATHN: Authentication attacks
            "wp-login.php",             -- WordPress login
            "action=lostpassword",      -- Password reset
            "action=register",          -- Registration
            
            -- WSTG-CONF: Cloud/Storage
            "s3-backup",                -- S3 backup path
        },

        -- static_asset_patterns: URI suffixes and path prefixes that identify
        -- static assets (CSS, JS, images, fonts).  Requests matching any of
        -- these are short-circuited through the production backend without threat
        -- scoring, session lookup, or pool-router evaluation.  This keeps
        -- per-asset-request overhead near zero on heavily-loaded pages.
        -- NOTE: Keep in sync with the static-asset location block in nginx.conf.
    },

    -- -----------------------------------------------------------------------
    -- vulnerability: Plugin list and CVE detection patterns.
    --
    --   plugins      – List of plugin directory names (as they appear in the
    --                  URL path /wp-content/plugins/<name>/) that are
    --                  intentionally installed in the honeypot instances but
    --                  absent from the production instance.  Any PHP file access
    --                  inside one of these directories triggers Stage 5 honeypot
    --                  routing in router.lua regardless of the threat score.
    --
    --   cve_patterns – Map of CVE ID → Lua string pattern.  threat_analyzer.lua
    --                  checks these against the URI, query string, and request
    --                  headers.  A single match scores +40 (Stage 3 routing).
    --                  Patterns use Lua magic-character escaping (%- for literal
    --                  hyphen, %[ %] for brackets, etc.).
    -- -----------------------------------------------------------------------
    -- -----------------------------------------------------------------------
    -- abuseipdb: AbuseIPDB threat-intelligence integration parameters.
    --
    --   api_key             – Read from ABUSEIPDB_API_KEY env var.  When nil or
    --                         the placeholder value, abuseipdb_client disables
    --                         itself (bulk feed, on-demand checks, report-back
    --                         all become no-ops) so the system runs fine
    --                         without a key configured.
    --   confidence_minimum  – AbuseIPDB confidence score (0-100) threshold used
    --                         when pulling the bulk /blacklist feed.  Only IPs
    --                         at or above this confidence are imported into
    --                         threat_intel.
    --   daily_check_limit   – Free-tier daily cap on on-demand /check calls.
    --                         abuseipdb_client tracks a counter in the
    --                         threat_intel shared dict keyed by UTC date and
    --                         refuses further checks once the cap is reached.
    -- -----------------------------------------------------------------------
    abuseipdb = {
        api_key = os.getenv("ABUSEIPDB_API_KEY"),
        confidence_minimum = tonumber(os.getenv("ABUSEIPDB_CONFIDENCE_MINIMUM")) or 90,
        daily_check_limit = tonumber(os.getenv("ABUSEIPDB_DAILY_CHECK_LIMIT")) or 1000,
        -- blacklist_enabled: separate opt-in from just "is an API key
        -- configured" (abuseipdb_client.is_enabled()) -- the bulk
        -- /blacklist pull is the single biggest quota consumer of the
        -- three AbuseIPDB integrations (bulk pull vs. one-IP-at-a-time
        -- check/report), and free-tier accounts can have a real daily cap
        -- as low as single digits. Defaults OFF: on-demand check/report
        -- stay available (their own, much cheaper, per-IP quota already
        -- tracked via daily_check_limit) even when this is off.
        blacklist_enabled = (os.getenv("ABUSEIPDB_BLACKLIST_ENABLED") or "false") == "true",
        -- blacklist_refresh_hours: minimum age (in the Redis-backed cache,
        -- see abuseipdb_client.lua's load_cached_blacklist()) before a
        -- fresh /blacklist call is allowed at all -- restarting
        -- reverse_proxy no longer forces a fresh API call by itself.
        -- Default 24h keeps this to at most 1 call/day even under
        -- frequent restarts, leaving headroom under a small daily quota.
        blacklist_refresh_hours = tonumber(os.getenv("ABUSEIPDB_BLACKLIST_REFRESH_HOURS")) or 24
    },

    -- internal_test_secret: shared secret gating the X-Route-Target /
    -- X-Threat-Score response headers (see nginx.conf's two
    -- header_filter_by_lua_block sites). Those headers exist so the
    -- testing/scenario_*.sh scripts can externally verify routing
    -- decisions, but shipping them on every response to every client
    -- hands a real attacker (or a blind pentest) the routing/threat-score
    -- oracle for free -- see BLIND_PENTEST_PROTOCOL.md §8.2. When this is
    -- set, the headers are only emitted for requests carrying a matching
    -- X-Internal-Test-Auth header; when unset/empty, the headers are never
    -- emitted (fail closed, not fail open).
    internal_test_secret = os.getenv("INTERNAL_TEST_SECRET") or "",

    vulnerability = {
        plugins = {
            "woocommerce-payments",           -- CVE-2023-28121
            "abandoned-cart-lite",            -- CVE-2023-2986
            "drag-and-drop-multiple-file-upload", -- CVE-2025-4403
            "cwmp",                           -- CVE-2025-2266
            "gift-voucher",                   -- CVE-2025-47577, CVE-2024-8425
            "advanced-form-integration",      -- CVE-2024-2387
            "pagseguro-connect-woocommerce",  -- CVE-2025-10142
            "wp-file-upload"                  -- CVE-2024-50508
        },
        cve_patterns = {
            -- CVE-2023-28121: WooCommerce Payments header-based auth bypass.
            -- Matches both header name (case-insensitive via Lua lower()) and
            -- the REST API user-creation endpoint.
            ["CVE-2023-28121"] = "X%-WCPAY%-PLATFORM%-CHECKOUT%-USER",

            -- CVE-2023-2986: Abandoned Cart Lite checkout token forgery.
            -- The wcal_action=checkout_link query parameter triggers the
            -- vulnerable code path.
            ["CVE-2023-2986"] = "wcal_action=checkout_link",

            -- CVE-2025-4403: DnD file upload MIME-type bypass.
            -- The dnd-wc-upload-file action name appears in POST bodies.
            ["CVE-2025-4403"] = "dnd%-wc%-upload%-file",

            -- CVE-2025-2266: CWMP unauthenticated WordPress options write.
            -- The cwmpUpdateOptions action is posted without a nonce check.
            ["CVE-2025-2266"] = "cwmpUpdateOptions",

            -- CVE-2025-47577 / CVE-2024-8425: Gift Voucher file upload RCE.
            -- Both CVEs share the same vulnerable AJAX action.
            ["CVE-2025-47577"] = "mwb_wgm_preview_mail",
            ["CVE-2024-8425"]  = "mwb_wgm_preview_mail",

            -- CVE-2024-2387: AFI SQL injection via integration_id parameter.
            -- Single-quote after the parameter value is the injection trigger.
            ["CVE-2024-2387"] = "integration_id.*'",

            -- CVE-2025-10142: PagSeguro Connect file path traversal.
            -- The pc_added_uploaded_image action accepts an unsanitised path.
            ["CVE-2025-10142"] = "pc_added_uploaded_image",

            -- CVE-2024-50508: WP File Upload directory traversal.
            -- The file[path] parameter is passed directly to a filesystem call.
            ["CVE-2024-50508"] = "file%[path%]"
        }
    }
}

-- ---------------------------------------------------------------------------
-- _G.utils – Stateless utility helpers shared across all Lua modules.
-- ---------------------------------------------------------------------------
_G.utils = {}

--- Check whether an IP address falls within any whitelisted range.
---
--- Uses a prefix-length-aware string comparison rather than a full CIDR
--- library to keep the dependency footprint minimal.  Sufficient for the
--- small, well-structured whitelist defined in _G.config.threat.ip_whitelist.
---
--- LIMITATION: The prefix-length field is parsed but the actual bit-mask
--- comparison is approximated by string prefix matching on the dotted-decimal
--- representation.  This works correctly for /8, /16, /24, and /32 masks
--- (which cover all entries in the default whitelist) but may produce wrong
--- results for non-octet-aligned prefixes such as /10 on a /12 boundary.
--- A production deployment with complex CIDR requirements should replace this
--- with a proper CIDR library.
---
--- @param  ip  string  IPv4 address in dotted-decimal notation.
--- @return boolean  true if the IP is whitelisted.
function _G.utils.is_ip_whitelisted(ip)
    local whitelisted_ranges = _G.config.threat.ip_whitelist
    local bit = require("bit")
    
    local function ip2num(ip_str)
        if not ip_str then return nil end
        local a, b, c, d = ip_str:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
        if not a then return nil end
        return bit.bor(bit.lshift(tonumber(a), 24), bit.lshift(tonumber(b), 16), bit.lshift(tonumber(c), 8), tonumber(d))
    end

    local ip_num = ip2num(ip)
    if not ip_num then return false end

    for _, range in ipairs(whitelisted_ranges) do
        if string.find(range, "/") then
            local network, prefix = range:match("([^/]+)/(%d+)")
            local net_num = ip2num(network)
            prefix = tonumber(prefix)
            if net_num and prefix then
                local mask = bit.lshift(-1, 32 - prefix)
                if bit.band(ip_num, mask) == bit.band(net_num, mask) then
                    return true
                end
            end
        else
            if ip == range then
                return true
            end
        end
    end
    return false
end

--- URL-decode a string (percent-encoding and "+" as space).
--- Shared by threat_analyzer.lua (URI pattern matching) and the
--- prompt-injection probe stage so both operate on decoded text instead of
--- each maintaining their own copy of this logic.
---
--- @param str string
--- @return string
function _G.utils.url_decode(str)
    if not str then return "" end
    str = string.gsub(str, "%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    str = string.gsub(str, "+", " ")
    return str
end

--- Generate a random UUID v4 string.
--- Used for session IDs and internal correlation tokens.
--- NOTE: Relies on Lua's math.random which is seeded per-worker in
--- init_worker.lua (math.randomseed(ngx.time() + ngx.worker.pid())).
--- Not cryptographically secure; use only for non-secret identifiers.
---
--- @return string  UUID string in 8-4-4-4-12 hex format.
function _G.utils.generate_uuid()
    local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    return string.gsub(template, '[xy]', function(c)
        local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)
        return string.format('%x', v)
    end)
end

--- Compute a combined threat score from individual sub-scores.
--- Used by threat_analyzer.lua as a final normalisation step.
---
--- Scoring weights:
---   patterns_matched  × 10 per pattern   (URI/header pattern hits)
---   cve_matched       × 25 per CVE        (CVE-specific pattern hits)
---   ip_reputation     raw value            (from threat_intel shared dict)
---
--- The result is clamped to max_threat_score (100) to prevent runaway values.
---
--- @param patterns_matched  integer  Number of generic patterns matched.
--- @param cve_matched       integer  Number of CVE-specific patterns matched.
--- @param ip_reputation     integer  IP reputation score (can be negative for
---                                   whitelisted IPs).
--- @return integer  Normalised threat score in [0..max_threat_score].
function _G.utils.calculate_threat_score(patterns_matched, cve_matched, ip_reputation)
    local base_score = 0
    
    -- Pattern matching score
    base_score = base_score + (patterns_matched * 10)
    
    -- CVE matching score (higher impact)
    base_score = base_score + (cve_matched * 25)
    
    -- IP reputation score
    base_score = base_score + (ip_reputation or 0)
    
    return math.min(base_score, _G.config.threat.max_threat_score)
end

--- Append a structured security event to the Nginx error log.
--- The JSON-encoded entry is readable by Vector (nginx_error_in source in
--- vector.yaml) and forwarded to Elasticsearch via the Vector aggregator.
---
--- @param event_type  string  Short identifier (e.g. "cve_pattern_detected").
--- @param details     table   Arbitrary key-value context for the event.
function _G.utils.log_security_event(event_type, details)
    -- lua-cjson can't tell an empty array from an empty object -- a Lua
    -- table with zero elements is genuinely ambiguous -- and defaults to
    -- encoding it as `{}`. Confirmed live: this locks Elasticsearch's
    -- mapping for that field as `object` from whichever event reaches it
    -- first, silently dropping every later event whose same field (e.g.
    -- high_threat_request's/routing_to_honeypot's `cves`, or `patterns`/
    -- `signals`) actually has real array contents -- the same class of
    -- mapping-conflict bug the SIEM's vector.yaml already works around for
    -- Docker labels. Every field this function is ever called with is
    -- list-shaped when empty (never a genuinely-empty *object*), so
    -- tagging every empty-table value here to encode as `[]` is safe and
    -- fixes this at the source instead of downstream in Vector.
    if details then
        for _, v in pairs(details) do
            if type(v) == "table" and next(v) == nil then
                setmetatable(v, cjson.empty_array_mt)
            end
        end
    end

    local log_entry = {
        timestamp = ngx.time(),
        event_type = event_type,
        details = details,
        server_time = os.date("%Y-%m-%d %H:%M:%S")
    }

    ngx.log(ngx.WARN, "SECURITY_EVENT: ", cjson.encode(log_entry))
end

-- ---------------------------------------------------------------------------
-- _G.redis_pool – Redis keepalive connection management.
--
-- Wraps lua-resty-redis to provide a simple borrow/return interface.
-- All modules that need Redis call _G.redis_pool.get_connection() and MUST
-- call _G.redis_pool.close_connection() when done, even on error paths, to
-- return the socket to the keepalive pool and avoid connection leaks.
--
-- Connection lifecycle:
--   1. get_connection() checks the per-worker keepalive pool first (no TCP
--      handshake if a connection is available).
--   2. If the pool is empty, a new TCP connection is made and AUTH is sent.
--   3. close_connection() puts the socket back into the keepalive pool with
--      a 10-second idle timeout.  The pool holds up to pool_size sockets
--      per Nginx worker process.
-- ---------------------------------------------------------------------------
_G.redis_pool = {}

--- Borrow a Redis connection from the worker-local keepalive pool.
--- @return redis|nil, string|nil  Connection object or nil + error message.
function _G.redis_pool.get_connection()
    local red = redis:new()
    red:set_timeout(_G.config.redis.timeout)
    
    local ok, err = red:connect(_G.config.redis.host, _G.config.redis.port)
    if not ok then
        ngx.log(ngx.ERR, "Failed to connect to Redis: ", err)
        return nil, err
    end
    
    -- Authenticate if password is set.
    -- AUTH is sent even on keepalive-reused connections because resty-redis
    -- does not track auth state across the keepalive pool boundary.
    if _G.config.redis.password then
        local res, err = red:auth(_G.config.redis.password)
        if not res then
            ngx.log(ngx.ERR, "Failed to authenticate with Redis: ", err)
            return nil, err
        end
    end
    
    return red, nil
end

--- Return a Redis connection to the worker-local keepalive pool.
--- Always call this after get_connection(), even when an error occurred,
--- to prevent socket leaks that would exhaust the file-descriptor limit.
--- @param red  redis  Connection object returned by get_connection().
function _G.redis_pool.close_connection(red)
    if red then
        -- set_keepalive(idle_timeout_ms, pool_size)
        -- idle_timeout: 10 s — Redis server's default client timeout is 0
        -- (never), so the client-side timeout drives the keepalive eviction.
        local ok, err = red:set_keepalive(10000, _G.config.redis.pool_size)
        if not ok then
            ngx.log(ngx.WARN, "Failed to set keepalive: ", err)
        end
    end
end

-- ---------------------------------------------------------------------------
-- Shared dictionary initialisation
--
-- The four lua_shared_dict zones are declared in nginx.conf and are shared
-- across ALL worker processes (unlike regular Lua module variables which are
-- per-worker).  We initialise them here in the master process so that worker
-- 0's init_worker.lua does not need to re-seed on startup.
-- ---------------------------------------------------------------------------
local sessions      = ngx.shared.sessions        -- Session blob cache
local threat_intel  = ngx.shared.threat_intel    -- IP/UA reputation + health
local rate_limit    = ngx.shared.rate_limit      -- Per-IP rate counters
local honeypot_routes = ngx.shared.honeypot_routes -- Pool assignment cache

-- Seed threat_intel with static bootstrap data.
-- These entries are overwritten at runtime by:
--   - init_worker.lua: parse_suricata_logs() every 30 s
--   - pool_router.lua: health check results every 10 s
if threat_intel then
    -- Placeholder malicious IPs (real IPs accumulate from Suricata alerts).
    -- Replace or augment with a real threat-feed import for production use.
    threat_intel:set("malicious_ips", cjson.encode({
        ["1.2.3.4"] = { score = 90, reason = "known_botnet" },
        ["5.6.7.8"] = { score = 75, reason = "scanning_activity" }
    }))
    
    -- Malicious user-agent substrings checked in session_handler.lua and
    -- threat_analyzer.lua.  Adding a string here is sufficient to make it
    -- detectable system-wide without any other code change.
    threat_intel:set("malicious_agents", cjson.encode({
        "sqlmap",    -- SQL injection automation
        "nmap",      -- Network scanner
        "masscan",   -- Mass port scanner
        "zap",       -- OWASP ZAP proxy
        "nikto",     -- Web vulnerability scanner
        "dirb",      -- Directory brute-forcer
        "gobuster"   -- Directory/DNS brute-forcer
    }))
end

-- Pre-populate the honeypot_routes dict with plugin-name → "honeypot" entries.
-- router.lua's is_vulnerable_plugin_access() function checks this dict before
-- the Redis round-trip, so plugin endpoint accesses are caught at the fastest
-- possible code path (worker-local memory, no network I/O).
if honeypot_routes then
    for _, plugin in ipairs(_G.config.vulnerability.plugins) do
        honeypot_routes:set("plugin_" .. plugin, "honeypot")
    end
end

ngx.log(ngx.INFO, "Nginx Lua initialization completed successfully")