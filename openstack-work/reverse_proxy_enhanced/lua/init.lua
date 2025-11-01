-- init.lua - Nginx Lua initialization module
-- This module initializes shared components and configurations

local cjson = require "cjson"
local redis = require "resty.redis"

-- Global configuration
_G.config = {
    redis = {
        host = "session_store",
        port = 6379,
        password = "session_redis_password",
        timeout = 1000,
        pool_size = 100,
        backlog = nil
    },
    session = {
        cookie_name = "HONEYPOT_SESSION",
        max_idle_time = 3600,
        cleanup_interval = 300
    },
    threat = {
        ip_whitelist = {
            "127.0.0.1/32",
            "100.64.0.0/10",    -- Tailscale
            "172.16.0.0/12",    -- STUBA
            "10.0.0.0/8"        -- Private networks
        },
        max_threat_score = 100,
        honeypot_threshold = 80,  -- Raised from 50 to prevent false positives
        suspicious_patterns = {
            "%.%.%/",           -- Directory traversal
            "union.*select",    -- SQL injection
            "<script",          -- XSS
            "eval%(",          -- Code injection
            "base64_decode",   -- Suspicious PHP functions
            "system%(",        -- Command execution
            "exec%(",          -- Command execution
            "passthru%(",      -- Command execution
            "shell_exec%(",    -- Command execution
        }
    },
    vulnerability = {
        plugins = {
            "woocommerce-payments",
            "abandoned-cart-lite", 
            "drag-and-drop-multiple-file-upload",
            "cwmp",
            "gift-voucher",
            "advanced-form-integration",
            "pagseguro-connect-woocommerce",
            "wp-file-upload"
        },
        cve_patterns = {
            ["CVE-2023-28121"] = "X%-WCPAY%-PLATFORM%-CHECKOUT%-USER",
            ["CVE-2023-2986"] = "wcal_action=checkout_link",
            ["CVE-2025-4403"] = "dnd%-wc%-upload%-file",
            ["CVE-2025-2266"] = "cwmpUpdateOptions",
            ["CVE-2025-47577"] = "mwb_wgm_preview_mail",
            ["CVE-2024-8425"] = "mwb_wgm_preview_mail",
            ["CVE-2024-2387"] = "integration_id.*'",
            ["CVE-2025-10142"] = "pc_added_uploaded_image",
            ["CVE-2024-50508"] = "file%[path%]"
        }
    }
}

-- Utility functions
_G.utils = {}

function _G.utils.is_ip_whitelisted(ip)
    local whitelisted_ranges = _G.config.threat.ip_whitelist
    
    -- Simple IP range checking (basic implementation)
    for _, range in ipairs(whitelisted_ranges) do
        if string.find(range, "/") then
            local network, prefix = range:match("([^/]+)/(%d+)")
            -- Basic subnet checking - in production, use proper CIDR library
            if string.sub(ip, 1, string.len(network)) == network then
                return true
            end
        else
            if ip == range then
                return true
            end
        end
    end
    return false
end

function _G.utils.generate_uuid()
    local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    return string.gsub(template, '[xy]', function(c)
        local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)
        return string.format('%x', v)
    end)
end

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

function _G.utils.log_security_event(event_type, details)
    local log_entry = {
        timestamp = ngx.time(),
        event_type = event_type,
        details = details,
        server_time = os.date("%Y-%m-%d %H:%M:%S")
    }
    
    ngx.log(ngx.WARN, "SECURITY_EVENT: ", cjson.encode(log_entry))
end

-- Redis connection pool management
_G.redis_pool = {}

function _G.redis_pool.get_connection()
    local red = redis:new()
    red:set_timeout(_G.config.redis.timeout)
    
    local ok, err = red:connect(_G.config.redis.host, _G.config.redis.port)
    if not ok then
        ngx.log(ngx.ERR, "Failed to connect to Redis: ", err)
        return nil, err
    end
    
    -- Authenticate if password is set
    if _G.config.redis.password then
        local res, err = red:auth(_G.config.redis.password)
        if not res then
            ngx.log(ngx.ERR, "Failed to authenticate with Redis: ", err)
            return nil, err
        end
    end
    
    return red, nil
end

function _G.redis_pool.close_connection(red)
    if red then
        local ok, err = red:set_keepalive(10000, _G.config.redis.pool_size)
        if not ok then
            ngx.log(ngx.WARN, "Failed to set keepalive: ", err)
        end
    end
end

-- Initialize shared dictionaries
local sessions = ngx.shared.sessions
local threat_intel = ngx.shared.threat_intel
local rate_limit = ngx.shared.rate_limit
local honeypot_routes = ngx.shared.honeypot_routes

-- Populate initial threat intelligence data
if threat_intel then
    -- Known malicious IPs (example data)
    threat_intel:set("malicious_ips", cjson.encode({
        ["1.2.3.4"] = { score = 90, reason = "known_botnet" },
        ["5.6.7.8"] = { score = 75, reason = "scanning_activity" }
    }))
    
    -- Known user agents
    threat_intel:set("malicious_agents", cjson.encode({
        "sqlmap",
        "nmap",
        "masscan",
        "zap",
        "nikto",
        "dirb",
        "gobuster"
    }))
end

-- Initialize honeypot route mappings
if honeypot_routes then
    for _, plugin in ipairs(_G.config.vulnerability.plugins) do
        honeypot_routes:set("plugin_" .. plugin, "honeypot")
    end
end

ngx.log(ngx.INFO, "Nginx Lua initialization completed successfully")