-- init_worker.lua - Per-worker initialization for Nginx Lua
-- This module initializes worker-specific components and background tasks

local cjson = require "cjson"

-- Try to load optional modules
local http_ok, http = pcall(require, "resty.http")
if not http_ok then
    ngx.log(ngx.WARN, "lua-resty-http not available, connection pre-warming will be disabled")
    http = nil
end

local health_check_ok, health_check = pcall(require, "health_check")
if not health_check_ok then
    ngx.log(ngx.WARN, "health_check module not available, health checks will be disabled")
    health_check = nil
end

-- Worker-specific initialization
local function init_worker()
    -- Initialize random seed for this worker
    math.randomseed(ngx.time() + ngx.worker.pid())
    
    -- Pre-warm connection pools to prevent 503 on first requests
    local function prewarm_connections()
        if not http or not health_check then
            ngx.log(ngx.WARN, "[PREWARM] Required modules not available, skipping pre-warming")
            return
        end
        
        ngx.log(ngx.INFO, "[PREWARM] Starting connection pool pre-warming for worker ", ngx.worker.id())
        
        -- Number of honeypot pool instances – must match POOL_COUNT in pool_router.lua
        -- and the number of honeypot_eshop_N services in docker-compose.yml.
        local POOL_COUNT = 3

        -- Wait for production backend first (critical path).
        local production_ready = health_check.wait_for_backend(
            "production_backend", "http://production_eshop", 30)
        if not production_ready then
            ngx.log(ngx.ERR, "[PREWARM] Production backend not ready, pre-warming may fail")
        end

        -- Wait for each honeypot pool backend independently so that one slow
        -- instance does not block pre-warming of the others.
        local pool_ready = {}
        for i = 1, POOL_COUNT do
            local svc      = "honeypot_eshop_" .. i
            local upstream = "honeypot_backend_" .. i
            pool_ready[i]  = health_check.wait_for_backend(upstream, "http://" .. svc, 30)
            if not pool_ready[i] then
                ngx.log(ngx.WARN,
                    "[PREWARM] Honeypot pool ", i, " (", svc, ") not ready – ",
                    "pre-warming skipped for this pool")
            end
        end

        -- Pre-warm production backend connections (more connections – high traffic).
        if production_ready then
            local success, failed = health_check.prewarm_backend_connections(
                "production_backend",
                "http://production_eshop",
                20  -- 20 keepalive connections for the production instance
            )
            ngx.log(ngx.INFO,
                "[PREWARM] Production backend: ",
                success, " connections established, ", failed, " failed")
        end

        -- Pre-warm each honeypot pool with a smaller connection budget.
        -- Fewer connections per pool are needed because attacker traffic is a
        -- fraction of total traffic and is spread across POOL_COUNT instances.
        for i = 1, POOL_COUNT do
            if pool_ready[i] then
                local svc      = "honeypot_eshop_" .. i
                local upstream = "honeypot_backend_" .. i
                local success, failed = health_check.prewarm_backend_connections(
                    upstream,
                    "http://" .. svc,
                    5  -- 5 keepalive connections per pool instance
                )
                ngx.log(ngx.INFO,
                    "[PREWARM] Honeypot pool ", i, " (", upstream, "): ",
                    success, " connections established, ", failed, " failed")
            end
        end
        
        ngx.log(ngx.INFO, "[PREWARM] Connection pool pre-warming completed for worker ", ngx.worker.id())
    end
    
    -- Schedule pre-warming after a short delay to let services start
    local ok, err = ngx.timer.at(3, function()
        local success, err = pcall(prewarm_connections)
        if not success then
            ngx.log(ngx.ERR, "[PREWARM] Connection pre-warming failed: ", err)
        end
    end)
    if not ok then
        ngx.log(ngx.ERR, "Failed to schedule connection pre-warming: ", err)
    end
    
    -- Set up periodic tasks only in worker 0 to avoid duplication
    if ngx.worker.id() == 0 then
        -- Schedule periodic health checks for production and all honeypot pool
        -- backends. The health status written here (to the shared
        -- ngx.shared.threat_intel dict, visible to every worker) is read by
        -- pool_router.lua's is_pool_healthy()/find_healthy_pool() to decide
        -- whether to fall back to a different honeypot pool when the assigned
        -- one is unhealthy -- production has no equivalent fallback target
        -- (there is only one production instance), so its health status is
        -- monitoring/logging-only; nginx's own upstream max_fails/fail_timeout
        -- (nginx.conf) independently provides production failover.
        --
        -- This registration used to sit OUTSIDE this worker-0 guard, so every
        -- nginx worker process ran its own independent copy of this timer --
        -- with N workers, each backend got checked ~N times every interval
        -- instead of once, and because all workers' timers fire at roughly
        -- the same relative offset (they all start at ~the same time), their
        -- checks landed in the same narrow instant. That let a single moment
        -- of real, transient backend contention trip "3 consecutive
        -- failures" across *different workers'* simultaneous checks almost
        -- instantly, rather than requiring genuine sustained unavailability
        -- across ~3 real intervals as the threshold is meant to represent --
        -- confirmed as the root cause of a real false-positive UNHEALTHY
        -- event in check-me.log (repo root), which fired while a legitimate
        -- user's page load was in progress. Moving this inside the worker-0
        -- guard (matching the AbuseIPDB/session-cleanup/Suricata-log-parser
        -- tasks below, which were already correctly scoped this way) fixes
        -- both the redundant load and the false-positive race.
        if health_check then
            -- Number of honeypot pool instances (keep in sync with pool_router.lua).
            local POOL_COUNT_HC = 3
            local interval = health_check.HEALTH_CHECK_INTERVAL or 10
            local ok, err = ngx.timer.every(interval, function()
                pcall(function()
                    -- Production instance – uses root path (WordPress returns 200-399).
                    health_check.perform_health_check("production_backend", "http://production_eshop")

                    -- Each honeypot pool instance checked independently so that a
                    -- single unhealthy pool does not affect the health status of others.
                    for i = 1, POOL_COUNT_HC do
                        health_check.perform_health_check(
                            "honeypot_backend_" .. i,
                            "http://honeypot_eshop_" .. i)
                    end
                end)
            end)
            if not ok then
                ngx.log(ngx.ERR, "Failed to schedule health checks: ", err)
            end
        end

        -- AbuseIPDB bulk blacklist feed. Populates threat_intel.threat_ips
        -- with high-confidence IPs from the free-tier /blacklist endpoint.
        local abuseipdb_ok, abuseipdb_client = pcall(require, "abuseipdb_client")
        if not abuseipdb_ok then
            ngx.log(ngx.WARN, "abuseipdb_client module not available, AbuseIPDB integration disabled")
        end
        
        -- Start session cleanup task
        local function cleanup_expired_sessions()
            local red, err = _G.redis_pool.get_connection()
            if not red then
                ngx.log(ngx.ERR, "Failed to connect to Redis for session cleanup: ", err)
                return
            end
            
            local current_time = ngx.time()
            local sessions_dict = ngx.shared.sessions
            local keys = sessions_dict:get_keys(1000)
            local cleaned = 0
            
            for _, key in ipairs(keys) do
                local session_data = sessions_dict:get(key)
                if session_data then
                    local session = cjson.decode(session_data)
                    if session.last_activity and (current_time - session.last_activity) > _G.config.session.max_idle_time then
                        sessions_dict:delete(key)
                        red:del("session:" .. key)
                        cleaned = cleaned + 1
                    end
                end
            end
            
            if cleaned > 0 then
                ngx.log(ngx.INFO, "Cleaned up ", cleaned, " expired sessions")
            end
            
            _G.redis_pool.close_connection(red)
        end
        
        -- Start Suricata log parser
        local function parse_suricata_logs()
            local red, err = _G.redis_pool.get_connection()
            if not red then
                ngx.log(ngx.ERR, "Failed to connect to Redis for Suricata log parsing: ", err)
                return
            end
            
            -- Parse fast.log file for new alerts
            local alert_file = "/var/log/suricata/fast.log"
            local file = io.open(alert_file, "r")
            if file then
                local last_position = red:get("suricata_log_position") or 0
                file:seek("set", tonumber(last_position))
                
                local alerts_processed = 0
                for line in file:lines() do
                    -- Parse Suricata alert format
                    local timestamp, priority, classification, src_ip, src_port, dst_ip, dst_port = 
                        line:match("(%d+/%d+/%d+%-%d+:%d+:%d+%.%d+)%s+%[%*%*%]%s+%[(%d+):(%d+):%d+%]%s+.-%s+%[Classification:%s+([^%]]+)%].-(%d+%.%d+%.%d+%.%d+):(%d+)%s+%-%>%s+(%d+%.%d+%.%d+%.%d+):(%d+)")
                    
                    if src_ip then
                        local alert_data = {
                            timestamp = timestamp,
                            priority = tonumber(priority),
                            classification = classification,
                            src_ip = src_ip,
                            src_port = tonumber(src_port),
                            dst_ip = dst_ip,
                            dst_port = tonumber(dst_port),
                            processed_time = ngx.time()
                        }
                        
                        -- Store alert in Redis
                        red:lpush("suricata_alerts", cjson.encode(alert_data))
                        red:ltrim("suricata_alerts", 0, 1000) -- Keep only last 1000 alerts
                        
                        -- Update threat intelligence
                        local current_intel = red:get("threat_ips")
                        local threat_ips = {}
                        if current_intel then
                            threat_ips = cjson.decode(current_intel)
                        end
                        
                        threat_ips[src_ip] = {
                            score = math.min((threat_ips[src_ip] and threat_ips[src_ip].score or 0) + 20, 100),
                            reason = "snort_alert_" .. classification,
                            updated = ngx.time(),
                            alert_count = (threat_ips[src_ip] and threat_ips[src_ip].alert_count or 0) + 1
                        }
                        
                        red:set("threat_ips", cjson.encode(threat_ips))
                        alerts_processed = alerts_processed + 1
                            
                        ngx.log(ngx.WARN, "Suricata alert processed: ", src_ip, " -> ", classification)
                    end
                end
                
                -- Update file position
                red:set("suricata_log_position", file:seek())
                file:close()
                    
                if alerts_processed > 0 then
                    ngx.log(ngx.INFO, "Processed ", alerts_processed, " Suricata alerts")
                end
            end
            
            _G.redis_pool.close_connection(red)
        end
        
        -- Start rate limit cleanup
        local function cleanup_rate_limits()
            local rate_limit_dict = ngx.shared.rate_limit
            local current_time = ngx.time()
            local keys = rate_limit_dict:get_keys(1000)
            local cleaned = 0
            
            for _, key in ipairs(keys) do
                local data = rate_limit_dict:get(key)
                if data then
                    local rate_data = cjson.decode(data)
                    if rate_data.expires and current_time > rate_data.expires then
                        rate_limit_dict:delete(key)
                        cleaned = cleaned + 1
                    end
                end
            end
            
            if cleaned > 0 then
                ngx.log(ngx.DEBUG, "Cleaned up ", cleaned, " expired rate limit entries")
            end
        end
        
        -- Schedule periodic tasks

        -- AbuseIPDB bulk blacklist feed: one delayed run shortly after startup
        -- (so it doesn't compete with connection pre-warming), then every 6h.
        -- The free tier is not meant to be polled more often than that.
        if abuseipdb_ok and abuseipdb_client.is_enabled() then
            local ok, err = ngx.timer.at(15, function(premature)
                if premature then return end
                pcall(abuseipdb_client.fetch_blacklist)
            end)
            if not ok then
                ngx.log(ngx.ERR, "Failed to schedule initial AbuseIPDB blacklist fetch: ", err)
            end

            local ok, err = ngx.timer.every(21600, function() -- Every 6 hours
                pcall(abuseipdb_client.fetch_blacklist)
            end)
            if not ok then
                ngx.log(ngx.ERR, "Failed to create AbuseIPDB blacklist timer: ", err)
            end
        else
            ngx.log(ngx.INFO, "[ABUSEIPDB] Integration disabled (no API key configured)")
        end

        local ok, err = ngx.timer.every(_G.config.session.cleanup_interval, function()
            pcall(cleanup_expired_sessions)
        end)
        if not ok then
            ngx.log(ngx.ERR, "Failed to create session cleanup timer: ", err)
        end
        
        local ok, err = ngx.timer.every(30, function() -- Every 30 seconds
            pcall(parse_suricata_logs)
        end)
        if not ok then
            ngx.log(ngx.ERR, "Failed to create Suricata log parser timer: ", err)
        end
        
        local ok, err = ngx.timer.every(60, function() -- Every minute
            pcall(cleanup_rate_limits)
        end)
        if not ok then
            ngx.log(ngx.ERR, "Failed to create rate limit cleanup timer: ", err)
        end
        
        ngx.log(ngx.INFO, "Background tasks initialized in worker 0")
    end
    
    -- Initialize worker-specific data
    local worker_info = {
        worker_id = ngx.worker.id(),
        worker_pid = ngx.worker.pid(),
        start_time = ngx.time()
    }
    
    ngx.log(ngx.INFO, "Worker ", worker_info.worker_id, " (PID: ", worker_info.worker_pid, ") initialized")
end

-- Execute worker initialization
init_worker()