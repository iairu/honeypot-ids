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
        
        -- Wait for backends to be ready first
        local production_ready = health_check.wait_for_backend("production_backend", "http://production_eshop", 30)
        local honeypot_ready = health_check.wait_for_backend("honeypot_backend", "http://honeypot_eshop", 30)
        
        if not production_ready then
            ngx.log(ngx.ERR, "[PREWARM] Production backend not ready, pre-warming may fail")
        end
        
        if not honeypot_ready then
            ngx.log(ngx.WARN, "[PREWARM] Honeypot backend not ready, pre-warming may fail")
        end
        
        -- Pre-warm production backend connections (more connections for high traffic)
        if production_ready then
            local success, failed = health_check.prewarm_backend_connections(
                "production_backend", 
                "http://production_eshop", 
                20  -- 20 connections for production
            )
            ngx.log(ngx.INFO, "[PREWARM] Production backend: ", success, " connections established, ", failed, " failed")
        end
        
        -- Pre-warm honeypot backend connections (fewer connections needed)
        if honeypot_ready then
            local success, failed = health_check.prewarm_backend_connections(
                "honeypot_backend", 
                "http://honeypot_eshop", 
                10  -- 10 connections for honeypot
            )
            ngx.log(ngx.INFO, "[PREWARM] Honeypot backend: ", success, " connections established, ", failed, " failed")
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
    
    -- Schedule periodic health checks for backends
    if health_check then
        local ok, err = ngx.timer.every(10, function()
            pcall(function()
                health_check.perform_health_check("production_backend", "http://production_eshop")
                health_check.perform_health_check("honeypot_backend", "http://honeypot_eshop")
            end)
        end)
        if not ok then
            ngx.log(ngx.ERR, "Failed to schedule health checks: ", err)
        end
    end
    
    -- Set up periodic tasks only in worker 0 to avoid duplication
    if ngx.worker.id() == 0 then
        -- Start threat intelligence updater
        local function update_threat_intel()
            local red, err = _G.redis_pool.get_connection()
            if not red then
                ngx.log(ngx.ERR, "Failed to connect to Redis for threat intel update: ", err)
                return
            end
            
            -- Update IP reputation data
            if not http then
                ngx.log(ngx.DEBUG, "Skipping threat intel update - lua-resty-http not available")
                _G.redis_pool.close_connection(red)
                return
            end
            
            local httpc = http.new()
            local res, err = httpc:request_uri("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", {
                method = "GET",
                ssl_verify = false,
                timeout = 5000
            })
            
            if res and res.status == 200 then
                local threat_ips = {}
                for line in res.body:gmatch("[^\r\n]+") do
                    if not line:match("^#") and line:match("%d+%.%d+%.%d+%.%d+") then
                        local ip = line:match("(%d+%.%d+%.%d+%.%d+)")
                        if ip then
                            threat_ips[ip] = {
                                score = 80,
                                reason = "ipsum_feed",
                                updated = ngx.time()
                            }
                        end
                    end
                end
                
                -- Store in Redis
                red:set("threat_ips", cjson.encode(threat_ips))
                ngx.log(ngx.INFO, "Updated threat intelligence with ", #threat_ips, " IPs")
            end
            
            _G.redis_pool.close_connection(red)
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
        local ok, err = ngx.timer.every(300, function() -- Every 5 minutes
            pcall(update_threat_intel)
        end)
        if not ok then
            ngx.log(ngx.ERR, "Failed to create threat intel timer: ", err)
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