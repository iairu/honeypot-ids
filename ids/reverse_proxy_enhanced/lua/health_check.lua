-- health_check.lua - Backend health check and readiness verification module
-- This module checks backend availability and manages connection pool health

local http = require "resty.http"
local cjson = require "cjson"

local _M = {}

-- Health check configuration
--
-- HEALTH_CHECK_TIMEOUT was previously declared here but never actually
-- consumed -- check_backend() below hardcoded its own literal 2000ms
-- instead. That mismatch is exactly the kind of thing that silently defeats
-- an attempt to tune this module later (change the constant, nothing
-- happens). Fixed: check_backend() now reads this constant, and its value
-- was raised from 2000ms to 5000ms after a real false-positive was traced
-- to it -- a legitimate, heavy page load (30+ concurrent asset requests)
-- pushed backend response times past 5s under transient PHP-FPM/DB
-- contention, and the 2s health-check timeout tripped on exactly that
-- contention, marking a perfectly healthy backend UNHEALTHY. See
-- check-me.log in the repo root for the original incident.
local HEALTH_CHECK_INTERVAL = 10 -- seconds. See init_worker.lua's use of this.
local HEALTH_CHECK_TIMEOUT = 5000 -- milliseconds
local UNHEALTHY_THRESHOLD = 3
local HEALTHY_THRESHOLD = 2

_M.HEALTH_CHECK_INTERVAL = HEALTH_CHECK_INTERVAL

-- Shared dictionary for health status
local health_status = ngx.shared.threat_intel -- Reuse existing dict

-- Check if a backend is healthy
function _M.check_backend(backend_name, backend_url)
    local httpc = http.new()
    httpc:set_timeouts(HEALTH_CHECK_TIMEOUT, HEALTH_CHECK_TIMEOUT, HEALTH_CHECK_TIMEOUT)
    
    -- Use root path instead of /nginx-health since WordPress doesn't have that endpoint
    local health_endpoint = backend_url .. "/"
    
    -- Try to connect to backend
    local res, err = httpc:request_uri(health_endpoint, {
        method = "HEAD",
        keepalive_timeout = 60000,
        keepalive_pool = 100
    })
    
    if not res then
        ngx.log(ngx.WARN, "[HEALTH] Backend ", backend_name, " check failed: ", err)
        return false, err
    end
    
    -- Accept 200-399 status codes (including redirects) as healthy
    if res.status >= 200 and res.status < 400 then
        ngx.log(ngx.DEBUG, "[HEALTH] Backend ", backend_name, " is healthy (status: ", res.status, ")")
        return true
    else
        ngx.log(ngx.WARN, "[HEALTH] Backend ", backend_name, " returned unhealthy status: ", res.status)
        return false, "unhealthy_status_" .. res.status
    end
end

-- Get backend health status
function _M.get_backend_status(backend_name)
    local status_key = "health:" .. backend_name
    local status_data = health_status:get(status_key)
    
    if not status_data then
        return {
            healthy = true, -- Assume healthy initially
            consecutive_failures = 0,
            consecutive_successes = 0,
            last_check = 0
        }
    end
    
    return cjson.decode(status_data)
end

-- Update backend health status
function _M.update_backend_status(backend_name, is_healthy)
    local status_key = "health:" .. backend_name
    local current_status = _M.get_backend_status(backend_name)
    
    if is_healthy then
        current_status.consecutive_successes = current_status.consecutive_successes + 1
        current_status.consecutive_failures = 0
        
        -- Mark as healthy if it passes threshold
        if current_status.consecutive_successes >= HEALTHY_THRESHOLD then
            current_status.healthy = true
        end
    else
        current_status.consecutive_failures = current_status.consecutive_failures + 1
        current_status.consecutive_successes = 0
        
        -- Mark as unhealthy if it fails threshold
        if current_status.consecutive_failures >= UNHEALTHY_THRESHOLD then
            current_status.healthy = false
            ngx.log(ngx.ERR, "[HEALTH] Backend ", backend_name, " marked as UNHEALTHY after ", 
                   current_status.consecutive_failures, " consecutive failures")
        end
    end
    
    current_status.last_check = ngx.time()
    
    -- Store updated status
    health_status:set(status_key, cjson.encode(current_status), 300) -- 5 min TTL
    
    return current_status
end

-- Perform health check and update status
function _M.perform_health_check(backend_name, backend_url)
    local is_healthy, err = _M.check_backend(backend_name, backend_url)
    local status = _M.update_backend_status(backend_name, is_healthy)
    
    return status.healthy, err
end

-- Check if backend is ready before routing
function _M.is_backend_ready(backend_name)
    local status = _M.get_backend_status(backend_name)
    
    -- If last check was more than 30 seconds ago, consider it stale
    local current_time = ngx.time()
    if status.last_check and (current_time - status.last_check) > 30 then
        ngx.log(ngx.WARN, "[HEALTH] Backend ", backend_name, " status is stale, assuming ready")
        return true -- Assume ready to avoid blocking traffic
    end
    
    return status.healthy
end

-- Wait for backend to become ready (blocking with timeout)
function _M.wait_for_backend(backend_name, backend_url, max_wait_seconds)
    local start_time = ngx.time()
    local wait_seconds = 0
    
    ngx.log(ngx.INFO, "[HEALTH] Waiting for backend ", backend_name, " to become ready...")
    
    while wait_seconds < max_wait_seconds do
        local is_healthy = _M.perform_health_check(backend_name, backend_url)
        
        if is_healthy then
            ngx.log(ngx.INFO, "[HEALTH] Backend ", backend_name, " is ready after ", wait_seconds, " seconds")
            return true
        end
        
        ngx.sleep(1) -- Wait 1 second between checks
        wait_seconds = ngx.time() - start_time
    end
    
    ngx.log(ngx.ERR, "[HEALTH] Backend ", backend_name, " did not become ready within ", max_wait_seconds, " seconds")
    return false
end

-- Pre-warm connections to a backend
function _M.prewarm_backend_connections(backend_name, backend_url, num_connections)
    ngx.log(ngx.INFO, "[PREWARM] Pre-warming ", num_connections, " connections to ", backend_name)
    
    local httpc = http.new()
    httpc:set_timeouts(5000, 5000, 5000) -- 5s timeouts
    
    local success_count = 0
    local fail_count = 0
    
    for i = 1, num_connections do
        local res, err = httpc:request_uri(backend_url, {
            method = "HEAD",
            keepalive_timeout = 120000,
            keepalive_pool = 512
        })
        
        if res and res.status == 200 then
            success_count = success_count + 1
            ngx.log(ngx.DEBUG, "[PREWARM] Connection ", i, "/", num_connections, " to ", backend_name, " successful")
        else
            fail_count = fail_count + 1
            ngx.log(ngx.WARN, "[PREWARM] Connection ", i, "/", num_connections, " to ", backend_name, " failed: ", err or "status_" .. (res and res.status or "unknown"))
        end
        
        -- Small delay between connections
        if i < num_connections then
            ngx.sleep(0.1)
        end
    end
    
    ngx.log(ngx.INFO, "[PREWARM] Pre-warming complete for ", backend_name, 
           ": ", success_count, " successful, ", fail_count, " failed")
    
    return success_count, fail_count
end

-- Get all backend statuses.
-- Single-eshop / two-database topology: there is only production_backend now
-- (the honeypot is the same HTTP backend with a per-request database switch),
-- so there are no honeypot_backend_N pools to report. POOL_COUNT stays 0; the
-- `honeypot` field mirrors production for backward compatibility with any
-- tooling that still reads it.
function _M.get_all_statuses()
    local POOL_COUNT = 0

    local statuses = {
        production = _M.get_backend_status("production_backend"),
        -- No separate honeypot backend any more -- mirror production so callers
        -- that read this legacy field don't see a phantom-backend status.
        honeypot   = _M.get_backend_status("production_backend"),
        pools      = {},
    }

    for i = 1, POOL_COUNT do
        local upstream = "honeypot_backend_" .. i
        statuses.pools[i] = {
            pool_id  = i,
            upstream = upstream,
            service  = "honeypot_eshop_" .. i,
            status   = _M.get_backend_status(upstream),
        }
    end

    return statuses
end

return _M