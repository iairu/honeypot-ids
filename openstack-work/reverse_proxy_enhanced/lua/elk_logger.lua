-- DEAD CODE: elk_logger.lua - ELK SIEM Integration Module
-- This module is never required by any other Lua file or by nginx.conf.
-- It was intended to let the Nginx layer push security events directly into
-- Elasticsearch, but this responsibility was delegated to the vector service
-- (which ships Nginx access/error logs and Suricata EVE JSON to the SIEM).
-- Retained as a reference implementation for future ELK-direct integration.
-- Sends structured security events to Elasticsearch via HTTP

local cjson = require "cjson"
local http = require "resty.http"

local _M = {}

-- Configuration
local elk_config = {
    enabled = os.getenv("ELK_ENABLED") == "true",
    host = os.getenv("ELASTICSEARCH_HOST") or "localhost",
    port = tonumber(os.getenv("ELASTICSEARCH_PORT")) or 9200,
    protocol = os.getenv("ELASTICSEARCH_PROTOCOL") or "https",
    user = os.getenv("ELASTICSEARCH_USER") or "",
    password = os.getenv("ELASTICSEARCH_PASSWORD") or "",
    index_prefix = "honeypot-nginx",
    timeout = 1000,  -- 1 second timeout to avoid blocking requests
    ssl_verify = os.getenv("ELASTICSEARCH_SSL_VERIFY") == "full",
    batch_size = 10,
    flush_interval = 5  -- seconds
}

-- Batch queue for buffering events
local event_queue = {}
local last_flush_time = ngx.time()

-- Build Elasticsearch URL
local function get_elasticsearch_url()
    local index_name = string.format("%s-%s", elk_config.index_prefix, os.date("%Y.%m.%d"))
    return string.format("%s://%s:%d/%s/_doc",
        elk_config.protocol,
        elk_config.host,
        elk_config.port,
        index_name
    )
end

-- Create Basic Auth header
local function get_auth_header()
    if elk_config.user ~= "" and elk_config.password ~= "" then
        local credentials = elk_config.user .. ":" .. elk_config.password
        return "Basic " .. ngx.encode_base64(credentials)
    end
    return nil
end

-- Send event to Elasticsearch
local function send_to_elasticsearch(event)
    if not elk_config.enabled then
        return true  -- Silent success if disabled
    end

    local httpc = http.new()
    httpc:set_timeout(elk_config.timeout)

    local url = get_elasticsearch_url()
    local headers = {
        ["Content-Type"] = "application/json"
    }

    local auth = get_auth_header()
    if auth then
        headers["Authorization"] = auth
    end

    local res, err = httpc:request_uri(url, {
        method = "POST",
        body = cjson.encode(event),
        headers = headers,
        ssl_verify = elk_config.ssl_verify
    })

    if not res then
        ngx.log(ngx.ERR, "[ELK] Failed to send event to Elasticsearch: ", err)
        return false
    end

    if res.status ~= 201 and res.status ~= 200 then
        ngx.log(ngx.WARN, "[ELK] Elasticsearch returned status ", res.status, ": ", res.body)
        return false
    end

    return true
end

-- Flush queued events
local function flush_events()
    if #event_queue == 0 then
        return
    end

    for _, event in ipairs(event_queue) do
        send_to_elasticsearch(event)
    end

    event_queue = {}
    last_flush_time = ngx.time()
end

-- Add event to queue and flush if needed
local function queue_event(event)
    table.insert(event_queue, event)

    local current_time = ngx.time()
    if #event_queue >= elk_config.batch_size or (current_time - last_flush_time) >= elk_config.flush_interval then
        flush_events()
    end
end

-- Log security event
function _M.log_security_event(event_data)
    local event = {
        ["@timestamp"] = os.date("!%Y-%m-%dT%H:%M:%S.000Z"),
        event_type = "security_event",
        source = "nginx_lua",
        honeypot_system = "reverse_proxy",
        environment = os.getenv("ENVIRONMENT") or "development",

        -- Request details
        client_ip = event_data.client_ip or ngx.var.remote_addr,
        method = event_data.method or ngx.var.request_method,
        uri = event_data.uri or ngx.var.request_uri,
        host = event_data.host or ngx.var.host,
        user_agent = event_data.user_agent or ngx.var.http_user_agent,
        referer = event_data.referer or ngx.var.http_referer,

        -- Security details
        session_id = event_data.session_id,
        threat_score = event_data.threat_score,
        route_decision = event_data.route_decision,
        attack_type = event_data.attack_type,
        cve_matched = event_data.cve_matched,
        patterns_matched = event_data.patterns_matched,

        -- Additional context
        headers = event_data.headers,
        query_string = event_data.query_string,
        request_body = event_data.request_body,

        -- Metadata
        tags = {"honeypot", "nginx", "security", "lua"},
        severity = event_data.severity or "medium"
    }

    queue_event(event)

    -- Also log locally for redundancy
    ngx.log(ngx.WARN, "[SECURITY] ", cjson.encode(event))
end

-- Log routing decision
function _M.log_routing_decision(session_id, decision, threat_score, reason)
    local event = {
        ["@timestamp"] = os.date("!%Y-%m-%dT%H:%M:%S.000Z"),
        event_type = "routing_decision",
        source = "nginx_lua",
        honeypot_system = "reverse_proxy",
        environment = os.getenv("ENVIRONMENT") or "development",

        session_id = session_id,
        route_target = decision,
        threat_score = threat_score,
        reason = reason,

        client_ip = ngx.var.remote_addr,
        uri = ngx.var.request_uri,
        method = ngx.var.request_method,

        tags = {"honeypot", "nginx", "routing", "lua"},
        severity = "info"
    }

    queue_event(event)
end

-- Log attack attempt
function _M.log_attack_attempt(attack_details)
    local event = {
        ["@timestamp"] = os.date("!%Y-%m-%dT%H:%M:%S.000Z"),
        event_type = "attack_attempt",
        source = "nginx_lua",
        honeypot_system = "reverse_proxy",
        environment = os.getenv("ENVIRONMENT") or "development",

        attack_type = attack_details.attack_type,
        cve = attack_details.cve,
        pattern = attack_details.pattern,
        severity = attack_details.severity or "high",

        client_ip = ngx.var.remote_addr,
        uri = ngx.var.request_uri,
        method = ngx.var.request_method,
        user_agent = ngx.var.http_user_agent,

        session_id = attack_details.session_id,
        threat_score = attack_details.threat_score,

        tags = {"honeypot", "nginx", "attack", "lua", "critical"},
        alert = true
    }

    -- High severity attacks are sent immediately
    send_to_elasticsearch(event)

    -- Also log locally
    ngx.log(ngx.WARN, "[ATTACK] ", cjson.encode(event))
end

-- Log session activity
function _M.log_session_activity(session_data)
    local event = {
        ["@timestamp"] = os.date("!%Y-%m-%dT%H:%M:%S.000Z"),
        event_type = "session_activity",
        source = "nginx_lua",
        honeypot_system = "reverse_proxy",
        environment = os.getenv("ENVIRONMENT") or "development",

        session_id = session_data.session_id,
        client_ip = session_data.client_ip or ngx.var.remote_addr,
        action = session_data.action,  -- created, updated, expired, bound_to_honeypot

        threat_score = session_data.threat_score,
        route_preference = session_data.route_preference,
        honeypot_bound = session_data.honeypot_bound,

        tags = {"honeypot", "nginx", "session", "lua"},
        severity = "low"
    }

    queue_event(event)
end

-- Periodic flush function (called from init_worker)
function _M.periodic_flush()
    local current_time = ngx.time()
    if (current_time - last_flush_time) >= elk_config.flush_interval then
        flush_events()
    end
end

-- Get ELK status
function _M.get_status()
    return {
        enabled = elk_config.enabled,
        host = elk_config.host,
        port = elk_config.port,
        queue_size = #event_queue,
        last_flush = last_flush_time
    }
end

ngx.log(ngx.INFO, "[ELK] Logger initialized. Enabled: ", elk_config.enabled,
    ", Endpoint: ", elk_config.protocol, "://", elk_config.host, ":", elk_config.port)

return _M
