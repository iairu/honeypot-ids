-- threat_intel.lua
--
-- The read-modify-write boilerplate around the shared `threat_ips` record,
-- extracted from the four places that each open-coded it identically:
-- admin_handler, upload_handler, vulnerability_handler, and init_worker
-- (Suricata alert ingestion). Each of those had its own copy of the same
-- three concerns, with the same bugs to get right each time:
--
--   1. red:get("threat_ips") returns the ngx.null userdata sentinel (NOT
--      Lua nil) for a missing key, so `x or "{}"`/`if x then` don't catch
--      an absent key -- cjson.decode() then crashed with "string expected,
--      got userdata" on a fresh/flushed Redis. load() handles it once.
--   2. threat_ips[ip] must be defaulted to a clean entry before it's bumped.
--   3. The mutated table has to be written back to Redis AND mirrored into
--      the ngx.shared.threat_intel dict that threat_analyzer.lua reads on
--      the hot path (it never touches Redis directly, for latency) -- miss
--      the mirror and the detection updates durable storage but has zero
--      effect on live routing until something else refreshes the dict.
--
-- Each caller keeps its OWN scoring logic (how much to add, the reason
-- string, any handler-specific fields like alert_count/upload_attempts) --
-- only the load/default/persist plumbing lives here.
--
-- Pure of nothing: depends on the same ambient globals every handler here
-- already uses (ngx, cjson). No behavioural change vs. the inlined copies.

local cjson = require "cjson"

local _M = {}

_M.SHARED_DICT = "threat_intel"
_M.KEY = "threat_ips"

--- Decode the threat_ips table from a Redis connection, tolerating a
--- missing key (nil OR ngx.null) and undecodable JSON -- both yield {}.
--- @param red  a connected resty.redis client
--- @return     table  ip -> entry (possibly empty)
function _M.load(red)
    local raw = red:get(_M.KEY)
    if not raw or raw == ngx.null then
        return {}
    end
    local ok, decoded = pcall(cjson.decode, tostring(raw))
    if ok and type(decoded) == "table" then
        return decoded
    end
    return {}
end

--- Return threats[ip], creating a clean default entry first if absent.
--- The returned table is the live entry -- mutate it in place, then call
--- persist(). `extra_defaults` (optional) seeds handler-specific fields on
--- a freshly-created entry (e.g. { vulnerability_attempts = {} }).
--- @param threats        table
--- @param ip             string
--- @param extra_defaults table|nil
--- @return               table  the entry for ip
function _M.ensure(threats, ip, extra_defaults)
    local entry = threats[ip]
    if not entry then
        entry = { raw_score = 0, reason = "clean", updated = ngx.time() }
        if extra_defaults then
            for k, v in pairs(extra_defaults) do
                entry[k] = v
            end
        end
        threats[ip] = entry
    end
    return entry
end

--- Persist the whole threats table to Redis AND mirror it into the
--- shared-memory dict threat_analyzer.lua reads on the hot path. Returns
--- the encoded JSON (handy for logging). `red` may be nil -- the
--- shared-dict mirror still happens, matching admin_handler's original
--- "update shared memory even if Redis is down" behaviour.
--- @param red      a connected resty.redis client, or nil
--- @param threats  table
--- @return         string  the encoded JSON that was stored
function _M.persist(red, threats)
    local encoded = cjson.encode(threats)
    if red then
        red:set(_M.KEY, encoded)
    end
    local shared = ngx.shared[_M.SHARED_DICT]
    if shared then
        shared:set(_M.KEY, encoded)
    end
    return encoded
end

return _M
