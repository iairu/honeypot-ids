-- test_threat_intel.lua - Standalone unit tests for threat_intel.lua
--
-- threat_intel.lua depends on ambient ngx.* and cjson, neither of which
-- exists under a plain `lua` interpreter -- so this test stubs both before
-- requiring the module, the same way the module runs inside OpenResty.
--
-- Usage:
--   cd ids/reverse_proxy_enhanced/lua/tests
--   lua test_threat_intel.lua

package.path = "../?.lua;" .. package.path

-- Minimal cjson stub good enough for round-tripping the small tables used
-- here. Registered under the module name require("cjson") resolves.
local function json_encode(v)
    if type(v) == "table" then
        local parts = {}
        for k, val in pairs(v) do
            parts[#parts + 1] = tostring(k) .. "=" .. json_encode(val)
        end
        table.sort(parts)
        return "{" .. table.concat(parts, ",") .. "}"
    end
    return tostring(v)
end
package.loaded["cjson"] = {
    encode = json_encode,
    -- decode is only exercised via the real Redis payloads below, which we
    -- hand back as pre-decoded Lua tables through the fake client instead;
    -- so decode just needs to survive being called on our encoded strings.
    decode = function(s) return package.loaded["cjson"].__decoded[s] end,
    __decoded = {},
}

-- Fake ngx with a controllable shared dict and time.
local shared_store = {}
_G.ngx = {
    null = setmetatable({}, { __tostring = function() return "userdata: NULL" end }),
    time = function() return 1000 end,
    shared = {
        threat_intel = {
            _data = shared_store,
            get = function(self, k) return self._data[k] end,
            set = function(self, k, v) self._data[k] = v end,
        },
    },
}

local ti = require "threat_intel"

local passed, failed = 0, 0
local function check(name, cond)
    if cond then passed = passed + 1; print("  [PASS] " .. name)
    else failed = failed + 1; print("  [FAIL] " .. name) end
end

-- Fake redis client: get returns whatever we seed; set records the write.
local function fake_redis(initial)
    return {
        _store = { threat_ips = initial },
        get = function(self, k) return self._store[k] end,
        set = function(self, k, v) self._store[k] = v end,
    }
end

-- load(): missing key as Lua nil -> {}
do
    local red = fake_redis(nil)
    local t = ti.load(red)
    check("load: nil key yields empty table", type(t) == "table" and next(t) == nil)
end

-- load(): missing key as ngx.null -> {} (the bug this centralizes)
do
    local red = fake_redis(ngx.null)
    local t = ti.load(red)
    check("load: ngx.null key yields empty table (not a crash)", type(t) == "table" and next(t) == nil)
end

-- load(): real JSON payload decodes back to a table
do
    local payload = "{stored=1}"
    package.loaded["cjson"].__decoded[payload] = { ["1.2.3.4"] = { raw_score = 42 } }
    local red = fake_redis(payload)
    local t = ti.load(red)
    check("load: decodes an existing payload", t["1.2.3.4"] and t["1.2.3.4"].raw_score == 42)
end

-- ensure(): creates a clean default entry, and seeds extra_defaults
do
    local threats = {}
    local entry = ti.ensure(threats, "9.9.9.9", { vulnerability_attempts = {} })
    check("ensure: default raw_score 0", entry.raw_score == 0)
    check("ensure: default reason clean", entry.reason == "clean")
    check("ensure: default updated from ngx.time", entry.updated == 1000)
    check("ensure: extra_defaults applied", type(entry.vulnerability_attempts) == "table")
    check("ensure: entry stored in table", threats["9.9.9.9"] == entry)
end

-- ensure(): existing entry is returned unchanged (no default clobber)
do
    local threats = { ["5.5.5.5"] = { raw_score = 77, reason = "known" } }
    local entry = ti.ensure(threats, "5.5.5.5")
    check("ensure: existing entry not clobbered", entry.raw_score == 77 and entry.reason == "known")
end

-- persist(): writes Redis AND mirrors the shared dict
do
    shared_store.threat_ips = nil
    local red = fake_redis(nil)
    local threats = { ["1.1.1.1"] = { raw_score = 50 } }
    local encoded = ti.persist(red, threats)
    check("persist: wrote to redis", red._store.threat_ips == encoded)
    check("persist: mirrored to shared dict", shared_store.threat_ips == encoded)
end

-- persist(): red == nil still mirrors the shared dict (Redis-down path)
do
    shared_store.threat_ips = nil
    local threats = { ["2.2.2.2"] = { raw_score = 10 } }
    local encoded = ti.persist(nil, threats)
    check("persist: nil redis still mirrors shared dict", shared_store.threat_ips == encoded)
end

print(string.format("\n%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
