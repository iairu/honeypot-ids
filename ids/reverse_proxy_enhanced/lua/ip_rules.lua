-- ip_rules.lua - Pure IPv4/IPv6 CIDR matching
--
-- Backs _G.utils.is_ip_whitelisted() (init.lua). The previous
-- implementation parsed dotted-quad IPv4 only, so an IPv6 client (including
-- loopback "::1") could never match the whitelist.
--
-- No ngx.* / _G.* / `bit` dependency: addresses are compared as byte arrays,
-- so this runs (and is unit-tested) under a plain Lua 5.1 interpreter.
--
-- IPv4-mapped IPv6 addresses ("::ffff:10.1.2.3") are normalised to their
-- IPv4 form, so an IPv4 range still matches a dual-stack socket's view of
-- the same client.

local _M = {}

local function parse_ipv4(s)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    local bytes = { tonumber(a), tonumber(b), tonumber(c), tonumber(d) }
    for i = 1, 4 do
        if bytes[i] > 255 then return nil end
    end
    return bytes
end

local function parse_ipv6(s)
    -- Drop a zone id ("fe80::1%eth0").
    s = s:gsub("%%.*$", "")
    if not s:find(":", 1, true) then return nil end

    -- A trailing embedded IPv4 ("::ffff:1.2.3.4") becomes two hextets.
    local tail4 = s:match(":(%d+%.%d+%.%d+%.%d+)$")
    if tail4 then
        local v4 = parse_ipv4(tail4)
        if not v4 then return nil end
        s = s:sub(1, #s - #tail4) ..
            string.format("%x:%x", v4[1] * 256 + v4[2], v4[3] * 256 + v4[4])
    end

    local head, tail = s, nil
    local dbl = s:find("::", 1, true)
    if dbl then
        if s:find("::", dbl + 1, true) then return nil end
        head, tail = s:sub(1, dbl - 1), s:sub(dbl + 2)
    end

    local function split(part)
        local groups = {}
        if part == "" then return groups end
        for g in (part .. ":"):gmatch("([^:]*):") do
            if not g:match("^%x%x?%x?%x?$") then return nil end
            table.insert(groups, tonumber(g, 16))
        end
        return groups
    end

    local hg, tg = split(head), split(tail or "")
    if not hg or not tg then return nil end

    local groups
    if dbl then
        local missing = 8 - #hg - #tg
        if missing < 1 then return nil end
        groups = hg
        for _ = 1, missing do table.insert(groups, 0) end
        for _, g in ipairs(tg) do table.insert(groups, g) end
    else
        if #hg ~= 8 then return nil end
        groups = hg
    end

    local bytes = {}
    for _, g in ipairs(groups) do
        table.insert(bytes, math.floor(g / 256))
        table.insert(bytes, g % 256)
    end
    return bytes
end

--- Parse an address into a byte array: 4 bytes for IPv4 (including
--- IPv4-mapped IPv6), 16 for IPv6. Returns nil for anything unparseable.
function _M.parse(s)
    if type(s) ~= "string" or s == "" then return nil end
    local v4 = parse_ipv4(s)
    if v4 then return v4 end
    local v6 = parse_ipv6(s)
    if not v6 then return nil end
    local mapped = true
    for i = 1, 10 do
        if v6[i] ~= 0 then mapped = false break end
    end
    if mapped and v6[11] == 255 and v6[12] == 255 then
        return { v6[13], v6[14], v6[15], v6[16] }
    end
    return v6
end

--- True if `ip` falls inside `cidr` ("10.0.0.0/8", "fc00::/7", or a bare
--- address, which means an exact match). Families never cross-match.
function _M.in_cidr(ip, cidr)
    if type(cidr) ~= "string" then return false end
    local addr = _M.parse(ip)
    if not addr then return false end

    local net_str, prefix_str = cidr:match("^([^/]+)/(%d+)$")
    net_str = net_str or cidr
    local net = _M.parse(net_str)
    if not net or #net ~= #addr then return false end

    local bits = #net * 8
    local prefix = prefix_str and tonumber(prefix_str) or bits
    if prefix > bits then return false end

    local full, rem = math.floor(prefix / 8), prefix % 8
    for i = 1, full do
        if addr[i] ~= net[i] then return false end
    end
    if rem > 0 then
        local div = 2 ^ (8 - rem)
        if math.floor(addr[full + 1] / div) ~= math.floor(net[full + 1] / div) then
            return false
        end
    end
    return true
end

--- True if `ip` matches any entry of `ranges`.
function _M.in_any(ip, ranges)
    for _, range in ipairs(ranges or {}) do
        if _M.in_cidr(ip, range) then return true end
    end
    return false
end

return _M
