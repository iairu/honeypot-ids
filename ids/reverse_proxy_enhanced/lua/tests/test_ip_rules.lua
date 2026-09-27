-- test_ip_rules.lua - Standalone unit tests for ip_rules.lua
--
-- Usage:
--   cd ids/reverse_proxy_enhanced/lua/tests
--   lua test_ip_rules.lua

package.path = "../?.lua;" .. package.path
local ip = require "ip_rules"

local passed, failed = 0, 0

local function check(name, condition)
    if condition then
        passed = passed + 1
        print("  [PASS] " .. name)
    else
        failed = failed + 1
        print("  [FAIL] " .. name)
    end
end

print("parse")
do
    check("IPv4 -> 4 bytes", #ip.parse("192.168.1.10") == 4)
    check("IPv4 octet over 255 rejected", ip.parse("256.1.1.1") == nil)
    check("IPv6 loopback -> 16 bytes", #ip.parse("::1") == 16 and ip.parse("::1")[16] == 1)
    check("full IPv6 form", #ip.parse("2001:0db8:0000:0000:0000:0000:0000:0001") == 16)
    check("IPv6 with zone id", ip.parse("fe80::1%eth0") ~= nil)
    check("IPv4-mapped IPv6 -> IPv4", #ip.parse("::ffff:10.1.2.3") == 4 and ip.parse("::ffff:10.1.2.3")[4] == 3)
    check("unspecified :: parses", #ip.parse("::") == 16)
    check("two '::' rejected", ip.parse("1::2::3") == nil)
    check("too many groups rejected", ip.parse("1:2:3:4:5:6:7:8:9") == nil)
    check("hextet over 4 digits rejected", ip.parse("12345::1") == nil)
    check("garbage rejected", ip.parse("not-an-ip") == nil and ip.parse("") == nil and ip.parse(nil) == nil)
end

print("in_cidr: IPv4")
do
    check("inside /8", ip.in_cidr("10.200.3.4", "10.0.0.0/8"))
    check("outside /8", not ip.in_cidr("11.0.0.1", "10.0.0.0/8"))
    check("/32 exact", ip.in_cidr("127.0.0.1", "127.0.0.1/32"))
    check("/32 neighbour", not ip.in_cidr("127.0.0.2", "127.0.0.1/32"))
    check("non-octet-aligned /10: first address", ip.in_cidr("100.64.0.0", "100.64.0.0/10"))
    check("non-octet-aligned /10: last address", ip.in_cidr("100.127.255.255", "100.64.0.0/10"))
    check("non-octet-aligned /10: just past", not ip.in_cidr("100.128.0.0", "100.64.0.0/10"))
    check("non-octet-aligned /10: just before", not ip.in_cidr("100.63.255.255", "100.64.0.0/10"))
    check("/0 matches everything", ip.in_cidr("8.8.8.8", "0.0.0.0/0"))
    check("bare address is exact match", ip.in_cidr("1.2.3.4", "1.2.3.4") and not ip.in_cidr("1.2.3.5", "1.2.3.4"))
    check("prefix longer than family rejected", not ip.in_cidr("1.2.3.4", "1.2.3.4/33"))
end

print("in_cidr: IPv6")
do
    check("::1 in ::1/128", ip.in_cidr("::1", "::1/128"))
    check("::2 not in ::1/128", not ip.in_cidr("::2", "::1/128"))
    check("ULA in fc00::/7", ip.in_cidr("fd12:3456::1", "fc00::/7"))
    check("global not in fc00::/7", not ip.in_cidr("2001:db8::1", "fc00::/7"))
    check("Tailscale IPv6 in fd7a:115c:a1e0::/48", ip.in_cidr("fd7a:115c:a1e0:ab12::1", "fd7a:115c:a1e0::/48"))
    check("mapped IPv4 client matches IPv4 range", ip.in_cidr("::ffff:10.9.8.7", "10.0.0.0/8"))
    check("IPv6 never matches an IPv4 range", not ip.in_cidr("::1", "0.0.0.0/0"))
    check("IPv4 never matches an IPv6 range", not ip.in_cidr("127.0.0.1", "::/0"))
end

print("in_any")
do
    local list = { "127.0.0.1/32", "::1/128", "10.0.0.0/8" }
    check("IPv4 loopback", ip.in_any("127.0.0.1", list))
    check("IPv6 loopback", ip.in_any("::1", list))
    check("public address", not ip.in_any("203.0.113.9", list))
    check("nil list", not ip.in_any("127.0.0.1", nil))
    check("nil ip", not ip.in_any(nil, list))
end

print()
print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
