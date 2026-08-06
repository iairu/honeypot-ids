-- test_suricata_rules.lua - Standalone unit tests
--
-- Runs under a plain `lua` interpreter (no OpenResty/ngx/cjson required),
-- since suricata_rules.lua has no ngx.*/_G.*/cjson dependency by design
-- (decoding stays in init_worker.lua, the impure caller -- see
-- suricata_rules.lua's module docstring).
--
-- Usage:
--   cd openstack-work/reverse_proxy_enhanced/lua/tests
--   lua test_suricata_rules.lua

package.path = "../?.lua;" .. package.path
local rules = require "suricata_rules"

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

-- Decoded form of a real alert event captured live from the honeypot's own
-- eve.json (see suricata_rules.lua's module docstring for how the previous
-- fast.log regex parser silently mis-assigned every field from this exact
-- alert -- src_ip ended up as the string "Attempted Denial of Service").
local REAL_ALERT = {
    timestamp = "2026-08-06T13:07:33.966684+0000",
    event_type = "alert",
    src_ip = "172.21.0.9",
    src_port = 48478,
    dest_ip = "172.21.0.6",
    dest_port = 80,
    proto = "TCP",
    alert = {
        action = "allowed", gid = 1, signature_id = 1000056, rev = 1,
        signature = "High Rate HTTP Requests",
        category = "Attempted Denial of Service",
        severity = 2,
    },
}

local CVE_ALERT = {
    timestamp = "2026-08-06T13:08:00.000000+0000",
    event_type = "alert",
    src_ip = "203.0.113.7",
    src_port = 51234,
    dest_ip = "172.21.0.6",
    dest_port = 443,
    alert = {
        action = "allowed", gid = 1, signature_id = 1000001, rev = 1,
        signature = "CVE-2023-28121 WooCommerce Payments Unauthorized Admin Access Attempt",
        category = "Web Application Attack",
        severity = 1,
    },
}

local NETFLOW_EVENT = {
    timestamp = "2026-08-06T13:10:36.407312+0000",
    event_type = "netflow",
    src_ip = "172.21.0.9", src_port = 53850,
    dest_ip = "172.21.0.6", dest_port = 80,
}

print("== is_alert_line() ==")
do
    check("nil line is not an alert line", rules.is_alert_line(nil) == false)
    check("empty line is not an alert line", rules.is_alert_line("") == false)
    check("a netflow line (event_type netflow) is filtered out cheaply, no decode needed",
          rules.is_alert_line('{"event_type":"netflow","src_ip":"1.2.3.4"}') == false)
    check("a flow line is filtered out",
          rules.is_alert_line('{"event_type":"flow","src_ip":"1.2.3.4"}') == false)
    check("a real alert line is recognized",
          rules.is_alert_line('{"timestamp":"x","event_type":"alert","src_ip":"1.2.3.4","alert":{}}') == true)
    check("substring check doesn't require well-formed JSON (partial/in-progress line is still filtered safely)",
          rules.is_alert_line('{"event_type":"alert", still being wri') == true)
end

print("== extract_alert() ==")
do
    check("non-table input returns nil, does not crash", rules.extract_alert("not a table") == nil)
    check("nil input returns nil", rules.extract_alert(nil) == nil)
    check("netflow event returns nil (wrong event_type)", rules.extract_alert(NETFLOW_EVENT) == nil)

    local alert = rules.extract_alert(REAL_ALERT)
    check("real alert extracts", alert ~= nil)
    check("src_ip extracted correctly (the exact field the old fast.log regex mis-parsed)",
          alert.src_ip == "172.21.0.9")
    check("src_port extracted correctly", alert.src_port == 48478)
    check("dest_ip extracted correctly", alert.dest_ip == "172.21.0.6")
    check("dest_port extracted correctly (silently dropped entirely by the old 7-var destructure)",
          alert.dest_port == 80)
    check("signature extracted correctly", alert.signature == "High Rate HTTP Requests")
    check("category extracted correctly", alert.category == "Attempted Denial of Service")
    check("severity extracted correctly", alert.severity == 2)
    check("signature_id extracted correctly", alert.signature_id == 1000056)

    local cve_alert = rules.extract_alert(CVE_ALERT)
    check("CVE-tagged alert extracts", cve_alert ~= nil)
    check("CVE-tagged alert signature includes the CVE id (rule msg convention in local.rules)",
          cve_alert.signature:find("CVE%-2023%-28121") ~= nil)
    check("CVE-tagged alert severity 1 (highest priority)", cve_alert.severity == 1)

    -- Missing required fields must not crash, just return nil.
    check("event_type alert but no alert table returns nil",
          rules.extract_alert({ event_type = "alert", src_ip = "1.2.3.4" }) == nil)
    check("alert table present but no signature field returns nil",
          rules.extract_alert({ event_type = "alert", src_ip = "1.2.3.4", alert = { severity = 1 } }) == nil)
    check("no src_ip at all returns nil",
          rules.extract_alert({ event_type = "alert", alert = { signature = "x", severity = 1 } }) == nil)
end

print("== severity_to_score() ==")
do
    check("severity 1 (highest) scores 50", rules.severity_to_score(1) == 50)
    check("severity 2 (medium) scores 25", rules.severity_to_score(2) == 25)
    check("severity 3 (low) scores the default 10", rules.severity_to_score(3) == 10)
    check("severity 4+ (unrecognized) falls to the default", rules.severity_to_score(4) == 10)
    check("nil severity falls to the default (never crashes)", rules.severity_to_score(nil) == 10)
    check("severity 1 outranks severity 2", rules.severity_to_score(1) > rules.severity_to_score(2))
    check("severity 2 outranks severity 3", rules.severity_to_score(2) > rules.severity_to_score(3))
end

print("== next_score() ==")
do
    check("first alert from a fresh IP (nil previous) starts at the severity delta",
          rules.next_score(nil, 1) == 50)
    check("second severity-1 alert accumulates (50+50=100, capped)",
          rules.next_score(50, 1) == 100)
    check("score is capped at 100 even with a huge previous value",
          rules.next_score(90, 1) == 100)
    check("score accumulates normally below the cap",
          rules.next_score(80, 3) == 90)
    check("a single severity-1 alert plus any prior severity-2 alert already crosses "
          .. "router.lua's Stage 6 >50 honeypot-diversion gate",
          rules.next_score(25, 1) > 50)
end

print("== build_reason() ==")
do
    local alert = rules.extract_alert(CVE_ALERT)
    local reason = rules.build_reason(alert)
    check("reason is prefixed for readability in threat_ips/session logs",
          reason:find("^suricata: ") ~= nil)
    check("reason carries the CVE id through to what router.lua sets as honeypot_reason",
          reason:find("CVE%-2023%-28121") ~= nil)
    check("reason is the full signature text, not truncated",
          reason == "suricata: CVE-2023-28121 WooCommerce Payments Unauthorized Admin Access Attempt")
end

print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
