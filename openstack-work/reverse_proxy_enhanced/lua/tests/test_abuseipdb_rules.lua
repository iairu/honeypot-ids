-- test_abuseipdb_rules.lua - Standalone unit tests
--
-- Usage:
--   cd openstack-work/reverse_proxy_enhanced/lua/tests
--   lua test_abuseipdb_rules.lua

package.path = "../?.lua;" .. package.path
local rules = require "abuseipdb_rules"

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

print("== is_reportable_reason() ==")
do
    check("cve_pattern_match is reportable", rules.is_reportable_reason("cve_pattern_match") == true)
    check("vulnerable_plugin_access is reportable", rules.is_reportable_reason("vulnerable_plugin_access") == true)
    check("multiple_admin_attempts is reportable", rules.is_reportable_reason("multiple_admin_attempts") == true)
    check("rapid_automation_detected is reportable", rules.is_reportable_reason("rapid_automation_detected") == true)
    check("suspicious_file_upload is reportable", rules.is_reportable_reason("suspicious_file_upload") == true)
    check("suricata_confirmed_alert is reportable", rules.is_reportable_reason("suricata_confirmed_alert") == true)
    check("bad_ip_reputation (the generic/non-Suricata IP-reputation reason) is NOT reportable -- "
          .. "only the specific Suricata-confirmed case is", rules.is_reportable_reason("bad_ip_reputation") == false)
    check("unknown reason is not reportable", rules.is_reportable_reason("some_soft_heuristic") == false)
    check("nil reason is not reportable", rules.is_reportable_reason(nil) == false)
end

print("== get_categories() ==")
do
    local cats = rules.get_categories("multiple_admin_attempts")
    check("brute-force maps to category 18", cats[1] == 18 and #cats == 1)

    cats = rules.get_categories("cve_pattern_match")
    check("cve match maps to Hacking(15) + WebAppAttack(21)", cats[1] == 15 and cats[2] == 21)

    cats = rules.get_categories("suricata_confirmed_alert")
    check("suricata-confirmed alert maps to Hacking(15) + WebAppAttack(21), same as cve_pattern_match",
          cats[1] == 15 and cats[2] == 21)

    check("unknown reason returns nil", rules.get_categories("nonexistent") == nil)
end

print("== build_report_comment() ==")
do
    check("basic comment format",
          rules.build_report_comment("multiple_admin_attempts", nil) == "Honeypot detection: multiple_admin_attempts")

    local with_cves = rules.build_report_comment("cve_pattern_match", { matched_cves = { "CVE-2023-2986", "CVE-2023-28121" } })
    check("comment includes matched CVEs",
          with_cves == "Honeypot detection: cve_pattern_match (CVEs: CVE-2023-2986, CVE-2023-28121)")

    check("empty matched_cves list doesn't append empty parens",
          rules.build_report_comment("cve_pattern_match", { matched_cves = {} }) == "Honeypot detection: cve_pattern_match")

    check("details without matched_cves key is ignored",
          rules.build_report_comment("multiple_admin_attempts", { some_other_field = 1 }) == "Honeypot detection: multiple_admin_attempts")
end

print(string.format("%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
