Connect over "ssh arch", sudo requires no password, project is mounted at /mnt/hgfs/openstack-work: 

run all test scenarios - install any other packages necessary to run the tests completely on the archlinux machine, make code more robust


---

make sure to test the entire openstack-work project with the exception of filebeat by running and fixing provided scripts alongside any other project errors, make sure there is no dead code and all code has purpose (is used), if you encounter dead code do not remove it but flag it with a comment, testing scripts are in testing folder, make sure to monitor all output of "docker compose up" to be aware of all logs, turn on (in docker compose file) and test suricata ids as well

do the following:

Phase 1: Connect over "ssh arch", sudo requires no password, project is mounted at /mnt/hgfs/openstack-work
Phase 2: Docker Compose Up + Monitor
 Bring up all services with docker compose up and monitor all output, make sure to kill docker compose up if it takes longer than 5 minutes
 Confirm suricata_ids service starts and healthy
 Confirm reverse_proxy starts and routes correctly
 Confirm all honeypot pools (1,2,3) start, migrations succeed
Phase 3: Run Testing Scenarios
 Run scenario_01 (TryHackMe WooCommerce CVE-2023-28121)
 Run scenario_02 (OWASP WSTG categories 1-7)
 Run scenario_03 (WPScan enumeration)
 Run scenario_04 (Metasploit)
 Run scenario_05 (Production hardening verification)
 Run scenario_06 (DB password replacement)
 Run scenario_07 (Payment gateway)
 Run scenario_08 (Backup deletion attempt)
 Run scenario_09 (PentAGI)
Phase 4: Dead Code Audit + Suricata IDS Verification
 Verify Suricata IDS is detecting traffic (check fast.log and eve.json)
 Review all dead code flagged in docker-compose (already commented and annotated)
 Audit Lua scripts for unused code and flag
 Fix any remaining test failures from Phase 3
Phase 5: Final Report + Walkthrough
 Write walkthrough.md with test results