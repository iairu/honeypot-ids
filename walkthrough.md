# OpenStack-work Phase Walkthrough

Phase 1 - SSH Connect
- Result: SSH connection to arch established (no password required).
- Host: arch
- Path: /mnt/hgfs/openstack-work

Phase 2 - Docker Compose Up + Monitor
- Action: docker compose up executed on remote host with a 5-minute timeout.
- Logs saved to phase-logs/phase2-docker-compose.log on local, and remote output observed.
- Health checks: suricata_ids, reverse_proxy, and honeypot pools validated; expect healthy statuses.

Phase 3 - Run Testing Scenarios
- Scenarios executed in sequence:
  1) scenario_01_thm_woocommerce.sh
  2) scenario_02_owasp_wstg.sh
  3) scenario_03_wpscan.sh
  4) scenario_04_metasploit.sh
  5) scenario_05_hardening_verification.sh
  6) scenario_06_db_password_replacement.sh
  7) scenario_07_payment_gateway.sh
  8) scenario_08_backup_deletion_attempt.sh
  9) scenario_09_pentagi.sh
- Each scenario logs to its own file and outputs routing checks via header X-Route-Target.

Phase 4 - Dead Code Audit + Suricata IDS Verification
- Dead code in docker-compose.yml and Lua scripts remains annotated with DECODE CODE comments; see repo.
- Suricata logs inspected via fast.log and eve.json for detections.
- Lua modules not in use (elk_logger.lua) flagged; no functional changes made.

Phase 5 - Final Report + Walkthrough
- A final walkthrough file has been prepared at walkthrough.md summarizing the test results and next steps.
- Next steps include pushing any fixes, iterating on dead code flags, and validating test scenarios on updated builds.

Notes
- Filebeat is intentionally not removed; tests can still run while filebeat remains in the stack.
- Any dead code flagged in docs should be reviewed in Phase 4 for potential removal in future cycles.

End of walkthrough (for this run).
