#!/usr/bin/env bash
set -euo pipefail

##############################################
# Phase orchestrator for the ids/ edge stack
# Target host: 'arch'. Requires passwordless SSH.
# Remote project path: /mnt/hgfs/ids
##############################################

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR/.."

SSH_HOST="${SSH_HOST:-arch}"
SSH_USER="${SSH_USER:-root}"
REMOTE_BASE="${REMOTE_BASE:-/mnt/hgfs/ids}"
PHASE_TIMEOUT="${PHASE_TIMEOUT:-300}" # seconds (5 minutes)
LOG_DIR="${LOG_DIR:-./phase-logs}"

SCENARIOS=(
  scenario_01_thm_woocommerce.sh
  scenario_02_owasp_wstg.sh
  scenario_03_wpscan.sh
  scenario_04_metasploit.sh
  scenario_05_hardening_verification.sh
  scenario_06_db_password_replacement.sh
  scenario_07_payment_gateway.sh
  scenario_08_backup_deletion_attempt.sh
  scenario_09_pentagi.sh
)

mkdir -p "$LOG_DIR"

echo "Phase 1: Connecting to remote host '$SSH_HOST'..."
ssh -o BatchMode=yes "${SSH_USER}@${SSH_HOST}" 'echo SSH_OK; uname -a' >/dev/null 2>&1 || {
  echo "SSH connection failed. Aborting."
  exit 1
}

echo "Phase 2: Bring up docker-compose stack and monitor output (5m timeout)."
ssh -o BatchMode=yes "${SSH_USER}@${SSH_HOST}" bash -lc "set -e; cd '${REMOTE_BASE}'; docker compose down || true; timeout ${PHASE_TIMEOUT} docker compose up" | tee "$LOG_DIR/phase2-docker-compose.log" 2>&1 || true

echo "Phase 2: Verify services health and routing."
ssh -o BatchMode=yes "${SSH_USER}@${SSH_HOST}" bash -lc "set -e; cd '${REMOTE_BASE}';\n  echo 'Suricata IDs health:'; docker inspect --format='{{.State.Health.Status}}' \$(docker ps -q -f name=suricata_ids) || true;\n  echo 'Reverse proxy health (logs):'; docker logs --since 5m reverse_proxy 2>/dev/null || true;\n  echo 'Honeypot pools: '; for i in 1 2 3; do if docker ps --format '{{.Names}}' | grep -q honeypot_eshop_${i}; then echo '  honeypot_eshop_'${i} 'running'; else echo '  honeypot_eshop_'${i} 'not found'; fi; done" || true

echo "Phase 3: Run testing scenarios..."
for s in "${SCENARIOS[@]}"; do
  echo "Running remote: testing/$s"
  if ssh -o BatchMode=yes "${SSH_USER}@${SSH_HOST}" bash -lc "set -e; cd '${REMOTE_BASE}'; bash testing/$s"; then
    echo "Scenario $s completed";
  else
    echo "Scenario $s failed; continuing to next."
  fi
done

echo "Phase 4: Dead code audit + Suricata IDS verification (commented dead code remains)."
ssh -o BatchMode=yes "${SSH_USER}@${SSH_HOST}" bash -lc "set -e; cd '${REMOTE_BASE}';\n  echo 'Suricata logs (fast.log/eve.json) head:'; if [ -f '/mnt/hgfs/ids/suricata_logs/fast.log' ]; then tail -n 50 /mnt/hgfs/ids/suricata_logs/fast.log; fi;\n  if [ -f '/mnt/hgfs/ids/suricata_logs/eve.json' ]; then tail -n 50 /mnt/hgfs/ids/suricata_logs/eve.json; fi;\n  echo 'Dead code markers in repo:'; grep -R --color=never -n "DEAD CODE" . || true" || true

echo "Phase 5: Final walkthrough script preview"
ssh -o BatchMode=yes "${SSH_USER}@${SSH_HOST}" bash -lc "set -e; cd '${REMOTE_BASE}'; cat <<'EOF' > /tmp/walkthrough_preview.md
# ids/ Edge Stack Phase Walkthrough (Preview)

- Phase 1: SSH connectivity to ${SSH_HOST} (OK)
- Phase 2: docker-compose up invoked; logs written to phase-logs/phase2-docker-compose.log
- Phase 3: Result of scenarios captured in remote logs; see per-scenario output
- Phase 4: Suricata logs inspected; Dead code flagged in repo
- Phase 5: Final wrap-up prepared; details in walkthrough file on remote
EOF
" 

echo "All phases launched. Check logs in the local phase-logs/ and remote host for details."
