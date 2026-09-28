# honeypot_content_sync runs on mysql:5.7 purely for its mysql/mysqldump
# client tools; redis-cli (for the honeypot_pool_replicating:<N> flag, see
# scripts/replicate_content_to_honeypot.sh) is added here once at build
# time instead of by a `yum install` on every container start, which
# re-downloaded the EL7 repo metadata each time.
#
# Deliberately non-fatal, same as the old runtime install: without
# redis-cli the script still replicates, it only skips the flag, so a
# failed install must not block the whole stack from building. Rebuild to
# retry: `docker compose build --pull honeypot_content_sync`.
FROM mysql:5.7
RUN (yum install -y redis && yum clean all && rm -rf /var/cache/yum) \
    || echo 'WARNING: failed to install redis-cli -- replication flag gating will be skipped'
