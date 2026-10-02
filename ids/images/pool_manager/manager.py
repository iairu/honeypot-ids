"""pool_manager: keeps a spare honeypot pool ready for the next attacker.

A pool is a honeypot_eshop_N (WordPress) + honeypot_database_N (MySQL) pair.
pool_router.lua gives each new attacker IP a free ready pool exclusively and
queues a wake-up on honeypot_pool:provision; this service then builds an
additional pool so one is always waiting. See pool_router_rules.lua for the
Redis key schema both sides share.

Two honeypot layers, chosen with POOL_MODE:
  wordpress (default)  pool = honeypot_eshop_N + honeypot_database_N. Pools 1-3
                       come from docker-compose.yml.
  database             pool = honeypot_database_N only (docker-compose.db-proxy.yml:
                       one shared WordPress picks the database per request, see
                       wp-content/db.php). Pool 1 is the compose `honeypot_database`.
Compose-declared pools are only adopted here (registered in Redis once healthy).
Pools above them are created and destroyed through the Docker API. Their containers deliberately carry no
com.docker.compose.* labels, so `docker compose up --remove-orphans` leaves
them alone; they are found again by the `honeypot.pool` label.

SECURITY: this container mounts the Docker socket (root-equivalent on the
host). It publishes no ports, joins only session_network (Redis), and runs no
attacker-reachable code. Do not put it on honeynet-facing networks.
"""
from __future__ import annotations

import os
import secrets
import socket
import sys
import threading
import time

import docker
import redis

import pool_logic as pl

READY_KEY = "honeypot_pool:ready"
FREE_KEY = "honeypot_pool:free"
OWNER_PREFIX = "honeypot_pool:owner:"
PROVISION_KEY = "honeypot_pool:provision"
CAPPED_KEY = "honeypot_pool:capped"
PW_PREFIX = "honeypot_pool:pw:"
IP_KEY_PREFIX = "honeypot_pool_ip:"

PROJECT = os.environ.get("COMPOSE_PROJECT", "honeypot-ids-system-v1")
MODE = os.environ.get("POOL_MODE", "wordpress")
if MODE not in ("wordpress", "database"):
    sys.exit(f"pool_manager: POOL_MODE must be 'wordpress' or 'database', not {MODE!r}")
# Pools declared in the compose file (never created/destroyed here).
STATIC_COUNT = int(os.environ.get("POOL_STATIC_COUNT", "3" if MODE == "wordpress" else "1"))
POLL_SECONDS = float(os.environ.get("POOL_POLL_SECONDS", "5"))
SPARES = int(os.environ.get("POOL_SPARES", "1"))
MAX_POOLS = int(os.environ.get("POOL_MAX", "10"))
READY_TIMEOUT_S = int(os.environ.get("POOL_READY_TIMEOUT_SECONDS", "900"))
RETRY_BACKOFF_S = int(os.environ.get("POOL_RETRY_BACKOFF_SECONDS", "60"))

MYSQL_IMAGE = "mysql:5.7"
WORDPRESS_IMAGE = "wordpress:6.8.3-php8.1"
WPCLI_IMAGE = "wordpress:cli-php8.1"
DB_NAME = "production_database"
DB_USER = "production_user"

LOG_CONFIG = {"type": "json-file", "config": {"max-size": "10m", "max-file": "3"}}
NS = 1_000_000_000


def log(msg: str) -> None:
    print(f"[pool_manager {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def env_required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        sys.exit(f"pool_manager: required environment variable {name} is not set")
    return value


class Manager:
    def __init__(self) -> None:
        self.docker = docker.from_env()
        self.redis = redis.Redis(
            host=os.environ.get("REDIS_HOST", "session_store"),
            password=env_required("REDIS_PASSWORD"),
            decode_responses=True)
        self.mysql_password = env_required("MYSQL_PASSWORD")
        self.host_paths = self._own_mount_sources()
        self.image = self.docker.containers.get(socket.gethostname()).image
        self.worker: threading.Thread | None = None
        self.in_flight: int | None = None
        self.backoff_until = 0.0

    # ---- discovery -------------------------------------------------------

    def _own_mount_sources(self) -> dict[str, str]:
        """Container path -> host path for this container's bind mounts. Helper
        containers mount the same host directories (the Docker daemon resolves
        paths on the host, not inside this container)."""
        me = self.docker.containers.get(socket.gethostname())
        return {m["Destination"]: m["Source"] for m in me.attrs.get("Mounts", [])}

    def _net(self, short: str) -> str:
        return f"{PROJECT}_{short}"

    def runtime_pools(self) -> set[int]:
        """Numbers of pools this service created (by label), running or not."""
        out = set()
        for c in self.docker.containers.list(all=True, filters={"label": "honeypot.pool"}):
            try:
                out.add(int(c.labels["honeypot.pool"]))
            except ValueError:
                pass
        return out

    def static_pool_up(self, n: int) -> bool:
        """A compose-declared pool counts once its serving container (the eshop,
        or the database in database mode) is healthy."""
        service = f"honeypot_eshop_{n}" if MODE == "wordpress" else (
            "honeypot_database" if n == 1 else f"honeypot_database_{n}")
        for c in self.docker.containers.list(filters={
                "label": [f"com.docker.compose.project={PROJECT}",
                          f"com.docker.compose.service={service}"]}):
            if c.attrs["State"].get("Health", {}).get("Status") == "healthy":
                return True
        return False

    def pool_container_healthy(self, n: int) -> bool:
        try:
            prefix = "honeypot_eshop_" if MODE == "wordpress" else "honeypot_database_"
            c = self.docker.containers.get(f"{prefix}{n}")
        except docker.errors.NotFound:
            return False
        c.reload()
        return c.attrs["State"].get("Health", {}).get("Status") == "healthy"

    # ---- Redis registry --------------------------------------------------

    def register_ready(self, n: int, owned: bool = False) -> None:
        self.redis.sadd(READY_KEY, n)
        if not owned:
            self.redis.zadd(FREE_KEY, {str(n): n}, nx=True)
        log(f"pool {n} is ready ({'owned' if owned else 'free'})")

    def unregister(self, n: int) -> None:
        self.redis.srem(READY_KEY, n)
        self.redis.zrem(FREE_KEY, str(n))
        self.redis.delete(OWNER_PREFIX + str(n))

    def adopt_static_pools(self) -> None:
        for n in range(1, STATIC_COUNT + 1):
            if self.redis.sismember(READY_KEY, n):
                continue
            if self.static_pool_up(n):
                self.register_ready(n, owned=bool(self.redis.scard(OWNER_PREFIX + str(n))))

    def adopt_runtime_pools(self) -> None:
        """After a manager restart: re-register pools created earlier that are
        still healthy (Redis may have been wiped, which loses ready/free)."""
        for n in sorted(self.runtime_pools()):
            if self.in_flight == n or self.redis.sismember(READY_KEY, n):
                continue
            if self.pool_container_healthy(n):
                self.register_ready(n, owned=bool(self.redis.scard(OWNER_PREFIX + str(n))))

    # ---- capacity --------------------------------------------------------

    def can_grow(self) -> tuple[bool, str]:
        return True, ""

    # ---- provisioning ----------------------------------------------------

    def provision(self, n: int) -> None:
        """Build pool n end to end. Raises on failure (caller cleans up)."""
        if MODE == "database":
            self.provision_database(n)
        else:
            self.provision_wordpress(n)

    def provision_database(self, n: int) -> None:
        """Database layer: one more honeypot database, cloned from production and
        scrubbed, the same way honeypot_db_init prepares the first one. All
        honeypot databases share production's credentials (the isolation is the
        separate database host, see wp-content/db.php)."""
        db_name = f"honeypot_database_{n}"
        db_vol = f"{PROJECT}_{db_name}_data"
        labels = {"honeypot.pool": str(n), "honeypot.pool.managed-by": "pool_manager"}
        log(f"pool {n}: provisioning database {db_name} (volume {db_vol})")
        self.docker.volumes.create(name=db_vol, labels=labels)
        db = self._create_database_container(db_name, db_vol, self.mysql_password, labels)
        db.start()
        self._wait_healthy(db, "database")
        self._run_helper(
            MYSQL_IMAGE, ["bash", "-c", CLONE_SCRIPT],
            binds={self.host_paths["/migrations"]: ("/migrations", "ro"),
                   self.host_paths["/migrations_override"] + "/01_clean-honeypot-data.sql":
                       ("/migrations/01_clean-honeypot-data.sql", "ro")},
            labels=labels, what="clone + scrub", network=self._net("honeypot_network"),
            extra_networks=[self._net("production_network")],
            environment={"HP": db_name, "PROD": "production_database",
                         "MYSQL_USER": DB_USER, "MYSQL_PASSWORD": self.mysql_password,
                         "MYSQL_DATABASE": DB_NAME})
        self.register_ready(n)

    def _create_database_container(self, name, volume, password, labels):
        return self.docker.containers.create(
            MYSQL_IMAGE, name=name, labels=labels, detach=True,
            command=["bash", "-c", "rm -f /var/lib/mysql/placeholder; docker-entrypoint.sh mysqld"],
            environment={"MYSQL_DATABASE": DB_NAME, "MYSQL_USER": DB_USER,
                         "MYSQL_PASSWORD": password,
                         "MYSQL_ROOT_PASSWORD": env_required("MYSQL_ROOT_PASSWORD")},
            volumes={volume: {"bind": "/var/lib/mysql", "mode": "rw"}},
            network=self._net("honeypot_network"),
            security_opt=["no-new-privileges:true"], cap_drop=["ALL"],
            cap_add=["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID", "SYS_NICE"],
            mem_limit="512m", nano_cpus=500_000_000, pids_limit=200,
            log_config=LOG_CONFIG, restart_policy={"Name": "unless-stopped"},
            healthcheck={"test": ["CMD", "mysqladmin", "ping", "-h", "localhost"],
                         "interval": 10 * NS, "timeout": 5 * NS, "retries": 5,
                         "start_period": 60 * NS})

    def provision_wordpress(self, n: int) -> None:
        """WordPress layer: a full honeypot_eshop_N + honeypot_database_N pair."""
        project, db_name, wp_name = PROJECT, f"honeypot_database_{n}", f"honeypot_eshop_{n}"
        db_vol, files_vol = f"{project}_{db_name}_data", f"{project}_{wp_name}_files"
        labels = {"honeypot.pool": str(n), "honeypot.pool.managed-by": "pool_manager"}
        password = secrets.token_hex(12)
        self.redis.set(PW_PREFIX + str(n), password)
        log(f"pool {n}: provisioning (volumes {db_vol}, {files_vol})")

        for vol in (db_vol, files_vol):
            self.docker.volumes.create(name=vol, labels=labels)

        # 1. seed volumes: WordPress files from production (minus the
        #    production-only hardening plugin) and a raw copy of the database
        #    directory, exactly as init_setup does for pools 1-3.
        self._run_helper(
            self.image, ["sh", "-c", (
                "rsync -a /source_files/ /dest_files/ && "
                "rm -f /dest_files/wp-content/mu-plugins/production-hardening.php "
                "/dest_files/wp-content/sql-routing.log /dest_files/wp-content/db.php.backup && "
                "tar -C /source_db -cf - . | tar -C /dest_db -xf -")],
            binds={self.host_paths["/source_files"]: ("/source_files", "ro"),
                   self.host_paths["/source_db"]: ("/source_db", "ro"),
                   files_vol: ("/dest_files", "rw"), db_vol: ("/dest_db", "rw")},
            labels=labels, what="seed volumes")

        # 2. database container
        db = self._create_database_container(
            db_name, db_vol, self.mysql_password, labels)
        db.start()
        self._wait_healthy(db, "database")

        # 3. rotate the DB password to this pool's own, apply migrations
        self._run_helper(
            MYSQL_IMAGE, ["bash", "-c", MIGRATE_SCRIPT],
            binds={self.host_paths["/migrations"]: ("/migrations", "ro")},
            labels=labels, what="migrations", entrypoint=[],
            environment={"DB_HOST": db_name, "DB_USER": DB_USER, "DB_NAME": DB_NAME,
                         "OLD_PASSWORD": self.mysql_password, "NEW_PASSWORD": password},
            network=self._net("honeypot_network"))

        # 4. install WordPress into the pool database (same script as db_seed_N)
        self._run_helper(
            WPCLI_IMAGE, ["sh", "/seed_wordpress_db.sh"],
            binds={files_vol: ("/var/www/html", "rw"),
                   self.host_paths["/scripts"] + "/seed_wordpress_db.sh": ("/seed_wordpress_db.sh", "ro")},
            labels=labels, what="WordPress seed", user="root",
            environment={
                "WORDPRESS_DB_HOST": f"{db_name}:3306", "WORDPRESS_DB_NAME": DB_NAME,
                "WORDPRESS_DB_USER": DB_USER, "WORDPRESS_DB_PASSWORD": password,
                "WP_ADMIN_USER": os.environ.get("WP_ADMIN_USER", "admin"),
                "WP_ADMIN_PASSWORD": os.environ.get("WP_ADMIN_PASSWORD", "change_this_wp_admin_password"),
                "WP_ADMIN_EMAIL": os.environ.get("WP_ADMIN_EMAIL", "admin@example.com"),
                "WP_SITE_URL": os.environ.get("WP_SITE_URL", "http://localhost"),
                "WP_SITE_TITLE": os.environ.get("WP_SITE_TITLE", "Demo eShop"),
                "FORCE_RESEED": "0", "IMPORT_SAMPLE_CONTENT": "0",
                "STRIPE_TEST_PUBLISHABLE_KEY": os.environ.get("STRIPE_TEST_PUBLISHABLE_KEY", ""),
                "STRIPE_TEST_SECRET_KEY": os.environ.get("STRIPE_TEST_SECRET_KEY", "")},
            network=self._net("honeypot_network"),
            caps=["DAC_OVERRIDE", "CHOWN", "FOWNER", "SETGID", "SETUID"])

        # 5. the WordPress container itself
        wp = self.docker.containers.create(
            WORDPRESS_IMAGE, name=wp_name, labels=labels, detach=True,
            command=["sh", "-c", WP_START_SCRIPT],
            environment={
                "WORDPRESS_DB_HOST": f"{db_name}:3306", "WORDPRESS_DB_NAME": DB_NAME,
                "WORDPRESS_DB_USER": DB_USER, "WORDPRESS_DB_PASSWORD": password,
                "WORDPRESS_DEBUG": "1", "WORDPRESS_DEBUG_LOG": "1",
                "HONEYPOT_POOL_ID": str(n)},
            volumes={files_vol: {"bind": "/var/www/html", "mode": "rw"}},
            network=self._net("honeypot_network"),
            security_opt=["no-new-privileges:true"], cap_drop=["ALL"],
            cap_add=["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID",
                     "NET_BIND_SERVICE", "KILL"],
            mem_limit="1024m", nano_cpus=1_000_000_000, pids_limit=300,
            log_config=LOG_CONFIG, restart_policy={"Name": "unless-stopped"},
            healthcheck={"test": ["CMD", "curl", "-f", "http://localhost/"],
                         "interval": 30 * NS, "timeout": 10 * NS, "retries": 3,
                         "start_period": 60 * NS})
        for extra in ("production_network", "monitoring_network"):
            self.docker.networks.get(self._net(extra)).connect(wp)
        wp.start()
        self._wait_healthy(wp, "WordPress")
        self.register_ready(n)

    def _run_helper(self, image, command, binds, labels, what, user=None,
                    environment=None, network=None, caps=None, entrypoint=None,
                    extra_networks=()):
        """Run a short-lived container to completion; raise unless it exits 0."""
        volumes = {src: {"bind": dst, "mode": mode} for src, (dst, mode) in binds.items()}
        c = self.docker.containers.create(
            image, command=command, labels=labels, volumes=volumes, user=user,
            environment=environment, network=network, entrypoint=entrypoint,
            cap_drop=["ALL"] if caps else None, cap_add=caps, log_config=LOG_CONFIG)
        try:
            for extra in extra_networks:
                self.docker.networks.get(extra).connect(c)
            c.start()
            result = c.wait(timeout=READY_TIMEOUT_S)
            if result.get("StatusCode") != 0:
                tail = c.logs(tail=30).decode(errors="replace")
                raise RuntimeError(f"helper '{what}' exited {result.get('StatusCode')}:\n{tail}")
        finally:
            c.remove(force=True)

    def _wait_healthy(self, container, what: str) -> None:
        deadline = time.time() + READY_TIMEOUT_S
        while time.time() < deadline:
            container.reload()
            state = container.attrs["State"]
            if state.get("Health", {}).get("Status") == "healthy":
                return
            if state.get("Status") in ("exited", "dead"):
                raise RuntimeError(f"{what} container {container.name} stopped: "
                                   + container.logs(tail=20).decode(errors="replace"))
            time.sleep(3)
        raise TimeoutError(f"{what} container {container.name} not healthy after {READY_TIMEOUT_S}s")

    def destroy(self, n: int) -> None:
        """Remove pool n's containers and volumes (runtime pools only)."""
        if n <= STATIC_COUNT:
            raise ValueError("static pools are owned by docker compose")
        self.unregister(n)
        for c in self.docker.containers.list(all=True, filters={"label": f"honeypot.pool={n}"}):
            c.remove(force=True, v=True)
        for v in self.docker.volumes.list(filters={"label": f"honeypot.pool={n}"}):
            v.remove(force=True)
        self.redis.delete(PW_PREFIX + str(n))
        log(f"pool {n}: destroyed")

    def _provision_thread(self, n: int) -> None:
        try:
            self.provision(n)
        except Exception as e:  # noqa: BLE001 -- keep the manager alive
            log(f"pool {n}: provisioning FAILED: {e}")
            try:
                self.destroy(n)
            except Exception as e2:  # noqa: BLE001
                log(f"pool {n}: cleanup after failure also failed: {e2}")
            self.backoff_until = time.time() + RETRY_BACKOFF_S
        finally:
            self.in_flight = None

    # ---- main loop -------------------------------------------------------

    def drain_wakeups(self) -> int:
        n = 0
        while self.redis.lpop(PROVISION_KEY) is not None:
            n += 1
        return n

    def reconcile(self) -> None:
        self.adopt_static_pools()
        self.adopt_runtime_pools()
        self.drain_wakeups()

        ready = {int(x) for x in self.redis.smembers(READY_KEY)}
        free = self.redis.zcard(FREE_KEY)
        in_flight = 0 if self.in_flight is None else 1
        need = pl.spares_needed(free, in_flight, SPARES, len(ready), MAX_POOLS)
        if need <= 0 or in_flight or time.time() < self.backoff_until:
            return
        ok, reason = self.can_grow()
        if not ok:
            self.redis.set(CAPPED_KEY, reason, ex=int(POLL_SECONDS * 6))
            return
        self.redis.delete(CAPPED_KEY)
        n = pl.next_pool_number(ready | self.runtime_pools(), STATIC_COUNT)
        self.in_flight = n
        self.worker = threading.Thread(target=self._provision_thread, args=(n,), daemon=True)
        self.worker.start()

    def run(self) -> None:
        log(f"started (project {PROJECT}, mode {MODE}, spares {SPARES}, max pools {MAX_POOLS})")
        while True:
            try:
                self.reconcile()
            except Exception as e:  # noqa: BLE001
                log(f"reconcile error: {e}")
            time.sleep(POLL_SECONDS)


# Same steps as honeypot_db_init in docker-compose.db-proxy.yml, for one database.
CLONE_SCRIPT = r"""
set -e
wait_for() {
  TRIES=0
  until mysqladmin ping -h"$1" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" 2>/dev/null | grep -q 'mysqld is alive'; do
    TRIES=$((TRIES+1)); [ "$TRIES" -ge 90 ] && { echo "$1 never became reachable"; exit 1; }
    sleep 2
  done
}
wait_for "$PROD"; wait_for "$HP"
HAS_SCHEMA=$(mysql -h"$HP" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$MYSQL_DATABASE' AND table_name='wp_options'" 2>/dev/null || echo 0)
if [ "$HAS_SCHEMA" = 0 ]; then
  mysqldump -h"$PROD" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" --single-transaction --no-tablespaces --skip-add-locks "$MYSQL_DATABASE" \
    | mysql -h"$HP" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"
fi
for m in $(ls /migrations/*.sql 2>/dev/null | sort); do
  mysql -h"$HP" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" --force "$MYSQL_DATABASE" < "$m" || echo "  (non-zero from $m, continuing)"
done
mysql -h"$HP" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" \
  -e "UPDATE wp_options SET option_value='Demo Honeypot eShop' WHERE option_name='blogname';" || true
"""

MIGRATE_SCRIPT = r"""
set -u
for i in $(seq 1 60); do
  mysqladmin ping -h"$DB_HOST" -u"$DB_USER" -p"$OLD_PASSWORD" 2>&1 | grep -q 'mysqld is alive' && break
  sleep 2
done
if ! mysql -h"$DB_HOST" -u"$DB_USER" -p"$NEW_PASSWORD" -e 'SELECT 1' >/dev/null 2>&1; then
  mysql -h"$DB_HOST" -u"$DB_USER" -p"$OLD_PASSWORD" \
    -e "ALTER USER '$DB_USER'@'%' IDENTIFIED BY '$NEW_PASSWORD'; FLUSH PRIVILEGES;" || exit 1
fi
failed=0
for f in $(ls /migrations/*.sql | sort); do
  if [ "$(basename "$f")" = 01_clean-honeypot-data.sql ]; then
    mysql -h"$DB_HOST" -u"$DB_USER" -p"$NEW_PASSWORD" "$DB_NAME" --force < "$f" 2>/dev/null
  else
    mysql -h"$DB_HOST" -u"$DB_USER" -p"$NEW_PASSWORD" "$DB_NAME" --force < "$f" || failed=1
  fi
done
exit $failed
"""

# Same start-up as honeypot_eshop_N in docker-compose.yml: remap www-data to the
# volume's owner, then run apache.
WP_START_SCRIPT = """
HOST_UID=$(stat -c '%u' /var/www/html)
HOST_GID=$(stat -c '%g' /var/www/html)
usermod -u "$HOST_UID" www-data
groupmod -g "$HOST_GID" www-data
chown -R www-data:www-data /var/www/html/wp-content
exec apache2-foreground
"""

if __name__ == "__main__":
    Manager().run()
