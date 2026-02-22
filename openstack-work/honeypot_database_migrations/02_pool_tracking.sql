-- ============================================
-- Honeypot Database Migration
-- 02_pool_tracking.sql
-- ============================================
-- This migration creates the honeynet pooling metadata tables.
--
-- CONTEXT:
--   The honeynet architecture assigns each attacking IP address to a dedicated
--   honeypot pool instance (honeypot_eshop_N + honeypot_database_N).  Redis is
--   the primary store for these assignments (fast, low-latency lookups on every
--   request), but this SQL schema provides a durable, queryable audit trail that
--   survives Redis restarts and enables post-hoc analysis of which attacker was
--   active in which pool instance.
--
-- TABLE OVERVIEW:
--   honeypot_pool_registry     - Static registry of all pool instances.
--   honeypot_ip_assignments    - Append-only log of IP → pool mappings.
--                                The ip_suffix column stores the sanitized IP
--                                (dots replaced with underscores) which can be
--                                used as a safe table-name or file-name suffix
--                                when per-attacker artefacts need to be isolated.
--
-- NOTE: This migration is applied to every honeypot database instance
--       (honeypot_database_1, honeypot_database_2, honeypot_database_3) by the
--       honeypot_db_migration service in docker-compose.yml.  Each instance
--       therefore carries its own copy of these tables which reflects the
--       assignments that Nginx / pool_router.lua has recorded in Redis.
-- ============================================

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";

-- ============================================
-- TABLE: honeypot_pool_registry
-- ============================================
-- Identifies each pool instance: its sequential ID, the Docker service name of
-- the WordPress container, and the Docker service name of its database backend.
-- This table is static – rows are inserted once at migration time and never
-- updated during normal operation.
-- ============================================
CREATE TABLE IF NOT EXISTS `honeypot_pool_registry` (
    `pool_id`             TINYINT UNSIGNED NOT NULL
                              COMMENT 'Sequential pool number matching pool_router.lua POOL_COUNT (1..N)',
    `pool_instance_name`  VARCHAR(100)     NOT NULL
                              COMMENT 'Docker Compose service name of the WordPress container, e.g. honeypot_eshop_1',
    `pool_db_host`        VARCHAR(100)     NOT NULL
                              COMMENT 'Docker Compose service name of the MySQL container, e.g. honeypot_database_1',
    `nginx_upstream`      VARCHAR(100)     NOT NULL
                              COMMENT 'Nginx upstream block name used in nginx.conf, e.g. honeypot_backend_1',
    `created_at`          DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`pool_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COMMENT='Static registry of honeypot pool instances – one row per pool.';

-- Insert one row per pool instance.  If the row already exists (e.g. the
-- migration is re-run) the ON DUPLICATE KEY clause is a no-op update that
-- keeps the existing timestamps intact.
INSERT INTO `honeypot_pool_registry`
    (`pool_id`, `pool_instance_name`, `pool_db_host`, `nginx_upstream`)
VALUES
    (1, 'honeypot_eshop_1', 'honeypot_database_1', 'honeypot_backend_1'),
    (2, 'honeypot_eshop_2', 'honeypot_database_2', 'honeypot_backend_2'),
    (3, 'honeypot_eshop_3', 'honeypot_database_3', 'honeypot_backend_3')
ON DUPLICATE KEY UPDATE
    `pool_instance_name` = VALUES(`pool_instance_name`),
    `pool_db_host`       = VALUES(`pool_db_host`),
    `nginx_upstream`     = VALUES(`nginx_upstream`);

-- ============================================
-- TABLE: honeypot_ip_assignments
-- ============================================
-- Records every IP address that has been routed to the honeypot and the pool
-- instance it was assigned to.
--
-- COLUMN NOTES:
--   ip_address    Plain IPv4 or IPv6 address of the attacker.
--   ip_suffix     Sanitized form of the IP suitable for embedding in identifiers:
--                   192.168.1.100  →  192_168_1_100
--                 This is the "IP address suffix" referenced in the checklist and
--                 can be appended to table names, file names, or log prefixes to
--                 namespace per-attacker artefacts without unsafe characters.
--   pool_id       Which pool instance this IP was assigned to (FK to registry).
--   honeypot_reason  The trigger that caused this IP to be flagged (matches the
--                 honeypot_reason field written by router.lua / pool_router.lua).
--   request_count Running tally of honeypot requests from this IP (incremented
--                 by application-level code or a periodic Redis sync job).
--   first_seen    Timestamp of the very first honeypot request (immutable after
--                 INSERT).
--   last_seen     Automatically updated to NOW() on every UPDATE, providing a
--                 "last active" time for the attacker session.
-- ============================================
CREATE TABLE IF NOT EXISTS `honeypot_ip_assignments` (
    `id`              BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
    `ip_address`      VARCHAR(45)      NOT NULL
                          COMMENT 'Raw attacker IP address (IPv4 or IPv6)',
    `ip_suffix`       VARCHAR(64)      NOT NULL
                          COMMENT 'Sanitized IP usable as a table/file name suffix (dots → underscores)',
    `pool_id`         TINYINT UNSIGNED NOT NULL
                          COMMENT 'Pool instance this IP is assigned to',
    `honeypot_reason` VARCHAR(100)         NULL DEFAULT NULL
                          COMMENT 'Trigger that caused honeypot routing (from pool_router.lua)',
    `request_count`   INT UNSIGNED     NOT NULL DEFAULT 0
                          COMMENT 'Total honeypot requests recorded from this IP',
    `first_seen`      DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP
                          COMMENT 'Timestamp of the first routed honeypot request',
    `last_seen`       DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP
                                       ON UPDATE CURRENT_TIMESTAMP
                          COMMENT 'Timestamp of the most recent honeypot request',
    PRIMARY KEY (`id`),
    -- One row per IP address: duplicate inserts use ON DUPLICATE KEY UPDATE.
    UNIQUE  KEY `uq_ip_address`  (`ip_address`),
    -- Fast look-up by pool when analysing a specific instance.
    INDEX   `idx_pool_id`        (`pool_id`),
    -- Range queries by assignment time (e.g. "all attackers seen today").
    INDEX   `idx_first_seen`     (`first_seen`),
    -- Range queries by activity time (e.g. "currently active attackers").
    INDEX   `idx_last_seen`      (`last_seen`),
    -- Allow look-up by sanitized suffix (used in per-attacker table naming).
    INDEX   `idx_ip_suffix`      (`ip_suffix`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COMMENT='Audit log mapping attacker IPs to their assigned honeypot pool instances.';

-- ============================================
-- TABLE: honeypot_pool_events
-- ============================================
-- Optional fine-grained event log: one row per notable per-IP event (pool
-- assignment, pool fallback due to unhealthy instance, TTL refresh, etc.).
-- Unlike honeypot_ip_assignments (which holds one row per IP), this table
-- accumulates a timeline of events for forensic replay.
-- ============================================
CREATE TABLE IF NOT EXISTS `honeypot_pool_events` (
    `id`          BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
    `ip_address`  VARCHAR(45)      NOT NULL
                      COMMENT 'Attacker IP address that triggered the event',
    `pool_id`     TINYINT UNSIGNED     NULL DEFAULT NULL
                      COMMENT 'Pool instance involved (NULL for events not tied to a specific pool)',
    `event_type`  VARCHAR(50)      NOT NULL
                      COMMENT 'e.g. new_assignment, fallback_assignment, ttl_refresh, session_compromised',
    `event_detail` TEXT                NULL DEFAULT NULL
                      COMMENT 'Optional JSON blob with additional context (reason, score, CVEs, etc.)',
    `occurred_at` DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP
                      COMMENT 'Wall-clock time of the event',
    PRIMARY KEY (`id`),
    INDEX `idx_ip_address`  (`ip_address`),
    INDEX `idx_event_type`  (`event_type`),
    INDEX `idx_occurred_at` (`occurred_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COMMENT='Fine-grained event timeline for per-IP pool routing decisions.';

-- ============================================
-- Mark this pool tracking migration as installed
-- (reuses the honeypot marker pattern from migration 01)
-- ============================================
INSERT INTO `wp_options` (`option_name`, `option_value`, `autoload`) VALUES
    ('_honeypot_pool_migration_02', NOW(), 'no')
ON DUPLICATE KEY UPDATE `option_value` = VALUES(`option_value`);

-- ============================================
-- Migration Complete
-- ============================================
SELECT 'Honeypot database migration 02_pool_tracking.sql completed successfully' AS status;