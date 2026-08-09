#!/bin/sh
# seed_wordpress_db.sh - One-time WordPress + WooCommerce + Elementor
# bootstrap, run by production_db_seed (production_database) and
# honeypot_db_seed_1/2/3 (each honeypot pool's own database) -- see
# docker-compose.yml. Same script for all four: which WordPress instance
# it targets and how much content it seeds are entirely controlled by
# the environment variables below, not by which service runs it.
#
# PROBLEM THIS FIXES:
#   A freshly-cloned repo already ships the entire WordPress codebase --
#   core, plugins, themes, uploads -- for production (git-tracked under
#   production_eshop_files/) and, once init_setup's rsync has run, for
#   each honeypot pool too (named volumes honeypot_eshop_files[_N]) --
#   but every one of those FOUR databases starts with ZERO tables:
#   nothing had ever run `wp core install` against any of them. Every
#   request touching wp_options (nearly every request -- this is
#   WordPress core itself, not an Elementor-specific bug) errored with
#   "Table '...production_database.wp_options' doesn't exist" until a
#   human manually clicked through wp-admin/install.php in a browser --
#   including wp_install_state.lua's own 30s health-probe timer against
#   production, which is why the error recurred on a clock, AND
#   honeypot_content_sync's own periodic replication cycle against each
#   pool (its scoped DELETE/INSERT assumes the destination tables
#   already exist -- it creates content ROWS, never SCHEMA). This script
#   does the install automatically, once, idempotently, before anything
#   downstream ever sees a schemaless database -- see docker-compose.yml's
#   depends_on chains (production_eshop/honeypot_eshop_N on their
#   respective seed service; honeypot_content_sync on ALL FOUR).
#
# WHY A SCRIPT, NOT A COMMITTED SQL DUMP / git-lfs BINARY:
#   This is a few KB of plain-text, reviewable-in-a-normal-`git diff`
#   WP-CLI commands that deterministically rebuild the same demo
#   storefront from the already-git-tracked plugin/theme code, rather
#   than a large opaque binary blob that would eat GitHub's free LFS
#   quota (1GB storage / 1GB month bandwidth total across the whole
#   repo) and need regenerating and recommitting on every content change.
#   backup_service's own point-in-time dumps (openstack-work/backups/)
#   remain the disaster-recovery mechanism for a stack that's already
#   been running -- this script is purely about first-boot bring-up.
#
# IDEMPOTENCY:
#   Safe to run on every `docker compose up` -- bails out immediately if
#   WordPress is already installed. Pass FORCE_RESEED=1 (e.g. from the
#   dashboard's Backups page "Reset demo store" button, or
#   manage_backups.sh) to wipe every WordPress table and rebuild from
#   scratch -- useful to restore a clean, known-good storefront between
#   exploit test runs, since exploits are expected to modify/corrupt
#   this database.
#
# IMPORT_SAMPLE_CONTENT (default "1"):
#   production_db_seed leaves this at its default -- production is the
#   one and only source of real content (WooCommerce sample catalog +
#   the Elementor demo pages authored by seed_elementor_pages.sh).
#   honeypot_db_seed_1/2/3 set this to "0": a honeypot pool is meant to
#   have IDENTICAL content to production, not its own independently
#   authored copy -- that's already handled by
#   scripts/replicate_content_to_honeypot.sh's own scoped-mirror logic
#   once real schema exists to mirror INTO. Authoring separate content
#   here too would just leave orphaned rows alongside whatever
#   replication brings in, with no schema/content conflict but no
#   purpose either. Schema/theme/plugin setup happens identically either
#   way -- pools need to actually LOOK like production, just not have
#   their own independently-sourced data.
#
# RESILIENCE:
#   `wp core install` itself is the one step allowed to fail loudly and
#   abort (set -e) -- without it nothing downstream makes sense, and the
#   dependent eshop container's depends_on (service_completed_successfully)
#   means the whole stack correctly stays down rather than serving a
#   broken site. Everything past that (product catalog import needs a
#   one-time wordpress.org plugin download; the Elementor pages are
#   cosmetic) is best-effort: a transient network hiccup on first boot
#   degrades to a working-but-emptier storefront instead of blocking
#   startup entirely.
set -eu

: "${WORDPRESS_DB_HOST:?WORDPRESS_DB_HOST environment variable is required}"
: "${WORDPRESS_DB_NAME:?WORDPRESS_DB_NAME environment variable is required}"
: "${WORDPRESS_DB_USER:?WORDPRESS_DB_USER environment variable is required}"
: "${WORDPRESS_DB_PASSWORD:?WORDPRESS_DB_PASSWORD environment variable is required}"
: "${WP_ADMIN_USER:?WP_ADMIN_USER environment variable is required}"
: "${WP_ADMIN_PASSWORD:?WP_ADMIN_PASSWORD environment variable is required}"
: "${WP_ADMIN_EMAIL:?WP_ADMIN_EMAIL environment variable is required}"
: "${WP_SITE_URL:?WP_SITE_URL environment variable is required}"
: "${WP_SITE_TITLE:?WP_SITE_TITLE environment variable is required}"

cd /var/www/html

# --allow-root: this container runs wp-cli as root (matches production_eshop's
# own container, which the official wordpress:apache image also runs as root
# by default) -- wp-cli refuses by default as a safety rail meant for
# multi-user shared hosting, irrelevant here.
WP="wp --allow-root --path=/var/www/html"

now_iso() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log() { echo "[SEED] $(now_iso) $*"; }

# depends_on: service_healthy only proves mysqld itself is accepting
# connections -- for a MySQL container, that's a mysqladmin ping using
# WHATEVER credentials that healthcheck happens to use, which isn't
# necessarily WORDPRESS_DB_USER/PASSWORD as seen from THIS container
# (confirmed live: honeypot_database_2/3 start out cloned from
# production's own data directory and keep production's password until
# honeypot_db_migration's own ALTER USER step rotates it -- a real race
# against this container if that dependency were ever missing or
# insufficient).
#
# A plain TCP-readiness check, not `wp db check`/`mysql -e` -- confirmed
# live those fail here with "TLS/SSL error: Certificate verification
# failure", unrelated to credentials: this image's bundled mysql CLI
# client (MariaDB 15.2) defaults to verifying certs and rejects the
# self-signed one a mysql:5.7 server presents, the same class of issue
# backup.sh already works around for mysqldump with --skip-ssl. `wp core
# install` itself, just below, does NOT go through that CLI binary at
# all -- WordPress/wpdb connects via PHP's mysqli extension directly,
# which doesn't hit this -- so a CLI-based pre-flight check was actively
# wrong here, not just unnecessary: it could fail (and block startup)
# on a perfectly healthy database that `wp core install` would have
# connected to just fine. A raw TCP connect (PHP's fsockopen, still
# nothing MySQL-protocol-specific) is what actually waits out a genuine
# "container just started, not accepting connections yet" race without
# reintroducing that mismatch.
db_host="${WORDPRESS_DB_HOST%%:*}"
db_port="${WORDPRESS_DB_HOST##*:}"
[ "$db_port" = "$WORDPRESS_DB_HOST" ] && db_port=3306  # no ":port" suffix present

log "Waiting for ${db_host}:${db_port} to accept connections..."
attempt=0
max_attempts=30
until php -r "exit(@fsockopen('${db_host}', ${db_port}, \$e, \$s, 2) ? 0 : 1);"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge "$max_attempts" ]; then
        log "ERROR: ${db_host}:${db_port} still not accepting connections after ${max_attempts} attempts (60s) -- giving up."
        exit 1
    fi
    sleep 2
done
log "${db_host}:${db_port} reachable."

if $WP core is-installed 2>/dev/null; then
    if [ "${FORCE_RESEED:-0}" != "1" ]; then
        log "WordPress already installed -- nothing to do (set FORCE_RESEED=1 to wipe and rebuild)."
        exit 0
    fi
    log "FORCE_RESEED=1 -- dropping and recreating all WordPress tables..."
    $WP db reset --yes
fi

log "Installing WordPress core..."
$WP core install \
    --url="$WP_SITE_URL" \
    --title="$WP_SITE_TITLE" \
    --admin_user="$WP_ADMIN_USER" \
    --admin_password="$WP_ADMIN_PASSWORD" \
    --admin_email="$WP_ADMIN_EMAIL" \
    --skip-email

log "Setting permalink structure..."
$WP rewrite structure '/%postname%/' --hard

log "Activating theme (Omega Storefront)..."
if $WP theme is-installed omega-storefront 2>/dev/null; then
    $WP theme activate omega-storefront
else
    log "  omega-storefront not found, leaving default theme active"
fi

# Only the two plugins the storefront actually needs to function are
# activated here. Everything else under wp-content/plugins/ (akismet,
# jetpack, wordfence, mailpoet, the various WooCommerce payment gateways,
# ...) is deliberately left installed-but-inactive: their PHP files are
# still reachable at their normal paths (which is what most classic
# pre-auth plugin CVEs actually target -- WordPress "active" status in
# wp_options is irrelevant to that), but activating them for real risks
# unpredictable side effects with no upside here -- e.g. Wordfence
# actively firewalling/blocking the exact traffic this honeypot exists
# to let through, or Jetpack hanging startup on an external
# WordPress.com connection attempt that will never succeed offline.
log "Activating WooCommerce and Elementor..."
$WP plugin activate woocommerce
$WP plugin activate elementor

log "Configuring WooCommerce base settings..."
$WP option update woocommerce_store_address "60 29th Street"
$WP option update woocommerce_store_city "San Francisco"
$WP option update woocommerce_default_country "US:CA"
$WP option update woocommerce_store_postcode "94110"
$WP option update woocommerce_currency "USD"
$WP option update woocommerce_price_thousand_sep ","
$WP option update woocommerce_price_decimal_sep "."
$WP option update woocommerce_allow_tracking "no"
# Marks WooCommerce's setup wizard as already completed so a real visit
# to wp-admin doesn't immediately redirect into it -- {"skipped":true} is
# the same shape WooCommerce itself writes when a human clicks "Skip
# setup" on that wizard.
$WP option update woocommerce_onboarding_profile '{"skipped":true}' --format=json
# WooCommerce's own activation hook (triggered by `plugin activate` above)
# already creates the Shop/Cart/Checkout/My Account pages and their
# associated wc_get_page_id() option entries -- no separate step needed.

if [ "${IMPORT_SAMPLE_CONTENT:-1}" != "1" ]; then
    log "IMPORT_SAMPLE_CONTENT=0 -- schema/theme/plugins ready, skipping content"
    log "  authoring (honeypot_content_sync will mirror production's real"
    log "  content into this database instead)."
    log "Seed complete (schema only)."
    exit 0
fi

# Best-effort from here: a working (if emptier) storefront on failure,
# not a blocked startup -- see the file header's RESILIENCE note.
log "Importing WooCommerce's official sample product catalog..."
if $WP plugin install wordpress-importer --activate 2>/var/log/wp_seed_importer_install.log; then
    if $WP import wp-content/plugins/woocommerce/sample-data/sample_products.xml \
            --authors=create 2>/var/log/wp_seed_import.log; then
        log "  Sample product catalog imported."
    else
        log "  WARNING: product import failed -- see /var/log/wp_seed_import.log inside this container. Continuing with an empty catalog."
    fi
    $WP plugin deactivate wordpress-importer || true
    $WP plugin uninstall wordpress-importer || true
else
    log "  WARNING: could not install the wordpress-importer plugin (offline first boot?) -- skipping sample product import."
fi

log "Authoring Elementor demo pages..."
if [ -x /seed_elementor_pages.sh ]; then
    /seed_elementor_pages.sh || log "  WARNING: Elementor page authoring failed -- continuing without it."
else
    log "  WARNING: seed_elementor_pages.sh not found -- skipping."
fi

log "Demo storefront ready."
