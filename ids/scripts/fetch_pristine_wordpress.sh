#!/usr/bin/env bash
# Recreates production_eshop_files_fresh_for_diff/: an untouched WordPress
# core of the same version production runs, for diffing against
# production_eshop_files/ (e.g. to spot tampered core files).
#
# It used to be committed (~81 MB, 3,200 files), but every file in it was
# a stock WordPress file, so it is now downloaded on demand and gitignored
# (ids/.gitignore's *_diff* rule).
#
# Usage: ids/scripts/fetch_pristine_wordpress.sh [version]
#   version defaults to $wp_version in production_eshop_files/wp-includes/version.php
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:-$(sed -n "s/^\$wp_version = '\(.*\)';/\1/p" production_eshop_files/wp-includes/version.php)}"
dest=production_eshop_files_fresh_for_diff
[ -n "$version" ] || { echo "Could not read the WordPress version; pass it as an argument." >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading WordPress $version..."
curl -fsSL "https://wordpress.org/wordpress-${version}.tar.gz" -o "$tmp/wp.tar.gz"
curl -fsSL "https://wordpress.org/wordpress-${version}.tar.gz.sha1" -o "$tmp/wp.sha1"
echo "$(cat "$tmp/wp.sha1")  $tmp/wp.tar.gz" | sha1sum -c --quiet -
tar -xzf "$tmp/wp.tar.gz" -C "$tmp"

rm -rf "$dest"
mv "$tmp/wordpress" "$dest"
echo "Pristine WordPress $version is in ids/$dest"
echo "Compare with: diff -rq ids/$dest ids/production_eshop_files | grep -v '^Only in ids/production_eshop_files'"
