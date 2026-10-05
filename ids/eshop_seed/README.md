# eshop_seed -- the Fernhill Coffee Roasters demo store

Everything the storefront shows is generated, not scraped: the brand, farms and
reviewers are invented, and the product photography is procedural illustration.

| Path | What |
|---|---|
| `catalog.py` | Single source of truth: categories, 26 products, copy, variations, reviews |
| `art.py`, `build_assets.py` | QPainter illustration engine and the renderer |
| `catalog.json`, `products/`, `site/` | Rendered output (committed; a fresh clone never needs to rebuild) |
| `pages.php`, `journal.php` | Static pages and journal posts |

Rebuild after editing `catalog.py`:

    QT_QPA_PLATFORM=offscreen ../../dashboard/venv/bin/python build_assets.py
    cp site/* ../production_eshop_files/wp-content/themes/omega-storefront/assets/fernhill/img/

`scripts/seed_storefront_content.php` authors it into WordPress (production only;
mounted at `/eshop_seed` in the production seed container). It is version-gated:
bump `FH_CATALOG_VERSION` in that file to re-author an existing install, then run
`docker compose run --rm production_db_seed`.

## What is replicated to the honeypot pools

`honeypot_content_sync` copies posts, postmeta, terms and attachments -- not
options, comments, nav-menu items or term meta. So the storefront keeps to that:
reviews live in postmeta (`_fh_reviews`), the navigation is built in code, and
site/store settings come from option filters in
`wp-content/mu-plugins/fernhill-storefront.php`. Pools never delete rows, so after
changing the catalog, clear a pool's old products first (or reseed), then restart
`honeypot_content_sync` to mirror the new ones immediately.
