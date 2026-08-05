<?php
/**
 * Plugin Name: Production Hardening
 * Description: Hardens the production WordPress/WooCommerce instance by disabling
 *              XML-RPC, stripping version fingerprints from HTML output, REST API
 *              responses and HTTP headers, and removing information-disclosure
 *              artefacts that attackers commonly probe before launching exploits.
 *
 *              This file lives in mu-plugins/ so it is always loaded and cannot
 *              be deactivated through the WordPress admin panel.  It is ONLY
 *              applied to the production instance.  The honeypot instances
 *              intentionally keep these fingerprints visible so that attackers
 *              believe they are interacting with a real, unpatched installation.
 *
 * Version:     1.0.0
 * Author:      Honeynet Research System
 *
 * SECURITY MODEL:
 *   - XML-RPC disabled entirely: the endpoint is a common brute-force and
 *     amplification vector (CVE-2015-3135, CVE-2020-28032 etc.).  Legitimate
 *     WordPress features that used XML-RPC (Jetpack remote, WP mobile app) have
 *     modern REST API equivalents.
 *   - Version strings stripped from <script>/<link> query args (?ver=X.Y.Z),
 *     from the HTML <head> generator meta, from RSS/Atom feeds, and from the
 *     wp-json index response.  This prevents automated scanners (WPScan, Nuclei)
 *     from fingerprinting the exact software version without actually exploiting
 *     a vulnerability.
 *   - PHP version removed from the X-Powered-By header (sent by PHP before
 *     WordPress loads; handled here via header_remove for any late responses).
 *   - WooCommerce version removed from REST API /wc/v3/ index and from
 *     storefront HTML comments that WooCommerce themes occasionally emit.
 *   - Nginx server version is controlled separately in nginx.conf
 *     (server_tokens off) and in the more_set_headers directive.
 */

// Guard: only run inside a proper WordPress request.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// ============================================================================
// 1. XML-RPC – completely disabled on production.
//    Attackers routinely probe /xmlrpc.php for:
//      * Credential brute-force via system.multicall
//      * DDoS amplification via pingback.extensions.getPingbacks
//      * Remote code execution chains (CVE-2019-17671, etc.)
//    Disabling XML-RPC and returning 403 at the WordPress layer is a belt-and-
//    suspenders measure on top of any Nginx-level block.
// ============================================================================

/**
 * Disable XML-RPC transport entirely.
 *
 * The filter 'xmlrpc_enabled' was introduced in WordPress 3.5 and is the
 * canonical way to turn off the feature without deleting xmlrpc.php (which
 * would be overwritten on every WordPress update).
 */
add_filter( 'xmlrpc_enabled', '__return_false' );

/**
 * Remove XML-RPC advertised methods and authentication so that any bypass
 * that manages to reach the handler still cannot do anything useful.
 */
add_filter( 'xmlrpc_methods', function ( array $methods ): array {
    // Return an empty array – no methods exposed.
    return [];
} );

/**
 * Close the XML-RPC request with an explicit 403 Forbidden before WordPress
 * processes any part of the payload.  This fires on 'xmlrpc_call' which is
 * the very first action dispatched by xmlrpc.php after the request is parsed.
 *
 * Belt-and-suspenders: even if the 'xmlrpc_enabled' filter is bypassed by a
 * plugin that re-hooks it, this action will still abort the request.
 */
add_action( 'xmlrpc_call', function (): void {
    // Send 403 and stop execution immediately.
    http_response_code( 403 );
    header( 'Content-Type: text/plain; charset=UTF-8' );
    exit( 'XML-RPC services are disabled on this server.' );
} );

/**
 * Remove the X-Pingback header that advertises the XML-RPC endpoint URL in
 * every HTTP response.  Without this, even browsers that follow links from
 * the site would report the XML-RPC endpoint to the requester.
 */
add_filter( 'wp_headers', function ( array $headers ): array {
    unset( $headers['X-Pingback'] );
    return $headers;
} );

/**
 * Strip the xmlrpc link element that WordPress injects into <head>.
 * This prevents passive discovery via HTML parsing.
 */
remove_action( 'wp_head', 'rsd_link' );

// ============================================================================
// 2. WordPress version fingerprint removal.
//    WPScan and Nuclei templates identify the WP version primarily from:
//      (a) <meta name="generator" content="WordPress X.Y.Z">
//      (b) ?ver=X.Y.Z query strings on enqueued scripts and styles
//      (c) /feed/ and /comments/feed/ <generator> elements
//      (d) /wp-json/ index response "version" field
// ============================================================================

/**
 * Remove the generator <meta> tag from <head> (type a above).
 */
remove_action( 'wp_head', 'wp_generator' );

/**
 * Remove the WP version from RSS / Atom feed <generator> elements (type c).
 */
add_filter( 'the_generator', '__return_empty_string' );

/**
 * Strip or replace ?ver= query strings on all enqueued scripts and styles
 * (type b above).
 *
 * Strategy: replace the version with a static hash derived from a secret salt
 * so that cache-busting still works (different salt → different hash) but the
 * WP version is no longer embedded in page source.
 *
 * The salt is taken from the AUTH_KEY constant defined in wp-config.php; that
 * constant is unique per installation, so the resulting hash is installation-
 * specific rather than version-specific.
 */
add_filter( 'style_loader_src',  'production_hardening_strip_version', 9999 );
add_filter( 'script_loader_src', 'production_hardening_strip_version', 9999 );

/**
 * Replace the ?ver= query argument with a short installation-specific hash.
 *
 * @param  string $src  Original enqueue URL.
 * @return string       URL with version replaced by an opaque hash.
 */
function production_hardening_strip_version( string $src ): string {
    // Leave admin-area requests untouched so the WP update notices work.
    if ( is_admin() ) {
        return $src;
    }

    if ( strpos( $src, '?ver=' ) === false && strpos( $src, '&ver=' ) === false ) {
        return $src;
    }

    // Build an opaque, stable cache-busting token from the installation's
    // secret key.  We only take 8 characters so the URLs stay readable.
    $salt  = defined( 'AUTH_KEY' ) ? AUTH_KEY : 'hardening-fallback-salt';
    $token = substr( md5( $salt ), 0, 8 );

    // Replace ?ver=<anything> or &ver=<anything> with the opaque token.
    $src = preg_replace( '/([?&])ver=[^&]+/', '$1ver=' . $token, $src );

    return $src;
}

/**
 * Scrub the "version" field from the /wp-json/ (REST API) index response
 * (type d above).  Tools like WPScan query this endpoint specifically because
 * it returns a structured JSON object with the WP version in plain text.
 */
add_filter( 'rest_index_data', function ( array $data ): array {
    // Remove the top-level version key entirely.
    unset( $data['description'] ); // often contains "WordPress" branding
    if ( isset( $data['namespaces'] ) ) {
        // Namespaces are harmless; retain them so REST clients continue to work.
    }
    // Replace the version with an opaque string so the field still exists
    // (removing it causes some clients to error) but carries no useful info.
    $data['version'] = '1.0';
    return $data;
} );

// ============================================================================
// 3. PHP version removal from HTTP headers.
//    PHP emits "X-Powered-By: PHP/X.Y.Z" by default.  WordPress cannot prevent
//    PHP from sending this header before the request reaches WordPress, but we
//    can remove it on the way out via header_remove().
//
//    The definitive fix is php.ini "expose_php = Off" in the Docker image, but
//    adding header_remove() here handles any environment where php.ini cannot be
//    changed (e.g. a shared host or an upstream Docker image without a custom
//    php.ini).
// ============================================================================

add_action( 'send_headers', function (): void {
    // Remove X-Powered-By regardless of what PHP or other code set it to.
    header_remove( 'X-Powered-By' );

    // Remove the Link: <...>; rel="https://api.w.org/" header that advertises
    // the REST API endpoint on every front-end page response.  Automated scanners
    // use this to discover the JSON API without parsing HTML.
    header_remove( 'Link' );
} );

/**
 * Also strip the REST API discovery link that WordPress adds to wp_head and
 * to the HTTP Link header via 'rest_output_link_header'.
 */
remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
remove_action( 'template_redirect', 'rest_output_link_header', 11 );

// ============================================================================
// 4. WooCommerce version fingerprint removal.
//    WooCommerce version is exposed in several places:
//      (a) HTML <meta name="generator" content="WooCommerce X.Y.Z">
//      (b) /wp-json/wc/v3/ index "version" field
//      (c) Script/style query args (covered by filter above)
//      (d) woocommerce_version body class (e.g. woocommerce-3-X-Y)
// ============================================================================

/**
 * Remove the WooCommerce generator meta tag from <head> (type a).
 */
add_action( 'init', function (): void {
    // WooCommerce hooks its generator into 'get_the_generator_html' and also
    // directly onto 'wp_head' with 'wc_generator_tag'.
    remove_action( 'wp_head', 'wc_generator_tag' );
} );

/**
 * Strip WooCommerce version from the /wp-json/wc/ REST index (type b).
 * The filter name is 'woocommerce_rest_prepare_system_status' for the status
 * endpoint and 'rest_prepare_*' for the namespace index.
 */
add_filter( 'woocommerce_rest_system_status', function ( array $data ): array {
    // The system status endpoint exposes detailed server info including WC/WP
    // versions, PHP version, MySQL version etc.  Restrict access to admins only
    // by returning an empty array for non-authenticated requests.
    if ( ! current_user_can( 'manage_woocommerce' ) ) {
        return [];
    }
    return $data;
} );

/**
 * Remove woocommerce-version-X-Y-Z from body class (type d).
 * The body class is parsed by WPScan to extract the WC version.
 */
add_filter( 'body_class', function ( array $classes ): array {
    return array_filter( $classes, function ( string $class ): bool {
        // Drop any class matching "woocommerce-X-Y-Z" or "wc-X-Y-Z".
        return ! preg_match( '/^(woocommerce|wc)-\d/', $class );
    } );
} );

// ============================================================================
// 5. Miscellaneous information-disclosure hardening.
//    These small removals collectively prevent passive fingerprinting by
//    automated scanners that harvest meta-data from HTTP responses.
// ============================================================================

/**
 * Remove the Windows Live Writer manifest link.
 * Rarely used in 2024; its presence is a scanner signal.
 */
remove_action( 'wp_head', 'wlwmanifest_link' );

/**
 * Remove the shortlink <link> element and header.
 * The shortlink endpoint (/?p=N) can be used to enumerate post IDs.
 */
remove_action( 'wp_head', 'wp_shortlink_wp_head', 10 );
remove_action( 'template_redirect', 'wp_shortlink_header', 11 );

/**
 * Prevent WordPress from exposing user login information via the REST API
 * user endpoint (/wp-json/wp/v2/users).  Enumerating users is the first
 * step of many brute-force attacks.
 *
 * This does NOT disable user authentication; logged-in admins can still
 * retrieve user data via the API.
 */
add_filter( 'rest_endpoints', function ( array $endpoints ): array {
    // Block unauthenticated access to the users and users/<id> endpoints.
    foreach ( [ '/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)' ] as $endpoint ) {
        if ( isset( $endpoints[ $endpoint ] ) ) {
            foreach ( $endpoints[ $endpoint ] as $index => $handler ) {
                // Not every entry under a route is a handler definition --
                // WP_REST_Server::get_routes() also stores a 'schema'
                // entry per route (a callable, not an array of
                // methods/callback/permission_callback), and in some
                // dispatch contexts (confirmed via WP-CLI + WooCommerce's
                // WC_CLI_Runner, which calls get_routes() before the
                // normal rest_api_init route-registration order settles)
                // that entry -- or others -- can show up as something
                // other than the expected array shape. Blindly assuming
                // every entry is an array and writing
                // $endpoints[$endpoint][$index]['permission_callback']
                // into it fataled with "Cannot access offset of type
                // string on string" whenever $handler wasn't an array.
                // Skipping non-array entries is safe: only real
                // method/callback/permission_callback handler arrays need
                // (or can use) a permission_callback at all.
                if ( ! is_array( $handler ) ) {
                    continue;
                }
                // Wrap the existing permission callback to require authentication.
                if ( isset( $handler['permission_callback'] ) ) {
                    $original = $handler['permission_callback'];
                    $endpoints[ $endpoint ][ $index ]['permission_callback'] = function () use ( $original ) {
                        return is_user_logged_in() && call_user_func( $original );
                    };
                } else {
                    $endpoints[ $endpoint ][ $index ]['permission_callback'] = 'is_user_logged_in';
                }
            }
        }
    }
    return $endpoints;
} );

/**
 * Disable the ?author=N user-enumeration trick.
 * WordPress redirects /?author=1 to /author/admin-username/ which leaks
 * valid usernames.  We redirect it to the home page instead.
 */
add_action( 'template_redirect', function (): void {
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    if ( isset( $_GET['author'] ) && ! is_admin() ) {
        wp_redirect( home_url( '/' ), 301 );
        exit;
    }
} );

/**
 * Remove the WordPress readme.html and license.txt links from the head.
 * These files (when accessible) contain the exact WP version in plain text.
 * Access to readme.html is blocked at the Nginx layer via the
 * "location ~* \.(sql|log|ini|conf|bak|backup|old|tmp)$" deny-all block,
 * but we also strip any HTML references here as defence in depth.
 */
add_action( 'wp_head', function (): void {
    // Remove any dynamically generated link to readme.html (none by default,
    // but some themes or plugins add one).  Nothing to remove by default;
    // this hook is a placeholder for future removals.
}, 1 );

/**
 * Disable the wp-embed script injection on the front-end.
 * The oEmbed endpoint (/wp-json/oembed/1.0/embed?url=...) discloses the
 * WordPress version in its JSON response.  Disabling the script also removes
 * the oEmbed discovery links from <head>.
 */
add_action( 'init', function (): void {
    // Remove oEmbed provider support (WP acting as provider to other sites).
    remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
    remove_action( 'wp_head', 'wp_oembed_add_host_js' );

    // Remove the REST route for oEmbed (source of version disclosure).
    remove_action( 'rest_api_init', 'wp_oembed_register_route' );

    // Disable embed rewrite rules.
    add_filter( 'rewrite_rules_array', function ( array $rules ): array {
        foreach ( $rules as $key => $val ) {
            if ( strpos( $key, 'embed' ) !== false ) {
                unset( $rules[ $key ] );
            }
        }
        return $rules;
    } );
} );

// ============================================================================
// 6. Disable WordPress file editing via the admin panel.
//    The built-in theme/plugin editor (Appearance → Editor, Plugins → Editor)
//    allows an attacker who gains wp-admin access to achieve RCE by modifying
//    PHP files directly from the browser.  Disabling this closes the most
//    immediate post-authentication RCE vector.
// ============================================================================

if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
    define( 'DISALLOW_FILE_EDIT', true );
}

// Also prevent plugin/theme installation from the admin panel (limits RCE
// surface if an attacker obtains admin credentials).
if ( ! defined( 'DISALLOW_FILE_MODS' ) ) {
    define( 'DISALLOW_FILE_MODS', true );
}

// ============================================================================
// 7. Enforce strong cookie security flags on WordPress auth cookies.
//    The WordPress default sets HttpOnly but does not always set SameSite=Lax.
//    Explicitly setting SameSite=Strict and Secure on auth cookies mitigates
//    CSRF attacks and ensures cookies are never sent over plain HTTP.
// ============================================================================

add_action( 'set_auth_cookie', function (
    string $auth_cookie,
    int    $expire,
    int    $expiration,
    int    $user_id,
    string $scheme
): void {
    // Replace the default cookie with one that has Secure + SameSite=Strict.
    // The cookie name varies by scheme ('auth' vs 'secure_auth').
    $cookie_name = ( $scheme === 'secure_auth' )
        ? SECURE_AUTH_COOKIE
        : AUTH_COOKIE;

    // Build the Set-Cookie header manually because PHP < 7.3 does not support
    // the SameSite attribute in setcookie() options.
    $cookie_value = $auth_cookie;
    $expires_str  = ( $expire > 0 ) ? '; Expires=' . gmdate( 'D, d M Y H:i:s', $expire ) . ' GMT' : '';
    $path         = COOKIEPATH ?: '/';
    $domain       = COOKIE_DOMAIN ?: '';
    $domain_str   = $domain ? '; Domain=' . $domain : '';

    $header = sprintf(
        '%s=%s%s; Path=%s%s; Secure; HttpOnly; SameSite=Strict',
        $cookie_name,
        rawurlencode( $cookie_value ),
        $expires_str,
        $path,
        $domain_str
    );

    header( 'Set-Cookie: ' . $header, false );
}, 10, 5 );

// ============================================================================
// END OF PRODUCTION HARDENING MU-PLUGIN
// ============================================================================