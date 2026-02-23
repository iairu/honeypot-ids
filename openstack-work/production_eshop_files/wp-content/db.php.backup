<?php
/**
 * Custom Database Connection Handler for Honeypot SQL Routing
 *
 * This drop-in file extends WordPress's wpdb class to enable dynamic database routing
 * based on threat analysis performed by the Nginx reverse proxy layer.
 *
 * Architecture:
 * 1. Nginx Lua analyzes each request for threat patterns
 * 2. Sets X-DB-Target header (production/honeypot) based on threat score
 * 3. WordPress reads this header and connects to the appropriate database
 * 4. SQL queries are automatically routed without needing a SQL proxy
 *
 * This achieves single WordPress frontend with dual-database backend routing.
 *
 * @package HoneypotIDS
 * @version 1.0.0
 */

// Ensure this is only loaded in WordPress context
if (!defined('ABSPATH')) {
    die('Direct access not permitted');
}

/**
 * Extended wpdb class with dynamic database routing capability
 */
class Honeypot_Routing_WPDB extends wpdb {

    /**
     * Track which database we're connected to for logging
     * @var string
     */
    private $current_target = 'production';

    /**
     * Track routing statistics
     * @var array
     */
    private static $routing_stats = [
        'production' => 0,
        'honeypot' => 0,
        'total' => 0
    ];

    /**
     * Override database connection to support dynamic routing
     *
     * This method is called when WordPress needs to establish a database connection.
     * We intercept it to read the X-DB-Target header set by Nginx and route
     * to the appropriate database backend.
     *
     * @param bool $allow_bail Optional. Allows the function to bail. Default true.
     * @return bool True on successful connection, false on failure.
     */
    public function db_connect($allow_bail = true) {
        // Determine target database from Nginx routing decision
        $db_target = $this->get_routing_target();
        $this->current_target = $db_target;

        // Override database host based on routing decision
        if ($db_target === 'honeypot') {
            $original_host = $this->dbhost;
            $this->dbhost = 'honeypot_database:3306';

            // Log the routing decision
            $this->log_routing_decision($db_target, $original_host, $this->dbhost);

            // Increment statistics
            self::$routing_stats['honeypot']++;
        } else {
            $original_host = $this->dbhost;
            $this->dbhost = 'production_database:3306';

            // Log the routing decision
            $this->log_routing_decision($db_target, $original_host, $this->dbhost);

            // Increment statistics
            self::$routing_stats['production']++;
        }

        self::$routing_stats['total']++;

        // Call parent connection method
        $result = parent::db_connect($allow_bail);

        // Log connection result
        if ($result) {
            $this->log_message("Successfully connected to {$db_target} database");
        } else {
            $this->log_message("Failed to connect to {$db_target} database", 'error');
        }

        return $result;
    }

    /**
     * Determine routing target from HTTP headers
     *
     * Priority:
     * 1. X-DB-Target header from Nginx (primary method)
     * 2. X-Honeypot-Route header as fallback
     * 3. Default to production for safety
     *
     * @return string 'production' or 'honeypot'
     */
    private function get_routing_target() {
        // Primary method: Read X-DB-Target header set by Nginx Lua
        if (isset($_SERVER['HTTP_X_DB_TARGET'])) {
            $target = strtolower(trim($_SERVER['HTTP_X_DB_TARGET']));
            if (in_array($target, ['production', 'honeypot'])) {
                $this->log_message("Routing target from X-DB-Target: {$target}");
                return $target;
            }
        }

        // Fallback: Check X-Honeypot-Route header
        if (isset($_SERVER['HTTP_X_HONEYPOT_ROUTE']) && $_SERVER['HTTP_X_HONEYPOT_ROUTE'] === 'true') {
            $this->log_message("Routing target from X-Honeypot-Route: honeypot");
            return 'honeypot';
        }

        // Default: Route to production for safety
        $this->log_message("No routing header found, defaulting to: production");
        return 'production';
    }

    /**
     * Log routing decisions for monitoring and debugging
     *
     * @param string $target Target database (production/honeypot)
     * @param string $original_host Original database host
     * @param string $new_host New database host after routing
     */
    private function log_routing_decision($target, $original_host, $new_host) {
        $remote_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $request_uri = $_SERVER['REQUEST_URI'] ?? 'unknown';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        $routing_reason = $_SERVER['HTTP_X_ROUTE_REASON'] ?? 'not_specified';

        $log_entry = sprintf(
            "[SQL ROUTING] Target: %s | IP: %s | URI: %s | Reason: %s | Original Host: %s | New Host: %s | User-Agent: %s\n",
            strtoupper($target),
            $remote_ip,
            $request_uri,
            $routing_reason,
            $original_host,
            $new_host,
            substr($user_agent, 0, 100)
        );

        // Log to WordPress debug.log if WP_DEBUG_LOG is enabled
        if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            error_log($log_entry);
        }

        // Also write to custom SQL routing log
        $log_file = WP_CONTENT_DIR . '/sql-routing.log';
        @file_put_contents($log_file, date('[Y-m-d H:i:s] ') . $log_entry, FILE_APPEND);
    }

    /**
     * Generic logging method
     *
     * @param string $message Log message
     * @param string $level Log level (info/error/warning)
     */
    private function log_message($message, $level = 'info') {
        $remote_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

        $log_entry = sprintf(
            "[SQL ROUTING %s] %s | IP: %s\n",
            strtoupper($level),
            $message,
            $remote_ip
        );

        if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            error_log($log_entry);
        }
    }

    /**
     * Get routing statistics (for debugging/monitoring)
     *
     * @return array Routing statistics
     */
    public static function get_routing_stats() {
        return self::$routing_stats;
    }

    /**
     * Log query execution with routing context
     *
     * Extends parent query method to add routing context to query logs
     *
     * @param string $query SQL query
     * @return int|bool Query result
     */
    public function query($query) {
        // Add routing context to query log if SAVEQUERIES is enabled
        if (defined('SAVEQUERIES') && SAVEQUERIES) {
            $query_context = [
                'db_target' => $this->current_target,
                'remote_ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'routing_reason' => $_SERVER['HTTP_X_ROUTE_REASON'] ?? 'not_specified'
            ];

            // Store context for later retrieval
            add_filter('log_query_custom_data', function($custom_data) use ($query_context) {
                return array_merge((array)$custom_data, $query_context);
            });
        }

        return parent::query($query);
    }
}

// Load the original wpdb class first
require_once(ABSPATH . WPINC . '/wp-db.php');

// Replace the global $wpdb with our custom class
if (!isset($wpdb)) {
    $wpdb = new Honeypot_Routing_WPDB(DB_USER, DB_PASSWORD, DB_NAME, DB_HOST);
}

// Add shutdown hook to log statistics
add_action('shutdown', function() {
    $stats = Honeypot_Routing_WPDB::get_routing_stats();
    if ($stats['total'] > 0) {
        error_log(sprintf(
            "[SQL ROUTING STATS] Total: %d | Production: %d | Honeypot: %d",
            $stats['total'],
            $stats['production'],
            $stats['honeypot']
        ));
    }
}, 999);

// Log that custom DB handler is loaded
if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
    error_log('[SQL ROUTING] Custom database routing handler loaded successfully');
}
