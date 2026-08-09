-- ============================================
-- Honeypot Database Migration
-- 01_clean-honeypot-data.sql
-- ============================================
-- This migration cleans sensitive data from the honeypot database
-- and replaces it with dummy/fake data for security purposes.
-- Uses --force in mysql command to ignore errors for non-existent tables.
-- ============================================

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";

-- ============================================
-- Clean tables (ignore errors if tables don't exist)
-- ============================================
-- Clean Users
DELETE FROM `wp_users` WHERE 1=1;
DELETE FROM `wp_usermeta` WHERE 1=1;

-- Clean Comments
DELETE FROM `wp_comments` WHERE 1=1;
DELETE FROM `wp_commentmeta` WHERE 1=1;

-- Clean WooCommerce Orders
DELETE FROM `wp_wc_orders` WHERE 1=1;
DELETE FROM `wp_wc_orders_meta` WHERE 1=1;
DELETE FROM `wp_woocommerce_order_items` WHERE 1=1;
DELETE FROM `wp_woocommerce_order_itemmeta` WHERE 1=1;

-- Clean Customer Data
DELETE FROM `wp_wc_customer_lookup` WHERE 1=1;

-- Clean Payment Tokens and API Keys
DELETE FROM `wp_woocommerce_payment_tokens` WHERE 1=1;
DELETE FROM `wp_woocommerce_payment_tokenmeta` WHERE 1=1;
DELETE FROM `wp_woocommerce_api_keys` WHERE 1=1;

-- Clean Sessions
DELETE FROM `wp_woocommerce_sessions` WHERE 1=1;

-- Clean Logs
DELETE FROM `wp_woocommerce_log` WHERE 1=1;

-- Clean Action Scheduler
DELETE FROM `wp_actionscheduler_actions` WHERE `status` = 'complete';
DELETE FROM `wp_actionscheduler_logs` WHERE 1=1;

-- Clean post meta
DELETE FROM `wp_postmeta` WHERE `meta_key` LIKE '%_customer_%';
DELETE FROM `wp_postmeta` WHERE `meta_key` LIKE '%_billing_%';
DELETE FROM `wp_postmeta` WHERE `meta_key` LIKE '%_shipping_%';

-- Remove sensitive options
DELETE FROM `wp_options` WHERE `option_name` LIKE '%api_key%';
DELETE FROM `wp_options` WHERE `option_name` LIKE '%secret%';
DELETE FROM `wp_options` WHERE `option_name` LIKE '%token%';
DELETE FROM `wp_options` WHERE `option_name` LIKE '%password%';
DELETE FROM `wp_options` WHERE `option_name` LIKE '%stripe%';
DELETE FROM `wp_options` WHERE `option_name` LIKE '%paypal%';
DELETE FROM `wp_options` WHERE `option_name` LIKE '%merchant%';

-- ============================================
-- Insert dummy data (ignore errors if tables don't exist yet)
-- ============================================

-- Insert dummy users
INSERT IGNORE INTO `wp_users` (`ID`, `user_login`, `user_pass`, `user_nicename`, `user_email`, `user_url`, `user_registered`, `user_activation_key`, `user_status`, `display_name`) VALUES
(1, 'admin', '$P$BzVxT5g3h7YhXq9Y8kF5cP2qN1mR3p/', 'admin', 'admin@example.com', 'http://localhost', NOW(), '', 0, 'Administrator'),
(2, 'webmaster', '$P$B8vGxK5h3g7YzXq9Z8mF5dQ2rN1oS4q/', 'webmaster', 'webmaster@example.com', '', NOW(), '', 0, 'Webmaster'),
(3, 'editor', '$P$B7uHyJ4g2f6XyWp8Y7lE4cP1qM0nR3p/', 'editor', 'editor@example.com', '', NOW(), '', 0, 'Editor');

-- Insert dummy user meta
INSERT IGNORE INTO `wp_usermeta` (`umeta_id`, `user_id`, `meta_key`, `meta_value`) VALUES
(1, 1, 'nickname', 'admin'),
(2, 1, 'first_name', 'Admin'),
(3, 1, 'last_name', 'User'),
(4, 1, 'description', 'Site Administrator'),
(5, 1, 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}'),
(6, 1, 'wp_user_level', '10'),
(7, 2, 'nickname', 'webmaster'),
(8, 2, 'first_name', 'Web'),
(9, 2, 'last_name', 'Master'),
(10, 2, 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}'),
(11, 2, 'wp_user_level', '10'),
(12, 3, 'nickname', 'editor'),
(13, 3, 'first_name', 'Content'),
(14, 3, 'last_name', 'Editor'),
(15, 3, 'wp_capabilities', 'a:1:{s:6:"editor";b:1;}'),
(16, 3, 'wp_user_level', '7');

-- Insert dummy comments
INSERT IGNORE INTO `wp_comments` (`comment_ID`, `comment_post_ID`, `comment_author`, `comment_author_email`, `comment_author_url`, `comment_author_IP`, `comment_date`, `comment_date_gmt`, `comment_content`, `comment_karma`, `comment_approved`, `comment_agent`, `comment_type`, `comment_parent`, `user_id`) VALUES
(1, 1, 'John Doe', 'john@example.com', '', '192.168.1.100', NOW(), NOW(), 'Great product! Fast shipping.', 0, '1', 'Mozilla/5.0', 'comment', 0, 0),
(2, 1, 'Jane Smith', 'jane@example.com', '', '192.168.1.101', NOW(), NOW(), 'Excellent service, highly recommended!', 0, '1', 'Mozilla/5.0', 'comment', 0, 0),
(3, 1, 'Bob Wilson', 'bob@example.com', '', '192.168.1.102', NOW(), NOW(), 'Good quality, will buy again.', 0, '1', 'Mozilla/5.0', 'comment', 0, 0);

-- Insert dummy comment meta
INSERT IGNORE INTO `wp_commentmeta` (`meta_id`, `comment_id`, `meta_key`, `meta_value`) VALUES
(1, 1, 'verified', '1'),
(2, 2, 'verified', '1'),
(3, 3, 'verified', '1');

-- Insert dummy homepage
INSERT IGNORE INTO `wp_posts` (`ID`, `post_author`, `post_date`, `post_date_gmt`, `post_content`, `post_title`, `post_excerpt`, `post_status`, `comment_status`, `ping_status`, `post_password`, `post_name`, `to_ping`, `pinged`, `post_modified`, `post_modified_gmt`, `post_content_filtered`, `post_parent`, `guid`, `menu_order`, `post_type`, `post_mime_type`, `comment_count`) VALUES
(1, 1, NOW(), NOW(), 'Welcome to our online store. Browse our products and place your orders today!', 'Home', '', 'publish', 'open', 'open', '', 'home', '', '', NOW(), NOW(), '', 0, '', 0, 'post', '', 1);

-- Insert dummy page
INSERT IGNORE INTO `wp_posts` (`ID`, `post_author`, `post_date`, `post_date_gmt`, `post_content`, `post_title`, `post_excerpt`, `post_status`, `comment_status`, `ping_status`, `post_password`, `post_name`, `to_ping`, `pinged`, `post_modified`, `post_modified_gmt`, `post_content_filtered`, `post_parent`, `guid`, `menu_order`, `post_type`, `post_mime_type`, `comment_count`) VALUES
(2, 1, NOW(), NOW(), 'This is the about page for our company.', 'About', '', 'publish', 'closed', 'open', '', 'about', '', '', NOW(), NOW(), '', 0, '', 0, 'page', '', 0);

-- Insert dummy post meta
INSERT IGNORE INTO `wp_postmeta` (`meta_id`, `post_id`, `meta_key`, `meta_value`) VALUES
(1, 1, '_wp_page_template', 'default'),
(2, 2, '_wp_page_template', 'default');

-- Insert dummy options
INSERT IGNORE INTO `wp_options` (`option_id`, `option_name`, `option_value`, `autoload`) VALUES
(1, 'siteurl', 'http://localhost', 'yes'),
(2, 'home', 'http://localhost', 'yes'),
(3, 'blogname', 'Demo WooCommerce Shop', 'yes'),
(4, 'blogdescription', 'Just another WordPress site', 'yes'),
(5, 'permalink_structure', '/%postname%/', 'yes');

-- Insert dummy product
INSERT IGNORE INTO `wp_posts` (`ID`, `post_author`, `post_date`, `post_date_gmt`, `post_content`, `post_title`, `post_excerpt`, `post_status`, `comment_status`, `ping_status`, `post_password`, `post_name`, `to_ping`, `pinged`, `post_modified`, `post_modified_gmt`, `post_content_filtered`, `post_parent`, `guid`, `menu_order`, `post_type`, `post_mime_type`, `comment_count`) VALUES
(100, 1, NOW(), NOW(), 'This is a sample product description.', 'Sample Product', '', 'publish', 'open', 'closed', '', 'sample-product', '', '', NOW(), NOW(), '', 0, '', 0, 'product', '', 0);

-- Insert dummy product meta
INSERT IGNORE INTO `wp_postmeta` (`meta_id`, `post_id`, `meta_key`, `meta_value`) VALUES
(100, 100, '_price', '29.99'),
(101, 100, '_regular_price', '29.99'),
(102, 100, '_stock', '100'),
(103, 100, '_stock_status', 'instock'),
(104, 100, '_visibility', 'visible');
