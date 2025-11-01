-- ============================================
-- Honeypot Database Migration
-- 01_clean-honeypot-data.sql
-- ============================================
-- This migration cleans sensitive data from the honeypot database
-- and replaces it with dummy/fake data for security purposes.
-- The honeypot should look real but contain no actual sensitive information.
-- ============================================

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";

-- ============================================
-- PHASE 1: Clean all tables first
-- ============================================

-- Clean Users
TRUNCATE TABLE `wp_users`;
TRUNCATE TABLE `wp_usermeta`;

-- Clean Comments
DELETE FROM `wp_comments` WHERE `comment_ID` > 0;
DELETE FROM `wp_commentmeta` WHERE `meta_id` > 0;

-- Clean WooCommerce Orders
DELETE FROM `wp_wc_orders` WHERE `id` > 0;
DELETE FROM `wp_wc_orders_meta` WHERE `id` > 0;
DELETE FROM `wp_woocommerce_order_items` WHERE `order_item_id` > 0;
DELETE FROM `wp_woocommerce_order_itemmeta` WHERE `meta_id` > 0;

-- Clean Customer Data
DELETE FROM `wp_wc_customer_lookup` WHERE `customer_id` > 0;

-- Clean Payment Tokens and API Keys
DELETE FROM `wp_woocommerce_payment_tokens` WHERE `token_id` > 0;
DELETE FROM `wp_woocommerce_payment_tokenmeta` WHERE `meta_id` > 0;
DELETE FROM `wp_woocommerce_api_keys` WHERE `key_id` > 0;

-- Clean Sessions
DELETE FROM `wp_woocommerce_sessions` WHERE `session_id` > 0;

-- Clean Logs
DELETE FROM `wp_woocommerce_log` WHERE `log_id` > 0;

-- Clean Action Scheduler (keep structure, remove completed actions)
DELETE FROM `wp_actionscheduler_actions` WHERE `status` = 'complete';
DELETE FROM `wp_actionscheduler_logs` WHERE `log_id` > 0;

-- Clean post meta that might contain sensitive data
DELETE FROM `wp_postmeta` WHERE `meta_key` LIKE '%_customer_%';
DELETE FROM `wp_postmeta` WHERE `meta_key` LIKE '%_billing_%';
DELETE FROM `wp_postmeta` WHERE `meta_key` LIKE '%_shipping_%';

-- Remove any stored API keys or tokens in options
DELETE FROM `wp_options` WHERE `option_name` LIKE '%api_key%';
DELETE FROM `wp_options` WHERE `option_name` LIKE '%secret%';
DELETE FROM `wp_options` WHERE `option_name` LIKE '%token%';
DELETE FROM `wp_options` WHERE `option_name` LIKE '%password%';
DELETE FROM `wp_options` WHERE `option_name` LIKE '%stripe%';
DELETE FROM `wp_options` WHERE `option_name` LIKE '%paypal%';
DELETE FROM `wp_options` WHERE `option_name` LIKE '%merchant%';

-- ============================================
-- PHASE 2: Insert dummy data
-- ============================================

-- ============================================
-- Insert dummy users
-- ============================================
-- Insert dummy admin user (weak credentials for honeypot)
INSERT INTO `wp_users` (`ID`, `user_login`, `user_pass`, `user_nicename`, `user_email`, `user_url`, `user_registered`, `user_activation_key`, `user_status`, `display_name`) VALUES
(1, 'admin', '$P$BzVxT5g3h7YhXq9Y8kF5cP2qN1mR3p/', 'admin', 'admin@example.com', 'http://localhost', NOW(), '', 0, 'Administrator'),
(2, 'webmaster', '$P$B8vGxK5h3g7YzXq9Z8mF5dQ2rN1oS4q/', 'webmaster', 'webmaster@example.com', '', NOW(), '', 0, 'Webmaster'),
(3, 'editor', '$P$B7uHyJ4g2f6XyWp8Y7lE4cP1qM0nR3p/', 'editor', 'editor@example.com', '', NOW(), '', 0, 'Editor');

-- Insert dummy user meta
INSERT INTO `wp_usermeta` (`umeta_id`, `user_id`, `meta_key`, `meta_value`) VALUES
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

-- ============================================
-- Insert dummy comments
-- ============================================
-- Insert fake comments to make site look active
INSERT INTO `wp_comments` (`comment_ID`, `comment_post_ID`, `comment_author`, `comment_author_email`, `comment_author_url`, `comment_author_IP`, `comment_date`, `comment_date_gmt`, `comment_content`, `comment_karma`, `comment_approved`, `comment_agent`, `comment_type`, `comment_parent`, `user_id`) VALUES
(1, 1, 'Ján Kováč', 'jan.kovac@example.com', '', '192.168.1.100', NOW(), NOW(), 'Skvelý produkt! Rýchle dodanie a vynikajúca kvalita.', 0, '1', 'Mozilla/5.0', 'comment', 0, 0),
(2, 1, 'Mária Horvátová', 'maria.horvatova@example.com', '', '192.168.1.101', NOW(), NOW(), 'Veľmi spokojná s nákupom. Vrelo odporúčam!', 0, '1', 'Mozilla/5.0', 'comment', 0, 0),
(3, 1, 'Peter Novák', 'peter.novak@example.com', '', '192.168.1.102', NOW(), NOW(), 'Dobrý pomer ceny a kvality. Určite si kúpim znova.', 0, '1', 'Mozilla/5.0', 'comment', 0, 0);

-- ============================================
-- Insert dummy orders
-- ============================================
-- Insert dummy orders
INSERT INTO `wp_wc_orders` (`id`, `status`, `currency`, `type`, `tax_amount`, `total_amount`, `customer_id`, `billing_email`, `date_created_gmt`, `date_updated_gmt`, `parent_order_id`, `payment_method`, `payment_method_title`, `transaction_id`, `ip_address`, `user_agent`, `customer_note`) VALUES
(100, 'wc-completed', 'EUR', 'shop_order', '5.00', '55.00', 1, 'zakaznik1@example.com', NOW(), NOW(), 0, 'cod', 'Dobierka', '', '192.168.1.50', 'Mozilla/5.0', ''),
(101, 'wc-processing', 'EUR', 'shop_order', '8.50', '93.50', 2, 'zakaznik2@example.com', NOW(), NOW(), 0, 'bacs', 'Bankový prevod', '', '192.168.1.51', 'Mozilla/5.0', ''),
(102, 'wc-completed', 'EUR', 'shop_order', '3.75', '41.25', 3, 'zakaznik3@example.com', NOW(), NOW(), 0, 'cod', 'Dobierka', '', '192.168.1.52', 'Mozilla/5.0', '');

-- Add order metadata (billing/shipping addresses with fake data)
INSERT INTO `wp_wc_orders_meta` (`order_id`, `meta_key`, `meta_value`) VALUES
(100, '_billing_first_name', 'Marián'),
(100, '_billing_last_name', 'Varga'),
(100, '_billing_address_1', 'Hlavná 15'),
(100, '_billing_city', 'Bratislava'),
(100, '_billing_state', 'Bratislavský kraj'),
(100, '_billing_postcode', '81101'),
(100, '_billing_country', 'SK'),
(100, '_billing_phone', '+421 912 345 678'),
(100, '_shipping_first_name', 'Marián'),
(100, '_shipping_last_name', 'Varga'),
(100, '_shipping_address_1', 'Hlavná 15'),
(100, '_shipping_city', 'Bratislava'),
(100, '_shipping_state', 'Bratislavský kraj'),
(100, '_shipping_postcode', '81101'),
(100, '_shipping_country', 'SK'),
(101, '_billing_first_name', 'Zuzana'),
(101, '_billing_last_name', 'Tkáčová'),
(101, '_billing_address_1', 'Štúrova 23'),
(101, '_billing_city', 'Košice'),
(101, '_billing_state', 'Košický kraj'),
(101, '_billing_postcode', '04001'),
(101, '_billing_country', 'SK'),
(101, '_billing_phone', '+421 907 654 321'),
(101, '_shipping_first_name', 'Zuzana'),
(101, '_shipping_last_name', 'Tkáčová'),
(101, '_shipping_address_1', 'Štúrova 23'),
(101, '_shipping_city', 'Košice'),
(101, '_shipping_state', 'Košický kraj'),
(101, '_shipping_postcode', '04001'),
(101, '_shipping_country', 'SK'),
(102, '_billing_first_name', 'Ján'),
(102, '_billing_last_name', 'Baláž'),
(102, '_billing_address_1', 'Nám. SNP 8'),
(102, '_billing_city', 'Žilina'),
(102, '_billing_state', 'Žilinský kraj'),
(102, '_billing_postcode', '01001'),
(102, '_billing_country', 'SK'),
(102, '_billing_phone', '+421 905 123 456'),
(102, '_shipping_first_name', 'Ján'),
(102, '_shipping_last_name', 'Baláž'),
(102, '_shipping_address_1', 'Nám. SNP 8'),
(102, '_shipping_city', 'Žilina'),
(102, '_shipping_state', 'Žilinský kraj'),
(102, '_shipping_postcode', '01001'),
(102, '_shipping_country', 'SK');

-- ============================================
-- Insert dummy customer data
-- ============================================
-- Insert dummy customer lookup data
INSERT INTO `wp_wc_customer_lookup` (`customer_id`, `user_id`, `username`, `first_name`, `last_name`, `email`, `date_last_active`, `date_registered`, `country`, `postcode`, `city`, `state`) VALUES
(1, 0, '', 'Marián', 'Varga', 'zakaznik1@example.com', NOW(), NOW(), 'SK', '81101', 'Bratislava', 'Bratislavský kraj'),
(2, 0, '', 'Zuzana', 'Tkáčová', 'zakaznik2@example.com', NOW(), NOW(), 'SK', '04001', 'Košice', 'Košický kraj'),
(3, 0, '', 'Ján', 'Baláž', 'zakaznik3@example.com', NOW(), NOW(), 'SK', '01001', 'Žilina', 'Žilinský kraj');

-- ============================================
-- Update options and posts
-- ============================================
-- Update admin email to dummy
UPDATE `wp_options` SET `option_value` = 'admin@example.com' WHERE `option_name` = 'admin_email';

-- Update site URL if needed (will be set by WordPress on first load)
-- UPDATE `wp_options` SET `option_value` = 'http://localhost' WHERE `option_name` IN ('siteurl', 'home');

-- Update Post Authors to dummy user
UPDATE `wp_posts` SET `post_author` = 1 WHERE `post_author` > 0;

-- ============================================
-- Add Honeypot Marker
-- ============================================
-- Add a hidden option to identify this as honeypot database
INSERT INTO `wp_options` (`option_name`, `option_value`, `autoload`) VALUES 
('_honeypot_instance', '1', 'no'),
('_honeypot_initialized', NOW(), 'no')
ON DUPLICATE KEY UPDATE `option_value` = VALUES(`option_value`);

-- ============================================
-- Migration Complete
-- ============================================
SELECT 'Honeypot database migration 01_clean-honeypot-data.sql completed successfully' AS status;
