=== WPify Woo - Withdrawal, CRN/VAT, QR payments, Heureka and more for WooCommerce ===
Contributors: wpify, vasikgreif, mejta, martinsvoboda
Tags: WooCommerce, Czech, Heureka, IČ DIČ, QR Payment
Requires at least: 6.2
Tested up to: 7.0
Requires PHP: 8.1
Stable tag: 5.4.18
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
WC requires at least: 7.0
WC tested up to: 10.6
Requires Plugins: woocommerce

WooCommerce features for CZ/SK e-shops: withdrawal & claim, Heureka, CRN/VAT, QR payments, delivery dates, async emails and more.

== Description ==

A free plugin extending WooCommerce with essential features for the Czech, Slovak and EU market. The free plugin includes:

* Heureka XML Feed
* Heureka Ověřeno Zákazníky
* Extra CRN and VAT fields on checkout
* Notification to get free shipping
* Emails vocative
* Asynchronous emails sending.
* QR Code Payment
* Sklik retargeting
* Zbozi.cz/Sklik Conversions Limited
* Template
* Email attachments
* Prices
* Prices log
* Comments
* Delivery dates
* Withdrawal & Claim

There are also premium modules available:

* [Gopay](https://wpify.io/produkt/wpify-woo-gopay/) - Add Gopay payment gateway to your store, with payment method selection and specific gateways for every Gopay payment methof
* [Comgate](https://wpify.io/produkt/wpify-woo-comgate/) - Add Comgate payment gateway to your store, with support for automatic recurring payments using WooCommerce Subscriptions
* [ThePay](https://wpify.io/produkt/wpify-woo-thepay/) - Add ThePay payment gateway to your store. Works with ThePay 2.0!
* [Fakturoid](https://wpify.io/produkt/wpify-woo-fakturoid/) - Automatically generate Fakturoid proforma invoices and invoices
* [Conditional shipping](https://wpify.io/produkt/wpify-woo-conditional-shipping/) - Adjust shipping rates prices and visibility with rules like cart amount, products in cart, currency, user role etc.
* [DPD](https://wpify.io/produkt/wpify-woo-dpd/) - Complete DPD and WooCommerce integration - create packages, print labels and add tracking links directly from admin.
* [GLS](https://wpify.io/produkt/wpify-woo-gls/) - Add GLS ParcelShops selection to checkout.
* [WPify Woo Česká pošta](https://wpify.io/produkt/wpify-woo-balikovna/) - Add Balíkovna, Na poštu shipping method to your store and batch export orders to Podání online from the Orders dashboard.
* [Feeds](https://wpify.io/produkt/wpify-woo-feeds/) - Feed generation for Google, Heureka and Zboží.cz
* [Phone validation](https://wpify.io/produkt/wpify-woo-validace-telefonu/) - Display prefix selector and validate entered phone on checkout
* [Benefit Plus](https://wpify.io/produkt/wpify-woo-benefit-plus/) - Add Benefit plus payment gateway to your store
* [Benefity CZ](https://wpify.io/produkt/wpify-woo-benefity-cz/) - Add Benefity CZ payment gateway to your store!
* [Gallery Beta](https://wpify.io/produkt/wpify-woo-gallery-beta/) - Add Gallery Beta payment gateway to your store!
* [Sodexo](https://wpify.io/produkt/wpify-woo-sodexo/) - Add Sodexo payment gateway to your store
* [Smartform](https://wpify.io/produkt/wpify-woo-smartform-cz/) - It whispers and auto-completes the postal address.
* [Zbozi.cz conversion tracking](https://wpify.io/produkt/wpify-woo-konverze-zbozi-cz/) - Track Zbozi.cz conversions
* [Vivnetworks affiliate tracking](https://wpify.io/produkt/wpify-woo-vivnetworks-affiliate/) - Tracking for Vivnetworks Affiliate
* [SmartEmailing](https://wpify.io/produkt/wpify-woo-smartemailing/) - Connection to the newletter service with the possibility of subscribe and tracing

The plugin is built for speed. Only the enabled modules are loaded, scripts are lazy-loaded only on the needed pages, and the number of database queries is limited to the bare minimum.

The plugin is brought to you by Václav Greif and Daniel Mejta, the WordPress and WooCommerce experts at [wpify.io](https://wpify.io).

## Features

The plugin includes the following modules:

### Heureka XML Feed

* Generate valid Heureka XML feed
* Map WooCommerce Categories to Heureka categories
* Choose delivery methods and prices
* Choose delivery date
* Cron URL to re-generate the feed
* Generates feed in chunks to prevent issues with memory limit and server timeouts

### Heureka Ověřeno zákazníky

* Automatically send order to Heureka Ověřeno zákazníky.
* Optionally show optout checkbox at checkout.
* Show Heureka Ověřeno zákazníky widget.

### Heureka Měření konverzí

* Ad Heureka Měření konverzí to thank you page and product pages.

### Extra CRN and VAT fields on checkout

* Add CRN and VAT number fields to the checkout, WooCommerce admin and emails.
* Supported block checkout.
* Validate the entered CRN using ARES database.
* Validate the entered VAT no using VIES database.
* Autofill the company details by the entered CRN number from ARES.
* Move the Company field to the end of the form.
* Move the VAT fields under the Company field at the top of the checkout form.
* Show checkbox "Enter company details" to reveal the company fields only if needed.
* Option to display narrowed VAT fields side by side.
* Option to require an Company field when the "Enter company details" is checked.
* Option to require an identification number when purchasing for a company (In the case of a Slovak company, the VAT number field is also required).
* Show prices without VAT for subjects with valid VAT number from selected countries.

### Notification to get free shipping

* Display notification "Buy for xxx more to get free shipping" at various places in the store.
* Change the message as you need.
* A shortcode to display the widget anywhere.
* Change background and text colours.
* Display a progress bar and change its colour.
* Option to load min amount from WooCommerce Free shipping settings.

### Emails vocative

* Automatically change the salutation in emails to use correct Czech vocative

### Asynchronous emails sending

* Send WooCommerce emails asynchronously using Action Scheduler to speed up the checkout processing.

### QR Code Payment

* Support for multiple QR standards - QR Platba (CZ), Pay BY Square (SK), Hungarian standard (HU), EPC/SEPA (EU)
* Auto-detection of QR standard based on order billing country
* Configure multiple bank accounts for different payment methods
* Load bank account details from WooCommerce BACS settings or enter manually
* Display QR code on thank you page, email notifications and PDF invoices
* Shortcode `[wpify_woo_render_qr_code]` to display QR code anywhere
* Filter QR code display by payment method, currency and billing country
* Customize message and titles with placeholders for order details
* Compatibility mode for servers without XZ utils
* Developer hooks and filters for customization

### Sklik retargeting

* Option to sending data on the basis of allowing marketing cookies.
* Option to add an e-shop offer identifier also from a custom field.
* Option to add a category identifier from a custom field or automatically loaded from the premium [WPify Woo Feeds](https://wpify.io/produkt/wpify-woo-feeds/) plug-in.

### Zbozi.cz/Sklik Conversions Limited

* Adding frontend conversion code for Sklik or Zboží.cz or both together.
* Option to restrict the data sent by allowing marketing cookies.

### Template

* Option to change the label of the button to send the order.
* Add custom notifications to cart, checkout or any place in the template.

### Email attachments

* Add any attachments to any Woocommerce emails.
* Add any attachments to emails for individual products.
* Option to restrict attachments to specific countries only.

### Prices

* Add info to default prices with the possibility of conditions according to stock status.
* Add custom prices with label, more info, label for default price and product badge.
* Add Option to display the lowest price recorded in the last 30 days.
* Add option to display the price by unit.
* Multicurrency from plugin WooCommerce Multilingual & Multicurrency supported.

### Prices log

* Log history of product prices whenever they change.
* Display the lowest price recorded in the last 30 days below the product price field.

### Comments

* Add option to set custom labels to product reviews.

### Delivery dates

* Add option to display delivery dates in product detail.
* Add option to display available payment methods in product detail.
* Possibility to set days for different stock states.
* Option to change settings for each product.
* Option to insert multiple delivery dates.
* Option to add more information on the delivery date.
* Option to display specific shipping methods for delivery dates.

### Withdrawal & Claim

* Compliant "Withdraw from contract" button required by EU Directive 2023/2673 (effective 19 June 2026).
* Optional warranty claim form sharing the same UI.
* Two-step AJAX submission flow with guest access via order_key links from emails or 2-factor (order number + billing email match) for direct visits.
* Per-product overrides — exclude items from withdrawal/warranty, custom periods (extended warranty, longer return window).
* Native WooCommerce emails (4 types) — customizable subject, heading and content in WC email settings.
* Admin list table, order metabox and My Account integration (buttons + submitted-requests history).
* HPOS compatible, bot and spam protection, filters and actions for extensibility.


== Installation ==

1. Upload `wpify-woo` folder to the `/wp-content/plugins/` directory or install the plugin from the WordPress plugin repository.
1. Activate the plugin through the "Plugins" menu in WordPress.
1. Go to the administration area > WPify > WPify Woo.
1. Enable and configure modules.

If you have problems installing, activating or setting up modules, please refer to our [documentation](https://wpify.io/documentation/wpify-woo/).

== Frequently Asked Questions ==

= Do you have documentation for the plugin? =

Yes, the full documentation for the WPify Woo plugin is available on the website [wpify.io](https://wpify.io/documentation/wpify-woo/)

= How can I set a custom xz binary path for Slovak QR payments? =

Use the `wpify_woo_qr_payment_sk_options` filter and pass the `xzBinary` option to the Slovak QR payment generator:

`
add_filter( 'wpify_woo_qr_payment_sk_options', function ( $options ) {
	$options['xzBinary'] = '/usr/bin/xz';

	return $options;
} );
`

= Why did you create this plugin? =

Our plugin's functionality is (mostly) covered by other plugins, but during the years using these we encountered many issues and bugs.

That's why decided to write our own, highly optimized plugin and offer the basic version with the essential features for free.

= Why do you offer this for free? =

We believe it shouldn't be hard to get WooCommerce store up and running in the Czech environment. For that, we offer the essential features in this free plugin, and also provide premium addons for even more functionality.

= Why do you support WordPress 6.2+ only? =

We take advantage of the new WP features, and we strive to use modern development practices, which was not possible in the previous versions of WordPress.

= Why do you support PHP 8.1 and higher only? =

We support only actively supported versions to be sure, that our code is secure from the bottom up. It's also essential to have the PHP version regularly updated, co you can be sure that your e-shop is safe and fast.

= I need feature XYZ, what should I do? =

We are continually working on adding new modules - we will add some of them to the basic version, some will be available as paid addons. You can also use the framework to write your features, or [contact us](https://wpify.io) to write the module for you.

= I found a bug, what should I do? =

Drop us a message in the support section, or feel free to submit a pull request in the [plugin repository](https://gitlab.com/wpify/wpify-woo).

= Who is behind the plugin? =

This plugin is brought to you by the WordPress and WooCommerce experts at [wpify.io](https://wpify.io).

== Changelog ==

For older releases, see [changelog.txt](https://plugins.svn.wordpress.org/wpify-woo/trunk/changelog.txt).

= 5.4.18 =
* Fix Withdrawal & Claim — request detail in administration now shows the correct submission and period-end time.
* Add Withdrawal & Claim — internal note field on each request, visible in the admin list and detail (not shown to the customer).
* Add Withdrawal & Claim — admin notification emails now use the customer's address as Reply-To, so you can reply directly.

= 5.4.17 =
* Security — fixed a privilege escalation vulnerability and hardened the plugin's public REST API endpoints. Updating is strongly recommended.
* Compatibility with WordPress 7.0.

= 5.4.16 =
* Fix VAT fields (IČO/DIČ) — login and registration on the My Account page now work on the first attempt.
* Fix Withdrawal & Claim — public form now finds the order even when the order number is entered with an extra space or stray character.

= 5.4.15 =
* Fix CRN/VAT — display VIES warnings on classic checkout, debounce VAT checks while typing, and do not treat VIES service outages as invalid VAT numbers.

= 5.4.14 =
* Add QR Payment — developer filter for Slovak QR payment generator options.

= 5.4.13 =
* Fix Withdrawal & Claim — form now correctly resolves the order by its visible number when a custom order-numbering plugin is used.

= 5.4.12 =
* Fix Async emails — checkout error on WooCommerce 10.9 and newer.
* Fix Vocative — greeting in WooCommerce emails is now correctly inflected again.
* Fix Prices log — lowest price now respects WooCommerce VAT display settings and shows the "incl./excl. tax" suffix.
* Fix Withdrawal & Claim — late status changes on years-old orders no longer reopen the withdrawal window.

= 5.4.11 =
* Add Free shipping notice — developer filter for custom notice HTML.

= 5.4.10 =
* Fix Withdrawal & Claim submission for logged-in users.
* Fix Withdrawal & Claim form not submitting with required custom fields.

= 5.4.9 =
* Fix incorrect times shown in Withdrawal & Claim records.
* Add support for custom fields in Withdrawal & Claim form (e.g. IBAN).
* Add editable heading and description for the withdrawal link block in WooCommerce emails.
* Add editable intro text for Withdrawal & Claim notification emails.
A
= 5.4.8 =
* Add second VAT recalculation on classic checkout.
* Fix PHP warning when running CLI scripts.

= 5.4.7 =
* Fix translations of plugin fields in WooCommerce emails on multilingual stores (WPML).

= 5.4.6 =
* Fix Withdrawal & Claim — already refunded units are no longer offered for return or claim.
* Fix Withdrawal & Claim — admin recipient address now appears in the WooCommerce email settings list.

= 5.4.5 =
* Fix Vocative module applying to WooCommerce emails.
* Fix Withdrawal & Claim — variable product variants now respect the parent product's exclusion and period-override settings.
* Fix Withdrawal & Claim — request type, status and scope are now translatable in emails and the admin overview.

= 5.4.4 =
* Fix missing data builder

= 5.4.3 =
* Add Sklik retargeting sends the selected variation ID matching the Zboží.cz feed.
* Add Withdrawal & Claim — apply security setting defaults on existing installations.
* Add Withdrawal & Claim — support custom order numbers from Sequential Order Numbers and similar plugins.
* Add Withdrawal & Claim — block identical resubmits and tighten request cooldown defaults.
* Fix admin newsletter notice not staying hidden after dismissal.
* Fix Withdrawal & Claim – emails language on multilingual sites.
* Fix Withdrawal & Claim — "Order not found" error for logged-in users on the public form.
* Fix Withdrawal & Claim — claim form unsubmittable in the order verification step.

= 5.4.2 =
* Update wpify/custom-fields to 4.8.0.

= 5.4.1 =
* Add filter for providing custom QR payment image data before default QR code generation.

= 5.4.0 =
* Add new module Withdrawal & Claim — compliant "Withdraw from contract" button (EU Directive 2023/2673) + optional warranty claim form, AJAX flow, guest access, per-product overrides, native WC emails, admin overview, HPOS compatible.
* Fix input sanitization in admin settings.
* Fix nonce handling in Heureka reviews import and categories update buttons.
* Fix Heureka XML feed not applying custom Heureka fields on product variations.
* Strip whitespace from account number, bank code, IBAN and BIC in QR payment module.
* Move bundled scoped dependencies from deps to vendor.
* Add direct file access protection to PHP files.

= 5.3.4 =
* Add Store API updates for the free shipping notice in WooCommerce cart and checkout blocks.

= 5.3.3 =
* Add more data to Delivery Dates API response.

= 5.3.2 =
* Refactor delivery dates module — shared logic for rendering and API access.
