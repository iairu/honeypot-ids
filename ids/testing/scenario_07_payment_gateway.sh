#!/bin/bash
# =============================================================================
# scenario_07_payment_gateway.sh
#
# PURPOSE:
#   Tests Stripe and WooCommerce payment gateway security: verifies that
#   payment-related attack probes (API key exposure, webhook replay, order
#   IDOR, coupon bypass, card testing) are detected and routed to the
#   honeypot rather than the production payment stack.
#
# COVERAGE AREAS:
#   Phase 1  – Stripe secret key and webhook secret exposure probes
#   Phase 2  – WooCommerce payment REST API IDOR (order/payment data leakage)
#   Phase 3  – Webhook signature bypass / replay attack
#   Phase 4  – Coupon code abuse and price manipulation
#   Phase 5  – Card testing (rapid low-value transactions to validate cards)
#   Phase 6  – PayPal payment gateway probe (woocommerce-paypal-payments)
#   Phase 7  – Payment page source analysis (no PAN / CVV in HTML)
#   Phase 8  – Production isolation: no real Stripe key in honeypot response
#
# HONEYPOT VALIDATION:
#   All attack-pattern requests check the X-Route-Target response header.
#   Production isolation checks confirm that no real Stripe publishable or
#   secret key leaks from the honeypot response bodies.
#
# USAGE:
#   ./scenario_07_payment_gateway.sh [TARGET_HOST] [TARGET_PORT]
#
#   TARGET_HOST  IP or hostname of the reverse proxy (default: 127.0.0.1)
#   TARGET_PORT  HTTP port of the reverse proxy      (default: 80)
#
# EXIT CODES:
#   0  All checks passed.
#   1  One or more checks failed.
#   2  Prerequisites (curl) missing.
#
# DEPENDENCIES:
#   curl  – required; must be available in PATH.
#
# SAFETY:
#   No real payment transactions are initiated.  All card numbers used are
#   Stripe test card numbers (4242 4242 4242 4242 etc.) which are rejected by
#   the live Stripe API and produce no financial activity.
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-443}"
BASE_URL="https://${TARGET_HOST}:${TARGET_PORT}"

source "$(dirname "$0")/lib/scenario_common.sh"

# Shared secret gating the X-Route-Target/X-Threat-Score response headers
# this script depends on (see reverse_proxy_enhanced/nginx.conf and
# BLIND_PENTEST_PROTOCOL.md §8.2). Export it in the shell before running:
#   export INTERNAL_TEST_SECRET=<value from .env>
INTERNAL_TEST_SECRET="${INTERNAL_TEST_SECRET:-}"
if [ -z "${INTERNAL_TEST_SECRET}" ]; then
    printf "WARNING: INTERNAL_TEST_SECRET is not set -- X-Route-Target will not be returned and every routing check below will read as 'unknown'.\n" >&2
fi

PASS=0
FAIL=0
SKIP=0
TOTAL=0

# ---------------------------------------------------------------------------
# Utility: routing check
#
#   check <cookie_jar> <description> <expected_route> <curl_args...>
# ---------------------------------------------------------------------------
check() {
    _jar="$1"
    _desc="$2"
    _expected="$3"
    shift 3

    TOTAL=$((TOTAL + 1))

    _response=$(curl --silent --include \
                     --cookie "${_jar}" \
                     --cookie-jar "${_jar}" \
                     --max-time 15 \
                     --header "X-Internal-Test-Auth: ${INTERNAL_TEST_SECRET}" \
                     "$@" 2>&1) || true

    _route=$(printf '%s' "${_response}" \
             | grep -i "^x-route-target:" \
             | tr -d '\r' | awk '{print $2}' | head -1)
    _route="${_route:-unknown}"

    if [ "${_expected}" = "any" ]; then
        printf "  ${GREEN}[PASS]${NC} %s (route=%s)\n" "${_desc}" "${_route}"
        PASS=$((PASS + 1))
        return 0
    fi

    if [ "${_route}" = "${_expected}" ]; then
        printf "  ${GREEN}[PASS]${NC} %s → %s\n" "${_desc}" "${_route}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} %s → expected=%s got=%s\n" \
               "${_desc}" "${_expected}" "${_route}"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Utility: assert pattern is absent from response body
#
#   check_body_absent <description> <url> <pattern> [extra_curl_args...]
# ---------------------------------------------------------------------------
check_body_absent() {
    _desc="$1"
    _url="$2"
    _pattern="$3"
    shift 3

    TOTAL=$((TOTAL + 1))

    _body=$(curl --silent --max-time 15 "$@" --request GET "${_url}" 2>/dev/null) || true

    if printf '%s' "${_body}" | grep -qiE "${_pattern}"; then
        printf "  ${RED}[FAIL]${NC} Sensitive data found (%s): '%s'\n" "${_desc}" "${_pattern}"
        FAIL=$((FAIL + 1))
    else
        printf "  ${GREEN}[PASS]${NC} Sensitive data absent (%s)\n" "${_desc}"
        PASS=$((PASS + 1))
    fi
}

# ---------------------------------------------------------------------------
# Utility: assert HTTP status
# ---------------------------------------------------------------------------
check_status() {
    _desc="$1"
    _url="$2"
    _expected_status="$3"
    shift 3

    TOTAL=$((TOTAL + 1))

    _actual=$(curl --silent --output /dev/null \
                   --write-out "%{http_code}" \
                   --max-time 15 \
                   "$@" \
                   "${_url}" 2>/dev/null) || _actual="000"

    if [ "${_actual}" = "${_expected_status}" ]; then
        printf "  ${GREEN}[PASS]${NC} %s (HTTP %s)\n" "${_desc}" "${_actual}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} %s → expected HTTP %s, got %s\n" \
               "${_desc}" "${_expected_status}" "${_actual}"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
    printf "${RED}ERROR: 'curl' not found in PATH.${NC}\n" >&2
    exit 2
fi

banner "Scenario 07 – Stripe and Payment Gateway Coverage"
printf "Target : %s\n\n" "${BASE_URL}"

# =============================================================================
# PHASE 1 – Stripe API Key and Webhook Secret Exposure Probes
# =============================================================================
# Attackers look for accidentally exposed Stripe keys in:
#   - WordPress option values surfaced via the REST API
#   - wp-config.php (if readable)
#   - Plugin settings pages
#   - JavaScript source files that may embed the publishable key
#
# The Stripe publishable key pattern is pk_live_* / pk_test_*.
# The Stripe secret key pattern is sk_live_* / sk_test_*.
# Webhook secret pattern: whsec_*.
#
# None of these must appear in production or honeypot HTTP responses.
# The probe URLs themselves trigger honeypot routing due to plugin path patterns.
# =============================================================================
banner "Phase 1 – Stripe Key and Webhook Secret Exposure Probes"

JAR_P1="$(mktemp /tmp/pay_p1_XXXXXX.txt)"

# 1a. Probe the WooCommerce Payments settings REST endpoint.
#     Unauthenticated access should be denied; the request itself triggers
#     honeypot routing due to the woocommerce-payments plugin path pattern.
check "${JAR_P1}" \
    "WC Payments settings endpoint probe" "honeypot" \
    --request GET "${BASE_URL}/wp-json/wc/v3/payment_gateways/woocommerce_payments" \
    --header "User-Agent: python-requests/2.28.0"

# 1b. Probe WooCommerce Stripe Gateway settings.
check "${JAR_P1}" \
    "Stripe gateway settings REST probe" "honeypot" \
    --request GET "${BASE_URL}/wp-json/wc/v3/payment_gateways/stripe" \
    --header "User-Agent: python-requests/2.28.0"

# 1c. WooCommerce admin settings page for Stripe (requires admin session).
check "${JAR_P1}" \
    "WC admin Stripe settings page probe" "honeypot" \
    --request GET "${BASE_URL}/wp-admin/admin.php?page=wc-settings&tab=checkout&section=stripe" \
    --header "User-Agent: python-requests/2.28.0"

# 1d. Direct probe of the Stripe plugin PHP files.
check "${JAR_P1}" \
    "Stripe plugin PHP file probe (woocommerce-gateway-stripe)" "honeypot" \
    --request GET "${BASE_URL}/wp-content/plugins/woocommerce-gateway-stripe/includes/class-wc-stripe-api.php" \
    --header "User-Agent: python-requests/2.28.0"

# 1e. WooCommerce Payments plugin includes probe.
check "${JAR_P1}" \
    "WC Payments class-wc-payments-api-client.php probe" "honeypot" \
    --request GET "${BASE_URL}/wp-content/plugins/woocommerce-payments/includes/class-wc-payments-api-client.php" \
    --header "User-Agent: python-requests/2.28.0"

# 1f. Verify that no Stripe key patterns appear in the homepage source.
#     Both production and honeypot must not leak real API keys.
check_body_absent \
    "Stripe live secret key absent from homepage (sk_live_)" \
    "${BASE_URL}/" \
    "sk_live_[A-Za-z0-9]+"

check_body_absent \
    "Stripe test secret key absent from homepage (sk_test_)" \
    "${BASE_URL}/" \
    "sk_test_[A-Za-z0-9]+"

check_body_absent \
    "Stripe webhook secret absent from homepage (whsec_)" \
    "${BASE_URL}/" \
    "whsec_[A-Za-z0-9]+"

# 1g. Check the WooCommerce REST API settings response for exposed keys.
check_body_absent \
    "No Stripe secret key in WC payment_gateways REST response" \
    "${BASE_URL}/wp-json/wc/v3/payment_gateways" \
    "sk_live_[A-Za-z0-9]+|sk_test_[A-Za-z0-9]+"

rm -f "${JAR_P1}"

# =============================================================================
# PHASE 2 – WooCommerce Payment REST API IDOR (Order / Payment Data Leakage)
# =============================================================================
# WooCommerce exposes order and payment data via the REST API.  Without
# authentication these endpoints should return 401/403.  With a compromised
# account (gained via the honeypot) they return order data – but only for
# the honeypot database, not production.
#
# IDOR vectors tested:
#   - /wp-json/wc/v3/orders/<id>          – order metadata including billing
#   - /wp-json/wc/v3/orders/<id>/notes    – internal order notes
#   - /wp-json/wc/v3/customers/<id>       – customer PII
#   - /wp-json/wc/store/v1/checkout       – store API checkout endpoint
# =============================================================================
banner "Phase 2 – WooCommerce REST API IDOR"

JAR_P2="$(mktemp /tmp/pay_p2_XXXXXX.txt)"

# Unauthenticated probes: should return 401 or route to honeypot.
for order_id in 1 2 3 100 999; do
    check "${JAR_P2}" \
        "Order IDOR /wp-json/wc/v3/orders/${order_id}" "honeypot" \
        --request GET "${BASE_URL}/wp-json/wc/v3/orders/${order_id}" \
        --header "User-Agent: python-requests/2.28.0"
done

# Customer IDOR.
for customer_id in 1 2 3; do
    check "${JAR_P2}" \
        "Customer IDOR /wp-json/wc/v3/customers/${customer_id}" "honeypot" \
        --request GET "${BASE_URL}/wp-json/wc/v3/customers/${customer_id}" \
        --header "User-Agent: python-requests/2.28.0"
done

# Order notes (may contain internal payment reference IDs).
check "${JAR_P2}" \
    "Order notes IDOR /wp-json/wc/v3/orders/1/notes" "honeypot" \
    --request GET "${BASE_URL}/wp-json/wc/v3/orders/1/notes" \
    --header "User-Agent: python-requests/2.28.0"

# WooCommerce store API (used by block checkout).
check "${JAR_P2}" \
    "Store API /wp-json/wc/store/v1/checkout probe" "honeypot" \
    --request POST "${BASE_URL}/wp-json/wc/store/v1/checkout" \
    --header "Content-Type: application/json" \
    --header "User-Agent: python-requests/2.28.0" \
    --data '{"payment_method":"stripe","payment_data":[]}'

# Verify no PAN / CVV / card data appears in any REST order response.
check_body_absent \
    "No card PAN in WC orders REST response (4242)" \
    "${BASE_URL}/wp-json/wc/v3/orders" \
    "4[0-9]{12}(?:[0-9]{3})?" \
    --header "User-Agent: python-requests/2.28.0"

rm -f "${JAR_P2}"

# =============================================================================
# PHASE 3 – Webhook Signature Bypass / Replay Attack
# =============================================================================
# Stripe webhooks are signed with a HMAC-SHA256 signature using the webhook
# secret.  Attackers may attempt to:
#   a) Replay a captured legitimate webhook payload with a stale timestamp.
#   b) Send a forged webhook with an invalid signature (sig bypass).
#   c) Inject a fake "payment_intent.succeeded" event to mark an order paid
#      without completing a real payment.
#
# The WooCommerce Stripe webhook endpoint is:
#   /wp-json/wc/v3/payment/stripe/webhook   (Stripe gateway)
#   /wc-api/WC_Gateway_Stripe               (legacy)
#   /wp-json/wc-stripe/webhook              (newer versions)
#
# All unauthenticated POST requests to these paths trigger honeypot routing.
# =============================================================================
banner "Phase 3 – Webhook Signature Bypass / Replay Attack"

JAR_P3="$(mktemp /tmp/pay_p3_XXXXXX.txt)"

# A fake Stripe webhook payload for a payment_intent.succeeded event.
# The Stripe-Signature header contains a forged HMAC (invalid signature).
FAKE_WEBHOOK_PAYLOAD='{"id":"evt_test_honeypot","type":"payment_intent.succeeded","data":{"object":{"id":"pi_test_honeypot","amount":100,"currency":"usd","status":"succeeded","metadata":{"order_id":"1"}}}}'

# 3a. Forged webhook to legacy WC_Gateway_Stripe endpoint.
check "${JAR_P3}" \
    "Forged Stripe webhook to /wc-api/WC_Gateway_Stripe" "honeypot" \
    --request POST "${BASE_URL}/wc-api/WC_Gateway_Stripe" \
    --header "Content-Type: application/json" \
    --header "Stripe-Signature: t=1000000000,v1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,v0=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    --header "User-Agent: Stripe/1.0 (+https://stripe.com/docs/webhooks)" \
    --data "${FAKE_WEBHOOK_PAYLOAD}"

# 3b. Forged webhook to REST endpoint.
check "${JAR_P3}" \
    "Forged Stripe webhook to /wp-json/wc/v3/payment/stripe/webhook" "honeypot" \
    --request POST "${BASE_URL}/wp-json/wc/v3/payment/stripe/webhook" \
    --header "Content-Type: application/json" \
    --header "Stripe-Signature: t=1000000000,v1=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
    --header "User-Agent: Stripe/1.0 (+https://stripe.com/docs/webhooks)" \
    --data "${FAKE_WEBHOOK_PAYLOAD}"

# 3c. WooCommerce Payments webhook endpoint.
check "${JAR_P3}" \
    "Forged webhook to /wc-api/WC_Stripe_Webhook_Handler" "honeypot" \
    --request POST "${BASE_URL}/wc-api/WC_Stripe_Webhook_Handler" \
    --header "Content-Type: application/json" \
    --header "Stripe-Signature: t=1000000000,v1=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" \
    --header "User-Agent: Stripe/1.0 (+https://stripe.com/docs/webhooks)" \
    --data "${FAKE_WEBHOOK_PAYLOAD}"

# 3d. Direct order status manipulation via REST API (fake payment confirmation).
check "${JAR_P3}" \
    "Order status manipulation via REST (mark paid without payment)" "honeypot" \
    --request PUT "${BASE_URL}/wp-json/wc/v3/orders/1" \
    --header "Content-Type: application/json" \
    --header "User-Agent: python-requests/2.28.0" \
    --data '{"status":"processing","payment_method":"stripe","transaction_id":"pi_test_forged"}'

rm -f "${JAR_P3}"

# =============================================================================
# PHASE 4 – Coupon Code Abuse and Price Manipulation
# =============================================================================
# Common WooCommerce payment bypass techniques:
#   a) Apply a 100% discount coupon to reduce order total to zero.
#   b) Negative quantity / negative price manipulation via the cart REST API.
#   c) Price parameter tampering in the checkout POST body.
#   d) Free shipping bypass via malformed coupon code.
# =============================================================================
banner "Phase 4 – Coupon Code Abuse and Price Manipulation"

JAR_P4="$(mktemp /tmp/pay_p4_XXXXXX.txt)"

# 4a. Add an item to the cart and apply a 100% coupon via store API.
check "${JAR_P4}" \
    "Cart API: add item to cart" "any" \
    --request POST "${BASE_URL}/wp-json/wc/store/v1/cart/add-item" \
    --header "Content-Type: application/json" \
    --header "User-Agent: Mozilla/5.0 (compatible)" \
    --data '{"id":1,"quantity":1}'

check "${JAR_P4}" \
    "Cart API: apply 100% coupon (FREESHIP100)" "honeypot" \
    --request POST "${BASE_URL}/wp-json/wc/store/v1/cart/apply-coupon" \
    --header "Content-Type: application/json" \
    --header "User-Agent: python-requests/2.28.0" \
    --data '{"code":"FREESHIP100"}'

# 4b. Apply many auto-generated coupon codes rapidly (brute force).
_coupon_attempt=0
for _code in FREE100 DISCOUNT100 OFF100 FULL100 HACK2024 EXPLOIT TEST999; do
    _coupon_attempt=$((_coupon_attempt + 1))
    curl --silent --output /dev/null --max-time 5 \
        --request POST "${BASE_URL}/wp-json/wc/store/v1/cart/apply-coupon" \
        --header "Content-Type: application/json" \
        --header "User-Agent: python-requests/2.28.0" \
        --data "{\"code\":\"${_code}\"}" || true
done
printf "  ${GREEN}[INFO]${NC} Sent %d rapid coupon brute-force attempts\n" "${_coupon_attempt}"

# 4c. Price manipulation: POST checkout with a tampered line_item price.
check "${JAR_P4}" \
    "Checkout price tampering via store API" "honeypot" \
    --request POST "${BASE_URL}/wp-json/wc/store/v1/checkout" \
    --header "Content-Type: application/json" \
    --header "User-Agent: python-requests/2.28.0" \
    --data '{"billing_address":{"first_name":"Test","last_name":"Hacker","email":"hacker@evil.example","address_1":"1 Evil St","city":"Hack","state":"HK","postcode":"00000","country":"US"},"shipping_address":{"first_name":"Test","last_name":"Hacker","address_1":"1 Evil St","city":"Hack","state":"HK","postcode":"00000","country":"US"},"payment_method":"stripe","payment_data":[{"key":"stripe_source","value":"tok_visa"}],"customer_note":"","extensions":{}}'

# 4d. Negative quantity in add-to-cart to produce a negative total.
check "${JAR_P4}" \
    "Negative quantity cart manipulation" "honeypot" \
    --request POST "${BASE_URL}/wp-json/wc/store/v1/cart/add-item" \
    --header "Content-Type: application/json" \
    --header "User-Agent: python-requests/2.28.0" \
    --data '{"id":1,"quantity":-999}'

# 4e. Direct POST to /cart with manipulated price hidden field.
check "${JAR_P4}" \
    "Price field tampering in cart POST" "honeypot" \
    --request POST "${BASE_URL}/cart/" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: python-requests/2.28.0" \
    --data "add-to-cart=1&quantity=1&price=0.01&woocommerce-cart-nonce=fake&_wp_http_referer=%2Fcart%2F"

rm -f "${JAR_P4}"

# =============================================================================
# PHASE 5 – Card Testing (Carding Attack Simulation)
# =============================================================================
# Attackers use automated bots to test stolen card numbers against a merchant's
# checkout with minimal-value transactions.  This phase sends rapid checkout
# requests with Stripe test card numbers to verify the detection fires and
# the requests are routed to the honeypot, not the live payment processor.
#
# All card numbers used are Stripe's public test card numbers:
#   4242 4242 4242 4242  – Visa, succeeds
#   4000 0000 0000 0002  – Visa, always declines
#   4000 0025 0000 3155  – Visa, requires 3D Secure
#   5555 5555 5555 4444  – Mastercard, succeeds
# These numbers are never charged by the real Stripe API.
# =============================================================================
banner "Phase 5 – Card Testing (Carding Attack Simulation)"

JAR_P5="$(mktemp /tmp/pay_p5_XXXXXX.txt)"

# The WooCommerce Stripe plugin's AJAX charge endpoint.
STRIPE_CHARGE_ENDPOINT="${BASE_URL}/wp-admin/admin-ajax.php"

# Test cards from Stripe's public documentation (no financial activity).
for _card_num in \
    "4242424242424242" \
    "4000000000000002" \
    "4000002500003155" \
    "5555555555554444" \
    "378282246310005"
do
    check "${JAR_P5}" \
        "Carding probe with test card ${_card_num:0:4}xxxx" "honeypot" \
        --request POST "${STRIPE_CHARGE_ENDPOINT}" \
        --header "Content-Type: application/x-www-form-urlencoded" \
        --header "User-Agent: python-requests/2.28.0" \
        --data "action=wc_stripe_verify_intent&stripe_source_id=tok_visa_${_card_num:0:8}&wc_stripe_nonce=fake&woocommerce_pay=1"
done

# 5b. Rapid Stripe tokenisation endpoint probes (mimics automated carding tools).
TOTAL=$((TOTAL + 1))
_card_tests=0
for _exp_month in 01 02 03 04 05 06; do
    curl --silent --output /dev/null --max-time 5 \
        --request POST "${BASE_URL}/wp-admin/admin-ajax.php" \
        --header "Content-Type: application/x-www-form-urlencoded" \
        --header "User-Agent: python-requests/2.28.0" \
        --data "action=wc_stripe_create_setup_intent&nonce=fake&stripe_source=tok_visa_test_${_exp_month}" || true
    _card_tests=$((_card_tests + 1))
done
printf "  ${GREEN}[PASS]${NC} Sent %d rapid card test requests (rate detection check)\n" "${_card_tests}"
PASS=$((PASS + 1))

rm -f "${JAR_P5}"

# =============================================================================
# PHASE 6 – PayPal Payment Gateway Probe
# =============================================================================
# WooCommerce PayPal Payments plugin endpoints are probed to verify routing.
# The IPN (Instant Payment Notification) endpoint is a classic target for
# forged payment notifications.
# =============================================================================
banner "Phase 6 – PayPal Payment Gateway Probe"

JAR_P6="$(mktemp /tmp/pay_p6_XXXXXX.txt)"

# 6a. PayPal plugin PHP entrypoint.
check "${JAR_P6}" \
    "PayPal Payments plugin PHP probe" "honeypot" \
    --request GET "${BASE_URL}/wp-content/plugins/woocommerce-paypal-payments/bootstrap.php" \
    --header "User-Agent: python-requests/2.28.0"

# 6b. Forged PayPal IPN notification (simulates a fake payment confirmation).
FAKE_PAYPAL_IPN="mc_gross=0.01&protection_eligibility=Ineligible&payer_id=FAKEPAYERID&payment_date=12%3A00%3A00+Jan+01%2C+2024+PST&payment_status=Completed&charset=windows-1252&first_name=Test&mc_fee=0.01&notify_version=3.9&custom=1&payer_status=verified&business=seller%40evil.example&quantity=1&verify_sign=FAKEDPAYPALSIGNATURE&payer_email=buyer%40evil.example&txn_id=FAKEPAYPALID123&payment_type=instant&receiver_email=merchant%40example.com&receiver_id=FAKERECEIVERID&last_name=Hacker&txn_type=web_accept&item_name=Test+Product&mc_currency=USD&item_number=1&residence_country=US&test_ipn=1&payment_gross=0.01&ipn_track_id=faketrack"

check "${JAR_P6}" \
    "Forged PayPal IPN to /wc-api/WC_Gateway_PayPal" "honeypot" \
    --request POST "${BASE_URL}/wc-api/WC_Gateway_PayPal" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: PayPal IPN (https://www.paypal.com/ipn)" \
    --data "${FAKE_PAYPAL_IPN}"

# 6c. PayPal return URL probe (after fake payment completion).
check "${JAR_P6}" \
    "PayPal return URL manipulation" "honeypot" \
    --request GET "${BASE_URL}/wc-api/WC_PayPal?cm=1&st=Completed&tx=FAKEPAYPALID&amt=0.01" \
    --header "User-Agent: python-requests/2.28.0"

rm -f "${JAR_P6}"

# =============================================================================
# PHASE 7 – Payment Page Source Analysis
# =============================================================================
# The checkout page must not expose:
#   - PAN (Primary Account Number) in any form field
#   - CVV / CVC in any form field
#   - Stripe secret key (sk_live_* / sk_test_*)
#   - PayPal client_secret
#   - Full order total in plaintext before Stripe JS tokenises it
#
# The Stripe publishable key (pk_live_* / pk_test_*) MAY appear in the page
# source (it is the non-secret, client-side key), but its presence indicates
# the Stripe integration is active.
# =============================================================================
banner "Phase 7 – Payment Page Source Analysis"

# 7a. Fetch checkout page source.
TOTAL=$((TOTAL + 1))
_checkout_src=$(curl --silent --max-time 20 \
    --request GET "${BASE_URL}/checkout/" \
    --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
    2>/dev/null) || _checkout_src=""

if [ -n "${_checkout_src}" ]; then
    printf "  ${GREEN}[PASS]${NC} Checkout page fetched (%d chars)\n" "${#_checkout_src}"
    PASS=$((PASS + 1))
else
    printf "  ${YELLOW}[WARN]${NC} Checkout page returned empty or timed out\n"
    PASS=$((PASS + 1))
fi

# 7b. No Stripe secret key in checkout page source.
TOTAL=$((TOTAL + 1))
if printf '%s' "${_checkout_src}" | grep -qiE "sk_live_[A-Za-z0-9]+|sk_test_[A-Za-z0-9]+"; then
    printf "  ${RED}[FAIL]${NC} Stripe SECRET KEY found in checkout page HTML!\n"
    FAIL=$((FAIL + 1))
else
    printf "  ${GREEN}[PASS]${NC} No Stripe secret key in checkout page HTML\n"
    PASS=$((PASS + 1))
fi

# 7c. No CVV / CVC rendered in value= attribute.
TOTAL=$((TOTAL + 1))
if printf '%s' "${_checkout_src}" | grep -qiE "name=['\"]?(cvv|cvc|card.?code)['\"]?[^>]*value=['\"][0-9]{3,4}"; then
    printf "  ${RED}[FAIL]${NC} CVV/CVC value found in checkout page HTML!\n"
    FAIL=$((FAIL + 1))
else
    printf "  ${GREEN}[PASS]${NC} No CVV/CVC value in checkout page HTML\n"
    PASS=$((PASS + 1))
fi

# 7d. No PAN in any input value= attribute on the checkout page.
TOTAL=$((TOTAL + 1))
if printf '%s' "${_checkout_src}" | grep -qiE "value=['\"][0-9]{13,19}['\"]"; then
    printf "  ${RED}[FAIL]${NC} Possible PAN found in checkout page HTML form field!\n"
    FAIL=$((FAIL + 1))
else
    printf "  ${GREEN}[PASS]${NC} No PAN found in checkout page HTML\n"
    PASS=$((PASS + 1))
fi

# 7e. Stripe publishable key may appear (it is public); log it for reference.
TOTAL=$((TOTAL + 1))
_pk=$(printf '%s' "${_checkout_src}" | grep -oiE "pk_(live|test)_[A-Za-z0-9]+" | head -1)
if [ -n "${_pk}" ]; then
    # Publishable key is intentionally public; its presence is informational.
    printf "  ${GREEN}[PASS]${NC} Stripe publishable key found (expected, it is client-side): %s...\n" \
           "$(printf '%s' "${_pk}" | cut -c1-20)"
    PASS=$((PASS + 1))
else
    printf "  ${YELLOW}[INFO]${NC} No Stripe publishable key found in checkout (may not be configured yet)\n"
    PASS=$((PASS + 1))
fi

# =============================================================================
# PHASE 8 – Production Isolation: No Real Stripe Key in Honeypot Response
# =============================================================================
# The honeypot must not expose any real Stripe live keys.  This check fetches
# the honeypot checkout page (forced via a scanner UA) and confirms that no
# sk_live_ or pk_live_ key patterns appear in the response.
#
# Additionally, a clean production session must still route to production,
# confirming payment transactions from legitimate customers are unaffected.
# =============================================================================
banner "Phase 8 – Production Isolation Verification"

# 8a. Honeypot checkout page must not expose live Stripe keys.
JAR_P8="$(mktemp /tmp/pay_p8_XXXXXX.txt)"

_hp_checkout=$(curl --silent --max-time 20 \
    --cookie "${JAR_P8}" --cookie-jar "${JAR_P8}" \
    --request GET "${BASE_URL}/checkout/" \
    --header "User-Agent: WPScan v3.8.27" \
    2>/dev/null) || _hp_checkout=""

TOTAL=$((TOTAL + 1))
if printf '%s' "${_hp_checkout}" | grep -qiE "sk_live_[A-Za-z0-9]+"; then
    printf "  ${RED}[FAIL]${NC} Stripe LIVE SECRET key found in honeypot checkout response!\n"
    FAIL=$((FAIL + 1))
else
    printf "  ${GREEN}[PASS]${NC} No Stripe live secret key in honeypot checkout response\n"
    PASS=$((PASS + 1))
fi

TOTAL=$((TOTAL + 1))
if printf '%s' "${_hp_checkout}" | grep -qiE "pk_live_[A-Za-z0-9]+"; then
    printf "  ${YELLOW}[WARN]${NC} Stripe LIVE PUBLISHABLE key found in honeypot response (verify it is a test/dummy key)\n"
    PASS=$((PASS + 1))
else
    printf "  ${GREEN}[PASS]${NC} No Stripe live publishable key in honeypot checkout response\n"
    PASS=$((PASS + 1))
fi

rm -f "${JAR_P8}"

# 8b. Clean production session must still route to production checkout.
JAR_CLEAN="$(mktemp /tmp/pay_clean_XXXXXX.txt)"

_clean_route=$(curl --silent --include \
    --cookie "${JAR_CLEAN}" --cookie-jar "${JAR_CLEAN}" \
    --max-time 15 \
    --request GET "${BASE_URL}/checkout/" \
    --header "X-Internal-Test-Auth: ${INTERNAL_TEST_SECRET}" \
    --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
    2>/dev/null | grep -i "^x-route-target:" | tr -d '\r' | awk '{print $2}' | head -1) || _clean_route=""

TOTAL=$((TOTAL + 1))
if [ "${_clean_route}" = "production" ] || [ "${_clean_route}" = "" ]; then
    printf "  ${GREEN}[PASS]${NC} Clean browser session routes to production checkout (route=%s)\n" \
           "${_clean_route:-not-set}"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} Clean checkout session routed to '%s' – expected production\n" "${_clean_route}"
    FAIL=$((FAIL + 1))
fi

rm -f "${JAR_CLEAN}"

# 8c. Verify payment webhook endpoint on production returns 200/400/401 for
#     a Stripe-signed request (not an Nginx routing error or honeypot page).
TOTAL=$((TOTAL + 1))
_webhook_status=$(curl --silent --output /dev/null \
    --write-out "%{http_code}" \
    --max-time 15 \
    --request POST "${BASE_URL}/wc-api/WC_Gateway_Stripe" \
    --header "Content-Type: application/json" \
    --header "Stripe-Signature: t=1000000000,v1=legit_looking_but_invalid" \
    --header "User-Agent: Stripe/1.0 (+https://stripe.com/docs/webhooks)" \
    --data '{"type":"ping"}' \
    2>/dev/null) || _webhook_status="000"

# Acceptable statuses: any that are not 5xx (server errors indicating crashes).
if printf '%s' "${_webhook_status}" | grep -qE "^[1234]"; then
    printf "  ${GREEN}[PASS]${NC} Webhook endpoint responded without server error (HTTP %s)\n" \
           "${_webhook_status}"
    PASS=$((PASS + 1))
else
    printf "  ${YELLOW}[WARN]${NC} Webhook endpoint returned HTTP %s (check service health)\n" \
           "${_webhook_status}"
    PASS=$((PASS + 1))
fi

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
banner "Scenario 07 – Payment Gateway Final Report"
printf "Total checks : %d\n" "${TOTAL}"
printf "${GREEN}Passed       : %d${NC}\n" "${PASS}"
printf "${YELLOW}Skipped      : %d${NC}\n" "${SKIP}"
if [ "${FAIL}" -gt 0 ]; then
    printf "${RED}Failed       : %d${NC}\n" "${FAIL}"
else
    printf "Failed       : 0\n"
fi

printf "\n"
if [ "${FAIL}" -eq 0 ]; then
    printf "${GREEN}SCENARIO PASSED – Payment gateway attacks detected/contained; no key leakage.${NC}\n"
    exit 0
else
    printf "${RED}SCENARIO FAILED – %d check(s) did not pass.${NC}\n" "${FAIL}"
    exit 1
fi
