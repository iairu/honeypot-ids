
# Wordpress plugins

Preinstall the following plugins:
- WooCommerce Cart Abandonment Recovery
- WPify Slovensko or WPify Česko
- HubSpot Chatbot
- Elementor
- 2FA
- WP REST API
- WordFence
- Mail plugin
- Stripe
- Cloudflare

# Research

One wordpress frontend connected to both production and honeypot databases makes routing decisions
- Explanation of pros/cons of this over the existing setup of two frontedns with Nginx reverse proxy routing 

# Bonus

Honeypot Setup Frontend extended with the following AI/LLM feature: Fetch latest CVEs from internet and generate (duplicate and adjust existing scenarios) CVE-related LUA for Nginx

# Remaining test scenarios' issues

## scenario 1

Remaining Failures (7):**
- Session persistence works manually but test script shows empty cookie values (environmental issue)
- WC Payments CSS file doesn't exist (404)
- Phase 6 shows empty X-Route-Target header

The core honeypot routing functionality is working correctly. The remaining session persistence issue in the test script appears to be environmental - the same curl commands work correctly when run manually.

## scenario 2

