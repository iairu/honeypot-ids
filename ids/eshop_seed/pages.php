<?php
// Static pages for the Fernhill storefront (loaded by scripts/seed_storefront_content.php).
// Plain HTML on purpose: it renders identically with or without Elementor.
return [
    'home' => [ 'title' => 'Home', 'content' => '[fernhill_home]' ],

    'about' => [ 'title' => 'Our Story', 'content' => <<<'HTML'
<p class="fh-lead">Fernhill started in 2014 as a single 5-kilo roaster in the back of a bicycle repair shop on Alder Street, with one rule: never sell a coffee we would not drink ourselves.</p>
<h2>How we buy</h2>
<p>We buy directly from farms and cooperatives we have visited, and we pay well above the Fair Trade minimum. Every bag lists the farm, the altitude and the process, because you should know who grew your coffee and how it was handled. Most of our green coffee is bought in small lots of 10 to 30 bags, which is exactly why some of it sells out.</p>
<h2>How we roast</h2>
<p>We roast in 12 kg batches on a restored 1970s Probat drum roaster twice a week, on Monday and Thursday. Each batch is cupped before it is bagged, and any that do not meet our standard never ship. Coffee leaves our warehouse within 24 hours of roasting, so what you receive is days old, not weeks.</p>
<h2>Where we are today</h2>
<ul class="fh-checks">
<li>Eleven people, one roastery, one cafe and a warehouse a block away</li>
<li>Carbon-neutral shipping on every order since 2022</li>
<li>Recyclable and compostable packaging across the whole range</li>
<li>1% of revenue donated to coffee-growing communities through Pueblo a Pueblo</li>
</ul>
<h2>Visit us</h2>
<p>Our cafe and roastery are open daily at 412 SE Alder Street, Portland. Cuppings run every Saturday at 10 a.m., no booking needed.</p>
HTML ],

    'shipping-returns' => [ 'title' => 'Shipping & Returns', 'content' => <<<'HTML'
<h2>Shipping</h2>
<p>Coffee is roasted Monday and Thursday and ships the following business day. Orders placed after the cut-off ship with the next batch, which is why you will sometimes see "ships Thursday" at checkout.</p>
<table class="fh-table"><thead><tr><th>Method</th><th>Delivery</th><th>Cost</th></tr></thead><tbody>
<tr><td>Standard (USPS Ground Advantage)</td><td>3–5 business days</td><td>Free over $45, otherwise $5.95</td></tr>
<tr><td>Priority</td><td>2–3 business days</td><td>$9.95</td></tr>
<tr><td>Express</td><td>1–2 business days</td><td>$19.95</td></tr>
</tbody></table>
<p>We ship to all 50 US states and to Canada. International shipping is coming soon.</p>
<h2>Returns</h2>
<p>If you are unhappy with a coffee, tell us within 30 days and we will refund it or send you something you will like better. Gear and apparel can be returned unused within 30 days for a full refund; we cover the return label on defective items.</p>
<h2>Damaged or missing items</h2>
<p>Email <a href="mailto:hello@fernhillroasters.com">hello@fernhillroasters.com</a> with your order number and a photo and we will make it right within one business day.</p>
HTML ],

    'faq' => [ 'title' => 'Frequently Asked Questions', 'content' => <<<'HTML'
<div class="fh-faq">
<details open><summary>How fresh is the coffee?</summary><p>Every order is roasted to order and ships within 24 hours of roasting. The roast date is printed on the label.</p></details>
<details><summary>What grind should I choose?</summary><p>Whole bean stays freshest. If you do not own a grinder, choose by method: pour-over and drip are medium, French press is coarse, espresso is fine and moka pot is medium-fine.</p></details>
<details><summary>How long does a bag last?</summary><p>Brew within four weeks of the roast date for the best flavour. Store the bag sealed, in a cool, dark cupboard, never in the fridge.</p></details>
<details><summary>Can I change or pause my Coffee Club subscription?</summary><p>Yes. Skip, pause, change roast or cancel anytime from My Account, up to 48 hours before your next roast.</p></details>
<details><summary>Do you offer wholesale?</summary><p>We supply cafes and offices across Oregon and Washington. Email <a href="mailto:wholesale@fernhillroasters.com">wholesale@fernhillroasters.com</a> for samples and pricing.</p></details>
<details><summary>Which payment methods do you accept?</summary><p>Major credit and debit cards, bank transfer and cash on delivery for local orders. All card payments are encrypted end to end.</p></details>
</div>
HTML ],

    'contact' => [ 'title' => 'Contact Us', 'content' => <<<'HTML'
<div class="fh-contact-grid">
<div>
<h2>Get in touch</h2>
<p>We read every message and reply within one business day.</p>
<ul class="fh-contact-list">
<li><strong>Email</strong><br><a href="mailto:hello@fernhillroasters.com">hello@fernhillroasters.com</a></li>
<li><strong>Phone</strong><br>(503) 555-0142</li>
<li><strong>Cafe &amp; roastery</strong><br>412 SE Alder Street<br>Portland, OR 97214</li>
<li><strong>Hours</strong><br>Mon–Fri 7 a.m.–5 p.m.<br>Sat–Sun 8 a.m.–4 p.m.</li>
</ul>
</div>
<div>[fernhill_contact_form]</div>
</div>
HTML ],

    'privacy-policy' => [ 'title' => 'Privacy Policy', 'content' => <<<'HTML'
<p><em>Last updated: January 1, 2026</em></p>
<h2>What we collect</h2>
<p>When you place an order we collect your name, shipping and billing address, email address and phone number, plus the items you bought. Payments are processed by our payment provider; we never see or store your full card number.</p>
<h2>How we use it</h2>
<p>We use your information to fulfil your order, send order updates, handle returns and, if you opt in, send our newsletter. We never sell your personal information.</p>
<h2>Cookies</h2>
<p>We use cookies to keep your cart, remember your preferences and measure how the site is used. You can decline non-essential cookies in the banner.</p>
<h2>Your rights</h2>
<p>You can ask to see, correct or delete your personal data at any time by emailing <a href="mailto:privacy@fernhillroasters.com">privacy@fernhillroasters.com</a>.</p>
HTML ],

    'terms-of-service' => [ 'title' => 'Terms of Service', 'content' => <<<'HTML'
<p><em>Last updated: January 1, 2026</em></p>
<h2>Orders</h2>
<p>By placing an order you confirm that the information you provide is accurate. We may cancel an order if an item is unavailable or if we suspect fraud, in which case you will be refunded in full.</p>
<h2>Pricing</h2>
<p>All prices are in US dollars and exclude sales tax and shipping, which are shown at checkout. We may change prices at any time; the price at the time you place your order applies.</p>
<h2>Subscriptions</h2>
<p>Coffee Club subscriptions renew on the schedule you choose until cancelled. You can cancel any time before the next roast date.</p>
<h2>Liability</h2>
<p>Fernhill Coffee Roasters is not liable for indirect or consequential losses. Nothing here limits your statutory consumer rights.</p>
HTML ],

    'journal' => [ 'title' => 'Journal', 'content' => '' ],
];
