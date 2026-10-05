<?php
/**
 * Footer -- Fernhill storefront footer (replaces the stock Omega footer).
 * @package Omega Storefront
 */
do_action( 'omega_storefront_before_footer_content_action' );
$fh_link = static function ( $slug ) {
    return function_exists( 'fh_page_link' ) ? esc_url( fh_page_link( $slug ) ) : '#';
};
$fh_nav = function_exists( 'fh_primary_nav' ) ? fh_primary_nav() : array();
?>
</div>

<footer id="site-footer" class="fh-footer" role="contentinfo">
    <div class="fh-wrap fh-footer-grid">
        <div class="fh-footer-brand">
            <img src="<?php echo esc_url( function_exists( 'fh_asset' ) ? fh_asset( 'img/logo-light.png' ) : '' ); ?>" alt="<?php bloginfo( 'name' ); ?>" width="240" height="60" loading="lazy">
            <p>Small-batch coffee and brewing gear, roasted fresh in Portland, Oregon. Every bag names its farm.</p>
            <ul class="fh-social" aria-label="Social media">
                <li><a href="#" aria-label="Instagram"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="3.5" y="3.5" width="17" height="17" rx="5"/><circle cx="12" cy="12" r="4"/><circle cx="17" cy="7" r="1" fill="currentColor"/></svg></a></li>
                <li><a href="#" aria-label="Facebook"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M14 8h3V4h-3a4 4 0 00-4 4v3H7v4h3v6h4v-6h3l1-4h-4V8z"/></svg></a></li>
                <li><a href="#" aria-label="YouTube"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="3" y="6" width="18" height="12" rx="4"/><path d="M10 9.5v5l4.5-2.5z" fill="currentColor"/></svg></a></li>
            </ul>
        </div>
        <div>
            <h3>Shop</h3>
            <ul>
                <?php foreach ( $fh_nav as $item ) : if ( in_array( $item[2], array( 'journal', 'about' ), true ) ) { continue; } ?>
                    <li><a href="<?php echo esc_url( $item[1] ); ?>"><?php echo esc_html( $item[3] ); ?></a></li>
                <?php endforeach; ?>
            </ul>
        </div>
        <div>
            <h3>Help</h3>
            <ul>
                <li><a href="<?php echo $fh_link( 'shipping-returns' ); // phpcs:ignore ?>">Shipping &amp; returns</a></li>
                <li><a href="<?php echo $fh_link( 'faq' ); // phpcs:ignore ?>">FAQ</a></li>
                <li><a href="<?php echo $fh_link( 'contact' ); // phpcs:ignore ?>">Contact us</a></li>
                <li><a href="<?php echo esc_url( function_exists( 'wc_get_page_permalink' ) ? wc_get_page_permalink( 'myaccount' ) : '#' ); ?>">My account</a></li>
            </ul>
        </div>
        <div>
            <h3>Company</h3>
            <ul>
                <li><a href="<?php echo $fh_link( 'about' ); // phpcs:ignore ?>">Our story</a></li>
                <li><a href="<?php echo $fh_link( 'journal' ); // phpcs:ignore ?>">Journal</a></li>
                <li><a href="<?php echo $fh_link( 'privacy-policy' ); // phpcs:ignore ?>">Privacy policy</a></li>
                <li><a href="<?php echo $fh_link( 'terms-of-service' ); // phpcs:ignore ?>">Terms of service</a></li>
            </ul>
        </div>
        <div class="fh-footer-news">
            <h3>Join the list</h3>
            <p>New roasts, brewing tips and the occasional discount. No spam.</p>
            <?php echo function_exists( 'fh_notice' ) ? fh_notice() : ''; // phpcs:ignore ?>
            <?php echo function_exists( 'fh_newsletter_form' ) ? fh_newsletter_form( 'fh-newsletter-dark' ) : ''; // phpcs:ignore ?>
        </div>
    </div>
    <div class="fh-footer-bar">
        <div class="fh-wrap fh-footer-bar-inner">
            <p>&copy; <?php echo esc_html( gmdate( 'Y' ) ); ?> <?php bloginfo( 'name' ); ?> &middot; 412 SE Alder Street, Portland, OR 97214</p>
            <ul class="fh-pay" aria-label="Accepted payments"><li>Visa</li><li>Mastercard</li><li>Amex</li><li>Bank transfer</li><li>Pay on delivery</li></ul>
        </div>
    </div>
</footer>
</div>
<?php wp_footer(); ?>
</body>
</html>
