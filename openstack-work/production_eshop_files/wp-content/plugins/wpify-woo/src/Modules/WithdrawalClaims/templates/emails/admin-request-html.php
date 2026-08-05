<?php
/**
 * Admin withdrawal/claim email — HTML.
 *
 * Uses WooCommerce standard email markup: `class="td"` on tables/cells,
 * `class="order_item"` on item rows. Styling comes from WC's email-styles.php
 * (processed by Emogrifier into inline CSS at send time), so admin customizations
 * to WC email styles propagate to these tables automatically.
 *
 * @var string $email_heading
 * @var \WC_Email $email
 * @var \WC_Order|null $order
 * @var \WpifyWoo\Modules\WithdrawalClaims\WithdrawalClaimsModel|null $request
 * @var array $request_items
 * @var string $additional_content
 */

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template-scoped variables provided by the template loader, not globals.

$text_align = is_rtl() ? 'right' : 'left';

do_action( 'woocommerce_email_header', $email_heading, $email ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WooCommerce core email hook.
?>

<?php if ( $request && $order ) : ?>
	<?php if ( ! empty( $intro_content ) ) : ?>
		<?php echo wp_kses_post( wpautop( wptexturize( $intro_content ) ) ); ?>
	<?php endif; ?>

	<h2>
		<?php
		/* translators: %d: request id */
		printf( esc_html__( 'Request #%d', 'wpify-woo' ), (int) $request->id );
		?>
	</h2>

	<div style="margin-bottom: 40px;">
		<table class="td" cellspacing="0" cellpadding="6" style="width: 100%; font-family: 'Helvetica Neue', Helvetica, Roboto, Arial, sans-serif;" border="1">
			<tbody>
			<tr>
				<th class="td" scope="row" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php esc_html_e( 'Submitted at', 'wpify-woo' ); ?></th>
				<td class="td" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php echo esc_html( $submitted_at_formatted ); ?></td>
			</tr>
			<tr>
				<th class="td" scope="row" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php esc_html_e( 'Order', 'wpify-woo' ); ?></th>
				<td class="td" style="text-align:<?php echo esc_attr( $text_align ); ?>;">
					<a href="<?php echo esc_url( $order->get_edit_order_url() ); ?>">#<?php echo esc_html( $request->order_number ); ?></a>
				</td>
			</tr>
			<tr>
				<th class="td" scope="row" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php esc_html_e( 'Customer', 'wpify-woo' ); ?></th>
				<td class="td" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php echo esc_html( $request->customer_name . ' <' . $request->customer_email . '>' ); ?></td>
			</tr>
			<tr>
				<th class="td" scope="row" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php esc_html_e( 'Scope', 'wpify-woo' ); ?></th>
				<td class="td" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php echo esc_html( $request->scope_label() ); ?></td>
			</tr>
			<tr>
				<th class="td" scope="row" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php esc_html_e( 'Period end (at submission)', 'wpify-woo' ); ?></th>
				<td class="td" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php echo esc_html( $period_end_formatted ); ?></td>
			</tr>
			<?php if ( ! empty( $request->reason ) ) : ?>
				<tr>
					<th class="td" scope="row" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php esc_html_e( 'Reason / description', 'wpify-woo' ); ?></th>
					<td class="td" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php echo nl2br( esc_html( $request->reason ) ); ?></td>
				</tr>
			<?php endif; ?>
			<?php foreach ( ( $extra_fields ?? array() ) as $extra ) : ?>
				<tr>
					<th class="td" scope="row" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php echo esc_html( $extra['label'] ); ?></th>
					<td class="td" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php echo $extra['value']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pre-rendered by module ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</div>

	<?php if ( ! empty( $request_items ) ) : ?>
		<h2><?php esc_html_e( 'Items', 'wpify-woo' ); ?></h2>

		<div style="margin-bottom: 40px;">
			<table class="td" cellspacing="0" cellpadding="6" style="width: 100%; font-family: 'Helvetica Neue', Helvetica, Roboto, Arial, sans-serif;" border="1">
				<thead>
				<tr>
					<th class="td" scope="col" style="text-align:<?php echo esc_attr( $text_align ); ?>;"><?php esc_html_e( 'Item', 'wpify-woo' ); ?></th>
					<th class="td" scope="col" style="text-align:<?php echo $text_align === 'right' ? 'left' : 'right'; ?>;"><?php esc_html_e( 'Quantity', 'wpify-woo' ); ?></th>
				</tr>
				</thead>
				<tbody>
				<?php foreach ( $request_items as $row ) : ?>
					<tr class="order_item">
						<td class="td" style="text-align:<?php echo esc_attr( $text_align ); ?>; vertical-align: middle; word-wrap: break-word;"><?php echo esc_html( $row['name'] ); ?></td>
						<td class="td" style="text-align:<?php echo $text_align === 'right' ? 'left' : 'right'; ?>; vertical-align: middle;"><?php echo (int) $row['quantity']; ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>

	<?php
	$detail_url = admin_url( 'admin.php?page=wpify-woo-requests&request_id=' . (int) $request->id );
	?>
	<p>
		<a class="link" href="<?php echo esc_url( $detail_url ); ?>"><?php esc_html_e( 'View request in admin →', 'wpify-woo' ); ?></a>
	</p>
<?php endif; ?>

<?php if ( ! empty( $additional_content ) ) : ?>
	<p><?php echo wp_kses_post( wpautop( wptexturize( $additional_content ) ) ); ?></p>
<?php endif; ?>

<?php
do_action( 'woocommerce_email_footer', $email ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WooCommerce core email hook.
// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
