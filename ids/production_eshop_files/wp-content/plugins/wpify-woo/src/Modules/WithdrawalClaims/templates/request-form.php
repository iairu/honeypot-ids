<?php
/**
 * Withdrawal / Claim form template.
 *
 * Variables provided by the module via include:
 *
 * @var array                                                     $context Context built by WithdrawalClaimsModule::build_form_context().
 * @var \WpifyWoo\Modules\WithdrawalClaims\WithdrawalClaimsModule $module
 */

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template-scoped variables provided by the template loader, not globals.

$type   = $context['type'];
$module = $context['module'];

// Texts.
$label_button  = $type === 'withdrawal'
	? ( $module->get_setting( 'withdrawal_button_text' ) ?: __( 'Withdraw from contract', 'wpify-woo' ) )
	: ( $module->get_setting( 'claim_button_text' ) ?: __( 'File a claim', 'wpify-woo' ) );
$label_confirm = $type === 'withdrawal'
	? ( $module->get_setting( 'withdrawal_confirm_text' ) ?: __( 'Confirm withdrawal', 'wpify-woo' ) )
	: ( $module->get_setting( 'claim_confirm_text' ) ?: __( 'Submit claim', 'wpify-woo' ) );

$anchor_id = 'wpify-woo-' . $type . '-form';

$required_marker = '<abbr class="required" title="' . esc_attr__( 'required', 'wpify-woo' ) . '">*</abbr>';

// Step: submitted (thank you).
if ( ! empty( $context['submitted'] ) ) :
	?>
	<section id="<?php echo esc_attr( $anchor_id ); ?>" class="wpify-woo-form wpify-woo-form--submitted">
		<p class="woocommerce-message" role="status">
			<?php esc_html_e( 'Your request has been submitted. A confirmation email has been sent to you.', 'wpify-woo' ); ?>
		</p>
	</section>
	<?php
	return;
endif;

// Server-side error from PRG fail (no-JS fallback path).
// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only prefill of an error message for display; no state change.
$error_message = isset( $_GET['wcr_err'] ) ? sanitize_text_field( wp_unslash( $_GET['wcr_err'] ) ) : '';
// phpcs:enable WordPress.Security.NonceVerification.Recommended

$is_trusted    = ! empty( $context['is_trusted'] );
$has_order     = $context['order'] instanceof WC_Order;
$can_show_form = $has_order && $is_trusted;

?>
<section id="<?php echo esc_attr( $anchor_id ); ?>"
		 class="wpify-woo-form wpify-woo-form--<?php echo esc_attr( $type ); ?>">
	<?php if ( $error_message ) : ?>
		<div class="woocommerce-error" role="alert"><?php echo esc_html( $error_message ); ?></div>
	<?php endif; ?>

	<form method="post" class="woocommerce-form woocommerce-form-<?php echo esc_attr( $type ); ?>">
		<?php wp_nonce_field( 'wpify_woo_request_' . $type, '_wpify_woo_nonce' ); ?>
		<input type="hidden" name="wpify_woo_request_type" value="<?php echo esc_attr( $type ); ?>">
		<input type="hidden" name="wpify_woo_request_action" value="submit">
		<input type="hidden" name="_form_render_time"
			   value="<?php echo esc_attr( $module->generate_time_trap_value() ); ?>">

		<?php
		// Honeypot — non-email name to avoid browser autofill, hidden from sighted
		// users + screen readers, taken out of tab order.
		?>
		<div aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;">
			<label
				for="wpify-woo-url-<?php echo esc_attr( $type ); ?>"><?php esc_html_e( 'Leave this field empty', 'wpify-woo' ); ?></label>
			<input type="text"
				   id="wpify-woo-url-<?php echo esc_attr( $type ); ?>"
				   name="wpify_woo_url"
				   value=""
				   tabindex="-1"
				   autocomplete="off">
		</div>

		<?php if ( $context['order_key'] ) : ?>
			<input type="hidden" name="order_key" value="<?php echo esc_attr( $context['order_key'] ); ?>">
		<?php endif; ?>
		<?php if ( $is_trusted && $has_order ) : ?>
			<input type="hidden" name="order_id_trusted" value="<?php echo esc_attr( $context['order']->get_id() ); ?>">
		<?php endif; ?>

		<p class="form-row form-row-first">
			<label for="wcr-name">
				<?php esc_html_e( 'Name', 'wpify-woo' ); ?>
				<?php echo $required_marker; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			</label>
			<input type="text" id="wcr-name" name="name" required value="<?php echo esc_attr( $context['name'] ); ?>"
				   autocomplete="name">
		</p>

		<p class="form-row form-row-last">
			<label for="wcr-email">
				<?php esc_html_e( 'Email used for the order', 'wpify-woo' ); ?>
				<?php echo $required_marker; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			</label>
			<input type="email" id="wcr-email" name="email" required
				   value="<?php echo esc_attr( $context['email'] ); ?>" autocomplete="email"
				   aria-describedby="wcr-email-hint-<?php echo esc_attr( $type ); ?>">
			<small id="wcr-email-hint-<?php echo esc_attr( $type ); ?>" class="form-row-hint">
				<?php esc_html_e( 'Must match the email used on the order.', 'wpify-woo' ); ?>
			</small>
		</p>

		<p class="form-row form-row-wide">
			<label for="wcr-order-number">
				<?php esc_html_e( 'Order number', 'wpify-woo' ); ?>
				<?php echo $required_marker; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			</label>
			<input type="text" id="wcr-order-number" name="order_number" required
				   value="<?php echo esc_attr( $context['order_number'] ); ?>"
				<?php echo $context['order_key'] ? 'readonly' : ''; ?>>
		</p>

		<?php if ( $can_show_form ) : ?>
			<?php // Eligibility section (period info + scope radio + items table) rendered by shared helper.
			echo $module->render_eligibility_section_html( $context['order'], $type ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally
			?>
		<?php endif; ?>

		<?php // Reason field — hidden in 2FA scenario until validation reveals items. ?>
		<p class="form-row form-row-wide wpify-woo-reason"<?php echo $can_show_form ? '' : ' hidden'; ?>>
			<label for="wcr-reason">
				<?php
				if ( $type === 'claim' ) {
					esc_html_e( 'Defect description', 'wpify-woo' );
					echo ' ' . $required_marker; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				} else {
					esc_html_e( 'Reason', 'wpify-woo' );
					echo ' <small>(' . esc_html__( 'optional', 'wpify-woo' ) . ')</small>';
				}
				?>
			</label>
			<textarea id="wcr-reason" name="reason" rows="4"
					  <?php
					  if ( $type === 'claim' ) {
						  echo $can_show_form ? 'required' : 'data-claim-required="1"';
					  }
					  ?>><?php echo esc_textarea( $context['reason'] ); ?></textarea>
		</p>

		<?php
		// Developer-defined extra fields (e.g., IBAN) — always rendered hidden,
		// the form JS reveals them together with the items section (whether after
		// /validate or on initial page load when items are already visible).
		$extra_schema = $module->get_extra_fields_schema( $type );
		if ( $extra_schema ) :
			$extra_values = is_array( $context['extra_fields'] ?? null ) ? $context['extra_fields'] : array();
			foreach ( $extra_schema as $extra_field ) :
				$extra_value = $extra_values[ $extra_field['id'] ] ?? '';
				?>
				<p class="form-row form-row-wide wpify-woo-extra-field wpify-woo-extra-field--<?php echo esc_attr( $extra_field['id'] ); ?>" hidden>
					<label for="<?php echo esc_attr( $extra_field['id'] ); ?>">
						<?php echo esc_html( $extra_field['label'] ); ?>
						<?php
						if ( ! empty( $extra_field['required'] ) ) {
							echo ' ' . $required_marker; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						}
						?>
					</label>
					<?php echo $module->render_extra_field_input( $extra_field, $extra_value ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally ?>
				</p>
				<?php
			endforeach;
		endif;
		?>

		<p class="form-row">
			<button type="submit"
					class="button button-primary"
					data-confirm-text="<?php echo esc_attr( $label_confirm ); ?>">
				<?php
				echo esc_html(
					$can_show_form
						? $label_confirm
						: __( 'Check order', 'wpify-woo' )
				);
				?>
			</button>
			<?php if ( ! $can_show_form ) : ?>
				<small class="wpify-woo-helper-text" style="display:block;margin-top:8px;">
					<?php esc_html_e( 'After validating your order number and email, the eligible items will be shown here.', 'wpify-woo' ); ?>
				</small>
			<?php endif; ?>
		</p>
	</form>
</section>
<?php
// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
