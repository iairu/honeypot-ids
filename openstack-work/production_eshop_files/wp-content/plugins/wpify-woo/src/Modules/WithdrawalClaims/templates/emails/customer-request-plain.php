<?php
/**
 * Customer withdrawal/claim email — plain text.
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

echo "= " . esc_html( $email_heading ) . " =\n\n";

if ( $request && $order ) {
	if ( ! empty( $intro_content ) ) {
		echo esc_html( wp_strip_all_tags( wptexturize( $intro_content ) ) ) . "\n\n";
	}

	echo esc_html__( 'Type', 'wpify-woo' ) . ': ' . esc_html( $request->type_label() ) . "\n";
	echo esc_html__( 'Submitted at', 'wpify-woo' ) . ': ' . esc_html( $submitted_at_formatted ) . "\n";
	echo esc_html__( 'Order number', 'wpify-woo' ) . ': ' . esc_html( $request->order_number ) . "\n";
	echo esc_html__( 'Customer', 'wpify-woo' ) . ': ' . esc_html( $request->customer_name . ' <' . $request->customer_email . '>' ) . "\n";

	if ( ! empty( $request->reason ) ) {
		echo "\n" . esc_html__( 'Reason / description', 'wpify-woo' ) . ":\n";
		echo esc_html( $request->reason ) . "\n";
	}

	foreach ( ( $extra_fields ?? array() ) as $extra ) {
		echo esc_html( $extra['label'] ) . ': ' . esc_html( $extra['value'] ) . "\n";
	}

	if ( ! empty( $request_items ) ) {
		echo "\n" . esc_html__( 'Items', 'wpify-woo' ) . ":\n";
		foreach ( $request_items as $row ) {
			echo '- ' . esc_html( $row['name'] ) . ' × ' . (int) $row['quantity'] . "\n";
		}
	}
}

if ( ! empty( $additional_content ) ) {
	echo "\n" . esc_html( wp_strip_all_tags( wptexturize( $additional_content ) ) ) . "\n";
}

echo "\n" . esc_html( wp_strip_all_tags( get_option( 'blogname' ) ) );

// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
