/**
 * Editor registration for Withdrawal & Claim form blocks.
 *
 * Both blocks use ServerSideRender for live preview in the editor — actual HTML
 * comes from the PHP `render_callback` (the same shortcode rendering used on the
 * front end). No save() output — these are dynamic blocks.
 */
( function ( blocks, element, blockEditor, serverSideRender, i18n ) {
	const el = element.createElement;
	const ServerSideRender = serverSideRender;
	const useBlockProps = blockEditor.useBlockProps;
	const __ = i18n.__;

	function makeEdit( blockName, placeholder ) {
		return function () {
			const blockProps = useBlockProps();
			return el(
				'div',
				blockProps,
				el( ServerSideRender, {
					block: blockName,
					EmptyResponsePlaceholder: function () {
						return el(
							'div',
							{
								style: {
									padding: '12px',
									border: '1px dashed #ccc',
									textAlign: 'center',
									color: '#646970',
								},
							},
							placeholder
						);
					},
				} )
			);
		};
	}

	blocks.registerBlockType( 'wpify-woo/withdrawal-form', {
		edit: makeEdit(
			'wpify-woo/withdrawal-form',
			__( 'Withdrawal form (rendered on the front end).', 'wpify-woo' )
		),
		save: function () {
			return null;
		},
	} );

	blocks.registerBlockType( 'wpify-woo/claim-form', {
		edit: makeEdit(
			'wpify-woo/claim-form',
			__( 'Claim form (rendered on the front end).', 'wpify-woo' )
		),
		save: function () {
			return null;
		},
	} );
} )(
	window.wp.blocks,
	window.wp.element,
	window.wp.blockEditor,
	window.wp.serverSideRender,
	window.wp.i18n
);
