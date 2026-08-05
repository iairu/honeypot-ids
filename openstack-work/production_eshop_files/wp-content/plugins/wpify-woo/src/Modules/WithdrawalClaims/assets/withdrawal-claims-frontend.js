/**
 * Frontend behavior for withdrawal & claim forms.
 *
 * Two AJAX flows:
 *   1. Untrusted (guest, no order_key) — first submit calls /validate to
 *      authenticate via order_number + billing email match. Server returns
 *      pre-rendered HTML for the eligibility section, which we inject inline.
 *      Subsequent submit calls /submit.
 *   2. Trusted (logged-in or order_key in URL) — items already rendered, every
 *      submit goes straight to /submit.
 *
 * Scope radio toggles items list visibility (5.5.1):
 *   - whole_order → items list hidden (server uses ALL eligible items)
 *   - specific_items → items list shown (user picks per item)
 *
 * Without JS, the form falls back to a regular POST that the server-side handler
 * processes (no inline reveal, no scope toggle, but submission still works).
 */
( function () {
	'use strict';

	var config = window.wpifyWooWcrConfig;
	if ( ! config ) {
		return;
	}

	var FORM_SELECTOR = 'form.woocommerce-form-withdrawal, form.woocommerce-form-claim';

	function init() {
		document.querySelectorAll( FORM_SELECTOR ).forEach( setupForm );
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}

	function setupForm( form ) {
		if ( form.dataset.wpifyWcrInit === '1' ) {
			return;
		}
		form.dataset.wpifyWcrInit = '1';

		form.addEventListener( 'submit', onSubmit );
		form.addEventListener( 'change', onChange );

		// Initial scope toggle state.
		applyScopeToggle( form );

		// My Account flow: items section is server-rendered, no /validate happens,
		// so reveal extra fields right away (mirrors what /validate reveal does).
		if ( form.querySelector( '.wpify-woo-items' ) ) {
			revealExtraFields( form );
		}
	}

	function revealExtraFields( form ) {
		form.querySelectorAll( '.wpify-woo-extra-field' ).forEach( function ( row ) {
			row.hidden = false;
		} );
		form.querySelectorAll( '[data-extra-required="1"]' ).forEach( function ( el ) {
			el.required = true;
			el.removeAttribute( 'data-extra-required' );
		} );
	}

	function onChange( e ) {
		if ( e.target && e.target.name === 'scope' ) {
			applyScopeToggle( e.currentTarget );
		}
	}

	function applyScopeToggle( form ) {
		var checked = form.querySelector( 'input[name="scope"]:checked' );
		if ( ! checked ) {
			return;
		}
		var items = form.querySelector( '.wpify-woo-items' );
		if ( ! items ) {
			return;
		}
		items.hidden = checked.value === 'whole_order';
	}

	function onSubmit( e ) {
		var form = e.currentTarget;
		e.preventDefault();

		// Browser HTML5 validation first — abort if invalid (keeps native UX).
		if ( typeof form.checkValidity === 'function' && ! form.checkValidity() ) {
			form.reportValidity();
			return;
		}

		var itemsRevealed = !! form.querySelector( '.wpify-woo-items' );
		var endpoint = itemsRevealed ? 'submit' : 'validate';

		clearMessages( form );
		showLoading( form );

		var data = collectFormData( form );

		fetch( config.restUrl + '/' + endpoint, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-WP-Nonce': config.restNonce,
			},
			body: JSON.stringify( data ),
			credentials: 'same-origin',
		} )
			.then( function ( response ) {
				return response.json().then( function ( body ) {
					return { status: response.status, body: body };
				} );
			} )
			.then( function ( payload ) {
				var result = payload.body;
				if ( result.ok ) {
					if ( endpoint === 'validate' ) {
						revealItemsSection( form, result );
					} else {
						showSuccessAndReplaceForm( form, result.message );
					}
				} else {
					var errors = ( result.errors && result.errors.length )
						? result.errors
						: [ config.i18n.genericError || 'Error.' ];
					showErrors( form, errors );
				}
			} )
			.catch( function () {
				showErrors( form, [ config.i18n.networkError ] );
			} )
			.then( function () {
				hideLoading( form );
			} );
	}

	function collectFormData( form ) {
		var fd = new FormData( form );
		var data = {};
		fd.forEach( function ( value, key ) {
			var arrayMatch = key.match( /^([^\[]+)\[([^\]]+)\]$/ );
			if ( arrayMatch ) {
				if ( ! data[ arrayMatch[ 1 ] ] ) {
					data[ arrayMatch[ 1 ] ] = {};
				}
				data[ arrayMatch[ 1 ] ][ arrayMatch[ 2 ] ] = value;
			} else {
				data[ key ] = value;
			}
		} );
		return data;
	}

	function revealItemsSection( form, result ) {
		// Persist returned identifiers in hidden fields so subsequent submit has them.
		if ( result.order_key ) {
			ensureHidden( form, 'order_key', result.order_key );
		}

		// Lock auth fields once validated.
		var orderInput = form.querySelector( 'input[name="order_number"]' );
		if ( orderInput && result.order_number ) {
			orderInput.value = result.order_number;
			orderInput.readOnly = true;
		}
		var emailInput = form.querySelector( 'input[name="email"]' );
		if ( emailInput && emailInput.value ) {
			emailInput.readOnly = true;
		}

		// Insert items_html before the reason row (or before submit row as fallback).
		var insertBefore = form.querySelector( 'textarea[name="reason"]' );
		if ( insertBefore ) {
			insertBefore = closestFormRow( insertBefore );
		}
		if ( ! insertBefore ) {
			insertBefore = form.querySelector( 'button[type="submit"]' );
			if ( insertBefore ) {
				insertBefore = closestFormRow( insertBefore );
			}
		}
		if ( ! insertBefore ) {
			return;
		}

		var wrapper = document.createElement( 'div' );
		wrapper.innerHTML = result.items_html || '';
		while ( wrapper.firstChild ) {
			insertBefore.parentNode.insertBefore( wrapper.firstChild, insertBefore );
		}

		// Apply scope toggle for the newly injected items section.
		applyScopeToggle( form );

		// Reveal the reason field (hidden until validation in 2FA scenario).
		var reasonField = form.querySelector( '.wpify-woo-reason' );
		if ( reasonField ) {
			reasonField.hidden = false;
			// Promote deferred required marker → real HTML5 required (claim type only).
			// Avoids checkValidity() failing on a hidden field in step 1.
			var reasonTextarea = reasonField.querySelector( 'textarea[name="reason"]' );
			if ( reasonTextarea && reasonTextarea.dataset.claimRequired === '1' ) {
				reasonTextarea.required = true;
				reasonTextarea.removeAttribute( 'data-claim-required' );
			}
		}

		// Reveal developer-defined extra fields and promote their deferred required markers.
		revealExtraFields( form );

		// Swap button text from "Check order" to the configured confirm text.
		// Clear dataset.originalText so the trailing hideLoading() doesn't revert.
		var submitBtn = form.querySelector( 'button[type="submit"]' );
		if ( submitBtn && submitBtn.dataset.confirmText ) {
			submitBtn.textContent = submitBtn.dataset.confirmText;
			delete submitBtn.dataset.originalText;
		}

		// Hide helper text — items are now revealed.
		var helper = form.querySelector( '.wpify-woo-helper-text' );
		if ( helper ) {
			helper.style.display = 'none';
		}
	}

	function ensureHidden( form, name, value ) {
		var input = form.querySelector( 'input[name="' + cssEscape( name ) + '"]' );
		if ( ! input ) {
			input = document.createElement( 'input' );
			input.type = 'hidden';
			input.name = name;
			form.insertBefore( input, form.firstChild );
		}
		input.value = value;
	}

	function closestFormRow( el ) {
		while ( el && el !== document.body ) {
			if ( el.classList && el.classList.contains( 'form-row' ) ) {
				return el;
			}
			el = el.parentNode;
		}
		return null;
	}

	function showSuccessAndReplaceForm( form, message ) {
		var section = form.closest( '.wpify-woo-form' );
		if ( ! section ) {
			return;
		}
		var p = document.createElement( 'p' );
		p.className = 'woocommerce-message';
		p.setAttribute( 'role', 'status' );
		p.textContent = message || '';
		section.innerHTML = '';
		section.appendChild( p );
		section.scrollIntoView( { behavior: 'smooth', block: 'center' } );
	}

	function showErrors( form, errors ) {
		clearMessages( form );
		var div = document.createElement( 'div' );
		div.className = 'woocommerce-error wpify-woo-form-errors';
		div.setAttribute( 'role', 'alert' );
		errors.forEach( function ( err ) {
			var p = document.createElement( 'p' );
			p.textContent = err;
			div.appendChild( p );
		} );
		form.parentNode.insertBefore( div, form );
		div.scrollIntoView( { behavior: 'smooth', block: 'center' } );
	}

	function clearMessages( form ) {
		var parent = form.parentNode;
		if ( ! parent ) {
			return;
		}
		parent.querySelectorAll( '.wpify-woo-form-errors' ).forEach( function ( el ) {
			el.remove();
		} );
	}

	function showLoading( form ) {
		form.classList.add( 'wpify-woo-form--loading' );
		form.querySelectorAll( 'button[type="submit"]' ).forEach( function ( btn ) {
			btn.disabled = true;
			if ( ! btn.dataset.originalText ) {
				btn.dataset.originalText = btn.textContent;
			}
			btn.textContent = config.i18n.loading || 'Working…';
		} );
	}

	function hideLoading( form ) {
		form.classList.remove( 'wpify-woo-form--loading' );
		form.querySelectorAll( 'button[type="submit"]' ).forEach( function ( btn ) {
			btn.disabled = false;
			if ( btn.dataset.originalText ) {
				btn.textContent = btn.dataset.originalText;
				delete btn.dataset.originalText;
			}
		} );
	}

	function cssEscape( s ) {
		return String( s ).replace( /(["\\])/g, '\\$1' );
	}
} )();
