import {useDispatch, useSelect} from '@wordpress/data';
import {createRoot} from 'react-dom/client';
import {useEffect, useState, useRef} from "react";
import {createPortal} from 'react-dom';

const {CART_STORE_KEY, CHECKOUT_STORE_KEY, COLLECTIONS_STORE_KEY, VALIDATION_STORE_KEY} = window.wc.wcBlocksData;

export const useCart = () => {
	return useSelect((select) => {
		const store = select(CART_STORE_KEY);
		return store.getCartData();
	}, []);
};
export const useAdditionalFields = () => {
	return useSelect((select) => {
		const store = select(CHECKOUT_STORE_KEY);
		return store.getAdditionalFields();
	}, []);
};
export const useCustomerData = () => {
	return useSelect((select) => {
		const store = select(CART_STORE_KEY);
		return store.getCustomerData();
	}, []);
};

export const useCollections = () => {
	return useSelect((select) => {
		const store = select(COLLECTIONS_STORE_KEY);
		return store;
	}, []);
};
export const useValidationError = (id) => {
	return useSelect((select) => {
		const store = select(VALIDATION_STORE_KEY);
		return store.getValidationError(id);
	}, []);
};


const App = () => {
	const {extensionCartUpdate} = window.wc.blocksCheckout;
	const [aresAdded, setAresAdded] = useState(false)
	const [aresError, setAresError] = useState()
	const [isAresLoading, setIsAresLoading] = useState()
	const [aresStatus, setAresStatus] = useState() // 'success', 'error', null
	const [viesError, setViesError] = useState()
	const [isViesLoading, setIsViesLoading] = useState()
	const [viesStatus, setViesStatus] = useState() // 'success', 'error', null
	const cart = useCart();
	const customer = useCustomerData();
	const additionalFields = useAdditionalFields();
	const {setAdditionalFields} = useDispatch(CHECKOUT_STORE_KEY);
	const {showValidationError, setValidationErrors, showAllValidationErrors} = useDispatch(VALIDATION_STORE_KEY);
	const {setBillingAddress, setShippingAddress} = useDispatch(CART_STORE_KEY);

	// Use ref to always have fresh additionalFields values in event handlers
	const additionalFieldsRef = useRef(additionalFields);
	const previousToggleRef = useRef(additionalFields?.['wpify/ic_dic_toggle']);

	useEffect(() => {
		additionalFieldsRef.current = additionalFields;
	}, [additionalFields]);

	const dicError = useValidationError('contact-wpify-dic');
	const companyFieldWrap = document.querySelector('.wc-block-components-address-form__wpify-company');
	const icFieldWrap = document.querySelector('.wc-block-components-address-form__wpify-ic');
	const dicFieldWrap = document.querySelector('.wc-block-components-address-form__wpify-dic');
	const dicDphFieldWrap = document.querySelector('.wc-block-components-address-form__wpify-dic-dph');
	const contactWrap = document.querySelector('.wc-block-components-address-form__wpify-ic');
	const aresWrap = document.querySelector('#wpify-ares');

	const companyField = document.querySelector('#contact-wpify-company');
	const icField = document.querySelector('#contact-wpify-ic');
	const dicField = document.querySelector('#contact-wpify-dic');
	const dicDphField = document.querySelector('#contact-wpify-dic-dph');

	useEffect(() => {
		if (!companyFieldWrap) {
			return;
		}

		if (dicDphFieldWrap) {
			dicDphFieldWrap.style.display = 'none';
		}

		const currentToggle = additionalFields?.['wpify/ic_dic_toggle'];
		const previousToggle = previousToggleRef.current;

		// Handle toggle change
		if (currentToggle !== previousToggle) {
			if (!currentToggle) {
				// Toggle turned OFF - hide and clear all fields
				companyFieldWrap.style.display = 'none';
				icFieldWrap.style.display = 'none';
				dicFieldWrap.style.display = 'none';

				const currentFields = additionalFieldsRef.current;
				setAdditionalFields({
					...currentFields,
					'wpify/company': '',
					'wpify/ic': '',
					'wpify/dic': '',
					'wpify/dic-dph': ''
				});
			} else {
				// Toggle turned ON - show fields and prefill company if available
				companyFieldWrap.style.removeProperty('display');
				icFieldWrap.style.removeProperty('display');
				dicFieldWrap.style.removeProperty('display');

				if (customer.billingAddress.company) {
					const currentFields = additionalFieldsRef.current;
					setAdditionalFields({
						...currentFields,
						'wpify/company': customer.billingAddress.company
					});
				}
			}

			previousToggleRef.current = currentToggle;
		} else {
			// Toggle didn't change, just update visibility
			if (!currentToggle) {
				companyFieldWrap.style.display = 'none';
				icFieldWrap.style.display = 'none';
				dicFieldWrap.style.display = 'none';
			} else {
				companyFieldWrap.style.removeProperty('display');
				icFieldWrap.style.removeProperty('display');
				dicFieldWrap.style.removeProperty('display');
			}
		}

		if (additionalFields?.['wpify/ic_dic_toggle'] && customer.billingAddress.country === 'SK') {
			dicDphFieldWrap.style.removeProperty('display');
		}

		// Show/hide ARES button based on settings and country
		if (aresWrap && additionalFields?.['wpify/ic_dic_toggle'] && customer.billingAddress.country === 'CZ') {
			// Check if ARES validation on IC entered is enabled
			const aresOnIcEntered = window.wpifyWooIcDic.validateAres &&
				Array.isArray(window.wpifyWooIcDic.validateAres) &&
				window.wpifyWooIcDic.validateAres.includes('ic_entered');

			// Show button only if ARES validation on IC entered is NOT enabled
			aresWrap.style.display = !aresOnIcEntered ? 'block' : 'none';
		} else if (aresWrap) {
			aresWrap.style.display = 'none';
		}

	}, [additionalFields, companyField, icField, dicField, dicDphField, companyFieldWrap, icFieldWrap, dicFieldWrap, dicDphFieldWrap, customer]);

	// Reset status indicators when fields become empty
	useEffect(() => {
		// Reset ARES status if IC field is empty
		if (!additionalFields['wpify/ic'] || additionalFields['wpify/ic'].trim() === '') {
			setAresStatus(null);
			setAresError(null);
		}

		// Reset VIES status if DIC fields are empty
		const currentDic = customer.billingAddress.country === 'SK'
			? additionalFields['wpify/dic-dph']
			: additionalFields['wpify/dic'];

		if (!currentDic || currentDic.trim() === '') {
			setViesStatus(null);
			setViesError(null);
		}
	}, [additionalFields, customer.billingAddress.country]);

	// Reset VAT exempt on page load - always reset first, then check DIC
	useEffect(() => {
		// Always reset VAT exempt on page load first
		extensionCartUpdate({
			namespace: 'wpify_ic_dic',
			data: {
				validation: 'dic_cleared',
				country: customer.billingAddress.country,
				shipping_country: customer.shippingAddress.country
			}
		});

		// Then check if there are any DIC values on page load
		const currentDic = customer.billingAddress.country === 'SK'
			? additionalFields['wpify/dic-dph']
			: additionalFields['wpify/dic'];

		if (currentDic && currentDic.trim() !== '') {
			// DIC exists on page load - validate it after a short delay
			setTimeout(() => {
				if (window.wpifyWooIcDic.validateVies) {
					validateDic(normalizeDic(currentDic));
				} else {
					// No VIES validation - just set VAT exempt based on settings
					extensionCartUpdate({
						namespace: 'wpify_ic_dic',
						data: {
							validation: 'passed',
							country: customer.billingAddress.country,
							shipping_country: customer.shippingAddress.country,
							dic: currentDic
						}
					});
				}
			}, 500);
		}
	}, []); // Run only once on component mount

	// Clear validation errors and recalculate VAT exempt when billing or shipping country changes
	useEffect(() => {
		// Clear ARES errors when switching away from Czech Republic
		if (customer.billingAddress.country !== 'CZ') {
			setAresError(null);
			setAresStatus(null);
		}

		// Clear VIES errors when country changes
		setViesError(null);
		setViesStatus(null);

		// Clear any validation errors from the store
		setValidationErrors({});

		// Clear IČ DPH field when switching away from Slovakia
		let updatedFields = {...additionalFields};
		if (customer.billingAddress.country !== 'SK' && updatedFields['wpify/dic-dph']) {
			updatedFields['wpify/dic-dph'] = '';
			setAdditionalFields(updatedFields);
		}

		// Get current DIC values AFTER clearing fields for country change
		const currentDic = customer.billingAddress.country === 'SK'
			? (updatedFields['wpify/dic-dph'] || '')
			: (updatedFields['wpify/dic'] || '');

		// Reset VAT exempt on country change with current DIC state
		// Include both billing and shipping country for PHP to determine which to use based on sale_type
		extensionCartUpdate({
			namespace: 'wpify_ic_dic',
			data: {
				validation: 'country_change',
				country: customer.billingAddress.country,
				shipping_country: customer.shippingAddress.country,
				dic: currentDic
			}
		});

		// Revalidate existing field values for the new country if any exist
		if (currentDic && currentDic.length >= 4 && window.wpifyWooIcDic.validateVies) {
			// Revalidate the existing DIC for the new country context
			// Add delay to allow country change to process
			setTimeout(() => {
				validateDic(normalizeDic(currentDic));
			}, 300);
		}

	}, [customer.billingAddress.country, customer.shippingAddress.country]);


	useEffect(() => {
		if (!contactWrap) {
			return;
		}
		const div = document.createElement('div');
		div.id = 'wpify-ares';
		contactWrap.appendChild(div);
		setAresAdded(true);
	}, [contactWrap]);


	function normalizeDic(dic) {
		dic = dic.replace('', ' ');
		dic = dic.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();

		if (!dic.match(/^[A-Z]{2}/)) {
			return customer.billingAddress.country + dic;
		}

		return dic;
	}

	function normalizeIc(ic) {
		ic = ic.replace('', ' ');
		ic = ic.replace(/\D/g, '');

		return ic;
	}

	useEffect(() => {
		if (!icField) {
			return;
		}

		let typingTimeout;

		const handleIcInputChange = (e) => {
			clearTimeout(typingTimeout);
			const inputValue = e.target.value; // Store value before setTimeout
			const targetElement = e.target; // Store target element

			typingTimeout = setTimeout(() => {
				const normalizedValue = normalizeIc(inputValue);

				// Update DOM to make normalization visible
				targetElement.value = normalizedValue;

				// Read fresh values from ref and update only IC field
				const currentFields = additionalFieldsRef.current;
				const newFields = {...currentFields, 'wpify/ic': normalizedValue};
				setAdditionalFields(newFields);

				// Only call ARES autofill for Czech companies and if ic_entered validation is enabled
				if (customer.billingAddress.country === 'CZ') {
					const aresOnIcEntered = window.wpifyWooIcDic.validateAres &&
						Array.isArray(window.wpifyWooIcDic.validateAres) &&
						window.wpifyWooIcDic.validateAres.includes('ic_entered');

					if (aresOnIcEntered) {
						autofillAres();
					}
				} else {
					// Clear any previous ARES errors when switching away from CZ
					setAresError(null);
				}
			}, 2000);
		};

		icField.addEventListener('input', handleIcInputChange);

		return () => {
			clearTimeout(typingTimeout);
			icField.removeEventListener('input', handleIcInputChange);
		};
	}, [icField, customer.billingAddress.country]);

	// Separate useEffect for DIC field - only updates 'wpify/dic'
	useEffect(() => {
		if (!dicField) {
			return;
		}

		let timeout;

		const handleInput = (e) => {
			clearTimeout(timeout);
			const inputValue = e.target.value; // Store value before setTimeout
			const targetElement = e.target; // Store target element

			timeout = setTimeout(() => {
				// For Slovakia: DIC is just a number, for others: has country prefix
				const isSlovakia = customer.billingAddress.country === 'SK';
				const normalizedValue = isSlovakia ? normalizeIc(inputValue) : normalizeDic(inputValue);

				// Update DOM to make normalization visible
				targetElement.value = normalizedValue;

				// Read fresh values from ref and update only DIC field
				const currentFields = additionalFieldsRef.current;
				const newFields = {...currentFields, 'wpify/dic': normalizedValue};
				setAdditionalFields(newFields);

				// Only validate for non-Slovakia countries
				if (!isSlovakia && normalizedValue && normalizedValue.length >= 4) {
					validateDic(normalizedValue);
				} else if (!normalizedValue || normalizedValue.length < 4) {
					extensionCartUpdate({
						namespace: 'wpify_ic_dic',
						data: {
							validation: 'dic_cleared',
							country: customer.billingAddress.country,
							shipping_country: customer.shippingAddress.country
						}
					});
				}
			}, 1500);
		};

		dicField.addEventListener('input', handleInput);
		return () => {
			clearTimeout(timeout);
			dicField.removeEventListener('input', handleInput);
		};
	}, [dicField, customer.billingAddress.country]);

	// Separate useEffect for DIC DPH field - only updates 'wpify/dic-dph'
	useEffect(() => {
		if (!dicDphField) {
			return;
		}

		let timeout;

		const handleInput = (e) => {
			clearTimeout(timeout);
			const inputValue = e.target.value; // Store value before setTimeout
			const targetElement = e.target; // Store target element

			timeout = setTimeout(() => {
				const normalizedValue = normalizeDic(inputValue);

				// Update DOM to make normalization visible
				targetElement.value = normalizedValue;

				// Read fresh values from ref and update only DIC DPH field
				const currentFields = additionalFieldsRef.current;
				const newFields = {...currentFields, 'wpify/dic-dph': normalizedValue};
				setAdditionalFields(newFields);

				if (normalizedValue && normalizedValue.length >= 4) {
					validateDic(normalizedValue);
				} else {
					extensionCartUpdate({
						namespace: 'wpify_ic_dic',
						data: {
							validation: 'dic_cleared',
							country: customer.billingAddress.country,
							shipping_country: customer.shippingAddress.country
						}
					});
				}
			}, 1500);
		};

		dicDphField.addEventListener('input', handleInput);
		return () => {
			clearTimeout(timeout);
			dicDphField.removeEventListener('input', handleInput);
		};
	}, [dicDphField]);


	function fetchJson(url, options) {
		return new Promise((resolve, reject) => {
			fetch(url, options)
				.then(response => {
					if (response.ok) {
						response.json().then(resolve);
					} else {
						response.json().then(json => reject(json.message));
					}
				})
				.catch(reject);
		});
	}

	function validateDic(dic) {
		setViesError(null);
		setViesStatus(null);

		// Check if VIES validation is enabled in settings
		if (!window.wpifyWooIcDic.validateVies) {
			// VIES validation is disabled, don't validate
			return;
		}

		// Skip validation if DIC is empty or too short
		if (!dic || dic.length < 4) {
			return;
		}

		setIsViesLoading(true);
		if (window.wpifyWooIcDic.restUrl) {
			fetchJson(window.wpifyWooIcDic.restUrl + '/icdic-vies?in=' + dic)
				.then((response) => {
					const validation = response.validation || {};
					const warning = response.warning || null;

					// Clear previous errors if validation passed, show warning if present
					if (validation === 'passed' && !warning) {
						setViesError(null); // Clear any previous errors
						setViesStatus('success');
					} else if (warning) {
						setViesError(warning);
						setViesStatus('error');
					}

					// Don't overwrite field values - the user already entered the correct value
					// The validation is just confirming it's valid, not changing it
					// Let WooCommerce handle the field values naturally

					// Get country from the validated DIC value instead of customer object to ensure accuracy
					const dicCountry = dic.match(/^[A-Z]{2}/) ? dic.substring(0, 2) : customer.billingAddress.country;

					extensionCartUpdate({
						namespace: 'wpify_ic_dic',
						data: {
							validation: validation,
							country: dicCountry,
							shipping_country: customer.shippingAddress.country,
							dic: dic
						}
					})

					const evt = new CustomEvent("wpify_woo_ic_dic_vies_valid", {
						detail: {
							validation: validation,
							warning: warning
						}
					});
					window.dispatchEvent(evt);
				})
				.catch(error => {
					// Only show error as warning, don't block checkout
					// Final validation will happen server-side
					setViesError(error);
					setViesStatus('error');

					// Reset VAT exempt when VIES validation fails
					extensionCartUpdate({
						namespace: 'wpify_ic_dic',
						data: {
							validation: 'failed',
							country: customer.billingAddress.country,
							shipping_country: customer.shippingAddress.country,
							dic: dic
						}
					});
				})
				.finally(() => {
					setIsViesLoading(false);
				});
		}
	}

	const autofillAres = () => {
		// ARES is only for Czech companies
		if (customer.billingAddress.country !== 'CZ') {
			return;
		}

		setAresError(null);
		setAresStatus(null);
		setIsAresLoading(true);
		const ic = normalizeIc(additionalFieldsRef.current['wpify/ic']);
		fetchJson(window.wpifyWooIcDic.restUrl + '/icdic?in=' + ic)
			.then(({details = {}}) => {
				// Read fresh values from ref and only update ARES fields
				const currentFields = additionalFieldsRef.current;
				const newFields = {
					...currentFields,
					'wpify/company': details.billing_company,
					'wpify/ic': details.billing_ic,
					'wpify/dic': details.billing_dic
				};

				setAdditionalFields(newFields);

				// Only validate DIC if we have one and VIES validation is enabled
				if (details.billing_dic && window.wpifyWooIcDic.validateVies) {
					// Add small delay to ensure fields are updated first
					setTimeout(() => {
						validateDic(normalizeDic(details.billing_dic));
					}, 100);
				}

				const address = {
					company: details.billing_company,
					address_1: details.billing_address_1,
					city: details.billing_city,
					postcode: details.billing_postcode,
				};

				setBillingAddress(address);
				setShippingAddress(address);
				const evt = new CustomEvent("wpify_woo_ic_dic_ares_autofilled", {
					detail: {
						details: details,
					}
				});
				window.dispatchEvent(evt);
				setAresStatus('success');
			})
			.catch(error => {
				setAresError(error);
				setAresStatus('error');
			})
			.finally(() => {
				setIsAresLoading(false);
			});

	}
	// Create status indicator component
	const StatusIndicator = ({isLoading, status, error, fieldValue}) => {
		// Only show status indicators when field has content
		if (!fieldValue || fieldValue.trim() === '') {
			return null;
		}

		if (isLoading) {
			return (
				<div style={{
					position: 'absolute',
					top: '50%', right: '14px',
					transform: 'translateY(-50%)',
					color: '#0073aa'
				}}>
					<span style={{
						display: 'inline-block',
						width: '16px',
						height: '16px',
						border: '2px solid #f3f3f3',
						borderTop: '2px solid #0073aa',
						borderRadius: '50%',
						animation: 'spin 1s linear infinite'
					}}></span>
					<style>{`
						@keyframes spin {
							0% { transform: rotate(0deg); }
							100% { transform: rotate(360deg); }
						}
					`}</style>
				</div>
			);
		}

		if (status === 'success') {
			return (
				<div style={{
					position: 'absolute',
					top: '50%', right: '14px',
					transform: 'translatey(-50%)',
					color: '#46b450'
				}}>
					<span>✓</span>
				</div>
			);
		}

		if (status === 'error' || error) {
			return (
				<div style={{
					position: 'absolute',
					top: '50%', right: '14px',
					transform: 'translatey(-50%)',
					color: '#dc3232'}}>
					<span>!</span>
				</div>
			);
		}

		return null;
	};

	if (!aresAdded) {
		return null;
	}

	return (
		<div>
			{icFieldWrap && createPortal(
				<>
					<StatusIndicator
						isLoading={isAresLoading}
						status={aresStatus}
						error={aresError}
						fieldValue={additionalFields['wpify/ic']}
					/>
					{aresError && additionalFields['wpify/ic'] && <p style={{color: '#dc3232', fontSize: '14px', marginTop: '4px'}}>{aresError}</p>}
				</>,
				icFieldWrap
			)}

			{/* ARES button positioned after IC field */}
			{icFieldWrap && additionalFields?.['wpify/ic_dic_toggle'] && customer.billingAddress.country === 'CZ' && (() => {
				const aresOnIcEntered = window.wpifyWooIcDic.validateAres &&
					Array.isArray(window.wpifyWooIcDic.validateAres) &&
					window.wpifyWooIcDic.validateAres.includes('ic_entered');

				if (!aresOnIcEntered) {
					// Create a wrapper div that will be positioned right after the IC field
					let aresButtonWrapper = document.querySelector('.wpify-ares-button-wrapper');
					if (!aresButtonWrapper) {
						aresButtonWrapper = document.createElement('div');
						aresButtonWrapper.className = 'wpify-ares-button-wrapper';
						icFieldWrap.insertAdjacentElement('afterend', aresButtonWrapper);
					}

					return createPortal(
						<div style={{marginTop: '8px'}}>
							<input type="button" className="button wp-element-button" onClick={() => autofillAres()}
								   value={window.wpifyWooIcDic.searchAresText}
							/>
						</div>,
						aresButtonWrapper
					);
				}
				return null;
			})()}

			{createPortal(
				<>
					<StatusIndicator
						isLoading={isViesLoading}
						status={viesStatus}
						error={viesError}
						fieldValue={customer.billingAddress.country === 'SK' ? additionalFields['wpify/dic-dph'] : additionalFields['wpify/dic']}
					/>
					{viesError && (customer.billingAddress.country === 'SK' ? additionalFields['wpify/dic-dph'] : additionalFields['wpify/dic']) && <p style={{color: '#dc3232', fontSize: '14px', marginTop: '4px'}}>{viesError}</p>}
				</>,
				customer.billingAddress.country === 'SK' ? dicDphFieldWrap : dicFieldWrap
			)}
		</div>
	);
}

document.querySelectorAll('[data-app="wpify-ic-dic"]').forEach(function (el) {
	const root = createRoot(el)
	root.render(<App/>);
});




