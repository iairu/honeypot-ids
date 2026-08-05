const restFetch = (path) => {
	const root = window.wpApiSettings && window.wpApiSettings.root ? window.wpApiSettings.root : '/wp-json/';
	const url = root.replace(/\/$/, '') + path;
	const headers = {};

	if (window.wpApiSettings && window.wpApiSettings.nonce) {
		headers['X-WP-Nonce'] = window.wpApiSettings.nonce;
	}

	return fetch(url, {
		method: 'GET',
		credentials: 'same-origin',
		headers,
	});
};

const initContainer = (container) => {
	if (container.dataset.init) {
		return;
	}
	container.dataset.init = '1';

	const links = container.querySelectorAll('.wpify-woo-delivery-date__line a');

	if (links) {
		links.forEach(link => {
			link.addEventListener('click', function (e) {
				e.preventDefault();
				container.querySelector('#' + link.dataset.id).classList.toggle('show');
			});
		});
	}

	const selects = container.querySelectorAll('select');
	const lines = container.querySelectorAll('.wpify-woo-delivery-date__line');
	const tables = container.querySelectorAll('.wpify-woo-delivery-date__shipping-methods');

	if (selects) {
		selects.forEach(select => {
			select.addEventListener('change', function (e) {
				const target = e.currentTarget;
				const value = target.value;
				const country = target.options[target.selectedIndex].dataset.country;

				selects.forEach(select => {
					if (select.value !== value) {
						select.value = value;
					}
				})

				if (lines) {
					lines.forEach(line => {
						const zones = line.dataset.zones;

						if (zones) {
							if (zones.includes(value)) {
								line.style.display = "block";
							} else {
								line.style.display = "none";
							}
						}
					});
				}

				if (tables) {
					tables.forEach(table => {
						const id = table.getAttribute('id');

						if (id.includes(value)) {
							table.classList.add('show');
						} else {
							table.classList.remove('show')
						}
					});
				}

				if (country) {
					restFetch(`/${wpifyDeliveryDates.namespace}/delivery-dates-country?country=${country}`).catch(() => {});
				}
			});
		});
	}
};

const initAll = () => {
	const containers = document.querySelectorAll('.wpify-woo-delivery-date');

	if (!containers) {
		return;
	}

	containers.forEach(container => {
		if (container.classList.contains('wpify-woo-delivery-date--async')) {
			if (container.dataset.loading) {
				return;
			}
			container.dataset.loading = '1';
			const productId = container.dataset.productId;

			if (!productId) {
				return;
			}

			restFetch(`/${wpifyDeliveryDates.namespace}/delivery-dates-render?product_id=${productId}`).then((response) => {
				if (!response || !response.ok) {
					throw new Error('Request failed');
				}
				return response.json();
			}).then((response) => {
				if (response && response.html) {
					container.outerHTML = response.html;
					initAll();
				}
			}).catch(() => {
				container.dataset.loading = '0';
			});

			return;
		}

		initContainer(container);
	});
};

initAll();
