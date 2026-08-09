const NOTICE_SELECTOR = '.wpify-woo-free-shipping-notice__wrapper';

export const getCartStoreKey = (wcBlocksData = window.wc?.wcBlocksData || {}) =>
	wcBlocksData.CART_STORE_KEY || wcBlocksData.cartStore || 'wc/store/cart';

export const getFreeShippingNoticeHtml = (cartData) => {
	const html = cartData?.extensions?.wpifyWoo?.freeShippingNoticeHtml;

	return typeof html === 'string' ? html : '';
};

export const updateFreeShippingNoticeBlocks = (html) => {
	if (!html) {
		return;
	}

	document.querySelectorAll(NOTICE_SELECTOR).forEach((notice) => {
		if (notice.outerHTML === html) {
			return;
		}

		notice.outerHTML = html;
	});
};

const getCartData = (data, wcBlocksData) =>
	data?.select?.(getCartStoreKey(wcBlocksData))?.getCartData?.();

export const initializeFreeShippingNoticeBlockRefresh = ({
	data = window.wp?.data,
	wcBlocksData = window.wc?.wcBlocksData || {},
} = {}) => {
	if (typeof data?.subscribe !== 'function' || typeof data?.select !== 'function') {
		return undefined;
	}

	let lastHtml = getFreeShippingNoticeHtml(getCartData(data, wcBlocksData));

	updateFreeShippingNoticeBlocks(lastHtml);

	return data.subscribe(() => {
		const html = getFreeShippingNoticeHtml(getCartData(data, wcBlocksData));

		if (html === lastHtml) {
			return;
		}

		lastHtml = html;
		updateFreeShippingNoticeBlocks(html);
	});
};

const initializeWhenReady = () => {
	initializeFreeShippingNoticeBlockRefresh();
};

if (document.readyState === 'loading') {
	document.addEventListener('DOMContentLoaded', initializeWhenReady, { once: true });
} else {
	initializeWhenReady();
}
