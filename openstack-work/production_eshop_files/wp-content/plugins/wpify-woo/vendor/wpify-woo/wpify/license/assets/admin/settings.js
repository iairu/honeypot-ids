import { addFilter } from '@wordpress/hooks';
import LicenseControl from './components/LicenseControl';
addFilter('wcf_field_license', 'wpify-woo', () => LicenseControl);
addFilter('wpifycf_field_license', 'wpify-woo', () => LicenseControl);
