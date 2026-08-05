import {addFilter} from '@wordpress/hooks';
import GenerateFeedControl from './components/GenerateFeedControl';
import LicenseControl from './components/LicenseControl';

console.log('AAAA')
addFilter('wpifycf_field_generate_feed', 'wpify-woo', Component => GenerateFeedControl);
addFilter('wpifycf_field_license', 'wpify-woo', Component => LicenseControl);
