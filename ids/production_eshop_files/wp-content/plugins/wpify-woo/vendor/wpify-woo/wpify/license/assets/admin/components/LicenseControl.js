import React, {useEffect, useState} from 'react';
import {Button} from '@wordpress/components';
import {__} from '@wordpress/i18n';
import { dateI18n, getSettings } from '@wordpress/date';
import './LicenseControl.scss';

const LicenseControl = () => {
    const activated = window.wpifyWooLicenseSettings.activated;
    const [licenseDetails, setLicenseDetails] = useState(null);
    const dateSettings = getSettings();

    const fetchLicenseDetails = () => {
        try {
            const response = fetch(window.wpifyWooLicenseSettings.license_details_url).then(response => {
                if (response.status !== 200) {
                    return;
                }

                response.json().then(data => {
                    setLicenseDetails(data);
                });
            });
        } catch (e) {
        }
    };

    useEffect(() => {
        fetchLicenseDetails();
    }, []);

    // Primary source: stored data from PHP (affects actual functionality)
    const licenceValid = activated?.valid ?? false;
    const licenceUuid = activated?.license || licenseDetails?.item?.uuid;

    // Secondary source: API data (for display only)
    const subscriptionPay = licenseDetails?.subscription?.next_payment;
    const hasRenewal = subscriptionPay && subscriptionPay !== '0' && subscriptionPay !== 0;
    const formattedRenewal = hasRenewal
        ? dateI18n(dateSettings.formats.date, subscriptionPay)
        : __('Without renewal', 'wpify-license');

    const label = __('Status:', 'wpify-license') + ' ' + (
        activated
            ? (licenceValid === false ? __('Not valid', 'wpify-license') : __('Active', 'wpify-license'))
            : __('Not active', 'wpify-license')
    );
    const description = (
        activated
            ? __('Domain is connected with your subscription in WPify account.', 'wpify-license')
            : __('Please activate the domain by connecting it with your WPify account!', 'wpify-license')
    );
    const className = 'license-field ' + (activated ? (licenceValid === false ? 'warning' : 'active') : 'not-active');

    return (
        <div className={className}>
            <div className="license-field__text">
                <h3>{label}</h3>
                <p>{description}</p>
                {licenceValid === false && <p>
                    {__('The license is not valid, please go to your account and review your subscription .', 'wpify-license')}
                </p>}
                {licenceUuid && <p>
                    {__('Key:', 'wpify-license') + ' ' + licenceUuid}
                </p>}
                {licenseDetails?.subscription && <p>
                    {__('Renewal:', 'wpify-license') + ' ' + formattedRenewal}
                </p>} {
            }
            </div>
            {activated
                ? <Button href={window.wpifyWooLicenseSettings.deactivateUrl}
                          isPrimary>{__('Deactivate domain', 'wpify-license')}</Button>
                : <Button href={window.wpifyWooLicenseSettings.activateUrl}
                          isPrimary>{__('Activate domain', 'wpify-license')}</Button>
            }
        </div>
    );
};

export default LicenseControl;
