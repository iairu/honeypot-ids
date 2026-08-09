import React from 'react';
import { useEffect, useState } from 'react';
import { __ } from '@wordpress/i18n';
import { fetchAccessToken } from '../api/wordpressApiClient';
import { getOrCreateBackgroundApp } from './backgroundAppUtils';
import { isRefreshTokenAvailable } from './isRefreshTokenAvailable';
import ErrorHandler from '../shared/Common/ErrorHandler';

export function useGetEmbedder() {
  const [embedder, setEmbedder] = useState<any>(null);
  const [errorStatus, setErrorStatus] = useState<number | null>(null);

  const loadEmbedder = () => {
    fetchAccessToken()
      .then(
        ({
          accessToken,
          expiresIn,
        }: {
          accessToken: string;
          expiresIn: number;
        }) => {
          setEmbedder(getOrCreateBackgroundApp(accessToken, expiresIn));
        }
      )
      .catch((err: any) => setErrorStatus((err && err.status) || 500));
  };

  useEffect(() => {
    if (isRefreshTokenAvailable()) {
      loadEmbedder();
    }
  }, []);

  const errorElement =
    errorStatus !== null
      ? React.createElement(ErrorHandler, {
          status: errorStatus,
          resetErrorState: () => {
            setErrorStatus(null);
            loadEmbedder();
          },
          errorInfo: {
            header: __('Unable to load HubSpot', 'leadin'),
            message: __(
              'There was a problem connecting to HubSpot. Please try again.',
              'leadin'
            ),
            action: __('Retry', 'leadin'),
          },
        })
      : null;

  return {
    embedder,
    errorElement,
    isLoading:
      isRefreshTokenAvailable() && embedder === null && errorStatus === null,
  };
}
