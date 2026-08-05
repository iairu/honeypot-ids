import $ from 'jquery';

import Raven from '../lib/Raven';
import { restNonce, restUrl } from '../constants/leadinConfig';
import { addQueryObjectToUrl } from '../utils/queryParams';

function makeRequest(
  method: string,
  path: string,
  data: any = {},
  queryParams = {}
): Promise<any> {
  // eslint-disable-next-line compat/compat
  const restApiUrl = new URL(`${restUrl}leadin/v1${path}`);
  addQueryObjectToUrl(restApiUrl, queryParams);

  return new Promise((resolve, reject) => {
    const payload: { [key: string]: any } = {
      url: restApiUrl.toString(),
      method,
      contentType: 'application/json',
      beforeSend: (xhr: any) => xhr.setRequestHeader('X-WP-Nonce', restNonce),
      success: resolve,
      error: (response: any) => {
        Raven.captureMessage(
          `HTTP Request to ${restApiUrl} failed with error ${response.status}: ${response.responseText}`,
          {
            fingerprint: [
              '{{ default }}',
              path,
              response.status,
              response.responseText,
            ],
          }
        );
        reject(response);
      },
    };

    if (method !== 'get') {
      payload.data = JSON.stringify(data);
    }

    $.ajax(payload);
  });
}

export function healthcheckRestApi() {
  return makeRequest('get', '/healthcheck');
}

export function disableInternalTracking(value: boolean) {
  return makeRequest('put', '/internal-tracking', value ? '1' : '0');
}

export function fetchDisableInternalTracking() {
  return makeRequest('get', '/internal-tracking').then(message => ({
    message,
  }));
}

export function updateHublet(hublet: string) {
  return makeRequest('put', '/hublet', { hublet });
}

export function skipReview() {
  return makeRequest('post', '/skip-review');
}

export function trackConsent(canTrack: boolean) {
  return makeRequest('post', '/track-consent', { canTrack }).then(message => ({
    message,
  }));
}

export function setBusinessUnitId(businessUnitId: number) {
  return makeRequest('put', '/business-unit', { businessUnitId });
}

export function getBusinessUnitId() {
  return makeRequest('get', '/business-unit');
}

export function refreshProxyMappingsCache() {
  return makeRequest('post', '/wp-mappings-cache-reset');
}

export function fetchProxyMappingsEnabled() {
  return makeRequest('get', '/wp-mappings-proxy-enabled');
}

export function toggleProxyMappingsEnabled(value: boolean) {
  return makeRequest('put', '/wp-mappings-proxy-enabled', value);
}

const ACCESS_TOKEN_CACHE_KEY = 'leadin_access_token';
const ACCESS_TOKEN_MIN_TTL_SECONDS = 300;

let accessTokenRequest: Promise<any> | null = null;

export function fetchAccessToken() {
  try {
    const cached = sessionStorage.getItem(ACCESS_TOKEN_CACHE_KEY);
    if (cached) {
      const { accessToken, expiresAt } = JSON.parse(cached);
      if (
        accessToken &&
        expiresAt > Math.floor(Date.now() / 1000) + ACCESS_TOKEN_MIN_TTL_SECONDS
      ) {
        return Promise.resolve({
          accessToken,
          expiresIn: expiresAt - Math.floor(Date.now() / 1000),
        });
      }
    }
  } catch (_) {}

  if (!accessTokenRequest) {
    accessTokenRequest = makeRequest('get', '/access-token')
      .then((response: { accessToken: string; expiresIn: number }) => {
        try {
          sessionStorage.setItem(
            ACCESS_TOKEN_CACHE_KEY,
            JSON.stringify({
              accessToken: response.accessToken,
              expiresAt: Math.floor(Date.now() / 1000) + response.expiresIn,
            })
          );
        } catch (_) {}
        return response;
      })
      .finally(() => {
        accessTokenRequest = null;
      });
  }
  return accessTokenRequest;
}
