import { MessageType, PluginMessages } from './integratedMessages';
import {
  fetchDisableInternalTracking,
  trackConsent,
  disableInternalTracking,
  getBusinessUnitId,
  setBusinessUnitId,
  skipReview,
  refreshProxyMappingsCache,
  fetchProxyMappingsEnabled,
  toggleProxyMappingsEnabled,
} from '../api/wordpressApiClient';
import { removeQueryParamFromLocation } from '../utils/queryParams';
import { startActivation, startInstall } from '../utils/contentEmbedInstaller';

export type Message = { key: MessageType; payload?: any };

/*
 * We cannot postMessage error objects. We will run into serialization errors
 * Extract some properties we care about from the errors and create an error object from these
 */
function createSafeErrorPayload(
  error: any,
  defaultMessage: string = 'An error occurred'
) {
  const safePayload: any = {
    status: (error && error.status) || 500,
    statusText: (error && error.statusText) || 'Error',
    message:
      (error && error.responseJSON && error.responseJSON.message) ||
      (error && error.message) ||
      defaultMessage,
    code: error && error.responseJSON && error.responseJSON.code,
  };

  if (error && error.responseJSON && error.responseJSON.data) {
    safePayload.data = error.responseJSON.data;
  }

  return safePayload;
}

const messageMapper: Map<MessageType, Function> = new Map([
  [
    PluginMessages.TrackConsent,
    (message: Message) => {
      trackConsent(message.payload);
    },
  ],
  [
    PluginMessages.InternalTrackingChangeRequest,
    (message: Message, embedder: any) => {
      disableInternalTracking(message.payload)
        .then(() => {
          embedder.postMessage({
            key: PluginMessages.InternalTrackingFetchResponse,
            payload: message.payload,
          });
        })
        .catch(error => {
          // Extract only serializable properties from error. You cannot postMessage raw error obj with prototype methods
          embedder.postMessage({
            key: PluginMessages.InternalTrackingChangeError,
            payload: createSafeErrorPayload(error),
          });
        });
    },
  ],
  [
    PluginMessages.InternalTrackingFetchRequest,
    (__message: Message, embedder: any) => {
      fetchDisableInternalTracking()
        .then(({ message: payload }) => {
          embedder.postMessage({
            key: PluginMessages.InternalTrackingFetchResponse,
            payload,
          });
        })
        .catch(error => {
          embedder.postMessage({
            key: PluginMessages.InternalTrackingFetchError,
            payload: createSafeErrorPayload(error, 'Fetch error occurred'),
          });
        });
    },
  ],
  [
    PluginMessages.BusinessUnitFetchRequest,
    (__message: Message, embedder: any) => {
      getBusinessUnitId()
        .then(payload => {
          embedder.postMessage({
            key: PluginMessages.BusinessUnitFetchResponse,
            payload,
          });
        })
        .catch(error => {
          embedder.postMessage({
            key: PluginMessages.BusinessUnitFetchError,
            payload: createSafeErrorPayload(error, 'Business unit fetch error'),
          });
        });
    },
  ],
  [
    PluginMessages.BusinessUnitChangeRequest,
    (message: Message, embedder: any) => {
      setBusinessUnitId(message.payload)
        .then(payload => {
          embedder.postMessage({
            key: PluginMessages.BusinessUnitFetchResponse,
            payload,
          });
        })
        .catch(error => {
          embedder.postMessage({
            key: PluginMessages.BusinessUnitChangeError,
            payload: createSafeErrorPayload(
              error,
              'Business unit change error'
            ),
          });
        });
    },
  ],
  [
    PluginMessages.SkipReviewRequest,
    (__message: Message, embedder: any) => {
      skipReview()
        .then(payload => {
          embedder.postMessage({
            key: PluginMessages.SkipReviewResponse,
            payload,
          });
        })
        .catch(error => {
          embedder.postMessage({
            key: PluginMessages.SkipReviewError,
            payload: createSafeErrorPayload(error, 'Skip review error'),
          });
        });
    },
  ],
  [
    PluginMessages.RemoveParentQueryParam,
    (message: Message) => {
      removeQueryParamFromLocation(message.payload);
    },
  ],
  [
    PluginMessages.ContentEmbedInstallRequest,
    (message: Message, embedder: any) => {
      startInstall(message.payload.nonce)
        .then(payload => {
          embedder.postMessage({
            key: PluginMessages.ContentEmbedInstallResponse,
            payload: payload,
          });
        })
        .catch(error => {
          embedder.postMessage({
            key: PluginMessages.ContentEmbedInstallError,
            payload: createSafeErrorPayload(
              error,
              'Content embed install error'
            ),
          });
        });
    },
  ],
  [
    PluginMessages.ContentEmbedActivationRequest,
    (message: Message, embedder: any) => {
      startActivation(message.payload.activateAjaxUrl)
        .then(payload => {
          embedder.postMessage({
            key: PluginMessages.ContentEmbedActivationResponse,
            payload: payload,
          });
        })
        .catch(error => {
          embedder.postMessage({
            key: PluginMessages.ContentEmbedActivationError,
            payload: createSafeErrorPayload(
              error,
              'Content embed activation error'
            ),
          });
        });
    },
  ],
  [
    PluginMessages.RefreshProxyMappingsRequest,
    (__message: Message, embedder: any) => {
      refreshProxyMappingsCache()
        .then(() => {
          embedder.postMessage({
            key: PluginMessages.RefreshProxyMappingsResponse,
            payload: {},
          });
        })
        .catch(error => {
          embedder.postMessage({
            key: PluginMessages.RefreshProxyMappingsError,
            payload: createSafeErrorPayload(
              error,
              'Refresh proxy mappings error'
            ),
          });
        });
    },
  ],
  [
    PluginMessages.ProxyMappingsEnabledRequest,
    (__message: Message, embedder: any) => {
      fetchProxyMappingsEnabled()
        .then(payload => {
          embedder.postMessage({
            key: PluginMessages.ProxyMappingsEnabledResponse,
            payload,
          });
        })
        .catch(error => {
          embedder.postMessage({
            key: PluginMessages.ProxyMappingsEnabledError,
            payload: createSafeErrorPayload(
              error,
              'Proxy mappings enabled fetch error'
            ),
          });
        });
    },
  ],
  [
    PluginMessages.ProxyMappingsEnabledChangeRequest,
    ({ payload }: Message, embedder: any) => {
      toggleProxyMappingsEnabled(payload)
        .then(() => {
          embedder.postMessage({
            key: PluginMessages.ProxyMappingsEnabledResponse,
            payload,
          });
        })
        .catch(error => {
          embedder.postMessage({
            key: PluginMessages.ProxyMappingsEnabledChangeError,
            payload: createSafeErrorPayload(
              error,
              'Proxy mappings enabled change error'
            ),
          });
        });
    },
  ],
]);

export const messageMiddleware = (embedder: any) => (message: Message) => {
  const next = messageMapper.get(message.key);
  if (next) {
    next(message, embedder);
  }
};
