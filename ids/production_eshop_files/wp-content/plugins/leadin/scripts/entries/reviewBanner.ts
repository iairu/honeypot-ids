import $ from 'jquery';
import {
  getOrCreateBackgroundApp,
  initBackgroundApp,
} from '../utils/backgroundAppUtils';
import { domElements } from '../constants/selectors';
import { connectionStatus, activationTime } from '../constants/leadinConfig';
import { fetchAccessToken } from '../api/wordpressApiClient';
import { ProxyMessages } from '../iframe/integratedMessages';

const REVIEW_BANNER_INTRO_PERIOD_DAYS = 15;

const userIsAfterIntroductoryPeriod = () => {
  const activationDate = new Date(+activationTime * 1000);
  const currentDate = new Date();
  const timeElapsed = new Date(
    currentDate.getTime() - activationDate.getTime()
  );

  return timeElapsed.getUTCDate() - 1 >= REVIEW_BANNER_INTRO_PERIOD_DAYS;
};

/**
 * Adds some methods to window when review banner is
 * displayed to monitor events
 */
export function initMonitorReviewBanner() {
  if (connectionStatus !== 'Connected') return;

  fetchAccessToken()
    .then(
      ({
        accessToken,
        expiresIn,
      }: {
        accessToken: string;
        expiresIn: number;
      }) => {
        const embedder = getOrCreateBackgroundApp(accessToken, expiresIn);
        const container = $(domElements.reviewBannerContainer);
        if (container && userIsAfterIntroductoryPeriod()) {
          $(domElements.reviewBannerLeaveReviewLink)
            .off('click')
            .on('click', () => {
              embedder.postMessage({
                key: ProxyMessages.TrackReviewBannerInteraction,
              });
            });

          $(domElements.reviewBannerDismissButton)
            .off('click')
            .on('click', () => {
              embedder.postMessage({
                key: ProxyMessages.TrackReviewBannerDismissed,
              });
            });

          embedder
            .postAsyncMessage({
              key: ProxyMessages.FetchContactsCreateSinceActivation,
              payload: +activationTime * 1000,
            })
            .then(({ total }: any) => {
              if (total >= 5) {
                container.removeClass('leadin-review-banner--hide');
                embedder.postMessage({
                  key: ProxyMessages.TrackReviewBannerRender,
                });
              }
            });
        }
      }
    )
    .catch(err =>
      console.error('[leadin] Failed to load review banner embedder:', err)
    );
}

initBackgroundApp(initMonitorReviewBanner);
