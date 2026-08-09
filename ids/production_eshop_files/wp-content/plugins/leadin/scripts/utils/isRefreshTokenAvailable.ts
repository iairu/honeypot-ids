import { connectionStatus } from '../constants/leadinConfig';

export function isRefreshTokenAvailable() {
  return connectionStatus === 'Connected';
}
