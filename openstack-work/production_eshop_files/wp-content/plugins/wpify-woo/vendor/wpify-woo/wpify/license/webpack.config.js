const defaultConfig = require('@wordpress/scripts/config/webpack.config');

module.exports = {
  ...defaultConfig,
  entry: {
    'settings': [
      './assets/admin/settings.js',
      './assets/admin/settings.scss',
    ],
  },
};
