const path = require('path');

module.exports = {
  plugins: [
    [
      '@docusaurus/plugin-content-docs',
      {
        id: 'streams',
        path: path.resolve(__dirname, 'docs'),
        routeBasePath: 'streams',
        sidebarPath: path.resolve(__dirname, 'sidebars.js'),
        editUrl: 'https://github.com/iotaledger/streams/edit/develop/documentation',
      }
    ],
  ],
  staticDirectories: [path.resolve(__dirname, 'static')],
};
